// Package gnndataset accumulates GNN training examples that are collected
// during ordinary APK scans.
//
// Every call to [Writer.Append] atomically appends one JSONL record that
// contains the full raw graph tensor (CSR row-pointers, column indices, edge
// types, node feature vectors) alongside the model's current prediction and
// per-class probabilities.  The label field defaults to the predicted class,
// but can be corrected offline before re-training (set "label_confirmed":true
// after validation to distinguish reviewed rows from auto-labeled ones).
//
// The format is deliberately human-readable JSON Lines so you can:
//   - open it in any text editor or Python/Pandas and inspect entries,
//   - mark false-positives by editing "label" and setting "label_confirmed",
//   - feed the file directly to gnn-train via --dataset.
//
// File rotation: a new shard is started when the current shard exceeds
// maxShardBytes (default 64 MB).  Shards are named
//
//	gnn_dataset_YYYYMMDD_HHMMSS_<seq>.jsonl
//
// and written under ~/.analyzer/gnn-dataset/ (or a custom directory).
package gnndataset

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// DefaultDir is the sub-directory under the user home where shards land.
	DefaultDir = ".analyzer/gnn-dataset"

	// maxShardBytes is the soft cap after which a new shard is opened.
	maxShardBytes int64 = 64 * 1024 * 1024 // 64 MB

	// maxDatasetBytes is the total on-disk budget for the whole dataset
	// directory (shards left by previous runs included). Once reached,
	// Append returns ErrDatasetFull instead of growing the directory
	// without bound on every scan.
	maxDatasetBytes int64 = 1024 * 1024 * 1024 // 1 GB
)

// ErrDatasetFull is returned by [Writer.Append] once the dataset directory
// has reached maxDatasetBytes. Callers should treat it as a signal to stop
// collecting examples for this run, not as a scan failure.
var ErrDatasetFull = errors.New("gnndataset: dataset directory reached its size cap")

// Example is one JSONL record written to the dataset.
type Example struct {
	// Unique identifier — SHA-256 hex of the graph tensor (reuses gnncache key).
	GraphHash string `json:"graph_hash"`

	// Provenance fields — useful for debugging and deduplication.
	APKPath    string `json:"apk_path,omitempty"`
	MethodName string `json:"method_name,omitempty"`
	FilePath   string `json:"file_path,omitempty"`
	ScannedAt  string `json:"scanned_at"` // RFC3339

	// Raw graph tensor in CSR format.
	NumNodes   uint64      `json:"num_nodes"`
	FeatureDim uint64      `json:"feature_dim"`
	RowPtrs    []uint64    `json:"row_ptr"`
	ColIndices []uint64    `json:"col_idx"`
	EdgeTypes  []uint32    `json:"edge_types"`
	Features   [][]float32 `json:"features"` // [num_nodes][feature_dim]

	// FeatureSchema records the node-feature layout used to build this
	// tensor (see gnngraph.FeatureSchemaID). Empty means legacy (pre-v2);
	// the trainer refuses to mix a foreign schema into a training set.
	FeatureSchema string `json:"feature_schema,omitempty"`

	// Model prediction (auto-label).
	PredictedLabel int       `json:"label"` // index into VULN_CLASSES
	LabelName      string    `json:"label_name"`
	Confidence     float32   `json:"confidence"`
	ClassProbs     []float32 `json:"class_probs,omitempty"`

	// Human review fields — false by default, set to true after validation.
	LabelConfirmed bool   `json:"label_confirmed"`
	Notes          string `json:"notes,omitempty"`
}

// Writer is a thread-safe JSONL shard writer.
type Writer struct {
	mu        sync.Mutex
	dir       string
	seq       int
	f         *os.File
	written   int64
	total     int64 // bytes across all shards in dir, incl. previous runs
	startTime time.Time
}

// DefaultWriterDir returns the default dataset directory under the user's home.
func DefaultWriterDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, DefaultDir)
}

// Open creates (or re-opens) a Writer that appends to shards under dir.
func Open(dir string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("gnndataset: create dir %q: %w", dir, err)
	}
	w := &Writer{dir: dir, startTime: time.Now()}
	// Account for shards left by previous runs, so maxDatasetBytes bounds the
	// whole directory rather than only this process's writes.
	if entries, rerr := os.ReadDir(dir); rerr == nil {
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".jsonl" {
				continue
			}
			if info, ierr := entry.Info(); ierr == nil {
				w.total += info.Size()
			}
		}
	}
	return w, nil
}

// Append writes one example to the current shard and rotates if needed.
// It is safe to call from multiple goroutines.
func (w *Writer) Append(ex *Example) error {
	if ex.ScannedAt == "" {
		ex.ScannedAt = time.Now().UTC().Format(time.RFC3339)
	}
	data, err := json.Marshal(ex)
	if err != nil {
		return fmt.Errorf("gnndataset: marshal: %w", err)
	}
	data = append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.total+int64(len(data)) > maxDatasetBytes {
		return ErrDatasetFull
	}
	if w.f == nil {
		if err := w.openShard(); err != nil {
			return err
		}
	} else if w.written > 0 && w.written+int64(len(data)) > maxShardBytes {
		if rerr := w.rotateLocked(); rerr != nil {
			return rerr
		}
	}
	n, err := w.f.Write(data)
	if err != nil {
		return fmt.Errorf("gnndataset: write: %w", err)
	}
	w.written += int64(n)
	w.total += int64(n)
	return nil
}

// Close flushes and closes the current shard.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		err := w.f.Close()
		w.f = nil
		return err
	}
	return nil
}

func (w *Writer) openShard() error {
	ts := w.startTime.UTC().Format("20060102_150405")
	name := fmt.Sprintf("gnn_dataset_%s_%03d.jsonl", ts, w.seq)
	path := filepath.Join(w.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("gnndataset: open shard %q: %w", path, err)
	}
	// Track existing size so the soft-cap logic accounts for pre-existing data.
	fi, err := f.Stat()
	if err == nil {
		w.written = fi.Size()
	}
	w.f = f
	return nil
}

func (w *Writer) rotateLocked() error {
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("gnndataset: close shard: %w", err)
	}
	w.seq++
	w.written = 0
	return w.openShard()
}

// FlattenFeatures converts a flat feature slice (len = numNodes * featureDim)
// into a 2-D [][]float32.  It returns nil on dimension mismatch.
func FlattenFeatures(flat []float32, numNodes, featureDim uint64) [][]float32 {
	if numNodes == 0 || featureDim == 0 {
		return nil
	}
	if uint64(len(flat)) != numNodes*featureDim {
		return nil
	}
	out := make([][]float32, numNodes)
	for i := range out {
		start := uint64(i) * featureDim
		out[i] = flat[start : start+featureDim]
	}
	return out
}
