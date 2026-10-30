package experimental

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// BINARY SIMILARITY MODULE
// ═══════════════════════════════════════════════════════════════════════════════
//
// We use a dual-fingerprint scheme:
//
//   1. ssdeep-style rolling chunk digest — fast, robust to small edits.
//   2. K-shingled SHA-256 over instruction-grams (mimicked here via byte
//      n-grams since we don't run a disassembler in-tree). Gives us a
//      Jaccard estimate between binary blobs.
//
// The module's goal is NOT to be a research-grade BinDiff replacement. It is
// to flag clones and near-duplicates inside a single APK / IPA bundle so the
// rest of the analyzer can deduplicate or focus its effort.

// BinSimModule implements Module.
type BinSimModule struct{}

// NewBinSimModule constructs the module.
func NewBinSimModule() *BinSimModule { return &BinSimModule{} }

func (m *BinSimModule) ID() string   { return "binsim" }
func (m *BinSimModule) Name() string { return "Binary Similarity" }
func (m *BinSimModule) Description() string {
	return "Find clones and near-duplicates across native libraries and DEX shards"
}
func (m *BinSimModule) Aliases() []string { return []string{"clones", "dup", "similarity", "2"} }
func (m *BinSimModule) Tier() string      { return "experimental" }

const (
	binsimMinSize     = 4 * 1024         // smaller files are noise
	binsimMaxSize     = 64 * 1024 * 1024 // 64 MiB cap, anything larger is sampled
	binsimChunk       = 4 * 1024
	binsimNgram       = 8
	binsimMaxShingles = 4096
	binsimMinJaccard  = 0.65
)

// fingerprint is the per-file similarity fingerprint.
type fingerprint struct {
	Path     string
	Size     int64
	SHA256   string
	Chunks   []uint32 // rolling chunk digests
	Shingles map[uint64]struct{}
}

// Run implements Module.Run.
func (m *BinSimModule) Run(ctx context.Context, in Input) (*ModuleResult, error) {
	res := &ModuleResult{
		ModuleID:   m.ID(),
		ModuleName: m.Name(),
		Tier:       m.Tier(),
	}
	if in.TargetDir == "" {
		res.Skipped = true
		res.SkipReason = "no target directory"
		return res, nil
	}

	candidates, err := collectBinSimCandidates(ctx, in.TargetDir)
	if err != nil {
		return res, err
	}
	res.Bump("candidates", len(candidates))
	if len(candidates) < 2 {
		res.Notes = append(res.Notes, "Need at least two candidate binaries to compute similarity.")
		return res, nil
	}

	prints := make([]*fingerprint, 0, len(candidates))
	for _, path := range candidates {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		fp, err := fingerprintFile(path)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			continue
		}
		prints = append(prints, fp)
	}
	res.Bump("fingerprinted", len(prints))

	// First, exact duplicates by SHA-256.
	bySHA := make(map[string][]*fingerprint)
	for _, fp := range prints {
		bySHA[fp.SHA256] = append(bySHA[fp.SHA256], fp)
	}
	for _, group := range bySHA {
		if len(group) < 2 {
			continue
		}
		emitExactClone(res, group, in.TargetDir)
	}

	// Then near-duplicates via Jaccard over shingles.
	emitNearClones(res, prints, in.TargetDir)

	return res, nil
}

func collectBinSimCandidates(ctx context.Context, root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if !looksLikeBinary(d.Name(), path) {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		if info.Size() < binsimMinSize {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func looksLikeBinary(name, path string) bool {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".so"),
		strings.HasSuffix(lower, ".dex"),
		strings.HasSuffix(lower, ".dylib"),
		strings.HasSuffix(lower, ".a"),
		strings.HasSuffix(lower, ".o"),
		strings.HasSuffix(lower, ".bin"):
		return true
	}
	// Treat extensionless executables under /lib or /Frameworks as binary.
	if !strings.Contains(lower, ".") {
		if strings.Contains(path, "/lib/") || strings.Contains(path, "/Frameworks/") ||
			strings.Contains(path, "\\lib\\") || strings.Contains(path, "\\Frameworks\\") {
			return true
		}
	}
	return false
}

func fingerprintFile(path string) (*fingerprint, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := stat.Size()
	if size > binsimMaxSize {
		size = binsimMaxSize
	}

	limited := io.LimitReader(f, size)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(data)
	fp := &fingerprint{
		Path:     path,
		Size:     int64(len(data)),
		SHA256:   hex.EncodeToString(sum[:]),
		Chunks:   make([]uint32, 0, len(data)/binsimChunk+1),
		Shingles: make(map[uint64]struct{}, binsimMaxShingles),
	}

	// Chunk digests (FNV-32a over fixed chunks).
	for off := 0; off < len(data); off += binsimChunk {
		end := off + binsimChunk
		if end > len(data) {
			end = len(data)
		}
		fp.Chunks = append(fp.Chunks, fnv32a(data[off:end]))
	}

	// Shingles (FNV-64 over sliding n-grams, sampled).
	stride := 1
	if len(data) > binsimMaxShingles*binsimNgram {
		stride = len(data) / (binsimMaxShingles * binsimNgram)
		if stride < 1 {
			stride = 1
		}
	}
	for off := 0; off+binsimNgram <= len(data); off += stride {
		fp.Shingles[fnv64a(data[off:off+binsimNgram])] = struct{}{}
		if len(fp.Shingles) >= binsimMaxShingles {
			break
		}
	}

	return fp, nil
}

func emitExactClone(res *ModuleResult, group []*fingerprint, root string) {
	paths := make([]string, 0, len(group))
	for _, fp := range group {
		rel, _ := filepath.Rel(root, fp.Path)
		if rel == "" {
			rel = fp.Path
		}
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	res.AddFinding(Finding{
		ID:          "binsim-exact-clone",
		Title:       fmt.Sprintf("Exact binary clones (%d copies)", len(paths)),
		Severity:    SevMedium,
		Confidence:  1.0,
		Description: "Multiple files share the same SHA-256 — likely re-shipped copies.",
		Evidence:    paths,
		Tags:        []string{"binsim", "clone", "exact"},
		Extra:       map[string]string{"sha256": group[0].SHA256, "size_bytes": fmt.Sprintf("%d", group[0].Size)},
	})
	res.Bump("exact_clones", 1)
}

func emitNearClones(res *ModuleResult, prints []*fingerprint, root string) {
	for i := 0; i < len(prints); i++ {
		for j := i + 1; j < len(prints); j++ {
			a, b := prints[i], prints[j]
			if a.SHA256 == b.SHA256 {
				continue // already reported as exact clone
			}
			// Skip if size differs by > 8x — they cannot be near-clones.
			if a.Size*8 < b.Size || b.Size*8 < a.Size {
				continue
			}
			score := jaccard(a.Shingles, b.Shingles)
			if score < binsimMinJaccard {
				continue
			}
			rel := func(p string) string {
				r, _ := filepath.Rel(root, p)
				if r == "" {
					return p
				}
				return r
			}
			sev := SevLow
			if score >= 0.85 {
				sev = SevMedium
			}
			if score >= 0.95 {
				sev = SevHigh
			}
			res.AddFinding(Finding{
				ID:          "binsim-near-clone",
				Title:       fmt.Sprintf("Near-duplicate binaries (J=%.2f)", score),
				Severity:    sev,
				Confidence:  score,
				Description: "High Jaccard similarity over byte-shingles. Candidate for deduplication or hidden-mod detection.",
				Evidence:    []string{rel(a.Path), rel(b.Path)},
				Tags:        []string{"binsim", "clone", "near"},
				Extra: map[string]string{
					"jaccard": fmt.Sprintf("%.4f", score),
					"size_a":  fmt.Sprintf("%d", a.Size),
					"size_b":  fmt.Sprintf("%d", b.Size),
				},
			})
			res.Bump("near_clones", 1)
		}
	}
}

func jaccard(a, b map[uint64]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	// Iterate over smaller set.
	small, big := a, b
	if len(big) < len(small) {
		small, big = big, small
	}
	inter := 0
	for k := range small {
		if _, ok := big[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// fnv32a / fnv64a implementations to avoid pulling another import dependency
// and to keep allocation-free hot loops.
func fnv32a(data []byte) uint32 {
	const (
		offset uint32 = 2166136261
		prime  uint32 = 16777619
	)
	h := offset
	for _, c := range data {
		h ^= uint32(c)
		h *= prime
	}
	return h
}

func fnv64a(data []byte) uint64 {
	const (
		offset uint64 = 14695981039346656037
		prime  uint64 = 1099511628211
	)
	h := offset
	for _, c := range data {
		h ^= uint64(c)
		h *= prime
	}
	return h
}
