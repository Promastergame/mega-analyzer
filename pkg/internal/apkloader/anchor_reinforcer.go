package apkloader

import (
	"errors"
	"os"
	"sync"
)

// RustAnchorReinforcer is the production AnchorReinforcer that bridges
// active.Queue.Confirm() into the Rust HDC engine via the cgo
// `ReinforceAnchor` call.
//
// It owns the path to the persistent anchors JSON, reads/writes that
// file under a mutex (so concurrent confirmations don't race on the
// store), and is safe to share across goroutines.
//
// Implements active.AnchorReinforcer.
type RustAnchorReinforcer struct {
	mu   sync.Mutex
	path string
}

// NewRustAnchorReinforcer constructs the reinforcer. `anchorsPath` is the
// JSON file that the scanner reads at every run (typically
// `pkg/internal/configs/aetrium_anchors.json`).
func NewRustAnchorReinforcer(anchorsPath string) (*RustAnchorReinforcer, error) {
	if anchorsPath == "" {
		return nil, errors.New("anchor_reinforcer: empty path")
	}
	if _, err := os.Stat(anchorsPath); err != nil {
		return nil, err
	}
	return &RustAnchorReinforcer{path: anchorsPath}, nil
}

// Reinforce loads the anchors JSON, asks Rust to update the named anchor
// with `featureVector`, and writes the result back atomically. Errors
// surface to the caller so the active-learning loop can decide whether
// to retry or surface the failure to the user.
func (r *RustAnchorReinforcer) Reinforce(anchorName string, featureVector []float64) error {
	if anchorName == "" {
		return errors.New("anchor_reinforcer: empty anchor name")
	}
	if len(featureVector) == 0 {
		return nil // nothing to learn from
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	anchors, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}
	updated, err := ReinforceAnchor(anchors, anchorName, featureVector)
	if err != nil {
		return err
	}
	if len(updated) == 0 {
		return errors.New("anchor_reinforcer: empty result from Rust")
	}

	// Atomic write via temp + rename so a crash mid-write doesn't leave
	// the store half-serialized (which would crash every scan thereafter).
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, updated, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}
