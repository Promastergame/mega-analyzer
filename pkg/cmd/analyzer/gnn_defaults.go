package main

import (
	"context"
	"os"
	"path/filepath"

	"mega-analyzer/pkg/ml/gnncache"
)

// defaultContentCacheDir is the built-in default value of the
// -content-cache-dir flag. When the flag is left untouched, the GNN cache is
// placed under the per-user analyzer directory (~/.analyzer) instead of the
// working directory; see runner_gnn.go.
const defaultContentCacheDir = ".analyzer-cache/content"

// resolveGNNModelPath decides whether the GNN stage should run and with
// which weights. There is no enable flag by design: an explicit -gnn-model
// always wins ("__dummy__" selects random weights for testing the
// mechanics); otherwise weights dropped into
// ~/.analyzer/models/gnn_weights.json or a JSON model shipped with the binary
// are picked up automatically. Only formats supported by the Go validation
// contract are discovered.
func resolveGNNModelPath(configured string) string {
	if configured != "" {
		return configured
	}
	if weights := gnncache.DiscoverWeights(); weights != "" {
		return weights
	}
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	return discoverBundledGNNWeights(filepath.Dir(executable))
}

func discoverBundledGNNWeights(executableDir string) string {
	for _, dir := range []string{
		filepath.Join(executableDir, "models"), executableDir,
		filepath.Join(executableDir, "rust"),
		filepath.Join(executableDir, "..", "models"), filepath.Join(executableDir, "..", "rust"),
	} {
		path := filepath.Join(dir, "gnn_weights.json")
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return filepath.Clean(path)
		}
	}
	return ""
}

func gnnCacheDiskLimitBytes(megabytes int64) int64 {
	if megabytes < 0 {
		return -1
	}
	if megabytes == 0 {
		return 0
	}
	const (
		mib      = int64(1024 * 1024)
		maxInt64 = int64(1<<63 - 1)
	)
	if megabytes > maxInt64/mib {
		return maxInt64
	}
	return megabytes * mib
}

// feedGNNJobs stops promptly when either the caller or the GNN worker pool is
// cancelled. Keeping the cancellation arm next to the blocking send prevents
// a fatal model-load error from leaving the producer stuck after every worker
// has exited.
func feedGNNJobs[T any](ctx context.Context, jobs chan<- T, entries []T) bool {
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return true
		case jobs <- entry:
		}
	}
	return false
}
