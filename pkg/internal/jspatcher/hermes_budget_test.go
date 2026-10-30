package jspatcher

import "testing"

func TestHermesBudgetCacheIdentity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Apply = ApplyDryRun
	cfg.OutputDir = t.TempDir()
	cfg.HermesBudget = "compact"
	compact := NewPatcher(cfg).cachePath([]byte("same bundle"), nil)
	cfg.HermesBudget = "large"
	large := NewPatcher(cfg).cachePath([]byte("same bundle"), nil)
	if compact == large {
		t.Fatal("different coverage budgets must not reuse cached report")
	}
}
