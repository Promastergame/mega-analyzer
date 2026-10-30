package main

import (
	"testing"

	"mega-analyzer/pkg/cmd/analyzer/web"
)

// TestNoTUIFlagsAreAccepted guards the second half of the web UI failure: the
// help text advertised -no-tui and buildModeArgs passed -no-tui, but the
// flag was never registered, so flag.Parse rejected every spawned analysis with
// "flag provided but not defined".
func TestNoTUIFlagsAreAccepted(t *testing.T) {
	for _, flagName := range []string{"-no-tui"} {
		opts, err := NewCLIParser().Parse([]string{"-t", "./app", flagName})
		if err != nil {
			t.Fatalf("%s should be accepted, got error: %v", flagName, err)
		}
		if !opts.NoTUI {
			t.Errorf("%s should leave NoTUI true", flagName)
		}
	}

	// Explicit CLI mode must win over -tui so automated callers stay headless.
	opts, err := NewCLIParser().Parse([]string{"-t", "./app", "-tui", "-no-tui"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.NoTUI {
		t.Error("-no-tui should override -tui")
	}
}

// TestWebUIModeArgsUseRegisteredFlags makes sure every flag the web UI hands to
// the spawned analyzer actually exists in the CLI parser.
func TestWebUIModeArgsUseRegisteredFlags(t *testing.T) {
	modes := []string{
		"full", "decode", "machine-code", "firmware",
		"version-diff", "js-deobf", "js-patch", "sandbox",
	}
	for _, mode := range modes {
		args := web.BuildModeArgs(mode, []string{"a.apk", "b.apk"}, "out", "", "", "", nil)
		if _, err := NewCLIParser().Parse(args); err != nil {
			t.Errorf("mode %q produced unparsable args %v: %v", mode, args, err)
		}
	}
}
