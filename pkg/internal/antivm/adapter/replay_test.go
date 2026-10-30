package adapter

import (
	"context"
	"path/filepath"
	"testing"
)

func TestReplayAdapter_ReadState(t *testing.T) {
	st := NewDeviceState()
	st.Props["ro.product.model"] = "Pixel 8"
	r := NewReplayAdapter(st)
	ctx := context.Background()

	got, err := r.ReadState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Props["ro.product.model"] != "Pixel 8" {
		t.Errorf("replay returned wrong state: %v", got.Props)
	}
}

func TestReplayAdapter_ApplyDoesNotMutateState(t *testing.T) {
	st := NewDeviceState()
	st.Props["ro.product.model"] = "sdk_gphone64"
	r := NewReplayAdapter(st)
	ctx := context.Background()

	// Applying a different model must NOT change the replayed reality.
	_, err := r.ApplyTestConfig(ctx, TestConfig{Props: []PropSet{{"ro.product.model", "Pixel 8"}}})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := r.ReadState(ctx)
	if after.Props["ro.product.model"] != "sdk_gphone64" {
		t.Error("replay apply must not mutate captured state")
	}
	if len(r.Applied) != 1 {
		t.Errorf("apply not recorded: %d", len(r.Applied))
	}
}

func TestLoadReplay_BadPath(t *testing.T) {
	if _, err := LoadReplay(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("expected error for missing replay file")
	}
}
