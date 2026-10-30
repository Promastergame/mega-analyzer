package sandbox

import (
	"context"
	"testing"
	"time"
)

func TestObservationContextNoDeadline(t *testing.T) {
	parent, stop := context.WithCancel(context.Background())
	ctx, cancel := observationContext(parent, 0)
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("manual mode has a deadline")
	}
	stop()
	if ctx.Err() != context.Canceled {
		t.Fatal("Stop did not cancel manual mode")
	}
}
func TestObservationContextTimed(t *testing.T) {
	ctx, cancel := observationContext(context.Background(), 5*time.Second)
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("timed mode has no deadline")
	}
}
func TestManualDurationSurvivesNormalization(t *testing.T) {
	cfg := (Config{TargetPath: "test.exe"}).normalized()
	if cfg.Duration != 0 {
		t.Fatal("no-deadline mode replaced by a timeout")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Duration = -time.Second
	if cfg.Validate() == nil {
		t.Fatal("negative duration accepted")
	}
}
func TestManualObservationRespectsParentDeadline(t *testing.T) {
	parent, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	ctx, cancel := observationContext(parent, 0)
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("lost parent shutdown deadline")
	}
}
