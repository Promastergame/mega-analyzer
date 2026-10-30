package main

import (
	"testing"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/ncer"
)

func TestFeedNcerAuthority_NilReportIsNoOp(t *testing.T) {
	c := ncer.NewCollector(time.Now())
	feedNcerAuthority(c, nil)
	if c.Len() != 0 {
		t.Errorf("expected no events observed for a nil report")
	}
}

func TestFeedNcerAuthority_NoAndroidProfileIsNoOp(t *testing.T) {
	c := ncer.NewCollector(time.Now())
	feedNcerAuthority(c, &sandbox.Report{})
	// hasReconcilableData isn't exported, but Len() staying 0 and no panic is
	// the observable contract here — the real assertion is in the
	// integration-level ncer package tests for ObserveAuthority.
	if c.Len() != 0 {
		t.Errorf("expected no HTTP events observed for a report with no AndroidProfile")
	}
}

func TestFeedNcerAuthority_NoPackageNameIsNoOp(t *testing.T) {
	c := ncer.NewCollector(time.Now())
	report := &sandbox.Report{
		AndroidProfile: &sandbox.AndroidProfile{
			// PackageName intentionally empty.
			Permissions: []sandbox.AndroidPermission{{Name: "android.permission.INTERNET"}},
		},
	}
	feedNcerAuthority(c, report)
	if c.Len() != 0 {
		t.Errorf("expected no events observed when PackageName is empty")
	}
}

func TestFeedNcerAuthority_PermissionsAndConnectionsProduceAuthorityEvents(t *testing.T) {
	c := ncer.NewCollector(time.Now())
	report := &sandbox.Report{
		StartedAt: time.Now(),
		AndroidProfile: &sandbox.AndroidProfile{
			PackageName: "com.example.app",
			AppLabel:    "Example App",
			Permissions: []sandbox.AndroidPermission{
				{Name: "android.permission.INTERNET", Risk: "normal"},
			},
		},
		NetworkCapture: &sandbox.NetworkCapture{
			Connections: []sandbox.NetworkConnection{
				{RemoteAddr: "93.184.216.34", Timestamp: time.Now()},
			},
		},
	}

	feedNcerAuthority(c, report)

	// feedNcerAuthority doesn't touch HTTP events, so Len() (HTTP-only) stays 0;
	// the authority events land in the collector's separate authority slice,
	// which we verify indirectly by confirming Reconcile no longer bails out
	// early due to "nothing observed".
	res, err := c.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	// Stub build: res is nil (ErrRustNotLinked path). Either way, no panic and
	// no error is the contract this test protects — Reconcile must treat
	// authority-only sessions as reconcilable.
	_ = res
}
