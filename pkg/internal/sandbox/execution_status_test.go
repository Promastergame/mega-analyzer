package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestSandboxReliabilityNetworkPreflight(t *testing.T) {
	err := checkNetworkIsolationPrivilege(true, false)
	if err == nil {
		t.Fatal("non-elevated network guard accepted")
	}
	f := DescribeFailure(fmt.Errorf("outer: %w", err))
	if f.Code != "admin_required" || f.Stage != "preflight" {
		t.Fatalf("wrong diagnostic: %#v", f)
	}
	if err := checkNetworkIsolationPrivilege(true, true); err != nil {
		t.Fatal(err)
	}
	if err := checkNetworkIsolationPrivilege(false, false); err != nil {
		t.Fatal(err)
	}
	if f := DescribeFailure(context.Canceled); f.Code != "canceled" {
		t.Fatal(f)
	}
	if !errors.Is(executionError("x", "preflight", os.ErrPermission), os.ErrPermission) {
		t.Fatal("wrapped cause lost")
	}
}
func TestSandboxReliabilityCollectorCallbacks(t *testing.T) {
	c := newObservationCollector()
	pc, nc := 0, 0
	c.onProcess = func(p ObservedProcess) { pc++; c.Export() }
	c.onConnection = func(p ObservedConnection) { nc++; c.Export() }
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2; i++ {
			c.Merge([]ObservedProcess{{PID: 0, Name: "unknown"}, {PID: 41, Name: "sample.exe"}}, []ObservedConnection{{PID: 41, Protocol: "TCP", RemoteAddr: "192.0.2.1:443"}}, time.Now())
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback deadlocked under collector lock")
	}
	p, n, _ := c.Export()
	if pc != 1 || nc != 1 || len(p) != 1 || len(n) != 1 {
		t.Fatalf("callbacks %d/%d processes %d conns %d", pc, nc, len(p), len(n))
	}
}
func TestSandboxReliabilityUniqueSessionDirectories(t *testing.T) {
	dir := t.TempDir()
	a, e := prepareSessionLayout(dir)
	if e != nil {
		t.Fatal(e)
	}
	b, e := prepareSessionLayout(dir)
	if e != nil {
		t.Fatal(e)
	}
	if a.sessionDir == b.sessionDir {
		t.Fatal("concurrent sessions reused a directory")
	}
}
