package correlation

import (
	"testing"
	"time"
)

func TestGroup_SeparatesStaticFromRuntime(t *testing.T) {
	t0 := time.Now()
	signals := []*Signal{
		{ID: "a", Kind: KindAudit, Type: TypeHardcodedSecret},
		{ID: "b", Kind: KindMemory, Type: TypeRWXMemory, PID: 100, ProcessName: "x", Timestamp: t0},
		{ID: "c", Kind: KindNetwork, Type: TypeOutboundConnection, PID: 100, ProcessName: "x", Timestamp: t0.Add(time.Second)},
		{ID: "d", Kind: KindMemory, Type: TypeMemoryWrite, PID: 200, ProcessName: "y", Timestamp: t0.Add(2 * time.Second)},
	}
	ctx := Group(signals)
	if ctx == nil {
		t.Fatal("nil context")
	}
	if len(ctx.Static.Signals) != 1 {
		t.Fatalf("expected 1 static signal, got %d", len(ctx.Static.Signals))
	}
	if len(ctx.Processes) != 2 {
		t.Fatalf("expected 2 process buckets, got %d", len(ctx.Processes))
	}
	// Signals within a process must be in temporal order.
	first := ctx.Processes[0]
	if first.PID != 100 {
		t.Fatalf("expected first process PID=100 (earlier), got %d", first.PID)
	}
	if len(first.Signals) != 2 {
		t.Fatalf("expected 2 signals for PID=100, got %d", len(first.Signals))
	}
	if !first.Signals[0].Timestamp.Before(first.Signals[1].Timestamp) {
		t.Fatal("signals within a process should be sorted by timestamp")
	}
}

func TestExecutionContext_HasType(t *testing.T) {
	signals := []*Signal{
		{ID: "1", Kind: KindMemory, Type: TypeRWXMemory},
	}
	ctx := Group(signals)
	if !ctx.HasType(TypeRWXMemory) {
		t.Fatal("HasType should be true")
	}
	if ctx.HasType(TypeProcessInjection) {
		t.Fatal("HasType for missing type should be false")
	}
}

func TestExecutionContext_SignalsOfTypeInProcess(t *testing.T) {
	signals := []*Signal{
		{ID: "1", Kind: KindMemory, Type: TypeRWXMemory, PID: 5, ProcessName: "p"},
		{ID: "2", Kind: KindMemory, Type: TypeMemoryWrite, PID: 5, ProcessName: "p"},
		{ID: "3", Kind: KindMemory, Type: TypeRWXMemory, PID: 6, ProcessName: "q"},
	}
	ctx := Group(signals)
	got := ctx.SignalsOfTypeInProcess(processKey(5, "p"), TypeRWXMemory)
	if len(got) != 1 || got[0].PID != 5 {
		t.Fatalf("expected 1 signal for PID=5, got %+v", got)
	}
}

func TestBuildTimeline_Stable(t *testing.T) {
	t0 := time.Unix(1000, 0)
	signals := []*Signal{
		{ID: "z", Kind: KindAudit, Type: "x"}, // static — excluded
		{ID: "b", Kind: KindMemory, Type: "x", Timestamp: t0.Add(2 * time.Second)},
		{ID: "a", Kind: KindMemory, Type: "x", Timestamp: t0.Add(time.Second)},
		{ID: "c", Kind: KindMemory, Type: "x", Timestamp: t0.Add(2 * time.Second)},
	}
	tl := BuildTimeline(signals)
	if len(tl) != 3 {
		t.Fatalf("expected 3 timeline events, got %d", len(tl))
	}
	if tl[0].SignalID != "a" {
		t.Fatalf("expected first event to be 'a', got %s", tl[0].SignalID)
	}
	// Events with equal timestamps should sort by signal ID.
	if tl[1].SignalID != "b" || tl[2].SignalID != "c" {
		t.Fatalf("equal-timestamp events not stable: %s, %s", tl[1].SignalID, tl[2].SignalID)
	}
	for i, ev := range tl {
		if ev.Order != i+1 {
			t.Fatalf("Order should be 1-based and contiguous, got %d at idx %d", ev.Order, i)
		}
	}
}
