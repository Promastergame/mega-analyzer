package attackchain

import (
	"testing"

	"mega-analyzer/pkg/internal/correlation"
)

func TestUniqueSignals_Nil(t *testing.T) {
	result := uniqueSignals(nil)
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func TestUniqueSignals_Empty(t *testing.T) {
	result := uniqueSignals([]*correlation.Signal{})
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func TestUniqueSignals_NilElements(t *testing.T) {
	signals := []*correlation.Signal{nil, nil, nil}
	result := uniqueSignals(signals)
	if len(result) != 0 {
		t.Fatalf("expected empty, got %d", len(result))
	}
}

func TestUniqueSignals_Deduplicates(t *testing.T) {
	signals := []*correlation.Signal{
		{ID: "a", Kind: correlation.KindMemory},
		{ID: "b", Kind: correlation.KindNetwork},
		{ID: "a", Kind: correlation.KindMemory}, // duplicate
		{ID: "c", Kind: correlation.KindFile},
		{ID: "b", Kind: correlation.KindNetwork}, // duplicate
	}
	result := uniqueSignals(signals)
	if len(result) != 3 {
		t.Fatalf("expected 3 unique signals, got %d", len(result))
	}
	// Verify order preserved
	if result[0].ID != "a" || result[1].ID != "b" || result[2].ID != "c" {
		t.Fatalf("order not preserved: %v", result)
	}
}

func TestUniqueSignals_AllUnique(t *testing.T) {
	signals := []*correlation.Signal{
		{ID: "x"},
		{ID: "y"},
		{ID: "z"},
	}
	result := uniqueSignals(signals)
	if len(result) != 3 {
		t.Fatalf("expected 3, got %d", len(result))
	}
}

func TestInvolvedKinds_Nil(t *testing.T) {
	result := involvedKinds(nil)
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func TestInvolvedKinds_Empty(t *testing.T) {
	result := involvedKinds([]*correlation.Signal{})
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func TestInvolvedKinds_NilElements(t *testing.T) {
	signals := []*correlation.Signal{nil, nil}
	result := involvedKinds(signals)
	if len(result) != 0 {
		t.Fatalf("expected empty, got %d", len(result))
	}
}

func TestInvolvedKinds_Unique(t *testing.T) {
	signals := []*correlation.Signal{
		{ID: "1", Kind: correlation.KindMemory},
		{ID: "2", Kind: correlation.KindNetwork},
		{ID: "3", Kind: correlation.KindMemory}, // duplicate kind
		{ID: "4", Kind: correlation.KindFile},
	}
	result := involvedKinds(signals)
	if len(result) != 3 {
		t.Fatalf("expected 3 unique kinds, got %d", len(result))
	}
}

func TestInvolvedKinds_Sorted(t *testing.T) {
	signals := []*correlation.Signal{
		{ID: "1", Kind: correlation.KindNetwork},
		{ID: "2", Kind: correlation.KindAudit},
		{ID: "3", Kind: correlation.KindMemory},
	}
	result := involvedKinds(signals)
	for i := 1; i < len(result); i++ {
		if result[i] < result[i-1] {
			t.Fatalf("kinds not sorted: %v", result)
		}
	}
}

func TestFirstWithType_Found(t *testing.T) {
	signals := []*correlation.Signal{
		{ID: "1", Type: "type_a"},
		{ID: "2", Type: "type_b"},
		{ID: "3", Type: "type_a"},
	}
	result := firstWithType(signals, "type_b")
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.ID != "2" {
		t.Fatalf("expected ID=2, got %s", result.ID)
	}
}

func TestFirstWithType_NotFound(t *testing.T) {
	signals := []*correlation.Signal{
		{ID: "1", Type: "type_a"},
	}
	result := firstWithType(signals, "type_x")
	if result != nil {
		t.Fatalf("expected nil, got %+v", result)
	}
}

func TestFirstWithType_NilElements(t *testing.T) {
	signals := []*correlation.Signal{nil, {ID: "1", Type: "x"}}
	result := firstWithType(signals, "x")
	if result == nil || result.ID != "1" {
		t.Fatal("should skip nil and find the signal")
	}
}

func TestSignalsWithType(t *testing.T) {
	signals := []*correlation.Signal{
		{ID: "1", Type: "type_a"},
		{ID: "2", Type: "type_b"},
		{ID: "3", Type: "type_a"},
		nil,
		{ID: "4", Type: "type_a"},
	}
	result := signalsWithType(signals, "type_a")
	if len(result) != 3 {
		t.Fatalf("expected 3, got %d", len(result))
	}
}

func TestSignalsWithType_NoMatch(t *testing.T) {
	signals := []*correlation.Signal{
		{ID: "1", Type: "type_a"},
	}
	result := signalsWithType(signals, "type_x")
	if len(result) != 0 {
		t.Fatalf("expected 0, got %d", len(result))
	}
}

func TestProcessesWithType_NilCtx(t *testing.T) {
	result := processesWithType(nil, "any")
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func TestProcessesWithType_Found(t *testing.T) {
	ctx := &correlation.ExecutionContext{
		Processes: []*correlation.ProcessContext{
			{
				PID:         100,
				ProcessName: "proc1",
				Signals: []*correlation.Signal{
					{ID: "1", Type: "type_a"},
					{ID: "2", Type: "type_b"},
				},
			},
			{
				PID:         200,
				ProcessName: "proc2",
				Signals: []*correlation.Signal{
					{ID: "3", Type: "type_c"},
				},
			},
			{
				PID:         300,
				ProcessName: "proc3",
				Signals: []*correlation.Signal{
					{ID: "4", Type: "type_a"},
				},
			},
		},
	}
	result := processesWithType(ctx, "type_a")
	if len(result) != 2 {
		t.Fatalf("expected 2 processes with type_a, got %d", len(result))
	}
}

func TestProcessesWithType_NotFound(t *testing.T) {
	ctx := &correlation.ExecutionContext{
		Processes: []*correlation.ProcessContext{
			{
				PID:     100,
				Signals: []*correlation.Signal{{ID: "1", Type: "type_a"}},
			},
		},
	}
	result := processesWithType(ctx, "type_x")
	if len(result) != 0 {
		t.Fatalf("expected 0, got %d", len(result))
	}
}

func TestAsDetectorSlice(t *testing.T) {
	chains := []Chain{
		ProcessInjectionChain{},
		AuthBypassChain{},
	}
	detectors := asDetectorSlice(chains)
	if len(detectors) != 2 {
		t.Fatalf("expected 2 detectors, got %d", len(detectors))
	}
	if detectors[0].ID() != "process_injection_chain" {
		t.Fatalf("first detector ID = %s", detectors[0].ID())
	}
	if detectors[1].ID() != "auth_bypass_chain" {
		t.Fatalf("second detector ID = %s", detectors[1].ID())
	}
}

func TestChainIDs(t *testing.T) {
	tests := []struct {
		chain Chain
		id    string
		name  string
	}{
		{ProcessInjectionChain{}, "process_injection_chain", "Process Injection Chain"},
		{DownloaderChain{}, "downloader_chain", "Downloader Chain"},
		{PersistenceChain{}, "persistence_chain", "Persistence Chain"},
		{DataExfiltrationChain{}, "data_exfiltration_chain", "Data Exfiltration Chain"},
		{AuthBypassChain{}, "auth_bypass_chain", "Client-side Auth Bypass Chain"},
	}
	for _, tt := range tests {
		if tt.chain.ID() != tt.id {
			t.Errorf("%T.ID() = %q, want %q", tt.chain, tt.chain.ID(), tt.id)
		}
		if tt.chain.Name() != tt.name {
			t.Errorf("%T.Name() = %q, want %q", tt.chain, tt.chain.Name(), tt.name)
		}
		if tt.chain.Description() == "" {
			t.Errorf("%T.Description() is empty", tt.chain)
		}
	}
}

func TestAllChains_DetectNilContext(t *testing.T) {
	chains := []Chain{
		ProcessInjectionChain{},
		DownloaderChain{},
		PersistenceChain{},
		DataExfiltrationChain{},
		AuthBypassChain{},
	}
	for _, c := range chains {
		result := c.Detect(nil)
		if result != nil {
			t.Errorf("%s.Detect(nil) should return nil, got %+v", c.ID(), result)
		}
	}
}

func TestAllChains_DetectEmptyContext(t *testing.T) {
	ctx := correlation.Group(nil)
	chains := []Chain{
		ProcessInjectionChain{},
		DownloaderChain{},
		PersistenceChain{},
		DataExfiltrationChain{},
		AuthBypassChain{},
	}
	for _, c := range chains {
		result := c.Detect(ctx)
		if result != nil {
			t.Errorf("%s.Detect(empty) should return nil, got %+v", c.ID(), result)
		}
	}
}
