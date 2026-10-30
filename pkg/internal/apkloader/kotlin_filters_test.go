package apkloader

import "testing"

func TestIsKotlinSynthetic(t *testing.T) {
	cases := []struct {
		className   string
		methodName  string
		accessFlags uint32
		expected    bool
	}{
		{"Lcom/example/User;", "onCreate", 0x0001, false},
		{"Lcom/example/User;", "access$000", 0x1008, true},                    // synthetic static access helper
		{"Lcom/example/User;", "doAction$default", 0x0009, true},              // default arguments wrapper
		{"Lcom/example/User$sam$OnClickListener$0;", "onClick", 0x0001, true}, // SAM adapter class
		{"Lcom/example/User$doAction$1;", "invokeSuspend", 0x1001, true},      // coroutine continuation class
	}

	for _, tc := range cases {
		got := IsKotlinSynthetic(tc.className, tc.methodName, tc.accessFlags)
		if got != tc.expected {
			t.Errorf("IsKotlinSynthetic(%q, %q, 0x%x) = %v, want %v",
				tc.className, tc.methodName, tc.accessFlags, got, tc.expected)
		}
	}
}

func TestReconstructCoroutineFlow(t *testing.T) {
	// 1. Create a mocked CFG with an entry switch block
	cfg := &CFG{
		offsetToBlock: make(map[uint32]*BasicBlock),
	}

	entryBlock := &BasicBlock{
		ID:    0,
		Insns: []MIRInsn{{Kind: MIR_SWITCH, Offset: 0}},
	}
	succ1 := &BasicBlock{ID: 1}
	succ2 := &BasicBlock{ID: 2}

	entryBlock.Succs = append(entryBlock.Succs, succ1, succ2)
	cfg.Blocks = append(cfg.Blocks, entryBlock, succ1, succ2)
	cfg.Entry = entryBlock

	// 2. Run Flow Reconstruction
	transitions := ReconstructCoroutineFlow(cfg)

	if len(transitions) != 2 {
		t.Errorf("expected 2 state transitions, got %d", len(transitions))
	}

	if transitions[0].TargetBB != 1 || transitions[1].TargetBB != 2 {
		t.Errorf("incorrect transition targets: %v", transitions)
	}
}
