package crackpoint

import (
	"testing"

	"mega-analyzer/pkg/internal/cfg"
)

func TestCrackPointTypeString(t *testing.T) {
	cases := map[CrackPointType]string{
		CrackPointGateMethod:   "gate_method",
		CrackPointCondition:    "condition",
		CrackPointCallback:     "callback",
		CrackPointFieldCheck:   "field_check",
		CrackPointInvokeResult: "invoke_result",
		CrackPointType(99):     "unknown",
	}
	for tp, want := range cases {
		if got := tp.String(); got != want {
			t.Errorf("CrackPointType(%d).String() = %q, want %q", tp, got, want)
		}
	}
}

func TestIsFollowedByBooleanCheck(t *testing.T) {
	f := NewFinder()

	// move-result follows the call → true
	node := &cfg.CFGNode{Instructions: []cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual"},
		{Index: 1, Opcode: "move-result"},
	}}
	if !f.isFollowedByBooleanCheck(node, 0) {
		t.Error("move-result after invoke should be detected")
	}

	// if-eqz follows → true
	node2 := &cfg.CFGNode{Instructions: []cfg.InstructionRef{
		{Index: 5, Opcode: "invoke-virtual"},
		{Index: 6, Opcode: "if-eqz"},
	}}
	if !f.isFollowedByBooleanCheck(node2, 5) {
		t.Error("if-eqz after invoke should be detected")
	}

	// far-away — the function checks if-/move-result BEFORE its window
	// guard, so a far if-* still fires. Document that behaviour.
	far := &cfg.CFGNode{Instructions: []cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual"},
		{Index: 100, Opcode: "if-eqz"},
	}}
	if !f.isFollowedByBooleanCheck(far, 0) {
		t.Error("if-* match should fire regardless of distance — current behaviour")
	}

	// No move-result / if-* anywhere → false.
	none := &cfg.CFGNode{Instructions: []cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual"},
		{Index: 1, Opcode: "iget"},
		{Index: 2, Opcode: "iget"},
	}}
	if f.isFollowedByBooleanCheck(none, 0) {
		t.Error("plain iget tail should not match")
	}
}

func TestCategorizeField(t *testing.T) {
	f := NewFinder()
	// The classifier uses case-sensitive substring matching, so inputs must
	// be lowercase to hit the patterns.
	cases := map[string]string{
		"ispremium":     "premium",
		"isprouser":     "premium",
		"vipUser":       "premium",
		"hasPaidStuff":  "premium",
		"unlockedItems": "premium",
		"islicense":     "license",
		"isregistered":  "license",
		"isactivated":   "license",
		"showads":       "ads",
		"removeadsbtn":  "ads",
		"random":        "premium", // default fallback
	}
	for name, want := range cases {
		if got := f.categorizeField(name); got != want {
			t.Errorf("categorizeField(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestMinFloat(t *testing.T) {
	if got := minFloat(1.0, 2.0); got != 1.0 {
		t.Errorf("minFloat(1,2) = %v, want 1", got)
	}
	if got := minFloat(2.0, 1.0); got != 1.0 {
		t.Errorf("minFloat(2,1) = %v, want 1", got)
	}
	if got := minFloat(1.0, 1.0); got != 1.0 {
		t.Errorf("minFloat(1,1) = %v, want 1", got)
	}
}
