package gnngraph

import (
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/dexir"
	"mega-analyzer/pkg/internal/types"
)

func TestSmaliTensorIgnoresFormattingAndLiteralPunctuation(t *testing.T) {
	build := func(body []string) interface{} {
		return Build(BuildMethodCFG(nil, "LTest;", &types.SmaliMethod{Name: "f", ReturnType: "V", Body: body}))
	}
	plain := build([]string{`const-string v0, "abc"`, "if-eqz v0, :done", "invoke-static {v0}, LTest;->use(Ljava/lang/String;)V", ":done", "return-void"})
	formatted := build([]string{"# comment", ".locals 1", "const-string\tv0, \"a,#b,c\" # ignored", "if-eqz\tv0, :renamed # ignored", "invoke-static\t{v0} , LTest;->use(Ljava/lang/String;)V", ":renamed", "# gap", ".line 42", "return-void"})
	if !reflect.DeepEqual(plain, formatted) {
		t.Fatalf("equivalent structural inputs differ:\n%+v\n%+v", plain, formatted)
	}
}

func TestSmaliFeaturesCountOperandsAndConditions(t *testing.T) {
	for _, tc := range []struct {
		raw, op string
		count   float32
	}{
		{`const-string v0, "abc"`, "const-string", .2},
		{`const-string v0, "a,b,c"`, "const-string", .2},
		{"return v0", "return", .1},
		{"return-void", "return-void", 0},
		{"invoke-static/range {v0 .. v2}, LTest;->f(III)V", "invoke-static/range", .4},
		{"add-int/2addr v0, v1", "add-int/2addr", .2},
	} {
		f := ExtractFeatures(&cfg.CFGNode{Instructions: []cfg.InstructionRef{{Opcode: tc.op, Raw: tc.raw}}}, 1)
		if f[16] != tc.count {
			t.Errorf("%s: operand feature=%v want=%v", tc.raw, f[16], tc.count)
		}
	}
	branch := ExtractFeatures(&cfg.CFGNode{Instructions: []cfg.InstructionRef{{Opcode: "if-eqz", Raw: "if-eqz v0, :done"}}}, 1)
	if branch[17] != 1 || branch[20] != 1 {
		t.Fatalf("conditional comparison not represented: %v", branch)
	}
	typed := ExtractFeatures(&cfg.CFGNode{Instructions: []cfg.InstructionRef{{Opcode: "const-string", IR: &dexir.Instruction{Op: dexir.OpConstString, Dst: 0, HasStr: true, Str: "a,b"}}}}, 1)
	if typed[16] != .2 {
		t.Fatalf("typed input without Raw lost operands: %v", typed[16])
	}
}
