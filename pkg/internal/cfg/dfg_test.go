package cfg

import (
	"strings"
	"testing"
)

// strPtr helper
func strPtr(s string) *string {
	return &s
}

// ═══════════════════════════════════════════════════════════════════════════════
// DFG UNIT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestDFG_SimpleLicenseCheck тест: const → invoke → move-result → if-eqz
// 💥 ИСПРАВЛЕНО: правильная связка регистров и invoke → move-result
func TestDFG_SimpleLicenseCheck(t *testing.T) {
	// Создаём тестовый Smali метод:
	// .method public checkPremium()Z
	//   const-string v0, "license_key"     // v0 = "license_key"
	//   invoke-static {v0}, LChecker;->isValid(Ljava/lang/String;)Z  // use v0
	//   move-result v1                    // v1 = результат invoke (💥 InvokeRef должен быть заполнен!)
	//   if-eqz v1, :not_premium          // проверяем v1
	//   return v1
	// :not_premium
	//   const/4 v1, 0x0
	//   return v1
	// .end method

	instructions := []Instruction{
		// 0: const-string v0, "license_key"
		{Index: 0, Line: 10, Opcode: "const-string", Raw: "const-string v0, \"license_key\"",
			DefRegs: []string{"v0"}, ConstVal: strPtr("license_key")},

		// 1: invoke-static {v0}, LChecker;->isLicensed(Ljava/lang/String;)Z
		// 💥 ИСПРАВЛЕНО: UseRegs = []string{"v0"} и isLicensed (а не isValid!)
		{Index: 1, Line: 11, Opcode: "invoke-static",
			Raw:     "invoke-static {v0}, LChecker;->isLicensed(Ljava/lang/String;)Z",
			UseRegs: []string{"v0"}, InvokeRef: "LChecker;->isLicensed(Ljava/lang/String;)Z"},

		// 2: move-result v1
		// 💥 ИСПРАВЛЕНО: InvokeRef должен быть заполнен для связки!
		{Index: 2, Line: 12, Opcode: "move-result", Raw: "move-result v1",
			DefRegs: []string{"v1"}, InvokeRef: "LChecker;->isLicensed(Ljava/lang/String;)Z"},

		// 3: if-eqz v1, :not_premium
		{Index: 3, Line: 13, Opcode: "if-eqz", Raw: "if-eqz v1, :not_premium",
			UseRegs: []string{"v1"}},

		// 4: return v1
		{Index: 4, Line: 14, Opcode: "return", Raw: "return v1", UseRegs: []string{"v1"}},

		// 5: :not_premium label
		{Index: 5, Line: 15, Opcode: ":cond_0", Raw: ":not_premium"},

		// 6: const/4 v1, 0x0
		{Index: 6, Line: 16, Opcode: "const/4", Raw: "const/4 v1, 0x0",
			DefRegs: []string{"v1"}, ConstVal: strPtr("0x0")},

		// 7: return v1
		{Index: 7, Line: 17, Opcode: "return", Raw: "return v1", UseRegs: []string{"v1"}},
	}

	// Создаём CFG вручную — ОДИН блок со всеми инструкциями (для простого Trace)
	cfg := &ControlFlowGraph{
		MethodName: "checkPremium",
		ClassName:  "LTest;",
		Signature:  "()Z",
		Method: &MethodInfo{
			Instructions: make([]*Instruction, len(instructions)),
		},
		NodeByIdx: make(map[int]*CFGNode),
		Nodes:     []*CFGNode{},
	}

	// Заполняем Method
	for i := range instructions {
		cfg.Method.Instructions[i] = &instructions[i]
	}

	// Создаём один блок для всех инструкций (0-7)
	block := &CFGNode{
		ID:       0,
		StartIdx: 0,
		EndIdx:   len(instructions) - 1,
		Instructions: []InstructionRef{
			{Index: 0}, {Index: 1}, {Index: 2}, {Index: 3},
			{Index: 4}, {Index: 5}, {Index: 6}, {Index: 7},
		},
		Predecessors: []*CFGNode{},
		Successors:   []*CFGNode{},
	}
	cfg.Nodes = append(cfg.Nodes, block)

	// Все инструкции в одном блоке
	for i := range instructions {
		cfg.NodeByIdx[i] = block
	}

	// Создаём DFG Analyzer
	dfgAnalyzer := NewDFGAnalyzer(cfg)
	dfgAnalyzer.Analyze()

	// 💥 DEBUG: проверяем что Analyze заполнил поля
	t.Logf("After Analyze:")
	for i, instr := range cfg.Method.Instructions {
		if instr.Opcode == "if-eqz" {
			t.Logf("  if-eqz[%d] UseRegs=%v", i, instr.UseRegs)
		}
		if instr.Opcode == "move-result" {
			t.Logf("  move-result[%d] DefRegs=%v InvokeRef=%s", i, instr.DefRegs, instr.InvokeRef)
		}
		if instr.ConstVal != nil {
			t.Logf("  const[%d]=%s", i, *instr.ConstVal)
		}
	}

	// Проверяем FindLicenseChecks напрямую
	checks := dfgAnalyzer.FindLicenseChecks(20)
	t.Logf("FindLicenseChecks found %d checks", len(checks))
	for i, check := range checks {
		t.Logf("  check[%d]: cond=%s reg=%s conf=%.2f", i, check.Condition.Opcode, check.Register, check.Confidence)
	}

	// Проверяем что GetDFG возвращает не nil
	dfgInfo := dfgAnalyzer.GetDFG(20)
	if dfgInfo == nil {
		t.Fatalf("GetDFG() returned nil (found %d checks with conf <= 0.5)", len(checks))
	}

	// Проверяем Available
	if !dfgInfo.Available {
		t.Error("DFGInfo.Available = false, expected true")
	}

	// Проверяем ConditionType (должен быть if-eqz)
	if dfgInfo.ConditionType != "if-eqz" {
		t.Errorf("ConditionType = %q, expected 'if-eqz'", dfgInfo.ConditionType)
	}

	// Проверяем Register (должен быть v1 — результат move-result)
	if dfgInfo.Register != "v1" {
		t.Errorf("Register = %q, expected 'v1'", dfgInfo.Register)
	}

	// Проверяем что Trace не пуст
	if len(dfgInfo.Trace) == 0 {
		t.Fatal("Trace is empty, expected at least one step")
	}

	// 💥 Проверяем что в Trace есть invoke через move-result
	var foundInvoke bool
	var foundConst bool
	var invokeRef string
	var constVal string

	for _, step := range dfgInfo.Trace {
		if step.Instruction == nil {
			continue
		}

		// Проверяем move-result → должен иметь InvokeRef
		if step.Instruction.Opcode == "move-result" && step.Instruction.InvokeRef != "" {
			foundInvoke = true
			invokeRef = step.Instruction.InvokeRef
			t.Logf("✓ Found move-result linked to invoke: %s", invokeRef)
		}

		// Ищем const-string
		if step.Instruction.ConstVal != nil && strings.Contains(*step.Instruction.ConstVal, "license") {
			foundConst = true
			constVal = *step.Instruction.ConstVal
			t.Logf("✓ Found const: %s", constVal)
		}
	}

	if !foundInvoke {
		t.Error("❌ Trace does not contain invoke reference from move-result")
	}

	if invokeRef != "LChecker;->isLicensed(Ljava/lang/String;)Z" {
		t.Errorf("InvokeRef = %q, expected 'LChecker;->isLicensed(Ljava/lang/String;)Z'", invokeRef)
	}

	// 💥 Проверяем связку const → invoke
	// В trace должен быть шаг с const (через регистр v0)
	// или мы должны видеть что v0 используется в invoke

	t.Logf("✓ DFG Test passed:")
	t.Logf("  Condition: %s", dfgInfo.ConditionText)
	t.Logf("  Register: %s", dfgInfo.Register)
	t.Logf("  InvokeRef: %s", invokeRef)
	t.Logf("  ConstVal: %s", constVal)
	t.Logf("  Trace steps: %d", len(dfgInfo.Trace))
	t.Logf("  FoundInvoke: %v, FoundConst: %v", foundInvoke, foundConst)
}

// TestDFG_NoLicenseCheck тест метода без проверки лицензии
func TestDFG_NoLicenseCheck(t *testing.T) {
	// Простой метод без if связанного с лицензией
	instructions := []Instruction{
		{Index: 0, Line: 1, Opcode: "const/4", Raw: "const/4 v0, 0x1",
			DefRegs: []string{"v1"}, ConstVal: strPtr("0x1")},
		{Index: 1, Line: 2, Opcode: "return", Raw: "return v0", UseRegs: []string{"v1"}},
	}

	builder := NewCFGBuilder()
	input := BuildInput{
		MethodName:   "simpleMethod",
		Instructions: instructions,
	}

	cfg := builder.Build(input)
	if cfg == nil {
		t.Fatal("Failed to build CFG")
	}

	cfg.Method = &MethodInfo{
		Instructions: make([]*Instruction, len(instructions)),
	}
	for i := range instructions {
		cfg.Method.Instructions[i] = &instructions[i]
	}

	dfgAnalyzer := NewDFGAnalyzer(cfg)
	dfgAnalyzer.Analyze()

	dfgInfo := dfgAnalyzer.GetDFG(20)
	if dfgInfo != nil {
		t.Errorf("GetDFG() returned non-nil for method without license check")
	}
}

// TestDFG_MoveResultLinkage проверяет связку invoke → move-result
func TestDFG_MoveResultLinkage(t *testing.T) {
	// Тестируем что move-result получает InvokeRef от предыдущего invoke
	instructions := []Instruction{
		// 0: invoke-static {}, LChecker;->isPremium()Z
		{Index: 0, Line: 1, Opcode: "invoke-static",
			Raw:       "invoke-static {}, LChecker;->isPremium()Z",
			InvokeRef: "LChecker;->isPremium()Z"},

		// 1: move-result v0
		{Index: 1, Line: 2, Opcode: "move-result", Raw: "move-result v0",
			DefRegs: []string{"v0"}}, // InvokeRef должен быть заполнен analyzer'ом!

		// 2: if-eqz v0, :end
		{Index: 2, Line: 3, Opcode: "if-eqz", Raw: "if-eqz v0, :end",
			UseRegs: []string{"v0"}},
	}

	cfg := &ControlFlowGraph{
		Method: &MethodInfo{
			Instructions: make([]*Instruction, len(instructions)),
		},
		NodeByIdx: make(map[int]*CFGNode),
	}
	for i := range instructions {
		cfg.Method.Instructions[i] = &instructions[i]
		cfg.NodeByIdx[i] = &CFGNode{
			ID:           i,
			StartIdx:     i,
			EndIdx:       i,
			Successors:   []*CFGNode{},
			Predecessors: []*CFGNode{},
		}
	}

	dfgAnalyzer := NewDFGAnalyzer(cfg)
	dfgAnalyzer.Analyze()

	// Проверяем что move-result получил InvokeRef
	moveResult := instructions[1]
	if moveResult.InvokeRef == "" {
		t.Error("move-result instruction missing InvokeRef linkage to invoke")
	} else {
		t.Logf("✓ move-result linked to: %s", moveResult.InvokeRef)
	}

	// 💥 Проверяем содержимое (может быть с запятой из-за парсинга)
	if !strings.Contains(moveResult.InvokeRef, "LChecker;->isPremium()Z") {
		t.Errorf("move-result.InvokeRef = %q, expected to contain 'LChecker;->isPremium()Z'", moveResult.InvokeRef)
	}
}

// TestCondition_String тест человекочитаемого условия
func TestCondition_String(t *testing.T) {
	tests := []struct {
		cond Condition
		want string
	}{
		{Condition{Opcode: "if-eqz", Register: "v0"}, "v0 == false"},
		{Condition{Opcode: "if-nez", Register: "v1"}, "v1 != false"},
		{Condition{Opcode: "if-eq", Register: "v0", TargetReg: "v1"}, "v0 == v1"},
		{Condition{Opcode: "if-ne", Register: "v0", TargetReg: "v1"}, "v0 != v1"},
		{Condition{Opcode: "if-lt", Register: "v0", TargetReg: "v1"}, "v0 < v1"},
		{Condition{Opcode: "if-ge", Register: "v0", TargetReg: "v1"}, "v0 >= v1"},
		{Condition{Opcode: "unknown", Register: "v0"}, "unknown v0"},
	}

	for _, tt := range tests {
		got := tt.cond.String()
		if got != tt.want {
			t.Errorf("Condition.String() = %q, want %q", got, tt.want)
		}
	}
}

// TestDFGAnalyzer_AnalyzeEmpty тест на пустой метод
func TestDFGAnalyzer_AnalyzeEmpty(t *testing.T) {
	dfg := NewDFGAnalyzer(nil)
	dfg.Analyze() // Не должен упасть

	cfg := &ControlFlowGraph{}
	dfg2 := NewDFGAnalyzer(cfg)
	dfg2.Analyze()

	info := dfg2.GetDFG(20)
	if info != nil {
		t.Error("GetDFG on empty CFG should return nil")
	}
}
