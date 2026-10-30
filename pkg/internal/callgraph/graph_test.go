package callgraph

import (
	"slices"
	"testing"

	"mega-analyzer/pkg/internal/dexir"
)

func TestCHAAndRTA(t *testing.T) {
	base := testClass("LBase;", "Ljava/lang/Object;", testMethod("run", "V"))
	sub := testClass("LSub;", "LBase;", testMethod("run", "V"))
	other := testClass("LOther;", "LBase;", testMethod("run", "V"))
	callerMethod := testMethod("call", "V")
	callerMethod.Instructions = []*dexir.Instruction{
		{Op: dexir.OpNewInstance, Dst: 0, Type: "LSub;"},
		{Op: dexir.OpInvokeVirtual, Srcs: []int32{0}, Method: &dexir.MethodRef{Class: "LBase;", Name: "run", Proto: "()V", ReturnType: "V"}},
	}
	caller := testClass("LCaller;", "Ljava/lang/Object;", callerMethod)

	builder := NewBuilder()
	for _, class := range []*dexir.Class{base, sub, other, caller} {
		builder.AddClass(class)
	}
	before := builder.Build().Callees("LCaller;->call()V")
	if !slices.Contains(before, "LSub;->run()V") || !slices.Contains(before, "LOther;->run()V") {
		t.Fatalf("CHA targets missing: %v", before)
	}
	builder.ApplyRTA()
	after := builder.Build().Callees("LCaller;->call()V")
	if !slices.Contains(after, "LSub;->run()V") || slices.Contains(after, "LOther;->run()V") {
		t.Fatalf("RTA filtering wrong: %v", after)
	}
	if !slices.Contains(after, "LBase;->run()V") {
		t.Fatalf("declared target must be retained: %v", after)
	}
}

func TestInterfaceDispatch(t *testing.T) {
	iface := testClass("LIface;", "Ljava/lang/Object;", testMethod("go", "V"))
	impl := testClass("LImpl;", "Ljava/lang/Object;", testMethod("go", "V"))
	impl.Interfaces = []string{"LIface;"}
	callerMethod := testMethod("call", "V")
	callerMethod.Instructions = []*dexir.Instruction{{Op: dexir.OpInvokeInterface, Method: &dexir.MethodRef{Class: "LIface;", Name: "go", Proto: "()V"}}}
	caller := testClass("LCaller;", "Ljava/lang/Object;", callerMethod)

	builder := NewBuilder()
	for _, class := range []*dexir.Class{iface, impl, caller} {
		builder.AddClass(class)
	}
	if got := builder.Build().Callees("LCaller;->call()V"); !slices.Contains(got, "LImpl;->go()V") {
		t.Fatalf("interface implementation missing: %v", got)
	}
}

func TestReflectionEdge(t *testing.T) {
	target := testClass("Lcom/example/Target;", "Ljava/lang/Object;", testMethod("danger", "V"))
	method := testMethod("reflect", "V")
	method.Instructions = []*dexir.Instruction{
		{Op: dexir.OpConstString, Dst: 0, HasStr: true, Str: "com.example.Target"},
		{Op: dexir.OpInvokeStatic, Srcs: []int32{0}, Method: &dexir.MethodRef{Class: "Ljava/lang/Class;", Name: "forName", Proto: "(Ljava/lang/String;)Ljava/lang/Class;"}},
		{Op: dexir.OpMoveResultObject, Dst: 1},
		{Op: dexir.OpConstString, Dst: 2, HasStr: true, Str: "danger"},
		{Op: dexir.OpInvokeVirtual, Srcs: []int32{1, 2}, Method: &dexir.MethodRef{Class: "Ljava/lang/Class;", Name: "getMethod", Proto: "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;"}},
		{Op: dexir.OpMoveResultObject, Dst: 3},
		{Op: dexir.OpInvokeVirtual, Srcs: []int32{3}, Method: &dexir.MethodRef{Class: "Ljava/lang/reflect/Method;", Name: "invoke", Proto: "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"}},
	}
	caller := testClass("LCaller;", "Ljava/lang/Object;", method)
	builder := NewBuilder()
	builder.AddClass(target)
	builder.AddClass(caller)
	graph := builder.Build()
	if !slices.Contains(graph.Callees("LCaller;->reflect()V"), "Lcom/example/Target;->danger()V") {
		t.Fatalf("reflection edge missing: %v", graph.Callees("LCaller;->reflect()V"))
	}
	if graph.Stats().ReflectionEdges != 1 {
		t.Fatalf("reflection stats = %+v", graph.Stats())
	}
}

func TestHierarchyCycleSafe(t *testing.T) {
	a := testClass("LA;", "LB;")
	b := testClass("LB;", "LA;")
	h := NewClassHierarchy([]*dexir.Class{a, b})
	if got := h.Supers("LA;"); len(got) != 1 || got[0] != "LB;" {
		t.Fatalf("unexpected supers: %v", got)
	}
	if got := h.Subs("LA;"); len(got) != 1 || got[0] != "LB;" {
		t.Fatalf("unexpected subs: %v", got)
	}
}

func TestFanoutCapLimit(t *testing.T) {
	base := testClass("LBaseFanout;", "Ljava/lang/Object;", testMethod("handle", "V"))
	sub1 := testClass("LSub1;", "LBaseFanout;", testMethod("handle", "V"))
	sub2 := testClass("LSub2;", "LBaseFanout;", testMethod("handle", "V"))
	sub3 := testClass("LSub3;", "LBaseFanout;", testMethod("handle", "V"))

	callerMethod := testMethod("call", "V")
	callerMethod.Instructions = []*dexir.Instruction{
		{Op: dexir.OpInvokeVirtual, Method: &dexir.MethodRef{Class: "LBaseFanout;", Name: "handle", Proto: "()V", ReturnType: "V"}},
	}
	caller := testClass("LCaller;", "Ljava/lang/Object;", callerMethod)

	builder := NewBuilder()
	builder.SetFanoutCap(2) // limit to 2 speculative targets
	for _, class := range []*dexir.Class{base, sub1, sub2, sub3, caller} {
		builder.AddClass(class)
	}

	graph := builder.Build()
	// Candidates count is 3 (sub1, sub2, sub3), which exceeds fanoutCap=2
	// So builder falls back to base target with Resolved = false
	sites := graph.Sites()
	if len(sites) != 1 {
		t.Fatalf("expected 1 site after fanout cap, got %d", len(sites))
	}
	if sites[0].Resolved {
		t.Errorf("expected site to be unresolved due to fanout cap exceeded, got Resolved = %v", sites[0].Resolved)
	}
}

func testClass(desc, super string, methods ...*dexir.Method) *dexir.Class {
	return &dexir.Class{Descriptor: desc, SuperClass: super, Methods: methods}
}

func testMethod(name, ret string) *dexir.Method {
	return &dexir.Method{Name: name, ReturnType: ret}
}
