package callgraph

import (
	"slices"
	"testing"

	"mega-analyzer/pkg/internal/dexir"
)

func TestClassHierarchy_SuperAndSubMapping(t *testing.T) {
	// Grandparent -> Parent -> Child
	grand := testClass("LGrandparent;", "Ljava/lang/Object;", testMethod("greet", "V"))
	parent := testClass("LParent;", "LGrandparent;", testMethod("greet", "V"))
	child := testClass("LChild;", "LParent;")

	h := NewClassHierarchy([]*dexir.Class{grand, parent, child})

	// Supers of Child should include LParent; and LGrandparent;
	supers := h.Supers("LChild;")
	if !slices.Contains(supers, "LParent;") || !slices.Contains(supers, "LGrandparent;") {
		t.Errorf("Supers(LChild;) = %v, want LParent; and LGrandparent;", supers)
	}

	// Subs of Grandparent should include LParent; and LChild;
	subs := h.Subs("LGrandparent;")
	if !slices.Contains(subs, "LParent;") || !slices.Contains(subs, "LChild;") {
		t.Errorf("Subs(LGrandparent;) = %v, want LParent; and LChild;", subs)
	}
}

func TestClassHierarchy_OverrideResolution(t *testing.T) {
	// Base defines render()V
	// Sub1 overrides render()V
	// Sub2 inherits render()V without overriding
	// Sub3 overrides render()V
	base := testClass("LBaseRender;", "Ljava/lang/Object;", testMethod("render", "V"))
	sub1 := testClass("LSubRender1;", "LBaseRender;", testMethod("render", "V"))
	sub2 := testClass("LSubRender2;", "LBaseRender;")
	sub3 := testClass("LSubRender3;", "LBaseRender;", testMethod("render", "V"))

	h := NewClassHierarchy([]*dexir.Class{base, sub1, sub2, sub3})

	impls := h.FindImplementations("LBaseRender;", "render", "()V")
	expected := []string{"LBaseRender;", "LSubRender1;", "LSubRender3;"}
	if len(impls) != len(expected) {
		t.Fatalf("FindImplementations = %v, want %v", impls, expected)
	}
	for _, exp := range expected {
		if !slices.Contains(impls, exp) {
			t.Errorf("missing implementation %s in %v", exp, impls)
		}
	}
}

func TestClassHierarchy_InterfaceImplementation(t *testing.T) {
	// InterfaceListener with onEvent()V
	// ServiceA implements InterfaceListener
	// ServiceB implements InterfaceListener
	iface := testClass("LInterfaceListener;", "Ljava/lang/Object;", testMethod("onEvent", "V"))
	srvA := testClass("LServiceA;", "Ljava/lang/Object;", testMethod("onEvent", "V"))
	srvA.Interfaces = []string{"LInterfaceListener;"}
	srvB := testClass("LServiceB;", "Ljava/lang/Object;", testMethod("onEvent", "V"))
	srvB.Interfaces = []string{"LInterfaceListener;"}

	h := NewClassHierarchy([]*dexir.Class{iface, srvA, srvB})

	impls := h.FindImplementations("LInterfaceListener;", "onEvent", "()V")
	if !slices.Contains(impls, "LServiceA;") || !slices.Contains(impls, "LServiceB;") {
		t.Errorf("FindImplementations for interface = %v, want LServiceA and LServiceB", impls)
	}
}

func TestClassHierarchy_UnknownSDKTypes(t *testing.T) {
	// CustomActivity extends Landroid/app/Activity; (not present in dexir classes)
	// overrides onCreate(Landroid/os/Bundle;)V
	customAct := testClass("Lcom/app/CustomActivity;", "Landroid/app/Activity;", &dexir.Method{
		Name:       "onCreate",
		ReturnType: "V",
		Params:     []string{"Landroid/os/Bundle;"},
	})

	h := NewClassHierarchy([]*dexir.Class{customAct})

	// Known should return false for SDK type
	if h.Known("Landroid/app/Activity;") {
		t.Error("Expected Known(Landroid/app/Activity;) to be false")
	}

	// Subs of unknown SDK type should still return CustomActivity
	subs := h.Subs("Landroid/app/Activity;")
	if !slices.Contains(subs, "Lcom/app/CustomActivity;") {
		t.Errorf("Subs(Landroid/app/Activity;) = %v, want [Lcom/app/CustomActivity;]", subs)
	}

	// FindImplementations on unknown SDK type should find CustomActivity's method
	impls := h.FindImplementations("Landroid/app/Activity;", "onCreate", "(Landroid/os/Bundle;)V")
	if !slices.Contains(impls, "Lcom/app/CustomActivity;") {
		t.Errorf("FindImplementations for SDK type = %v, want [Lcom/app/CustomActivity;]", impls)
	}
}
