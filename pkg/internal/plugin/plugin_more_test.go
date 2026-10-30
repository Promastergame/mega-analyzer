package plugin

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// ─── severityToScore helper ───────────────────────────────────────────────

func TestSeverityToScore_Critical(t *testing.T) {
	score := severityToScore(types.SeverityCritical)
	if score != 10.0 {
		t.Errorf("expected 10.0 for Critical, got %f", score)
	}
}

func TestSeverityToScore_High(t *testing.T) {
	score := severityToScore(types.SeverityHigh)
	if score != 8.0 {
		t.Errorf("expected 8.0 for High, got %f", score)
	}
}

func TestSeverityToScore_Medium(t *testing.T) {
	score := severityToScore(types.SeverityMedium)
	if score != 5.0 {
		t.Errorf("expected 5.0 for Medium, got %f", score)
	}
}

func TestSeverityToScore_Low(t *testing.T) {
	score := severityToScore(types.SeverityLow)
	if score != 2.0 {
		t.Errorf("expected 2.0 for Low, got %f", score)
	}
}

func TestSeverityToScore_Info(t *testing.T) {
	score := severityToScore(types.SeverityInfo)
	if score != 1.0 {
		t.Errorf("expected 1.0 for Info, got %f", score)
	}
}

// ─── GetShared and SetShared (PluginContext methods) ───────────────────────

func TestPluginContext_GetShared_Empty(t *testing.T) {
	ctx := &PluginContext{}
	val, ok := ctx.GetShared("key")
	if ok {
		t.Error("expected key not found in empty context")
	}
	if val != nil {
		t.Error("expected nil value")
	}
}

func TestPluginContext_SetShared_AndGet(t *testing.T) {
	ctx := &PluginContext{}
	ctx.SetShared("key1", "value1")
	val, ok := ctx.GetShared("key1")
	if !ok {
		t.Fatal("expected key1 to be found")
	}
	if val != "value1" {
		t.Errorf("expected 'value1', got %v", val)
	}
}

func TestPluginContext_SetShared_Multiple(t *testing.T) {
	ctx := &PluginContext{}
	ctx.SetShared("k1", "v1")
	ctx.SetShared("k2", "v2")
	ctx.SetShared("k3", 123)

	v1, ok1 := ctx.GetShared("k1")
	v2, ok2 := ctx.GetShared("k2")
	v3, ok3 := ctx.GetShared("k3")

	if !ok1 || v1 != "v1" {
		t.Error("expected k1 with v1")
	}
	if !ok2 || v2 != "v2" {
		t.Error("expected k2 with v2")
	}
	if !ok3 || v3 != 123 {
		t.Error("expected k3 with 123")
	}
}

func TestPluginContext_SetShared_Overwrite(t *testing.T) {
	ctx := &PluginContext{}
	ctx.SetShared("key", "old")
	val1, _ := ctx.GetShared("key")
	if val1 != "old" {
		t.Errorf("expected 'old', got %v", val1)
	}

	ctx.SetShared("key", "new")
	val2, _ := ctx.GetShared("key")
	if val2 != "new" {
		t.Errorf("expected 'new', got %v", val2)
	}
}

// ─── PluginRegistry methods ──────────────────────────────────────────────

func TestPluginRegistry_NewRegistry(t *testing.T) {
	registry := NewPluginRegistry()
	if registry == nil {
		t.Fatal("expected non-nil registry")
	}
	count := registry.Count()
	if count != 0 {
		t.Errorf("expected 0 plugins in new registry, got %d", count)
	}
}

func TestPluginRegistry_List_Empty(t *testing.T) {
	registry := NewPluginRegistry()
	list := registry.List()
	if list == nil {
		t.Error("expected non-nil list")
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d items", len(list))
	}
}
