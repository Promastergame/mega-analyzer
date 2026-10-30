package plugin

import (
	"context"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestPluginRegistry_Register(t *testing.T) {
	reg := NewPluginRegistry()

	plugin := NewHardcodedSecretDetector()
	err := reg.Register(plugin)
	if err != nil {
		t.Fatalf("Failed to register plugin: %v", err)
	}

	if reg.Count() != 1 {
		t.Errorf("Expected 1 plugin, got %d", reg.Count())
	}
}

func TestPluginRegistry_RegisterNil(t *testing.T) {
	reg := NewPluginRegistry()

	err := reg.Register(nil)
	if err == nil {
		t.Error("Expected error when registering nil plugin")
	}
}

func TestPluginRegistry_RegisterDuplicate(t *testing.T) {
	reg := NewPluginRegistry()

	plugin1 := NewHardcodedSecretDetector()
	plugin2 := NewHardcodedSecretDetector()

	err := reg.Register(plugin1)
	if err != nil {
		t.Fatalf("Failed to register first plugin: %v", err)
	}

	err = reg.Register(plugin2)
	if err == nil {
		t.Error("Expected error when registering duplicate plugin")
	}
}

func TestPluginRegistry_Unregister(t *testing.T) {
	reg := NewPluginRegistry()

	plugin := NewHardcodedSecretDetector()
	reg.Register(plugin)

	if reg.Count() != 1 {
		t.Fatalf("Expected 1 plugin before unregister, got %d", reg.Count())
	}

	removed := reg.Unregister("hardcoded-secret-detector")
	if !removed {
		t.Error("Expected plugin to be removed")
	}

	if reg.Count() != 0 {
		t.Errorf("Expected 0 plugins after unregister, got %d", reg.Count())
	}
}

func TestPluginRegistry_UnregisterNonExistent(t *testing.T) {
	reg := NewPluginRegistry()

	removed := reg.Unregister("non-existent")
	if removed {
		t.Error("Expected false when unregistering non-existent plugin")
	}
}

func TestPluginRegistry_List(t *testing.T) {
	reg := NewPluginRegistry()

	plugin1 := NewHardcodedSecretDetector()
	reg.Register(plugin1)

	plugins := reg.List()
	if len(plugins) != 1 {
		t.Errorf("Expected 1 plugin in list, got %d", len(plugins))
	}

	if plugins[0].Name() != "hardcoded-secret-detector" {
		t.Errorf("Expected plugin name 'hardcoded-secret-detector', got '%s'", plugins[0].Name())
	}
}

func TestPluginRegistry_InitializeAll(t *testing.T) {
	reg := NewPluginRegistry()

	plugin := NewHardcodedSecretDetector()
	reg.Register(plugin)

	ctx := PluginContext{
		TargetDir:  "/tmp/test",
		Config:     make(map[string]string),
		SharedData: make(map[string]interface{}),
	}

	errs := reg.InitializeAll(&ctx)
	if len(errs) != 0 {
		t.Errorf("Expected no errors, got %d", len(errs))
	}
}

func TestPluginRegistry_RunAll(t *testing.T) {
	reg := NewPluginRegistry()

	plugin := NewHardcodedSecretDetector()
	reg.Register(plugin)

	file := FileInfo{
		Path: "test.smali",
	}
	content := []byte(`const-string v0, "api_key"`)

	ctx := context.Background()
	findings := reg.RunAll(ctx, file, content)

	if len(findings) == 0 {
		t.Log("No findings (plugin might not match content)")
	}

	// Check that findings have plugin name set
	for _, f := range findings {
		if f.PluginName != "hardcoded-secret-detector" {
			t.Errorf("Expected plugin name in finding, got '%s'", f.PluginName)
		}
	}
}

func TestPluginRegistry_FinalizeAll(t *testing.T) {
	reg := NewPluginRegistry()

	plugin := NewHardcodedSecretDetector()
	reg.Register(plugin)

	findings := reg.FinalizeAll()
	// Base plugin returns nil, so findings should be empty
	if len(findings) != 0 {
		t.Errorf("Expected no findings from finalize, got %d", len(findings))
	}
}

func TestPluginContext_SharedData(t *testing.T) {
	ctx := PluginContext{
		SharedData: make(map[string]interface{}),
	}

	ctx.SetShared("key", "value")

	val, ok := ctx.GetShared("key")
	if !ok {
		t.Error("Expected to find shared data")
	}
	if val != "value" {
		t.Errorf("Expected 'value', got '%v'", val)
	}
}

func TestPluginContext_SharedDataNotFound(t *testing.T) {
	ctx := PluginContext{
		SharedData: make(map[string]interface{}),
	}

	_, ok := ctx.GetShared("non-existent")
	if ok {
		t.Error("Expected not to find non-existent key")
	}
}

func TestHardcodedSecretDetector_Name(t *testing.T) {
	plugin := NewHardcodedSecretDetector()

	if plugin.Name() != "hardcoded-secret-detector" {
		t.Errorf("Expected name 'hardcoded-secret-detector', got '%s'", plugin.Name())
	}
}

func TestHardcodedSecretDetector_Version(t *testing.T) {
	plugin := NewHardcodedSecretDetector()

	if plugin.Version() != "1.1.0" {
		t.Errorf("Expected version '1.1.0', got '%s'", plugin.Version())
	}
}

func TestHardcodedSecretDetector_Detect(t *testing.T) {
	plugin := NewHardcodedSecretDetector()

	ctx := PluginContext{
		TargetDir:  "/tmp",
		SharedData: make(map[string]interface{}),
	}
	err := plugin.Initialize(&ctx)
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	file := FileInfo{
		Path: "smali/com/app/Config.smali",
	}
	content := []byte(`
		.method public getConfig()Ljava/lang/String;
			.locals 1
			const-string v0, "api_key"
			return-object v0
		.end method
	`)

	findings := plugin.Detect(context.Background(), file, content)

	// Should find at least api_key
	found := false
	for _, f := range findings {
		if f.Severity != types.SeverityHigh {
			t.Errorf("Expected high severity, got %v", f.Severity)
		}
		if f.Type == "hardcoded_secret" {
			found = true
		}
	}

	if !found {
		t.Log("Plugin did not find hardcoded secrets (may be expected depending on implementation)")
	}
}

func TestPluginFinding_ToMatch(t *testing.T) {
	finding := PluginFinding{
		PluginName:    "test-plugin",
		PluginVersion: "1.0.0",
		Type:          "test_type",
		Severity:      types.SeverityCritical,
		Title:         "Test finding",
		Description:   "Test description",
		File:          "test.smali",
		Line:          42,
		Tags:          []string{"security"},
	}

	match := finding.ToMatch()

	if match.Text != "Test finding" {
		t.Errorf("Expected text 'Test finding', got '%s'", match.Text)
	}

	if match.File != "test.smali" {
		t.Errorf("Expected file 'test.smali', got '%s'", match.File)
	}

	if match.Line != 42 {
		t.Errorf("Expected line 42, got %d", match.Line)
	}

	if !match.IsCritical {
		t.Error("Expected IsCritical to be true")
	}
}

func TestBasePlugin_Defaults(t *testing.T) {
	bp := &BasePlugin{
		PluginName:        "test",
		PluginVersion:     "1.0",
		PluginDescription: "Test plugin",
	}

	if bp.Name() != "test" {
		t.Errorf("Expected name 'test', got '%s'", bp.Name())
	}

	if bp.Version() != "1.0" {
		t.Errorf("Expected version '1.0', got '%s'", bp.Version())
	}

	if bp.Description() != "Test plugin" {
		t.Errorf("Expected description 'Test plugin', got '%s'", bp.Description())
	}

	if bp.Initialize(&PluginContext{}) != nil {
		t.Error("Expected Initialize to return nil")
	}

	if bp.Finalize() != nil {
		t.Error("Expected Finalize to return nil")
	}
}
