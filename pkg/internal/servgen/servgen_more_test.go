package servgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/protocol"
)

// ─── GenerateFromJSEndpoints ──────────────────────────────────────────────────

func TestGenerateFromJSEndpoints_Basic(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.OutputDir = filepath.Join(dir, "mock")
	cfg.ModuleName = "test-mock-server"

	endpoints := []string{
		"/api/v1/login",
		"/api/v1/profile",
		"/api/v1/inventory",
	}

	spec := protocol.NewProtocolSpec("Test")
	g := NewGenerator(cfg, spec)
	if err := g.GenerateFromJSEndpoints(endpoints); err != nil {
		t.Fatalf("GenerateFromJSEndpoints: %v", err)
	}

	// Verify handlers file exists and contains handler funcs
	handlersPath := filepath.Join(cfg.OutputDir, "pkg/handlers/endpoints.go")
	data, err := os.ReadFile(handlersPath)
	if err != nil {
		t.Fatalf("handlers file not created: %v", err)
	}
	content := string(data)

	for i := range endpoints {
		expected := "HandleMockEndpoint" + itoa(i)
		if !strings.Contains(content, expected) {
			t.Errorf("handlers.go missing %q", expected)
		}
	}
	if !strings.Contains(content, "package handlers") {
		t.Error("handlers.go missing package declaration")
	}

	// Verify main server file
	mainPath := filepath.Join(cfg.OutputDir, "cmd/mockserver/main.go")
	mainData, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("main.go not created: %v", err)
	}
	mainContent := string(mainData)
	if !strings.Contains(mainContent, "package main") {
		t.Error("main.go missing package main")
	}
	if !strings.Contains(mainContent, "/api/v1/login") {
		t.Error("main.go missing endpoint route registration")
	}

	// Verify go.mod
	gomodPath := filepath.Join(cfg.OutputDir, "go.mod")
	gomodData, err := os.ReadFile(gomodPath)
	if err != nil {
		t.Fatalf("go.mod not created: %v", err)
	}
	if !strings.Contains(string(gomodData), "module test-mock-server") {
		t.Errorf("go.mod missing module name: %s", gomodData)
	}
}

func TestGenerateFromJSEndpoints_Empty(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.OutputDir = filepath.Join(dir, "mock-empty")

	g := NewGenerator(cfg, protocol.NewProtocolSpec("X"))
	if err := g.GenerateFromJSEndpoints([]string{}); err != nil {
		t.Fatalf("GenerateFromJSEndpoints with empty endpoints: %v", err)
	}

	// handlers file should still be created, just with no handlers
	handlersPath := filepath.Join(cfg.OutputDir, "pkg/handlers/endpoints.go")
	if _, err := os.Stat(handlersPath); err != nil {
		t.Fatalf("handlers file should exist even with empty endpoints: %v", err)
	}
}

func TestGenerateFromJSEndpoints_OutputDirError(t *testing.T) {
	// Use a file path as directory — should fail at MkdirAll
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.OutputDir = filepath.Join(blocker, "child")

	g := NewGenerator(cfg, protocol.NewProtocolSpec("X"))
	if err := g.GenerateFromJSEndpoints([]string{"/test"}); err == nil {
		t.Error("expected error when output dir cannot be created")
	}
}

// ─── Generate — handler content verification ──────────────────────────────────

func TestGenerateHandlers_ContainDirectionAndSize(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.OutputDir = filepath.Join(dir, "server")

	spec := protocol.NewProtocolSpec("MyGame")
	spec.AddSample(10100, "C2S", []byte("hello world"))
	spec.AnnotateSupercell()

	g := NewGenerator(cfg, spec)
	if err := g.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	handlers, err := os.ReadFile(filepath.Join(cfg.OutputDir, "pkg/handler/handlers.go"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(handlers)
	// Direction and sample count should appear in handler comment
	if !strings.Contains(content, "Direction:") {
		t.Errorf("handlers.go missing Direction comment: %s", content)
	}
	if !strings.Contains(content, "Samples:") {
		t.Errorf("handlers.go missing Samples comment: %s", content)
	}
}

// ─── generateConfig — JSON content ───────────────────────────────────────────

func TestGenerateConfig_Content(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenPort = 9999
	cfg.AdminPort = 7777
	cfg.GameName = "MySpecialGame"

	spec := protocol.NewProtocolSpec("Test")
	g := NewGenerator(cfg, spec)
	content := g.generateConfig()

	if !strings.Contains(content, "9999") {
		t.Errorf("config missing listen port 9999: %s", content)
	}
	if !strings.Contains(content, "7777") {
		t.Errorf("config missing admin port 7777: %s", content)
	}
	if !strings.Contains(content, "MySpecialGame") {
		t.Errorf("config missing game name: %s", content)
	}
	if !strings.Contains(content, "Mega-Analyzer") {
		t.Errorf("config missing generator credit: %s", content)
	}
}

// ─── generateMain — content ───────────────────────────────────────────────────

func TestGenerateMain_Content(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ModuleName = "my-server"
	cfg.GameName = "AwesomeGame"
	cfg.ListenPort = 8888
	cfg.AdminPort = 9090

	spec := protocol.NewProtocolSpec("Test")
	g := NewGenerator(cfg, spec)
	content := g.generateMain()

	if !strings.Contains(content, "my-server/pkg/handler") {
		t.Errorf("main.go missing module import: %s", content)
	}
	if !strings.Contains(content, "AwesomeGame") {
		t.Errorf("main.go missing game name: %s", content)
	}
	if !strings.Contains(content, "8888") {
		t.Errorf("main.go missing listen port: %s", content)
	}
	// Admin panel line must keep a runtime %%d verb and pass the port as an arg.
	// Regression: older template baked the port into the format string and left
	// a dangling extra argument (go vet: "Printf call has arguments but no formatting directives").
	wantAdmin := `fmt.Printf("📊 Admin panel: http://localhost:%d\n", 9090)`
	if !strings.Contains(content, wantAdmin) {
		t.Errorf("main.go admin printf wrong; want %q\n--- got ---\n%s", wantAdmin, content)
	}
	if strings.Contains(content, `http://localhost:9090\n", 9090`) {
		t.Errorf("main.go still has baked-in admin port with dangling arg:\n%s", content)
	}
	if !strings.Contains(content, "log.Fatalf") {
		t.Errorf("main.go should Fatalf on listen failure:\n%s", content)
	}
}

// ─── generateGoMod ────────────────────────────────────────────────────────────

func TestGenerateGoMod_Content(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ModuleName = "github.com/test/myserver"
	g := NewGenerator(cfg, protocol.NewProtocolSpec("X"))
	content := g.generateGoMod()

	if !strings.Contains(content, "module github.com/test/myserver") {
		t.Errorf("go.mod missing module directive: %s", content)
	}
	if !strings.Contains(content, "go ") {
		t.Errorf("go.mod missing go directive: %s", content)
	}
}

// ─── generateReadme ───────────────────────────────────────────────────────────

func TestGenerateReadme_Content(t *testing.T) {
	cfg := DefaultConfig()
	cfg.GameName = "SuperGame"
	cfg.ListenPort = 9339

	spec := protocol.NewProtocolSpec("supercell")
	spec.AddSample(10100, "C2S", []byte("hello"))
	spec.AddSample(10100, "C2S", []byte("hello2"))

	g := NewGenerator(cfg, spec)
	readme := g.generateReadme()

	if !strings.Contains(readme, "SuperGame") {
		t.Errorf("README missing game name: %s", readme)
	}
	if !strings.Contains(readme, "9339") {
		t.Errorf("README missing listen port: %s", readme)
	}
	if !strings.Contains(readme, "educational") {
		t.Errorf("README missing disclaimer: %s", readme)
	}
}

// ─── generateSession ─────────────────────────────────────────────────────────

func TestGenerateSession_Content(t *testing.T) {
	cfg := DefaultConfig()
	g := NewGenerator(cfg, protocol.NewProtocolSpec("X"))
	content := g.generateSession()

	if !strings.Contains(content, "package session") {
		t.Errorf("session.go missing package: %s", content)
	}
	if !strings.Contains(content, "type Session struct") {
		t.Errorf("session.go missing Session struct: %s", content)
	}
	if !strings.Contains(content, "type Manager struct") {
		t.Errorf("session.go missing Manager struct: %s", content)
	}
}

// ─── generateStore ────────────────────────────────────────────────────────────

func TestGenerateStore_Content(t *testing.T) {
	cfg := DefaultConfig()
	g := NewGenerator(cfg, protocol.NewProtocolSpec("X"))
	content := g.generateStore()

	if !strings.Contains(content, "package database") {
		t.Errorf("store.go missing package: %s", content)
	}
	if !strings.Contains(content, "type Store struct") {
		t.Errorf("store.go missing Store struct: %s", content)
	}
	if !strings.Contains(content, "CreateDefaultPlayer") {
		t.Errorf("store.go missing CreateDefaultPlayer: %s", content)
	}
}

// ─── toGoName — edge cases ───────────────────────────────────────────────────

func TestToGoName_EdgeCases(t *testing.T) {
	// Single char
	if got := toGoName("a"); got != "A" {
		t.Errorf("toGoName('a') = %q, want 'A'", got)
	}
	// Multiple underscores
	if got := toGoName("some_multi_word"); got != "SomeMultiWord" {
		t.Errorf("toGoName('some_multi_word') = %q, want 'SomeMultiWord'", got)
	}
	// Already pascal case
	if got := toGoName("AlreadyPascal"); got != "Alreadypascal" {
		t.Errorf("toGoName('AlreadyPascal') = %q, want 'Alreadypascal'", got)
	}
}

// ─── helper ──────────────────────────────────────────────────────────────────

// itoa is a simple int-to-string helper for test use.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	result := ""
	for i > 0 {
		result = string(rune('0'+i%10)) + result
		i /= 10
	}
	return result
}
