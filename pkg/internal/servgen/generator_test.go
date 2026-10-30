package servgen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/protocol"
)

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.OutputDir == "" {
		t.Error("default OutputDir should be set")
	}
	if c.ListenPort == 0 {
		t.Error("default ListenPort should be set")
	}
	if c.GameName == "" {
		t.Error("default GameName should be set")
	}
	if c.DatabaseType == "" {
		t.Error("default DatabaseType should be set")
	}
}

func TestToGoName(t *testing.T) {
	cases := map[string]string{
		"ClientHello":   "Clienthello",
		"MSG_1234":      "Msg1234",
		"already_named": "AlreadyNamed",
		"":              "",
		"X":             "X",
	}
	for in, want := range cases {
		if got := toGoName(in); got != want {
			t.Errorf("toGoName(%q) = %q, want %q", in, got, want)
		}
	}
}

func newSpec() *protocol.ProtocolSpec {
	ps := protocol.NewProtocolSpec("Demo")
	ps.AddSample(10100, "C2S", []byte("hello"))
	ps.AddSample(20100, "S2C", []byte{0x01, 0x02, 0x03})
	ps.AnnotateSupercell()
	return ps
}

func TestSortedMessageIDs(t *testing.T) {
	ps := protocol.NewProtocolSpec("X")
	ps.AddSample(2000, "C2S", []byte{0})
	ps.AddSample(1000, "C2S", []byte{0})
	ps.AddSample(3000, "S2C", []byte{0})
	g := NewGenerator(DefaultConfig(), ps)
	ids := g.sortedMessageIDs()
	if len(ids) != 3 {
		t.Fatalf("expected 3 ids, got %d", len(ids))
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Errorf("ids not sorted ascending: %v", ids)
		}
	}
}

func TestGenerateWritesAllArtifacts(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.OutputDir = filepath.Join(dir, "server")
	cfg.GameName = "TestGame"

	g := NewGenerator(cfg, newSpec())
	if err := g.Generate(); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	wantFiles := []string{
		"go.mod",
		"cmd/server/main.go",
		"pkg/handler/router.go",
		"pkg/handler/handlers.go",
		"pkg/session/session.go",
		"pkg/database/store.go",
		"configs/server.json",
		"README.md",
	}
	for _, rel := range wantFiles {
		full := filepath.Join(cfg.OutputDir, rel)
		st, err := os.Stat(full)
		if err != nil {
			t.Errorf("missing generated file %s: %v", rel, err)
			continue
		}
		if st.Size() == 0 {
			t.Errorf("generated file %s is empty", rel)
		}
	}

	// Quick content sanity: the router must reference both message handlers.
	router, err := os.ReadFile(filepath.Join(cfg.OutputDir, "pkg/handler/router.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(router), "handleClienthello") {
		t.Errorf("router missing handleClienthello dispatch:\n%s", router)
	}

	// go.mod must use the configured module name.
	gomod, _ := os.ReadFile(filepath.Join(cfg.OutputDir, "go.mod"))
	if !strings.Contains(string(gomod), "module ") {
		t.Errorf("go.mod missing module directive: %s", gomod)
	}

	// configs/server.json must be valid JSON with the configured port.
	cfgBytes, _ := os.ReadFile(filepath.Join(cfg.OutputDir, "configs/server.json"))
	var parsed map[string]any
	if err := json.Unmarshal(cfgBytes, &parsed); err != nil {
		t.Fatalf("server.json not valid JSON: %v\n%s", err, cfgBytes)
	}
	if parsed["server"] == nil {
		t.Errorf("server.json missing 'server' section")
	}

	// README must mention the game name.
	readme, _ := os.ReadFile(filepath.Join(cfg.OutputDir, "README.md"))
	if !strings.Contains(string(readme), "TestGame") {
		t.Errorf("README missing game name")
	}
}

func TestGenerateOutputDirError(t *testing.T) {
	// Use a path that's already a regular file — MkdirAll will fail.
	dir := t.TempDir()
	conflict := filepath.Join(dir, "conflict")
	if err := os.WriteFile(conflict, []byte("blocker"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.OutputDir = filepath.Join(conflict, "child")
	g := NewGenerator(cfg, newSpec())
	if err := g.Generate(); err == nil {
		t.Error("Generate must fail when OutputDir cannot be created")
	}
}

func TestGenerateRouterEmptySpec(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OutputDir = filepath.Join(t.TempDir(), "empty")

	emptySpec := protocol.NewProtocolSpec("Empty")
	g := NewGenerator(cfg, emptySpec)
	if err := g.Generate(); err != nil {
		t.Fatalf("Generate empty spec: %v", err)
	}

	// Dispatch table should still compile-time render even with no messages.
	router, _ := os.ReadFile(filepath.Join(cfg.OutputDir, "pkg/handler/router.go"))
	if !strings.Contains(string(router), "switch msgType") {
		t.Errorf("router missing dispatch switch: %s", router)
	}
}
