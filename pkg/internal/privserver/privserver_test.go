package privserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverGenericTarget(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "AndroidManifest.xml"), `<manifest package="com.example.beatstar"><application/></manifest>`)
	writeFile(t, filepath.Join(root, "res", "values", "strings.xml"), `<resources><string name="api">https://api.beatstar.example.com/v1/login</string><string name="wss">wss://realtime.beatstar.example.com/ws</string></resources>`)
	writeFile(t, filepath.Join(root, "smali", "com", "example", "App.smali"), "const-string v0, \"okhttp3.CertificatePinner\"\n")

	plan, err := Discover(root, DiscoverOptions{GameName: "Beatstar"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.GameName != "Beatstar" {
		t.Fatalf("expected game name Beatstar, got %s", plan.GameName)
	}
	if plan.AppPackage != "com.example.beatstar" {
		t.Fatalf("expected app package com.example.beatstar, got %s", plan.AppPackage)
	}
	if !plan.Pinning.Detected {
		t.Fatalf("expected pinning detected, got %#v", plan.Pinning)
	}
	if plan.Transport.Protocol == "" {
		t.Fatalf("expected transport, got empty")
	}
	if len(plan.Endpoints) == 0 {
		t.Fatalf("expected at least one endpoint, got none")
	}
	if !strings.HasPrefix(plan.Module, "B") {
		t.Fatalf("expected module to start with uppercase letter, got %q", plan.Module)
	}
}

func TestGenerateElixirSkeleton(t *testing.T) {
	root := t.TempDir()
	plan, err := Discover(root, DiscoverOptions{GameName: "Mocky"})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out")
	dir, err := Generate(plan, out)
	if err != nil {
		t.Fatal(err)
	}
	mustExist := []string{
		"mix.exs",
		"README.md",
		"config/config.exs",
		filepath.Join("lib", strings.ToLower(plan.Module)+".ex"),
		filepath.Join("lib", strings.ToLower(plan.Module), "application.ex"),
		filepath.Join("lib", strings.ToLower(plan.Module), "router.ex"),
		filepath.Join("lib", strings.ToLower(plan.Module), "session.ex"),
		filepath.Join("lib", strings.ToLower(plan.Module), "replay_store.ex"),
		filepath.Join("lib", strings.ToLower(plan.Module), "state_machine.ex"),
		filepath.Join("lib", strings.ToLower(plan.Module), "admin", "router.ex"),
		filepath.Join("lib", strings.ToLower(plan.Module), "admin", "dashboard.ex"),
		filepath.Join("lib", strings.ToLower(plan.Module), "handlers", "default.ex"),
		"priv/replays/replays.json",
	}
	for _, rel := range mustExist {
		full := filepath.Join(dir, rel)
		if _, err := os.Stat(full); err != nil {
			t.Fatalf("expected file %s, err: %v", rel, err)
		}
	}
	mix, err := os.ReadFile(filepath.Join(dir, "mix.exs"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mix), plan.Module+".MixProject") {
		t.Fatalf("mix.exs should reference module name %s", plan.Module)
	}
	app, err := os.ReadFile(filepath.Join(dir, "lib", strings.ToLower(plan.Module), "application.ex"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(app), "authorized use only") {
		t.Fatal("application module must include authorized-use banner")
	}
}

func TestWriteReadinessAndPlan(t *testing.T) {
	plan, err := Discover(t.TempDir(), DiscoverOptions{GameName: "Probe"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := WritePlan(plan, dir); err != nil {
		t.Fatal(err)
	}
	if err := WriteReadiness(plan, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "private_server_plan.json")); err != nil {
		t.Fatal(err)
	}
	rd, err := os.ReadFile(filepath.Join(dir, "PRIVATE_SERVER_READINESS.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rd), "Private Server Readiness") {
		t.Fatal("readiness markdown should include heading")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
