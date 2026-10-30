package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/cmd/analyzer/web"
	"mega-analyzer/pkg/minecraft"
)

func TestMinecraftCLIAndWebDispatch(t *testing.T) {
	target := filepath.Join(t.TempDir(), "pack.mcpack")
	out := filepath.Join(t.TempDir(), "report")
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	f, err := zw.Create("pack.mcmeta")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte(`{"pack":{"pack_format":15,"description":"Test texture pack"}}`))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	args := web.BuildModeArgs("minecraft", []string{target}, out, "", "", "", nil)
	opts, err := NewCLIParser().Parse(args)
	if err != nil {
		t.Fatal(err)
	}
	if !opts.Minecraft || opts.Target != target {
		t.Fatalf("bad args %v", args)
	}
	if err := NewApp().Run(args); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(out, "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r minecraft.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if r.Format != "java-resource-pack" || !r.Complete {
		t.Fatalf("report %+v", r)
	}
	if _, err := os.Stat(filepath.Join(out, "REPORT.html")); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(after, b.Bytes()) {
		t.Fatal("input archive changed")
	}
}
func TestMinecraftRequiresTarget(t *testing.T) {
	if err := runMinecraft(&CLIOptions{Minecraft: true}); err == nil {
		t.Fatal("missing target accepted")
	}
}
