package apkloader

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func TestGenerateJavaClass(t *testing.T) {
	src := `.class public Lcom/example/J;
.super Ljava/lang/Object;
.field private count:I
.method public static add(II)I
    .registers 3
    add-int v0, v1, v2
    return v0
.end method
.method public run()V
    .registers 2
    const/4 v0, 0
    :loop
    if-ge v0, v0, :done
    add-int/lit8 v0, v0, 1
    goto :loop
    :done
    return-void
.end method
`
	dex, _, err := AssembleSmaliText("J.smali", src, 0)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	p, err := ParseDEXBytes(dex)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	cls := p.FindClassByName("Lcom/example/J;")
	if cls == nil {
		t.Fatal("class missing")
	}
	got := GenerateJavaClass(cls, p)
	for _, want := range []string{
		"package com.example;",
		"public class J {",
		"int count;",
		"int add(int arg0, int arg1)",
		"return v0;",
		"void run()",
		"while",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("java view missing %q\n%s", want, got)
		}
	}
	if !strings.Contains(got, "Smali is authoritative") {
		t.Error("missing authority disclaimer")
	}
}

func TestJavaViewSidecars(t *testing.T) {
	dir := testutil.TempDir(t)
	apk := filepath.Join(dir, "in.apk")
	writeJavaTestAPK(t, apk)
	out := filepath.Join(dir, "decoded")
	e := NewExtractor()
	if _, err := e.DecodeAPK(context.Background(), apk, DecodeOptions{
		OutputDir: out, NoResources: true, DexBackend: DecompileBackendNative, JavaView: true,
	}); err != nil {
		t.Fatalf("decode: %v", err)
	}
	javaFiles := 0
	_ = filepath.WalkDir(out, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(d.Name(), ".java") {
			javaFiles++
		}
		return nil
	})
	if javaFiles == 0 {
		t.Fatal("no .java sidecars emitted")
	}
}

func writeJavaTestAPK(t *testing.T, apk string) {
	t.Helper()
	dex, _, err := AssembleSmaliText("J.smali", `.class public Lj/J;
.super Ljava/lang/Object;
.method public static f()I
    .registers 1
    const/4 v0, 3
    return v0
.end method
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(apk)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := zip.NewWriter(f)
	defer w.Close()
	fw, err := w.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(dex); err != nil {
		t.Fatal(err)
	}
}
