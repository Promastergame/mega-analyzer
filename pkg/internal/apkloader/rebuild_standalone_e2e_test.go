package apkloader

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/apkloader/axml"
	"mega-analyzer/pkg/internal/testutil"
)

// TestStandaloneEditCycle proves the full no-external-tools loop: decode a
// synthetic APK natively, edit smali, rebuild with --standalone-equivalent
// policy, then verify v1+v2+v3 signatures, alignment, and that the edit
// actually landed in the output DEX (not silently dropped).
func TestStandaloneEditCycle(t *testing.T) {
	oldStandalone := Standalone()
	SetStandalone(true)
	defer SetStandalone(oldStandalone)

	dir := testutil.TempDir(t)
	dex, _, err := AssembleSmaliText("A.smali", `.class public Lcom/e2/A;
.super Ljava/lang/Object;
.field public static final LEVEL:I = 1
.method public static level()I
    .registers 1
    const/4 v0, 1
    return v0
.end method
`, 0)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	apkPath := filepath.Join(dir, "app.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, body := range map[string][]byte{
		"AndroidManifest.xml": axml.MinimalManifestXML(),
		"classes.dex":         dex,
		"resources.arsc":      axml.MinimalARSC(),
	} {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// 1. Decode natively.
	decDir := filepath.Join(dir, "decoded")
	e := NewExtractor()
	if _, err := e.DecodeAPK(context.Background(), apkPath, DecodeOptions{
		OutputDir: decDir, DexBackend: DecompileBackendNative,
	}); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// 2. Edit smali: const 1 -> 7 and static field 1 -> 7.
	smaliPath := filepath.Join(decDir, "smali", "com", "e2", "A.smali")
	raw, err := os.ReadFile(smaliPath)
	if err != nil {
		t.Fatalf("read smali (check class-path mapping): %v", err)
	}
	edited := strings.Replace(string(raw), "LEVEL:I", "LEVEL:I", 1)
	edited = strings.Replace(edited, "const/4 v0, 1", "const/4 v0, 7", 1)
	edited = strings.Replace(edited, "LEVEL:I = 1", "LEVEL:I = 7", 1)
	if edited == string(raw) {
		t.Fatalf("fixture smali did not contain editable patterns:\n%s", raw)
	}
	if err := os.WriteFile(smaliPath, []byte(edited), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Rebuild with only built-in tools.
	outAPK := filepath.Join(dir, "rebuilt.apk")
	r := NewAPKRebuilder(decDir)
	if err := r.Rebuild(context.Background(), outAPK); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	// 4. Verify signatures and alignment on the FINAL artifact.
	fp1, err := VerifyV1SignatureOffline(outAPK)
	if err != nil {
		t.Fatalf("v1 verify: %v", err)
	}
	v2out, err := VerifyV2V3Offline(outAPK)
	if err != nil {
		t.Fatalf("v2/v3 verify: %v", err)
	}
	if !v2out.V2 || !v2out.V3 {
		t.Fatalf("schemes incomplete: %+v", v2out)
	}
	if v2out.SignerSHA256 != fp1 {
		t.Fatal("v1 and v2/v3 signers differ")
	}
	if err := VerifyAlignment(outAPK); err != nil {
		t.Fatalf("alignment: %v", err)
	}

	// 5. The edit must be IN the output DEX: re-decode and inspect.
	dec2 := filepath.Join(dir, "decoded2")
	e2 := NewExtractor()
	SetStandalone(false)
	if _, err := e2.DecodeAPK(context.Background(), outAPK, DecodeOptions{
		OutputDir: dec2, DexBackend: DecompileBackendNative,
	}); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	SetStandalone(true)
	raw2, err := os.ReadFile(filepath.Join(dec2, "smali", "com", "e2", "A.smali"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw2), "const/4 v0, 7") {
		t.Fatalf("edited const missing from rebuilt DEX:\n%s", raw2)
	}
	if !strings.Contains(string(raw2), "LEVEL:I = 7") {
		t.Fatalf("edited static field missing from rebuilt DEX:\n%s", raw2)
	}
}
