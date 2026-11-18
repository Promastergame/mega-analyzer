// vuln_dynload_smali_test.go — AST dynamic code loading (audit P2-10).
package pipeline

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func runDynLoadAST(t *testing.T, content string) []types.Match {
	t.Helper()
	d := NewVulnDynamicLoadDetector()
	ctx := createDetectorCtx("smali/com/app/Loader.smali", []byte(content), types.FileTypeSmali)
	ctx.Class = parseCryptoFixture(t, content)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	d.Detect(ctx, analysis)
	return analysis.Matches
}

func TestDynLoad_ExternalStorageDexCritical(t *testing.T) {
	matches := runDynLoadAST(t, `
.class public Lcom/app/Loader;
.method public load()V
    .locals 2
    const-string v0, "/sdcard/Download/payload.jar"
    invoke-direct {v1, v0, v0, v0, v0}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V
    return-void
.end method
`)
	if len(matches) != 1 {
		t.Fatalf("expected exactly one finding, got %v", matches)
	}
	if !matches[0].IsCritical || matches[0].Category != types.CategoryDynamicLoad {
		t.Errorf("external-storage DEX load must be critical DynamicLoad, got %+v", matches[0])
	}
}

func TestDynLoad_LiteralPrivatePathNotFlagged(t *testing.T) {
	matches := runDynLoadAST(t, `
.class public Lcom/app/Loader;
.method public load()V
    .locals 2
    const-string v0, "/data/data/com.app/files/patch.dex"
    invoke-direct {v1, v0, v0, v0, v0}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V
    return-void
.end method
`)
	if len(matches) != 0 {
		t.Fatalf("literal app-private DEX path must not be flagged, got %v", matches)
	}
}

func TestDynLoad_ComputedDexPathFlagged(t *testing.T) {
	matches := runDynLoadAST(t, `
.class public Lcom/app/Loader;
.method public load(Ljava/lang/String;)V
    .locals 1
    invoke-direct {v0, p1, p1, p1, p1}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V
    return-void
.end method
`)
	if len(matches) != 1 || !matches[0].IsCritical {
		t.Fatalf("computed DEX path must produce a critical finding, got %v", matches)
	}
	if matches[0].Confidence != "medium" {
		t.Errorf("unresolved operand → Confidence=medium, got %q", matches[0].Confidence)
	}
}

func TestDynLoad_InMemoryDexIsSuspiciousNotCriticalWithoutSourceFlow(t *testing.T) {
	matches := runDynLoadAST(t, `
.class public Lcom/app/Loader;
.method public load(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V
    .locals 1
    invoke-direct {v0, p1, p2}, Ldalvik/system/InMemoryDexClassLoader;-><init>(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V
    return-void
.end method
`)
	if len(matches) != 1 || matches[0].IsCritical || matches[0].Severity != types.SeverityMedium {
		t.Fatalf("InMemoryDexClassLoader without an untrusted source must be medium, got %v", matches)
	}
}

func TestDynLoad_RuntimeLiteralArgumentUsesSecondRegister(t *testing.T) {
	matches := runDynLoadAST(t, `
.class public Lcom/app/Loader;
.method public load()V
    .locals 2
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    move-result-object v0
    const-string v1, "native"
    invoke-virtual {v0, v1}, Ljava/lang/Runtime;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
`)
	if len(matches) != 0 {
		t.Fatalf("literal Runtime.loadLibrary must not use the receiver as its argument, got %v", matches)
	}
}

func TestDynLoad_ExternalStoragePathUsesDirectoryBoundaries(t *testing.T) {
	if externalStoragePath("/data/user/0/com.app/files/mnt/sdcard-copy.dex") {
		t.Fatal("path containing an external-storage token must not be treated as external storage")
	}
	if externalStoragePath("/sdcard_backup/payload.dex") {
		t.Fatal("prefix lookalike must not be treated as /sdcard")
	}
	if !externalStoragePath("/storage/ABCD-1234/payload.dex") {
		t.Fatal("removable external-storage volume must be recognised")
	}
}

func TestDynLoad_LoadLibraryLiteralSilentComputedFlagged(t *testing.T) {
	literal := runDynLoadAST(t, `
.class public Lcom/app/Loader;
.method static constructor <clinit>()V
    const-string v0, "native"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
`)
	if len(literal) != 0 {
		t.Fatalf("literal loadLibrary must stay silent, got %v", literal)
	}

	computed := runDynLoadAST(t, `
.class public Lcom/app/Loader;
.method public load(Ljava/lang/String;)V
    invoke-static {p0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
`)
	if len(computed) != 1 || computed[0].Severity != types.SeverityMedium {
		t.Fatalf("computed loadLibrary name must produce a medium finding, got %v", computed)
	}
}

func TestDynLoad_SystemLoadExternalSo(t *testing.T) {
	matches := runDynLoadAST(t, `
.class public Lcom/app/Loader;
.method public load()V
    const-string v0, "/storage/emulated/0/Download/libevil.so"
    invoke-static {v0}, Ljava/lang/System;->load(Ljava/lang/String;)V
    return-void
.end method
`)
	if len(matches) != 1 || !matches[0].IsCritical {
		t.Fatalf("System.load from external storage must be critical, got %v", matches)
	}
}

// ReLinker (and Unity's bundled copy of it) extracts the .so out of the app's
// own APK into private storage and then calls System.load on the resulting
// absolute path. That operand is computed, but its origin is the signed APK,
// so it must not be reported as an unverifiable-path (CWE-427) finding.
func TestDynLoad_RelinkerPrivateExtractionNotFlagged(t *testing.T) {
	matches := runDynLoadAST(t, `
.class public Lcom/app/Engine;
.method public load(Landroid/content/Context;)V
    .locals 4
    invoke-virtual {p1, v0, v1}, Landroid/content/Context;->getDir(Ljava/lang/String;I)Ljava/io/File;
    move-result-object v0
    new-instance v1, Ljava/util/zip/ZipFile;
    invoke-virtual {v1, v2}, Ljava/util/zip/ZipFile;->getInputStream(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;
    invoke-virtual {v0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v0
    invoke-static {v0}, Ljava/lang/System;->load(Ljava/lang/String;)V
    return-void
.end method
`)
	if len(matches) != 0 {
		t.Fatalf("APK-private re-link must not be reported as CWE-427, got %v", matches)
	}
}

// The exemption needs BOTH halves: a computed path in a method that merely
// touches a ZIP somewhere is still an unverifiable load.
func TestDynLoad_ComputedSystemLoadWithoutPrivateExtractionFlagged(t *testing.T) {
	matches := runDynLoadAST(t, `
.class public Lcom/app/Engine;
.method public load(Ljava/lang/String;)V
    invoke-static {p1}, Ljava/lang/System;->load(Ljava/lang/String;)V
    return-void
.end method
`)
	if len(matches) != 1 || matches[0].Severity != types.SeverityHigh {
		t.Fatalf("computed System.load path must stay HIGH without private extraction, got %v", matches)
	}
}
