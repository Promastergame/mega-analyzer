// vuln_storage_smali_test.go — insecure storage detection (audit P2-11).
package pipeline

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func runStorageAST(t *testing.T, content string) []types.Match {
	t.Helper()
	d := NewVulnInsecureStorageDetector()
	ctx := createDetectorCtx("smali/com/app/Store.smali", []byte(content), types.FileTypeSmali)
	ctx.Class = parseCryptoFixture(t, content)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	d.Detect(ctx, analysis)
	return analysis.Matches
}

func TestStorage_WorldReadablePrefsFlagged(t *testing.T) {
	matches := runStorageAST(t, `
.class public Lcom/app/Store;
.method public prefs()V
    .locals 3
    const-string v0, "session"
    const/4 v1, 0x1
    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    return-void
.end method
`)
	if len(matches) != 1 || matches[0].Severity != types.SeverityHigh {
		t.Fatalf("MODE_WORLD_READABLE must produce a High finding, got %v", matches)
	}
	if matches[0].Confidence != "high" {
		t.Errorf("Confidence = %q, want high", matches[0].Confidence)
	}
}

func TestStorage_WorldWriteableCritical(t *testing.T) {
	matches := runStorageAST(t, `
.class public Lcom/app/Store;
.method public prefs()V
    .locals 3
    const-string v0, "session"
    const/4 v1, 0x3
    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    return-void
.end method
`)
	if len(matches) != 1 || matches[0].Severity != types.SeverityCritical {
		t.Fatalf("MODE_WORLD_READABLE|WRITEABLE must be Critical, got %v", matches)
	}
}

func TestStorage_ModePrivateSilent(t *testing.T) {
	matches := runStorageAST(t, `
.class public Lcom/app/Store;
.method public prefs()V
    .locals 3
    const-string v0, "session"
    const/4 v1, 0x0
    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    return-void
.end method
`)
	if len(matches) != 0 {
		t.Fatalf("MODE_PRIVATE must stay silent, got %v", matches)
	}
}

func TestStorage_ExternalStorageWriteViaEnvironment(t *testing.T) {
	matches := runStorageAST(t, `
.class public Lcom/app/Store;
.method public dump()V
    .locals 4
    invoke-static {}, Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;
    move-result-object v0
    const-string v1, "creds.txt"
    new-instance v2, Ljava/io/File;
    invoke-direct {v2, v0, v1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    invoke-direct {v3, v2}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    return-void
.end method
`)
	if len(matches) != 1 || matches[0].Severity != types.SeverityHigh {
		t.Fatalf("FileOutputStream on getExternalStorageDirectory must be flagged, got %v", matches)
	}
}

func TestStorage_LiteralExternalPathWrite(t *testing.T) {
	matches := runStorageAST(t, `
.class public Lcom/app/Store;
.method public dump()V
    .locals 2
    const-string v0, "/sdcard/Download/tokens.json"
    invoke-direct {v1, v0}, Ljava/io/FileWriter;-><init>(Ljava/lang/String;)V
    return-void
.end method
`)
	if len(matches) != 1 {
		t.Fatalf("FileWriter on literal /sdcard path must be flagged, got %v", matches)
	}
}

func TestStorage_InternalPathWriteSilent(t *testing.T) {
	matches := runStorageAST(t, `
.class public Lcom/app/Store;
.method public dump()V
    .locals 2
    const-string v0, "/data/data/com.app/files/tokens.json"
    invoke-direct {v1, v0}, Ljava/io/FileWriter;-><init>(Ljava/lang/String;)V
    return-void
.end method
`)
	if len(matches) != 0 {
		t.Fatalf("app-private path write must stay silent, got %v", matches)
	}
}
