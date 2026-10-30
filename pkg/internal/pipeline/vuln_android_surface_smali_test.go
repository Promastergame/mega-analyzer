package pipeline

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/parser"
	"mega-analyzer/pkg/internal/types"
)

func runAndroidSurface(t *testing.T, content string) []types.Match {
	t.Helper()
	class, err := parser.NewSmaliParser(content).Parse()
	if err != nil {
		t.Fatal(err)
	}
	ctx := createDetectorCtx("smali/com/app/Surface.smali", []byte(content), types.FileTypeSmali)
	ctx.Class = class
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	NewVulnAndroidSurfaceDetector().Detect(ctx, analysis)
	return analysis.Matches
}

func TestJSBridgeCapabilityInventory_CommandExec(t *testing.T) {
	matches := runAndroidSurface(t, `.class public Lcom/app/Bridge;
.super Ljava/lang/Object;
.method public run(Ljava/lang/String;)V
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation
    invoke-virtual {v0, p1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
    return-void
.end method`)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.Category != types.CategoryWebViewJSBridge {
		t.Errorf("category = %v, want %v (pattern=%q, method=%q, severity=%v)", m.Category, types.CategoryWebViewJSBridge, m.Pattern, m.MethodName, m.Severity)
	}
	if !m.IsCritical {
		t.Errorf("IsCritical = %v, want true for command execution (pattern=%q, method=%q, severity=%v)", m.IsCritical, m.Pattern, m.MethodName, m.Severity)
	}
	if m.Severity != types.SeverityCritical {
		t.Errorf("Severity = %v, want Critical (pattern=%q, method=%q)", m.Severity, m.Pattern, m.MethodName)
	}
	if m.MethodName != "run" {
		t.Errorf("MethodName = %q, want run", m.MethodName)
	}
	if !strings.Contains(m.Pattern, "command execution") {
		t.Errorf("Pattern = %q, expected to contain 'command execution'", m.Pattern)
	}
}

func TestJSBridgeCapabilityInventory_Safe(t *testing.T) {
	matches := runAndroidSurface(t, `.class public Lcom/app/SafeBridge;
.super Ljava/lang/Object;
.method public getAppVersion()Ljava/lang/String;
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation
    const-string v0, "1.0.0"
    return-object v0
.end method`)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.Category != types.CategoryWebViewJSBridge {
		t.Errorf("category = %v, want %v (pattern=%q, method=%q, severity=%v)", m.Category, types.CategoryWebViewJSBridge, m.Pattern, m.MethodName, m.Severity)
	}
	if m.IsCritical {
		t.Errorf("IsCritical = %v, want false for safe bridge (pattern=%q, method=%q, severity=%v)", m.IsCritical, m.Pattern, m.MethodName, m.Severity)
	}
	if m.Severity != types.SeverityMedium {
		t.Errorf("Severity = %v, want Medium (pattern=%q, method=%q)", m.Severity, m.Pattern, m.MethodName)
	}
}

func TestProviderOpenFileRequiresGuard(t *testing.T) {
	matches := runAndroidSurface(t, `.class public Lcom/app/Provider;
.super Landroid/content/ContentProvider;
.method public openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
    new-instance v0, Ljava/io/File;
    invoke-direct {v0, p1}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    return-object v1
.end method`)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.Category != types.CategoryExportedComponent {
		t.Errorf("category = %v, want %v (pattern=%q, method=%q, severity=%v)", m.Category, types.CategoryExportedComponent, m.Pattern, m.MethodName, m.Severity)
	}
	if m.Severity != types.SeverityHigh {
		t.Errorf("Severity = %v, want High (pattern=%q, method=%q)", m.Severity, m.Pattern, m.MethodName)
	}
	if m.IsCritical {
		t.Errorf("IsCritical = true with High severity (pattern=%q, method=%q)", m.Pattern, m.MethodName)
	}
	if m.MethodName != "openFile" {
		t.Errorf("MethodName = %q, want openFile", m.MethodName)
	}
}

func TestProviderCanonicalGuardSuppressesFinding(t *testing.T) {
	matches := runAndroidSurface(t, `.class public Lcom/app/Provider;
.super Landroid/content/ContentProvider;
.method public openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
    invoke-virtual {v0}, Ljava/io/File;->getCanonicalPath()Ljava/lang/String;
    return-object v1
.end method`)
	if len(matches) != 0 {
		m := matches[0]
		t.Fatalf("guarded provider flagged: count=%d category=%v severity=%v pattern=%q method=%q class=%q line=%d",
			len(matches), m.Category, m.Severity, m.Pattern, m.MethodName, m.ClassName, m.Line)
	}
}

func TestJSBridgeInventoryUsesExactMethodRange(t *testing.T) {
	matches := runAndroidSurface(t, `.class public Lcom/app/Bridge;
.super Ljava/lang/Object;
.method public harmless()V
    invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
    return-void
.end method
.method public version()Ljava/lang/String;
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation
    const-string v0, "1.0.0"
    return-object v0
.end method`)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	m := matches[0]
	if m.MethodName != "version" || m.Severity != types.SeverityMedium || m.IsCritical {
		t.Fatalf("method range leaked capability: method=%q severity=%v critical=%v pattern=%q line=%d",
			m.MethodName, m.Severity, m.IsCritical, m.Pattern, m.Line)
	}
}

func TestProviderSegmentValidationSuppressesFinding(t *testing.T) {
	matches := runAndroidSurface(t, `.class public Lcom/app/Provider;
.super Landroid/content/ContentProvider;
.method public openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
    invoke-virtual {p1}, Landroid/net/Uri;->getLastPathSegment()Ljava/lang/String;
    move-result-object v0
    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    return-object v2
.end method`)
	if len(matches) != 0 {
		t.Fatalf("segment-validated provider flagged: %+v", matches)
	}
}

func TestProviderUnrelatedContainsDoesNotSuppressFinding(t *testing.T) {
	matches := runAndroidSurface(t, `.class public Lcom/app/Provider;
.super Landroid/content/ContentProvider;
.method public openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
    invoke-virtual {p1}, Landroid/net/Uri;->getLastPathSegment()Ljava/lang/String;
    move-result-object v0
    const-string v1, "debug"
    invoke-virtual {p2, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    return-object v2
.end method`)
	if len(matches) != 1 {
		t.Fatalf("unrelated contains must not suppress finding, got %d: %+v", len(matches), matches)
	}
	m := matches[0]
	if m.MethodName != "openFile" || m.Severity != types.SeverityHigh {
		t.Fatalf("unexpected provider match: method=%q severity=%v pattern=%q", m.MethodName, m.Severity, m.Pattern)
	}
}
