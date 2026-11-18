package apkloader

import (
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

// writeSmaliTree drops one .smali file under <tmp>/smali/ and returns the root.
func writeSmaliTree(t *testing.T, name, body string) string {
	t.Helper()
	root := testutil.TempDir(t)
	dir := filepath.Join(root, "smali", filepath.Dir(name))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "smali", name), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return root
}

func countCode(diags []Diagnostic, code string) int {
	n := 0
	for _, d := range diags {
		if d.Code == code {
			n++
		}
	}
	return n
}

// baksmali separates instructions with blank lines and .line directives; a
// move-result that follows the invoke in instruction order is valid smali even
// when physical lines are not adjacent. This is the exact shape baksmali emits,
// and it used to trip a false SMALI_BAD_MOVE_RESULT on ~every real APK.
func TestValidateSmaliTree_MoveResultAcrossBlankLinesAndDirectives(t *testing.T) {
	root := writeSmaliTree(t, "Sample.smali", `.class public LSample;
.super Ljava/lang/Object;

.method public static run()Ljava/lang/String;
    .registers 2

    const-string v0, "x"

    .line 19
    invoke-static {v0}, LHelper;->frame(Ljava/lang/String;)Ljava/lang/String;

    .line 20
    :cond_0
    move-result-object v0

    return-object v0
.end method
`)
	diags := ValidateSmaliTree(root)
	if n := countCode(diags, "SMALI_BAD_MOVE_RESULT"); n != 0 {
		t.Fatalf("expected no SMALI_BAD_MOVE_RESULT across blank lines/labels/directives, got %d: %+v", n, diags)
	}
}

// A move-result whose preceding *instruction* is not an invoke is still a real
// error and must keep being reported.
func TestValidateSmaliTree_MoveResultAfterNonInvokeStillFlagged(t *testing.T) {
	root := writeSmaliTree(t, "Bad.smali", `.class public LBad;
.super Ljava/lang/Object;

.method public static run()V
    .registers 2

    const/4 v0, 0x0

    invoke-static {}, LHelper;->frame()V

    const/4 v1, 0x1

    move-result v0

    return-void
.end method
`)
	diags := ValidateSmaliTree(root)
	if n := countCode(diags, "SMALI_BAD_MOVE_RESULT"); n != 1 {
		t.Fatalf("expected exactly 1 SMALI_BAD_MOVE_RESULT when a real instruction intervenes, got %d: %+v", n, diags)
	}
}

// Two move-results after one invoke: only the first is adjacent.
func TestValidateSmaliTree_SecondMoveResultFlagged(t *testing.T) {
	root := writeSmaliTree(t, "Dup.smali", `.class public LDup;
.super Ljava/lang/Object;

.method public static run()V
    .registers 2

    invoke-static {}, LHelper;->frame()V

    move-result v0
    move-result v1

    return-void
.end method
`)
	diags := ValidateSmaliTree(root)
	if n := countCode(diags, "SMALI_BAD_MOVE_RESULT"); n != 1 {
		t.Fatalf("expected 1 SMALI_BAD_MOVE_RESULT for the non-adjacent second move-result, got %d: %+v", n, diags)
	}
}

// A packed-switch payload lists label *references*; the same name appearing as
// both a real label and a payload entry is valid smali, not a duplicate label.
func TestValidateSmaliTree_PayloadLabelReferenceIsNotDuplicate(t *testing.T) {
	root := writeSmaliTree(t, "Switch.smali", `.class public LSwitch;
.super Ljava/lang/Object;

.method public static run(I)V
    .registers 2

    packed-switch p0, :pswitch_data_0

    :pswitch_0
    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
`)
	diags := ValidateSmaliTree(root)
	if n := countCode(diags, "SMALI_DUPLICATE_LABEL"); n != 0 {
		t.Fatalf("payload label reference must not be a duplicate definition, got %d: %+v", n, diags)
	}
}

// A type descriptor like Landroid/support/v4/app/Foo; must not be read as a
// v4 register operand.
func TestValidateSmaliTree_TypePathVersionIsNotRegister(t *testing.T) {
	root := writeSmaliTree(t, "Proxy.smali", `.class public Landroid/support/v4/app/Proxy;
.super Ljava/lang/Object;

.field private mRemote:Landroid/os/IBinder;

.method constructor <init>(Landroid/os/IBinder;)V
    .registers 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroid/support/v4/app/Proxy;->mRemote:Landroid/os/IBinder;

    return-void
.end method
`)
	diags := ValidateSmaliTree(root)
	if n := countCode(diags, "SMALI_REGISTER_OVERFLOW"); n != 0 {
		t.Fatalf("v4 inside a package path must not count as a register, got %d: %+v", n, diags)
	}
}

// A genuine register overflow must still be reported.
func TestValidateSmaliTree_RealRegisterOverflowFlagged(t *testing.T) {
	root := writeSmaliTree(t, "Over.smali", `.class public LOver;
.super Ljava/lang/Object;

.method public static run()V
    .registers 2

    const/4 v7, 0x0

    return-void
.end method
`)
	diags := ValidateSmaliTree(root)
	if n := countCode(diags, "SMALI_REGISTER_OVERFLOW"); n != 1 {
		t.Fatalf("expected 1 SMALI_REGISTER_OVERFLOW for v7 with .registers 2, got %d: %+v", n, diags)
	}
}
