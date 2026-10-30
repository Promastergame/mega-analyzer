package ml

import (
	"strings"
	"testing"
)

func TestBuildBodyPreservingPatchVoidKeepsOriginalBody(t *testing.T) {
	body := []string{
		".method public logSnapshot()V",
		"    .registers 2",
		"    invoke-static {}, Lcom/app/Logger;->log()V",
		"    return-void",
		".end method",
	}

	patched, ok := buildBodyPreservingPatch(body, "V", kindVoid)
	if !ok {
		t.Fatal("expected a real body to be preserved")
	}
	if !strings.Contains(patched, "return-void\n    invoke-static") {
		t.Fatalf("expected an early return before the original instruction:\n%s", patched)
	}
	if !strings.Contains(patched, "invoke-static {}, Lcom/app/Logger;->log()V") || !strings.Contains(patched, ".end method") {
		t.Fatalf("expected the complete original body to remain:\n%s", patched)
	}
}

func TestBuildBodyPreservingPatchPrimitiveOverridesReturnInPlace(t *testing.T) {
	body := []string{
		".method public isLicensed()Z",
		"    .registers 2",
		"    invoke-static {}, Lcom/app/Logger;->log()V",
		"    const/4 v0, 0x0",
		"    return v0",
		".end method",
	}

	patched, ok := buildBodyPreservingPatch(body, "Z", kindTrue)
	if !ok {
		t.Fatal("expected a real body to be preserved")
	}
	if !strings.Contains(patched, "const/4 v0, 0x1") {
		t.Fatalf("expected the returned primitive to be forced true:\n%s", patched)
	}
	if !strings.Contains(patched, "invoke-static {}, Lcom/app/Logger;->log()V") {
		t.Fatalf("expected side-effecting instructions to remain:\n%s", patched)
	}
}

func TestBuildBodyPreservingPatchObjectDoesNotInventNullReturn(t *testing.T) {
	body := []string{
		".method public createView()Landroid/view/View;",
		"    .registers 2",
		"    invoke-static {}, Lcom/app/Factory;->create()Landroid/view/View;",
		"    move-result-object v0",
		"    return-object v0",
		".end method",
	}

	patched, ok := buildBodyPreservingPatch(body, "Landroid/view/View;", kindMaxInt)
	if !ok {
		t.Fatal("expected a real body to be preserved")
	}
	if patched != strings.Join(body, "\n") {
		t.Fatalf("object-returning body must remain unchanged, got:\n%s", patched)
	}
	if strings.Contains(patched, "const/4 v0, 0x0\n    return-object v0") {
		t.Fatal("must not replace a real object factory with a null-return stub")
	}
}

func TestBuildBodyPreservingPatchDefaultKeepsValueIntact(t *testing.T) {
	// kindDefault is the neutral intent (const_replace, unknown patch types):
	// it must never force a numeric return. Regression: const_replace on an
	// int method once injected const 0x7fffffff.
	body := []string{
		".method public getApiPort()I",
		"    .registers 2",
		"    const-string v0, \"https://api.example.com\"",
		"    sget v0, Lcom/app/Cfg;->port:I",
		"    return v0",
		".end method",
	}
	patched, ok := buildBodyPreservingPatch(body, "I", kindDefault)
	if !ok {
		t.Fatal("expected a real body to be preserved")
	}
	if strings.Contains(patched, "0x7fffffff") {
		t.Fatalf("neutral kind must not force MAX_INT:\n%s", patched)
	}
	if strings.Contains(patched, "const v0, 0x0") {
		t.Fatalf("neutral kind must not force zero either:\n%s", patched)
	}
	if !strings.Contains(patched, "sget v0, Lcom/app/Cfg;->port:I") {
		t.Fatalf("original value computation must survive:\n%s", patched)
	}
}
