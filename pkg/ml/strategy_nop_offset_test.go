package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OFFSET-SAFETY REGRESSION FOR NOP INJECTION (strategy_nop_injection.go)
//
// The analyzer disassembles with RAW NUMERIC branch offsets (code-unit relative),
// reassembled directly at the DEX level. The old nop strategy wrote a SINGLE
// `nop` for whatever it removed — a 2-unit const-string or a 3-unit invoke —
// shrinking the layout while leaving every branch delta stale, so an
// `if-eqz v4, +12` landed mid-instruction. It also zeroed an orphaned
// move-result with a 2-unit `const/16`, another size change; and it nopped a
// const-string even when a surviving instruction still read that register.
//
// These tests pin the fixes: each removal is size-neutral (N nops for an N-unit
// op, a 1-unit const/4 for a move-result), so numeric offsets stay valid; and a
// security string feeding a live instruction is preserved.
// ═══════════════════════════════════════════════════════════════════════════════

// TestNopInjection_SizePreservingKeepsOffsets is the zzg-shaped regression: a
// security invoke guarded by a numeric branch, plus a flagged const-string whose
// value a surviving (non-security) invoke still consumes. The nop-out must keep
// the branch offset byte-for-byte valid and must NOT strip the still-read string.
func TestNopInjection_SizePreservingKeepsOffsets(t *testing.T) {
	// Layout (code units): const-string@0(2) invoke-static@2(3) move-result@5(1)
	// if-eqz@6(2) invoke-virtual@8(3) const/4@11(1) return@12(1).
	// if-eqz targets @12 (delta +6). 3 nops for the 3-unit invoke + a 1-unit
	// const/4 for the move-result keep every offset identical.
	mi := &shared.MethodInfo{
		Name:               "zzcheck",
		ClassName:          "Guard",
		FilePath:           "com/example/Guard.smali",
		ReturnType:         "Z",
		ReturnsBoolean:     true,
		IsPublic:           true,
		RegisterCount:      3,
		HasSecurityAPI:     true,
		SecurityCalls:      []string{"Lsec;->isRooted()Z"},
		SecurityStrings:    []string{"magisk"},
		HasSecurityStrings: true,
		RawBody: []string{
			".method public zzcheck()Z",
			"    .registers 3",
			"    const-string v1, \"magisk\"",
			"    invoke-static {}, Lsec;->isRooted()Z",
			"    move-result v0",
			"    if-eqz v0, +6",
			"    invoke-virtual {v2, v1}, Llog;->w(Ljava/lang/String;)V",
			"    const/4 v0, 0x1",
			"    return v0",
			".end method",
		},
		MethodHeader: ".method public zzcheck()Z",
	}

	patch, err := NewNopInjectionStrategy().Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out := patch.PatchedCode

	// The 3-unit invoke becomes exactly 3 nops (old bug: 1).
	if got := countOccurrences(out, "nop"); got != 3 {
		t.Errorf("expected 3 nops for the 3-unit invoke, got %d:\n%s", got, out)
	}
	// The security call itself is gone.
	if strings.Contains(out, "isRooted") {
		t.Errorf("security invoke must be nopped out:\n%s", out)
	}
	// The orphaned move-result is zeroed with a SIZE-NEUTRAL const/4, never const/16.
	if !strings.Contains(out, "const/4 v0, 0x0") {
		t.Errorf("move-result must be zeroed with 1-unit const/4:\n%s", out)
	}
	if strings.Contains(out, "const/16 v0, 0x0") {
		t.Errorf("must not use 2-unit const/16 for a 1-unit move-result:\n%s", out)
	}
	// The branch delta is UNCHANGED — proof the layout did not shift.
	if !strings.Contains(out, "if-eqz v0, +6") {
		t.Errorf("branch offset must remain +6 (size-preserving):\n%s", out)
	}
	// The flagged string is still read by the surviving invoke-virtual → preserved.
	if !strings.Contains(out, "const-string v1, \"magisk\"") {
		t.Errorf("const-string read by a live instruction must be preserved:\n%s", out)
	}
	if !strings.Contains(out, "invoke-virtual {v2, v1}") {
		t.Errorf("non-security invoke must be preserved:\n%s", out)
	}
	assertOffsetsValid(t, out)
}

// TestNopInjection_DeadSecurityStringRemovedSizeCorrectly checks the other branch
// of the dataflow guard: a flagged const-string read ONLY by the nopped invoke is
// dead after the patch, so it IS removed — but with 2 nops (its code-unit size),
// not 1, keeping any layout intact.
func TestNopInjection_DeadSecurityStringRemovedSizeCorrectly(t *testing.T) {
	mi := &shared.MethodInfo{
		Name:               "hasSu",
		ClassName:          "Guard",
		FilePath:           "com/example/Guard.smali",
		ReturnType:         "Z",
		ReturnsBoolean:     true,
		IsPublic:           true,
		RegisterCount:      2,
		HasSecurityAPI:     true,
		HasSecurityStrings: true,
		SecurityCalls:      []string{"Lsec;->exists(Ljava/lang/String;)Z"},
		SecurityStrings:    []string{"su"},
		RawBody: []string{
			".method public hasSu()Z",
			"    .registers 2",
			"    const-string v0, \"su\"",
			"    invoke-static {v0}, Lsec;->exists(Ljava/lang/String;)Z",
			"    move-result v1",
			"    return v1",
			".end method",
		},
		MethodHeader: ".method public hasSu()Z",
	}

	patch, err := NewNopInjectionStrategy().Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out := patch.PatchedCode

	// const-string (2u) + invoke (3u) → 5 nops; move-result (1u) → const/4.
	if got := countOccurrences(out, "nop"); got != 5 {
		t.Errorf("expected 5 nops (2 for const-string + 3 for invoke), got %d:\n%s", got, out)
	}
	if strings.Contains(out, "\"su\"") {
		t.Errorf("dead security string must be removed:\n%s", out)
	}
	if strings.Contains(out, "exists") {
		t.Errorf("security invoke must be removed:\n%s", out)
	}
	if !strings.Contains(out, "const/4 v1, 0x0") {
		t.Errorf("move-result must be zeroed with const/4:\n%s", out)
	}
	assertOffsetsValid(t, out)
}

// TestNopInjection_RealBillingZzg is the exact method the audit flagged in the
// user's omnisec-patches.json (com/android/billingclient/api/zzn->zzg). The old
// binary collapsed each 2-unit const-string and 3-unit invoke to a SINGLE nop —
// shrinking the layout ~9 units while leaving `if-eqz v4, +12` stale (it then
// pointed mid-instruction) and leaving v1/v2 undefined for the surviving
// invoke-direct/addAction. The fixed generator must keep every offset valid,
// nop each flagged invoke by its true size, and preserve the still-read strings.
func TestNopInjection_RealBillingZzg(t *testing.T) {
	mi := &shared.MethodInfo{
		Name:               "zzg",
		ClassName:          "com/android/billingclient/api/zzn",
		FilePath:           "smali_classes9/com/android/billingclient/api/zzn.smali",
		ReturnType:         "V",
		ReturnsVoid:        true,
		RegisterCount:      5,
		HasSecurityAPI:     true,
		HasSecurityStrings: true,
		// The two invoke-virtual targets the old export nopped.
		SecurityCalls: []string{
			"Lcom/android/billingclient/api/zzm;->zza(Landroid/content/Context;Landroid/content/IntentFilter;)V",
			"Lcom/android/billingclient/api/zzm;->zzb(Landroid/content/Context;Landroid/content/IntentFilter;Ljava/lang/String;)V",
		},
		// Substrings covering all four flagged const-strings.
		SecurityStrings: []string{"vending.billing", "PLAY_BILLING"},
		RawBody: []string{
			".method final zzg(Z)V",
			"    .registers 5",
			"    new-instance v0, Landroid/content/IntentFilter;",
			"    const-string v1, \"com.android.vending.billing.PURCHASES_UPDATED\"",
			"    invoke-direct {v0, v1}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V",
			"    new-instance v1, Landroid/content/IntentFilter;",
			"    const-string v2, \"com.android.vending.billing.LOCAL_BROADCAST_PURCHASES_UPDATED\"",
			"    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V",
			"    const-string v2, \"com.android.vending.billing.ALTERNATIVE_BILLING\"",
			"    invoke-virtual {v1, v2}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V",
			"    iput-boolean v4, v3, Lcom/android/billingclient/api/zzn;->zzh:Z",
			"    iget-object v4, v3, Lcom/android/billingclient/api/zzn;->zzg:Lcom/android/billingclient/api/zzm;",
			"    iget-object v2, v3, Lcom/android/billingclient/api/zzn;->zza:Landroid/content/Context;",
			"    invoke-virtual {v4, v2, v1}, Lcom/android/billingclient/api/zzm;->zza(Landroid/content/Context;Landroid/content/IntentFilter;)V",
			"    iget-boolean v4, v3, Lcom/android/billingclient/api/zzn;->zzh:Z",
			"    if-eqz v4, +12",
			"    iget-object v4, v3, Lcom/android/billingclient/api/zzn;->zzf:Lcom/android/billingclient/api/zzm;",
			"    iget-object v1, v3, Lcom/android/billingclient/api/zzn;->zza:Landroid/content/Context;",
			"    const-string v2, \"com.google.android.finsky.permission.PLAY_BILLING_LIBRARY_BROADCAST\"",
			"    invoke-virtual {v4, v1, v0, v2}, Lcom/android/billingclient/api/zzm;->zzb(Landroid/content/Context;Landroid/content/IntentFilter;Ljava/lang/String;)V",
			"    return-void",
			"    iget-object v4, v3, Lcom/android/billingclient/api/zzn;->zzf:Lcom/android/billingclient/api/zzm;",
			"    iget-object v1, v3, Lcom/android/billingclient/api/zzn;->zza:Landroid/content/Context;",
			"    invoke-virtual {v4, v1, v0}, Lcom/android/billingclient/api/zzm;->zza(Landroid/content/Context;Landroid/content/IntentFilter;)V",
			"    return-void",
			".end method",
		},
		MethodHeader: ".method final zzg(Z)V",
	}

	patch, err := NewNopInjectionStrategy().Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out := patch.PatchedCode

	// The stale branch offset — the exact defect the audit reported — is gone:
	// the layout is unchanged, so +12 still lands on an instruction boundary.
	assertOffsetsValid(t, out)
	if !strings.Contains(out, "if-eqz v4, +12") {
		t.Errorf("branch offset must remain +12 (size-preserving); got:\n%s", out)
	}
	// Three 3-unit invokes nopped → 9 nops, by size, not one each. Count real
	// `nop` lines: a substring like "\n    nop\n" under-counts a run because
	// adjacent nop lines share the newline between them (non-overlapping match).
	if got := countNopLines(out); got != 9 {
		t.Errorf("expected 9 nops (3 per 3-unit invoke), got %d:\n%s", got, out)
	}
	// The flagged invoke-virtual calls are removed.
	if strings.Contains(out, "->zza(Landroid/content/Context;Landroid/content/IntentFilter;)V") ||
		strings.Contains(out, "->zzb(Landroid/content/Context;") {
		t.Errorf("flagged billing invokes must be nopped out:\n%s", out)
	}
	// Every const-string is preserved — each register is read by a surviving
	// invoke-direct/addAction, so nopping it would leave that register undefined.
	for _, s := range []string{
		"\"com.android.vending.billing.PURCHASES_UPDATED\"",
		"\"com.android.vending.billing.LOCAL_BROADCAST_PURCHASES_UPDATED\"",
		"\"com.android.vending.billing.ALTERNATIVE_BILLING\"",
		"\"com.google.android.finsky.permission.PLAY_BILLING_LIBRARY_BROADCAST\"",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("const-string %s feeds a live instruction and must be preserved:\n%s", s, out)
		}
	}
	// The surviving IntentFilter construction must be intact.
	if !strings.Contains(out, "invoke-direct {v0, v1}, Landroid/content/IntentFilter;-><init>") ||
		!strings.Contains(out, "->addAction(Ljava/lang/String;)V") {
		t.Errorf("non-security IntentFilter setup must be preserved:\n%s", out)
	}
}
