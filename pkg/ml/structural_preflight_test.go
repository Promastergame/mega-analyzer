package ml

import "testing"

func TestPreflightBodyStructurePreservesLabelsAndTryCatch(t *testing.T) {
	original := `.method public check()Z
    const/4 v0, 0x0
    :try_start_0
    if-eqz v0, :fail
    goto :done
    :fail
    return v0
    :done
    .catch Ljava/lang/Exception; {:try_start_0 .. :done} :handler
    :handler
    const/4 v0, 0x0
    return v0
.end method`
	patched := `.method public check()Z
    const/4 v0, 0x0
    :try_start_0
    if-nez v0, :fail
    goto :done
    :fail
    return v0
    :done
    .catch Ljava/lang/Exception; {:try_start_0 .. :done} :handler
    :handler
    const/4 v0, 0x1
    return v0
.end method`
	result := preflightBodyStructure(original, patched)
	if !result.Valid {
		t.Fatalf("valid preserving patch rejected: %+v", result)
	}
}

func TestPreflightBodyStructureRejectsMissingBranchLabel(t *testing.T) {
	original := ".method public check()Z\n    const/4 v0, 0x0\n    if-eqz v0, :fail\n    :fail\n    return v0\n.end method"
	patched := ".method public check()Z\n    const/4 v0, 0x0\n    if-eqz v0, :missing\n    :fail\n    return v0\n.end method"
	result := preflightBodyStructure(original, patched)
	if result.Valid {
		t.Fatal("missing branch label was accepted")
	}
}

func TestUseDefPreflightRejectsOrphanMoveResult(t *testing.T) {
	code := ".method public check()Z\n    move-result v0\n    return v0\n.end method"
	result := useDefPreflight(code)
	if result.Valid {
		t.Fatal("orphan move-result was accepted")
	}
}

func TestUseDefPreflightAcceptsInvokeResultPair(t *testing.T) {
	code := ".method public check()Z\n    invoke-static {}, Lcom/example/Checks;->ok()Z\n    move-result v0\n    return v0\n.end method"
	result := useDefPreflight(code)
	if !result.Valid {
		t.Fatalf("valid invoke/result pair rejected: %+v", result)
	}
}

func TestUseDefPreflightAcceptsRegistersStyleParameterAlias(t *testing.T) {
	code := ".method public getCoins()I\n" +
		"    .registers 4\n" +
		"    iget-object v0, v3, Lcom/megademo/testapp/WalletService;->prefs:Landroid/content/SharedPreferences;\n" +
		"    const-string v1, \"coins\"\n" +
		"    const/16 v2, 250\n" +
		"    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I\n" +
		"    move-result v0\n" +
		"    return v0\n" +
		".end method"
	result := useDefPreflight(code)
	if !result.Valid {
		t.Fatalf("registers-style parameter alias rejected: %+v", result)
	}
}

func TestUseDefPreflightStillRejectsTrulyUndefinedRegister(t *testing.T) {
	code := ".method public getCoins()I\n" +
		"    .registers 4\n" +
		"    iget-object v0, v2, Lcom/example/W;->prefs:Landroid/content/SharedPreferences;\n" +
		"    return v0\n" +
		".end method"
	result := useDefPreflight(code)
	if result.Valid {
		t.Fatal("undefined high register was accepted")
	}
}

func TestUseDefPreflightAcceptsBlankLineSeparatedPair(t *testing.T) {
	// Real baksmali output separates invoke and move-result with blank
	// lines and .line directives; the pair is still valid.
	code := ".method public static getIAPCoins()I\n" +
		"    .registers 1\n" +
		"\n" +
		"    .prologue\n" +
		"    .line 533\n" +
		"    sget-object v0, Lcom/example/Main;->instance:Lcom/example/Main;\n" +
		"\n" +
		"    if-eqz v0, :cond_f\n" +
		"\n" +
		"    .line 534\n" +
		"    invoke-virtual {v0}, Lcom/example/Main;->getContext()Landroid/content/Context;\n" +
		"\n" +
		"    move-result-object v0\n" +
		"    invoke-static {v0}, Lcom/example/Store;->getCoins(Landroid/content/Context;)I\n" +
		"    move-result v0\n" +
		"\n" +
		"    .line 536\n" +
		"    :goto_e\n" +
		"    const v0, 0x7fffffff\n" +
		"    return v0\n" +
		"\n" +
		"    :cond_f\n" +
		"    const/4 v0, 0x0\n" +
		"\n" +
		"    goto :goto_e\n" +
		".end method"
	result := useDefPreflight(code)
	if !result.Valid {
		t.Fatalf("blank-line separated invoke/result pair rejected: %+v", result)
	}
}

func TestUseDefPreflightStillRejectsLabelSeparatedPair(t *testing.T) {
	// A branch target between invoke and move-result genuinely orphans it:
	// control can arrive at the label without executing the invoke.
	code := ".method public check()Z\n" +
		"    invoke-static {}, Lcom/example/Checks;->ok()Z\n" +
		"    :entry\n" +
		"    move-result v0\n" +
		"    return v0\n" +
		".end method"
	result := useDefPreflight(code)
	if result.Valid {
		t.Fatal("label-separated move-result was accepted")
	}
}

func TestRequiresStructurePreservation(t *testing.T) {
	if !requiresStructurePreservation(PatchNop) || !requiresStructurePreservation(PatchConstReplace) {
		t.Fatal("surgical patch type is not gated")
	}
	if requiresStructurePreservation(PatchReturnTrue) {
		t.Fatal("whole-body return should not use preserving gate")
	}
}

func TestCFGStructuralDiffRejectsRemovedEdge(t *testing.T) {
	original := ".method public check()Z\n    if-eqz v0, :fail\n    goto :done\n    :fail\n    const/4 v0, 0x0\n    :done\n    return v0\n.end method"
	patched := ".method public check()Z\n    goto :done\n    :fail\n    const/4 v0, 0x0\n    :done\n    return v0\n.end method"
	result := cfgStructuralDiff(original, patched)
	if result.Valid {
		t.Fatal("CFG edge change was accepted")
	}
}

func TestCFGStructuralDiffAcceptsConstantOnlyEdit(t *testing.T) {
	original := ".method public check()Z\n    const/4 v0, 0x0\n    return v0\n.end method"
	patched := ".method public check()Z\n    const/4 v0, 0x1\n    return v0\n.end method"
	result := cfgStructuralDiff(original, patched)
	if !result.Valid {
		t.Fatalf("constant-only edit changed CFG: %+v", result)
	}
}

func TestDFGSemanticDiffAllowsReturnConstantOverride(t *testing.T) {
	original := ".method public check()Z\n    invoke-static {}, Lcom/example/Checks;->ok()Z\n    move-result v0\n    return v0\n.end method"
	patched := ".method public check()Z\n    invoke-static {}, Lcom/example/Checks;->ok()Z\n    move-result v0\n    const/4 v0, 0x1\n    return v0\n.end method"
	result := dfgSemanticDiff(original, patched)
	if !result.Valid {
		t.Fatalf("return override rejected: %+v", result)
	}
}

func TestDFGSemanticDiffRejectsBranchSourceChange(t *testing.T) {
	original := ".method public check()Z\n    invoke-static {}, Lcom/example/Checks;->ok()Z\n    move-result v0\n    if-eqz v0, :fail\n    :fail\n    return v0\n.end method"
	patched := ".method public check()Z\n    const/4 v0, 0x1\n    if-eqz v0, :fail\n    :fail\n    return v0\n.end method"
	result := dfgSemanticDiff(original, patched)
	if result.Valid {
		t.Fatal("branch source change was accepted")
	}
}
