package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// POWER-UPS REGRESSION — фиксы P0 + новые хирургические стратегии
// ═══════════════════════════════════════════════════════════════════════════════

func TestFlexiblePatchTypes_ConstantMatchesBothSignals(t *testing.T) {
	sel := NewStrategySelector()
	mi := &shared.MethodInfo{
		Name:           "isRooted",
		ClassName:      "RootGuard",
		ReturnsBoolean: true,
		ReturnType:     "Z",
		IsStatic:       true,
		RawBody: []string{
			".method public static isRooted()Z",
			"    .registers 2",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
		MethodHeader: ".method public static isRooted()Z",
	}
	signalsFalse := []VulnSignal{{Kind: VulnRootDetectionBypass, Confidence: 0.9}}
	if got := sel.SelectStrategyWithSignals(mi, PatchModeResearch, signalsFalse); got == nil {
		t.Fatal("expected strategy for return_false signal")
	} else if _, ok := got.(*ConstantInjectionStrategy); !ok {
		t.Fatalf("surgical must win for return_false signal, got %T", got)
	}
	signalsTrue := []VulnSignal{{Kind: VulnPremiumFeatureGate, Confidence: 0.9}}
	mi2 := &shared.MethodInfo{
		Name:           "hasPremium",
		ClassName:      "LicenseChecker",
		ReturnsBoolean: true,
		ReturnType:     "Z",
		IsStatic:       true,
		RawBody: []string{
			".method public static hasPremium()Z",
			"    .registers 2",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
		MethodHeader: ".method public static hasPremium()Z",
	}
	if got := sel.SelectStrategyWithSignals(mi2, PatchModeResearch, signalsTrue); got == nil {
		t.Fatal("expected strategy for return_true signal")
	} else if _, ok := got.(*ConstantInjectionStrategy); !ok {
		t.Fatalf("surgical must win for return_true signal, got %T", got)
	}
}

func TestPartialBypass_DefensiveDeclines(t *testing.T) {
	s := NewPartialBypassStrategy()
	mi := &shared.MethodInfo{
		Name:               "checkRoot",
		ReturnsBoolean:     true,
		ReturnType:         "Z",
		IfCheckCount:       3,
		HasDualReturn:      true,
		HasSecurityAPI:     true,
		SecurityCalls:      []string{"LRoot;->check()Z"},
		HasSecurityStrings: true,
		SecurityStrings:    []string{"su"},
		RawBody:            []string{"if-eqz v0, +2", "return v0"},
	}
	if s.CanApply(mi, PatchModeDefensive) {
		t.Fatal("PartialBypass must decline defensive mode (it is a no-op there)")
	}
	if !s.CanApply(mi, PatchModeResearch) {
		t.Fatal("PartialBypass must apply in research mode")
	}
}

func TestNopInjection_PolarityByGateKind(t *testing.T) {
	// Detection probe → 0x0
	detect := &shared.MethodInfo{
		Name:           "isRooted",
		ClassName:      "RootBeer",
		ReturnsBoolean: true,
		ReturnType:     "Z",
		HasSecurityAPI: true,
		SecurityCalls:  []string{"LRoot;->isRooted()Z"},
		MethodHeader:   ".method public isRooted()Z",
		RawBody: []string{
			".method public isRooted()Z",
			"    .registers 2",
			"    invoke-static {}, LRoot;->isRooted()Z",
			"    move-result v0",
			"    return v0",
			".end method",
		},
	}
	patch, err := NewNopInjectionStrategy().Generate(detect, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(patch.PatchedCode, "const/4 v0, 0x0") {
		t.Errorf("detection probe must zero the result:\n%s", patch.PatchedCode)
	}
	// Positive gate → 0x1 (old code always wrote 0x0 — wrong branch)
	licensed := &shared.MethodInfo{
		Name:           "isLicensed",
		ClassName:      "LicenseChecker",
		ReturnsBoolean: true,
		ReturnType:     "Z",
		HasSecurityAPI: true,
		SecurityCalls:  []string{"LLicense;->isLicensed()Z"},
		MethodHeader:   ".method public isLicensed()Z",
		RawBody: []string{
			".method public isLicensed()Z",
			"    .registers 2",
			"    invoke-static {}, LLicense;->isLicensed()Z",
			"    move-result v0",
			"    return v0",
			".end method",
		},
	}
	patch2, err := NewNopInjectionStrategy().Generate(licensed, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(patch2.PatchedCode, "const/4 v0, 0x1") {
		t.Errorf("positive gate must fill 0x1:\n%s", patch2.PatchedCode)
	}
}

func TestWideMaxInjection_LongCoins(t *testing.T) {
	mi := &shared.MethodInfo{
		Name:         "getCoins",
		NameLower:    "getcoins",
		ReturnType:   "J",
		IsStatic:     true,
		MethodHeader: ".method public static getCoins()J",
		FilePath:     "Wallet.smali",
		RawBody: []string{
			".method public static getCoins()J",
			"    .registers 4",
			"    sget-wide v0, LWallet;->coins:J",
			"    return-wide v0",
			".end method",
		},
	}
	s := NewWideMaxInjectionStrategy()
	if !s.CanApply(mi, PatchModeResearch) {
		t.Fatal("wide strategy must apply to long economy getter")
	}
	if s.CanApply(mi, PatchModeDefensive) {
		t.Fatal("wide strategy is research-only")
	}
	patch, err := s.Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(patch.PatchedCode, "const-wide") || !strings.Contains(patch.PatchedCode, "return-wide") {
		t.Errorf("wide patch must force via const-wide:\n%s", patch.PatchedCode)
	}
	if !NewSmaliValidator().ValidateStrict(patch.PatchedCode).Valid {
		t.Errorf("wide patch must validate:\n%s", patch.PatchedCode)
	}
}

func TestObjectReturnInjection_BooleanSwap(t *testing.T) {
	mi := &shared.MethodInfo{
		Name:         "isPremium",
		ReturnType:   "Ljava/lang/Boolean;",
		MethodHeader: ".method public isPremium()Ljava/lang/Boolean;",
		FilePath:     "License.smali",
		RawBody: []string{
			".method public isPremium()Ljava/lang/Boolean;",
			"    .registers 2",
			"    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;",
			"    return-object v0",
			".end method",
		},
	}
	s := NewObjectReturnInjectionStrategy()
	if !s.CanApply(mi, PatchModeResearch) {
		t.Fatal("object strategy must apply to Boolean getter")
	}
	patch, err := s.Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(patch.PatchedCode, "Ljava/lang/Boolean;->TRUE") {
		t.Errorf("Boolean FALSE must swap to TRUE size-neutrally:\n%s", patch.PatchedCode)
	}
	if !NewSmaliValidator().ValidateStrict(patch.PatchedCode).Valid {
		t.Errorf("object patch must validate:\n%s", patch.PatchedCode)
	}
}

func TestInvokeResultHijack_KeepsInvoke(t *testing.T) {
	mi := &shared.MethodInfo{
		Name:             "checkRoot",
		ReturnsBoolean:   true,
		ReturnType:       "Z",
		HasSecurityAPI:   true,
		SecurityCalls:    []string{"Lsec;->isRooted()Z"},
		MethodHeader:     ".method public checkRoot()Z",
		InstructionCount: 5,
		RawBody: []string{
			".method public checkRoot()Z",
			"    .registers 2",
			"    invoke-static {}, Lsec;->isRooted()Z",
			"    move-result v0",
			"    return v0",
			".end method",
		},
	}
	s := NewInvokeResultHijackStrategy()
	if !s.CanApply(mi, PatchModeResearch) {
		t.Fatal("hijack must apply to security invoke+move-result")
	}
	patch, err := s.Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Stealth: invoke жив, move-result заменен на const (1u→1u).
	if !strings.Contains(patch.PatchedCode, "invoke-static {}, Lsec;->isRooted()Z") {
		t.Errorf("hijack must KEEP the invoke:\n%s", patch.PatchedCode)
	}
	if strings.Contains(patch.PatchedCode, "move-result") {
		t.Errorf("hijack must replace move-result:\n%s", patch.PatchedCode)
	}
	if !strings.Contains(patch.PatchedCode, "const/4 v0, 0x0") {
		t.Errorf("detection hijack must force 0x0:\n%s", patch.PatchedCode)
	}
	if !NewSmaliValidator().ValidateStrict(patch.PatchedCode).Valid {
		t.Errorf("hijack patch must validate:\n%s", patch.PatchedCode)
	}
	assertOffsetsValid(t, patch.PatchedCode)
}

func TestEntryGate_NopsFirstGateSizeNeutral(t *testing.T) {
	mi := &shared.MethodInfo{
		Name:             "isRooted",
		ReturnsBoolean:   true,
		ReturnType:       "Z",
		IfCheckCount:     2,
		HasSecurityAPI:   true,
		SecurityCalls:    []string{"Lsec;->isRooted()Z"},
		MethodHeader:     ".method public isRooted()Z",
		InstructionCount: 8,
		RawBody: []string{
			".method public isRooted()Z",
			"    .registers 2",
			"    invoke-static {}, Lsec;->isRooted()Z",
			"    move-result v0",
			"    if-eqz v0, +4",
			"    const/4 v0, 0x1",
			"    return v0",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}
	s := NewEntryGateStrategy()
	if !s.CanApply(mi, PatchModeResearch) {
		t.Fatal("entry gate must apply")
	}
	if s.CanApply(mi, PatchModeDefensive) {
		t.Fatal("entry gate is research-only")
	}
	patch, err := s.Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(patch.PatchedCode, "if-eqz") {
		t.Errorf("entry gate if must be nopped:\n%s", patch.PatchedCode)
	}
	if got := countOccurrences(patch.PatchedCode, "nop"); got != 2 {
		t.Errorf("2-unit if → exactly 2 nops, got %d:\n%s", got, patch.PatchedCode)
	}
	if !NewSmaliValidator().ValidateStrict(patch.PatchedCode).Valid {
		t.Errorf("entry gate patch must validate:\n%s", patch.PatchedCode)
	}
	assertOffsetsValid(t, patch.PatchedCode)
}

func TestConstReplace_ExtractsLiteralFromFullLine(t *testing.T) {
	mi := &shared.MethodInfo{
		Name:               "fetchCoins",
		ReturnType:         "I",
		MethodHeader:       ".method public fetchCoins()I",
		HasSecurityStrings: true,
		// Анализатор кладет ЦЕЛУЮ СТРОКУ — стратегия обязана извлечь литерал.
		SecurityStrings: []string{`const-string v0, "http://127.0.0.1:5555/economy/coins"`},
		RawBody: []string{
			".method public fetchCoins()I",
			"    .registers 3",
			"    const-string v0, \"http://127.0.0.1:5555/economy/coins\"",
			"    invoke-static {v0}, LNet;->get(Ljava/lang/String;)I",
			"    move-result v0",
			"    return v0",
			".end method",
		},
	}
	s := NewConstReplaceStrategy()
	if !s.CanApply(mi, PatchModeResearch) {
		t.Fatal("const-replace must apply")
	}
	patch, err := s.Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Инструкция жива, заменен только payload.
	if !strings.Contains(patch.PatchedCode, "const-string v0,") {
		t.Errorf("const-string shape must survive:\n%s", patch.PatchedCode)
	}
	if strings.Contains(patch.PatchedCode, "/economy/coins") {
		t.Errorf("target literal must be replaced:\n%s", patch.PatchedCode)
	}
	if strings.Contains(patch.PatchedCode, "\n    \n") {
		t.Errorf("must not blank whole lines:\n%s", patch.PatchedCode)
	}
}

func TestSelector_GenerateBestFallbackChain(t *testing.T) {
	sel := NewStrategySelector()
	// Битый вход (v4 при .registers 2): топ-стратегия откажет/невалид —
	// цепочка обязана вернуть ВАЛИДНЫЙ патч от следующей.
	mi := &shared.MethodInfo{
		Name:               "F",
		FullSignature:      "F()I",
		ReturnType:         "I",
		MethodHeader:       ".method public static F()I",
		RegisterCount:      2,
		InstructionCount:   8,
		HasSecurityStrings: true,
		SecurityStrings:    []string{`const-string v4, "Emulator"`},
		HasSecurityAPI:     true,
		SecurityCalls:      []string{"Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z"},
		RawBody: []string{
			".method public static F()I",
			"    .registers 2",
			"    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;",
			"    const-string v4, \"Emulator\"",
			"    invoke-virtual {v0, v4}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z",
			"    move-result v0",
			"    return v0",
			".end method",
		},
	}
	ranked := sel.RankStrategies(mi, PatchModeResearch, nil)
	if len(ranked) == 0 {
		t.Fatal("expected ranked strategies")
	}
	for i := 1; i < len(ranked); i++ {
		if ranked[i].Score > ranked[0].Score {
			t.Fatal("ranked must be score-descending")
		}
	}
	patch, strategy, err := sel.GenerateBest(mi, PatchModeResearch, nil)
	if err != nil {
		t.Fatalf("GenerateBest: %v", err)
	}
	if patch == nil || strategy == nil {
		t.Fatal("GenerateBest must return a patch for fallback-capable input")
	}
	if !NewSmaliValidator().ValidateStrict(patch.PatchedCode).Valid {
		t.Errorf("GenerateBest must return VALID smali, got %T:\n%s", strategy, patch.PatchedCode)
	}
}

func TestValidator_WideRegisterAndLiteralWidths(t *testing.T) {
	v := NewSmaliValidator()
	badReg := ".method public static t()V\n    .registers 2\n    const/16 v300, 0x1\n    return-void\n.end method"
	if res := v.Validate(badReg); res.Valid {
		t.Error("const/16 v300 must fail 8-bit check")
	}
	badLit := ".method public static t()Z\n    .registers 2\n    const/4 v0, 0x8\n    return v0\n.end method"
	if res := v.Validate(badLit); res.Valid {
		t.Error("const/4 0x8 must fail nibble-range check")
	}
	good := ".method public static t()Z\n    .registers 2\n    const/4 v0, 0x1\n    return v0\n.end method"
	if res := v.Validate(good); !res.Valid {
		t.Errorf("valid stub must pass: %v", res.Errors)
	}
}

func TestOffset_RegFitsConstGuard(t *testing.T) {
	// v300 нельзя закодировать const — движок обязан отказаться (note),
	// а не эмитить битый smali.
	body := []string{
		".method public static t()I",
		"    .registers 301",
		"    return v300",
		".end method",
	}
	out, forced, note := overrideReturnsSafe(body, 1)
	_ = out
	if forced != 0 {
		t.Fatalf("unencodable register must force 0 sites, got %d", forced)
	}
	if note == "" {
		t.Fatal("expected honest note about refused relayout")
	}
	if !regFitsConst("v15", 1) || regFitsConst("v16", 1) && false {
		t.Fatal("sanity")
	}
	if regFitsConst("v300", 1) {
		t.Fatal("v300 must not fit const encoding")
	}
	if !regFitsConst("v200", 1) {
		t.Fatal("v200 must fit const/16")
	}
}

func TestCFG_FindEntryGate(t *testing.T) {
	body := []string{
		".method public isRooted()Z",
		"    .registers 2",
		"    invoke-static {}, Lsec;->isRooted()Z",
		"    move-result v0",
		"    if-eqz v0, +4",
		"    const/4 v0, 0x1",
		"    return v0",
		"    const/4 v0, 0x0",
		"    return v0",
		".end method",
	}
	gate := FindEntryGateCFG(body, 0)
	if gate < 0 {
		t.Fatal("CFG must find entry gate on path to 0-return")
	}
	if !strings.Contains(body[gate], "if-eqz") {
		t.Fatalf("gate must be the if, got line %d: %q", gate, body[gate])
	}
}

func TestSmartPatcher_AdRemoveDetector(t *testing.T) {
	sp := NewSmartPatcher()
	point := &PatchPoint{
		MethodName:      "shouldShowAd",
		MethodSignature: "Lcom/demo/PseudoAdController;->shouldShowAd()Z",
		ClassName:       "Lcom/demo/PseudoAdController;",
		FilePath:        "PseudoAdController.smali",
		MethodBody: []string{
			"    invoke-virtual {p0}, Lcom/demo/AdController;->isAdFree()Z",
			"    move-result v0",
			"    if-nez v0, :show",
			"    const/4 v0, 0x1",
			"    return v0",
			"    :show",
			"    const-string v1, \"rewarded\"",
			"    invoke-virtual {p0, v1}, Lcom/demo/AdController;->loadAd(Ljava/lang/String;)V",
			"    const/4 v0, 0x0",
			"    return v0",
		},
	}
	found := false
	for _, p := range sp.AnalyzeMethod(point) {
		if p.Target == TargetAdRemove {
			found = true
		}
	}
	if !found {
		t.Fatal("AdRemove detector must fire on ad decision point")
	}
	if TargetAdRemove.TargetName() == "Unknown" {
		t.Fatal("TargetAdRemove must have a human name")
	}
}

func TestSharedInversions_SingleSource(t *testing.T) {
	// Обе стратегии обязаны смотреть в одну таблицу.
	if conditionalInversions["if-eqz"] != "if-nez" {
		t.Fatal("shared inversion table broken")
	}
	if out, ok := InvertConditionalLine("    if-nez v0, +4"); !ok || !strings.Contains(out, "if-eqz") {
		t.Fatalf("InvertConditionalLine failed: %q", out)
	}
	if ClassifyFunnel(0, false, nil) != FunnelSingle {
		t.Fatal("branchless must be single funnel")
	}
	if ClassifyFunnel(4, true, []string{"if-eqz v0, +2", "return v0"}) != FunnelAND {
		t.Fatal("3+ ifs must be AND funnel (entry-gate only)")
	}
}

func TestObjectReturnInjection_DeclinesNeutralUtilities(t *testing.T) {
	// Hill Climb Racing case: SHA1/getDeviceId/doInBackground are neutral
	// utilities, not access gates — neutralising them with ""/null under a
	// return_true label is a false patch, not a bypass.
	s := NewObjectReturnInjectionStrategy()
	for _, name := range []string{"SHA1", "sha1", "getDeviceId", "doInBackground", "getAdUrl", "copyRawResourceToFilesDir"} {
		mi := &shared.MethodInfo{
			Name:         name,
			ReturnType:   "Ljava/lang/String;",
			MethodHeader: ".method public " + name + "()Ljava/lang/String;",
			FilePath:     "Util.smali",
			RawBody: []string{
				".method public " + name + "()Ljava/lang/String;",
				"    .registers 3",
				"    invoke-static {v1}, Lcom/example/Crypto;->digest(Ljava/lang/String;)Ljava/lang/String;",
				"    move-result-object v0",
				"    return-object v0",
				".end method",
			},
		}
		if s.CanApply(mi, PatchModeResearch) {
			t.Errorf("object strategy must decline neutral utility %s", name)
		}
	}
	for _, name := range []string{"isPremium", "getAuthToken", "isLicensed", "getSessionId"} {
		mi := &shared.MethodInfo{
			Name:         name,
			ReturnType:   "Ljava/lang/String;",
			MethodHeader: ".method public " + name + "()Ljava/lang/String;",
			FilePath:     "Gate.smali",
			RawBody: []string{
				".method public " + name + "()Ljava/lang/String;",
				"    .registers 2",
				"    const-string v0, \"x\"",
				"    return-object v0",
				".end method",
			},
		}
		if !s.CanApply(mi, PatchModeResearch) {
			t.Errorf("object strategy must apply to access gate %s", name)
		}
	}
}

func TestPatchPointToMethodInfo_PopulatesNameLower(t *testing.T) { // The real pipeline path (predictor → PatchPoint → planner) must carry
	// the lower-cased name: every int-economy strategy gates on NameLower,
	// and unit tests hand-build it while production left it empty — which
	// silently declined all coin getters on real APKs.
	pg := NewPatchGenerator()
	mi := pg.patchPointToMethodInfo(&PatchPoint{
		MethodName:   "getCoins",
		MethodHeader: ".method public static getCoins(Landroid/content/Context;)I",
		MethodBody:   []string{".method public static getCoins(Landroid/content/Context;)I", "    return v0", ".end method"},
	})
	if mi.NameLower != "getcoins" {
		t.Fatalf("NameLower = %q, want %q", mi.NameLower, "getcoins")
	}
	if !isEconomyGetterName(mi.NameLower) {
		t.Fatal("economy name gate must accept converted point")
	}
}

func TestConstReplace_DeclinesLifecycleCallbacks(t *testing.T) {
	// Hill Climb Racing case: blanking an error string inside onCreate is
	// noise, not a bypass. The heuristic (URL/security-string) path must
	// decline exact lifecycle callbacks; explicit target pairs still apply.
	s := NewConstReplaceStrategy()
	mi := &shared.MethodInfo{
		Name:            "onCreate",
		NameLower:       "oncreate",
		ReturnType:      "V",
		MethodHeader:    ".method protected onCreate(Landroid/os/Bundle;)V",
		RawBody:         []string{".method protected onCreate(Landroid/os/Bundle;)V", "    const-string v6, \"Unable to connect\"", "    return-void", ".end method"},
		SecurityStrings: []string{"Unable to connect"},
	}
	if s.CanApply(mi, PatchModeResearch) {
		t.Fatal("heuristic const_replace must decline onCreate")
	}
	explicit := NewConstReplaceStrategyWith("Unable to connect", "")
	if !explicit.CanApply(mi, PatchModeResearch) {
		t.Fatal("explicit const_replace pair must still apply to onCreate")
	}
}
