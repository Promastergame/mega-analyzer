package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

func economyTestMethod(name, signature, returnType string, body ...string) *MethodInfo {
	return &MethodInfo{
		Name:          name,
		NameLower:     strings.ToLower(name),
		FullSignature: signature,
		ReturnType:    returnType,
		ClassName:     "Lcom/game/Player;",
		ClassPath:     "Lcom/game/Player;",
		RawBody:       body,
	}
}

func TestEconomyDetectsBalanceGetter(t *testing.T) {
	mi := economyTestMethod("getCoins", "()I", "I",
		"    .locals 1",
		"    iget v0, p0, Lcom/game/Player;->coins:I",
		"    return v0",
	)
	info, _ := analyzeEconomyMethod(mi, nil)
	if info == nil {
		t.Fatal("getCoins must produce economy info")
	}
	if !containsString(info.Resources, "coins") {		t.Fatalf("resources = %v, want coins", info.Resources)
	}
	if info.Operation != EconomyBalanceRead {
		t.Fatalf("operation = %q, want %q", info.Operation, EconomyBalanceRead)
	}
	if !isEconomyCandidate(info) {
		t.Fatalf("balance getter must be a candidate: %+v", info)
	}
	if economyNeedsTransactionReview(info) {
		t.Fatal("plain balance read must not require transaction review")
	}
}

func TestEconomyPriceAndAffordOperations(t *testing.T) {
	if got := economyOperation("getPrice", "I"); got != EconomyPrice {
		t.Fatalf("getPrice op = %q, want price", got)
	}
	if got := economyOperation("canAfford", "Z"); got != EconomyAfford {
		t.Fatalf("canAfford op = %q, want afford", got)
	}
	spend := &EconomyInfo{Resources: []string{"coins"}, Operation: EconomySpend, ValueType: "I", ValueLinked: true}
	if !economyNeedsTransactionReview(spend) {
		t.Fatal("spend writer must require transaction review")
	}
	if !isEconomyCandidate(spend) {
		t.Fatal("linked spend writer must be a candidate")
	}
}

func TestEconomyIgnoresNonAmountNames(t *testing.T) {
	mi := economyTestMethod("getIcon", "()I", "I",
		"    .locals 1",
		"    iget v0, p0, Lcom/game/Player;->icon:I",
		"    return v0",
	)
	info, _ := analyzeEconomyMethod(mi, nil)
	if info != nil && info.Operation != EconomyDisplay {
		t.Fatalf("icon getter must be display at most, got %+v", info)
	}
	if info != nil && isEconomyCandidate(info) {
		t.Fatalf("icon getter must not be a patch candidate: %+v", info)
	}
}

func TestEconomyFloatDoubleMaxConstants(t *testing.T) {
	floatStub := buildStubMethodSmart(".method public getGems()F", "()F", "F", kindMaxInt)
	if !strings.Contains(floatStub, "0x7f7fffff") {
		t.Fatalf("float MAX stub must use Float.MAX_VALUE bits:\n%s", floatStub)
	}
	doubleStub := buildStubMethodSmart(".method public getGems()D", "()D", "D", kindMaxInt)
	if !strings.Contains(doubleStub, "0x7fefffffffffffff") {
		t.Fatalf("double MAX stub must use Double.MAX_VALUE bits:\n%s", doubleStub)
	}
	if strings.Contains(floatStub, "0x7fffffff") || strings.Contains(doubleStub, "0x7fffffffffffffff") {
		t.Fatal("integer MAX bits must never leak into float/double stubs (they decode as NaN)")
	}
	if !NewSmaliValidator().ValidateStrict(floatStub).Valid {
		t.Fatalf("float MAX stub must validate:\n%s", floatStub)
	}
	if !NewSmaliValidator().ValidateStrict(doubleStub).Valid {
		t.Fatalf("double MAX stub must validate:\n%s", doubleStub)
	}
}

func TestEconomyServerAuthorityAudited(t *testing.T) {
	mi := &MethodInfo{
		Name: "getBalance", NameLower: "getbalance", FullSignature: "getBalance()I",
		ReturnType: "I", ClassName: "com/acme/net/EconomyResponse", ClassPath: "com/acme/net/EconomyResponse",
		RawBody: []string{
			"    .locals 1",
			"    iget v0, p0, Lcom/acme/net/EconomyResponse;->balance:I",
			"    return v0",
		},
	}
	info, _ := analyzeEconomyMethod(mi, nil)
	if info == nil {
		t.Fatal("server response balance must still be discovered")
	}
	if info.Authority != "server_related" {
		t.Fatalf("authority = %q, want server_related", info.Authority)
	}
	if !economyNeedsTransactionReview(info) {
		t.Fatal("server-authoritative balance must require review, not a rewrite")
	}
	score := NewPatchScorer(NewPatchAnalyzer()).ScoreMethod(mi)
	if score.SuggestedPatch != "" {
		t.Fatalf("server copy must not suggest a patch, got %q", score.SuggestedPatch)
	}
}

func TestEconomyClassSeededUnknownFieldAudited(t *testing.T) {
	mi := &MethodInfo{
		Name: "a", NameLower: "a", FullSignature: "a()I",
		ReturnType: "I", ClassName: "com/acme/game/Wallet", ClassPath: "com/acme/game/Wallet",
		RawBody: []string{
			"    .locals 1",
			"    iget v0, p0, Lcom/acme/game/Wallet;->x:I",
			"    return v0",
		},
	}
	info, _ := analyzeEconomyMethod(mi, nil)
	if info == nil {
		t.Fatal("obfuscated getter in a Wallet class must be admitted via class context")
	}
	if !isEconomyCandidate(info) {
		t.Fatalf("class-seeded getter must be a candidate: %+v", info)
	}
	if info.ValueResolved {
		t.Fatalf("unknown field x must not count as resolved: %+v", info)
	}
	if !economyNeedsTransactionReview(info) {
		t.Fatal("unresolved value must go to audit, not to a rewrite")
	}
}

func TestEconomyMaxRefusesPrice(t *testing.T) {
	price := &shared.MethodInfo{
		Name: "getGemCost", NameLower: "getgemcost", FullSignature: "getGemCost()I",
		ReturnType: "I", Economy: &shared.EconomyInfo{Resources: []string{"currency"}, Operation: EconomyPrice, ValueType: "I"},
		RawBody: []string{".method public getGemCost()I", "    .registers 2", "    return v0", ".end method"},
	}
	if NewNumericMaxInjectionStrategy().CanApply(price, PatchModeResearch) {
		t.Fatal("numeric MAX must refuse a classified price (price goes to zero, never to max)")
	}
	widePrice := &shared.MethodInfo{
		Name: "getPrice", NameLower: "getprice", FullSignature: "getPrice()J",
		ReturnType: "J", Economy: &shared.EconomyInfo{Resources: []string{"currency"}, Operation: EconomyPrice, ValueType: "J"},
		RawBody: []string{".method public getPrice()J", "    .registers 4", "    return-wide v0", ".end method"},
	}
	if NewWideMaxInjectionStrategy().CanApply(widePrice, PatchModeResearch) {
		t.Fatal("wide MAX must refuse a classified price")
	}
	// Name-only fallback: no flow info, price tokens still refuse MAX.
	nameless := &shared.MethodInfo{
		Name: "getPrice", NameLower: "getprice", FullSignature: "getPrice()J",
		ReturnType: "J",
		RawBody: []string{".method public getPrice()J", "    .registers 4", "    return-wide v0", ".end method"},
	}
	if NewWideMaxInjectionStrategy().CanApply(nameless, PatchModeResearch) {
		t.Fatal("wide MAX must refuse price names even without flow info")
	}
}

func TestEconomyRelatedLinksSharedField(t *testing.T) {
	field := "Lcom/acme/game/Wallet;->coins:I"
	mkPoint := func(method, op string) PatchPoint {
		return PatchPoint{MethodName: method, ClassName: "com/acme/game/Wallet",
			Economy: &shared.EconomyInfo{Resources: []string{"coins"}, Operation: op, ValueType: "I",
				Evidence: []shared.EconomyEvidence{{Kind: "field", Reference: field}}}}
	}
	prediction := &PatchPrediction{
		HighRisk: []PatchPoint{mkPoint("getCoins", EconomyBalanceRead)},
		AuditFindings: []PatchPoint{
			mkPoint("spendCoins", EconomySpend),
			{MethodName: "getLevel", ClassName: "com/acme/game/Wallet",
				Economy: &shared.EconomyInfo{Resources: []string{"points"}, Operation: EconomyBalanceRead, ValueType: "I",
					Evidence: []shared.EconomyEvidence{{Kind: "field", Reference: "Lcom/acme/game/Wallet;->level:I"}}}},
		},
	}
	linkEconomyRelated(prediction)
	if len(prediction.HighRisk[0].Economy.Related) == 0 {
		t.Fatal("getter must link to the spender over the shared field")
	}
	found := false
	for _, rel := range prediction.HighRisk[0].Economy.Related {
		if rel.Method == "spendCoins" && rel.Operation == EconomySpend { found = true }
	}
	if !found {
		t.Fatalf("related must contain spendCoins/spend, got %+v", prediction.HighRisk[0].Economy.Related)
	}
	if len(prediction.AuditFindings[1].Economy.Related) != 0 {
		t.Fatalf("unrelated level field must not link, got %+v", prediction.AuditFindings[1].Economy.Related)
	}
}

func TestDecoyConstantReturnClearsRewrite(t *testing.T) {
	constant := &DecoyAnalysis{IsDecoy: true, ConfidenceScore: 0.9,
		Matches: []DecoyMatch{{Kind: DecoyAlwaysSameReturn, Confidence: 0.85}}}
	if !decoyConstantReturn(constant) {
		t.Fatal("proven constant return must be detected")
	}
	weak := &DecoyAnalysis{IsDecoy: true, ConfidenceScore: 0.5,
		Matches: []DecoyMatch{{Kind: DecoyAlwaysSameReturn, Confidence: 0.5}}}
	if decoyConstantReturn(weak) {
		t.Fatal("low-confidence const signal must not clear the patch")
	}
	if decoyConstantReturn(nil) {
		t.Fatal("nil decoy must not match")
	}
}

func TestEconomyZeroKindForcesZero(t *testing.T) {
	if patchKindFor(PatchReturnZero) != kindZero {
		t.Fatalf("PatchReturnZero must map to kindZero, got %d", patchKindFor(PatchReturnZero))
	}
	priceBody := []string{
		".method public getPrice()I",
		"    .registers 2",
		"    iget v0, p0, Lcom/app/Shop;->price:I",
		"    return v0",
		".end method",
	}
	out, ok := buildBodyPreservingPatch(priceBody, "I", kindZero)
	if !ok {
		t.Fatal("body-preserving zero must apply to int price")
	}
	if strings.Contains(out, "0x7fffffff") {
		t.Fatalf("return_zero must never emit MAX_INT:\n%s", out)
	}
	if !strings.Contains(out, "0x0") {
		t.Fatalf("return_zero must force zero:\n%s", out)
	}
	floatBody := []string{
		".method public getPrice()F",
		"    .registers 2",
		"    iget v0, p0, Lcom/app/Shop;->price:F",
		"    return v0",
		".end method",
	}
	floatOut, ok := buildBodyPreservingPatch(floatBody, "F", kindZero)
	if !ok || !strings.Contains(floatOut, "const") || strings.Contains(floatOut, "0x7fffffff") {
		t.Fatalf("float zero must be plain const 0 (0.0f bits):\n%s", floatOut)
	}
	wideBody := []string{
		".method public getPrice()J",
		"    .registers 4",
		"    iget-wide v0, p0, Lcom/app/Shop;->price:J",
		"    return-wide v0",
		".end method",
	}
	wideOut, ok := buildBodyPreservingPatch(wideBody, "J", kindZero)
	if !ok {
		t.Fatal("body-preserving zero must apply to long price")
	}
	if !strings.Contains(wideOut, "const-wide v0, 0x0") {
		t.Fatalf("long zero must use const-wide 0:\n%s", wideOut)
	}
}

func TestEconomyPriceTierIsNotAPrice(t *testing.T) {
	for _, name := range []string{"getPriceTier", "getPriceLevel", "getCostIndex", "getGemType"} {
		if got := economyOperation(name, "I"); got == EconomyPrice {
			t.Fatalf("%s must not classify as price, got %q", name, got)
		}
	}
	if got := economyOperation("getCosts", "I"); got != EconomyPrice {
		t.Fatalf("getCosts must stay a price, got %q", got)
	}
}

func TestEconomyAffixAndTranslitNames(t *testing.T) {
	if resources := resourcesIn("mycoins"); !containsString(resources, "coins") {
		t.Fatalf("mycoins must resolve to coins, got %v", resources)
	}
	if resources := resourcesIn("monety"); !containsString(resources, "coins") {
		t.Fatalf("monety must resolve to coins, got %v", resources)
	}
	if resources := resourcesIn("almazy"); !containsString(resources, "diamonds") {
		t.Fatalf("almazy must resolve to diamonds, got %v", resources)
	}
	// The affix guard: a garment is not a price.
	if got := economyOperation("getCostume", "I"); got == EconomyPrice {
		t.Fatalf("getCostume must not classify as price, got %q", got)
	}
	if got := economyOperation("getCostumes", "I"); got == EconomyPrice {
		t.Fatalf("getCostumes must not classify as price, got %q", got)
	}
}

func TestEconomyTransactionImmuneToDecoy(t *testing.T) {
	mi := economyTestMethod("spendCoins", "(I)V", "V",
		"    .registers 3",
		"    iget v0, p0, Lcom/game/Player;->coins:I",
		"    sub-int/2addr v0, p1",
		"    iput v0, p0, Lcom/game/Player;->coins:I",
		"    return-void",
	)
	info, _ := analyzeEconomyMethod(mi, nil)
	if info == nil || info.Operation != EconomySpend {
		t.Fatalf("spend writer must classify as spend, got %+v", info)
	}
	if !isEconomyTransactionMethod(mi) {
		t.Fatal("linked spend writer must be a transaction method")
	}
	if decoy := AnalyzeDecoy(mi); decoy != nil && decoy.IsDecoy {
		t.Fatalf("linked spend must not be a decoy, got %q", decoy.PrimaryReason)
	}
	if !economyNeedsTransactionReview(info) {
		t.Fatal("spend writer must require transaction review")
	}
	score := NewPatchScorer(NewPatchAnalyzer()).ScoreMethod(mi)
	if score.SuggestedPatch != "" {
		t.Fatalf("spend writer must not suggest a patch, got %q", score.SuggestedPatch)
	}
}

func TestEconomySyntheticSuggestsNoPatch(t *testing.T) {
	mi := economyTestMethod("access$getCoins$p", "()I", "I",
		"    .locals 1",
		"    iget v0, p0, Lcom/game/Player;->coins:I",
		"    return v0",
	)
	mi.IsSynthetic = true
	mi.IsAccessor = true
	score := NewPatchScorer(NewPatchAnalyzer()).ScoreMethod(mi)
	if score.SuggestedPatch != "" {
		t.Fatalf("synthetic accessor must not suggest a patch, got %q", score.SuggestedPatch)
	}
	// Direct scoring suppresses the compiler helper entirely; the full
	// predictor still rescues it into audit/currency (see probe case
	// synthetic_coin_accessor). Either outcome carries no rewrite.
	if score.PatchCategory != PatchCatCurrency && score.PatchCategory != "" {
		t.Fatalf("accessor category must be currency or suppressed, got %q", score.PatchCategory)
	}
}

