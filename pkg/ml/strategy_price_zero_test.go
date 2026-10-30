package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// reconstructStubHeader — заголовок стаба обязан сохранять параметры
// ═══════════════════════════════════════════════════════════════════════════════

func TestReconstructStubHeaderKeepsParameters(t *testing.T) {
	mi := &shared.MethodInfo{
		Name:          "purchase",
		FullSignature: "purchase(IJLjava/lang/String;)I",
		ReturnType:    "I",
		IsPublic:      true,
	}
	got := shared.ReconstructStubHeader(mi)
	want := ".method public purchase(IJLjava/lang/String;)I"
	if got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
}

func TestReconstructStubHeaderStaticAndFinal(t *testing.T) {
	mi := &shared.MethodInfo{
		Name:          "calc",
		FullSignature: "calc(Z[D)V",
		ReturnType:    "V",
		IsPrivate:     true,
		IsStatic:      true,
		IsFinal:       true,
	}
	want := ".method private static final calc(Z[D)V"
	if got := shared.ReconstructStubHeader(mi); got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
}

func TestReconstructStubHeaderNilSafe(t *testing.T) {
	if got := shared.ReconstructStubHeader(nil); got != "" {
		t.Fatalf("expected empty header for nil, got %q", got)
	}
}

// Регрессия: стратегии-стабы (return_true/false/nop) раньше строили заголовок
// с пустым () дескриптором, что давало невалидный smali для методов с параметрами.
func TestReturnTrueStrategyHeaderWithParameters(t *testing.T) {
	s := NewReturnTrueStrategy()
	mi := &shared.MethodInfo{
		Name:          "isPurchased",
		FullSignature: "isPurchased(Ljava/lang/String;I)Z",
		ReturnType:    "Z",
		ReturnsBoolean: true,
		IsPublic:      true,
		RawBody:       []string{".method public isPurchased(Ljava/lang/String;I)Z", "    return false", ".end method"},
	}
	patch, err := s.Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(patch.PatchedCode, "isPurchased(Ljava/lang/String;I)Z") {
		t.Fatalf("patched header dropped parameters:\n%s", patch.PatchedCode)
	}
}

func TestReturnFalseStrategyHeaderWithParameters(t *testing.T) {
	s := NewReturnFalseStrategy()
	mi := &shared.MethodInfo{
		Name:          "checkLicense",
		FullSignature: "checkLicense([BLjava/lang/Object;)Z",
		ReturnType:    "Z",
		ReturnsBoolean: true,
		IsPublic:      true,
	}
	patch, err := s.Generate(mi, PatchModeDefensive)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(patch.PatchedCode, "checkLicense([BLjava/lang/Object;)Z") {
		t.Fatalf("patched header dropped parameters:\n%s", patch.PatchedCode)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PriceZeroInjectionStrategy
// ═══════════════════════════════════════════════════════════════════════════════

func priceZeroFixture() *shared.MethodInfo {
	return &shared.MethodInfo{
		Name:          "getGemCost",
		ClassName:     "Lcom/app/Shop;",
		FilePath:      "smali/com/app/Shop.smali",
		FullSignature: "getGemCost(Ljava/lang/String;I)I",
		ReturnType:    "I",
		NameLower:     "getgemcost",
		IsPublic:      true,
		RawBody: []string{
			".method public getGemCost(Ljava/lang/String;I)I",
			"    .registers 4",
			"",
			"    invoke-static {p1}, Lcom/app/Sku;->parse(Ljava/lang/String;)I",
			"    move-result v0",
			"    mul-int/2addr v0, p2",
			"    return v0",
			".end method",
		},
	}
}

func TestPriceZeroCanApplyGating(t *testing.T) {
	s := NewPriceZeroInjectionStrategy()

	ok := s.CanApply(priceZeroFixture(), PatchModeResearch)
	if !ok {
		t.Fatal("price getter in research mode must be applicable")
	}

	// Оборонительный режим не трогаем.
	if s.CanApply(priceZeroFixture(), PatchModeDefensive) {
		t.Fatal("must not apply in defensive mode")
	}

	// Boolean-геттер цены — территория return_true/false.
	boolMi := priceZeroFixture()
	boolMi.ReturnType = "Z"
	boolMi.ReturnsBoolean = true
	if s.CanApply(boolMi, PatchModeResearch) {
		t.Fatal("boolean methods are out of scope")
	}

	// Wide-возврат (J) не поддерживается точечной инъекцией.
	wideMi := priceZeroFixture()
	wideMi.ReturnType = "J"
	wideMi.FullSignature = "getGemCost(Ljava/lang/String;I)J"
	if s.CanApply(wideMi, PatchModeResearch) {
		t.Fatal("wide returns must be skipped")
	}

	// Не ценовое имя — мимо.
	otherMi := priceZeroFixture()
	otherMi.Name = "getUserAge"
	otherMi.NameLower = "getuserage"
	otherMi.FullSignature = "getUserAge()I"
	if s.CanApply(otherMi, PatchModeResearch) {
		t.Fatal("non-price names must not match")
	}

	// Конструктор никогда.
	ctorMi := priceZeroFixture()
	ctorMi.Name = "<init>"
	ctorMi.IsConstructor = true
	if s.CanApply(ctorMi, PatchModeResearch) {
		t.Fatal("constructors must never be patched")
	}
}

func TestPriceZeroGeneratePreservesBodyAndZeroesReturns(t *testing.T) {
	s := NewPriceZeroInjectionStrategy()
	mi := priceZeroFixture()

	patch, err := s.Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if patch.PatchType != PatchReturnZero {
		t.Fatalf("PatchType = %q, want %q", patch.PatchType, PatchReturnZero)
	}
	// Тело сохранено: исходная инструкция на месте.
	if !strings.Contains(patch.PatchedCode, "mul-int/2addr v0, p2") {
		t.Fatal("original instructions must survive")
	}
	// Перед возвратом внедрён ноль.
	if !strings.Contains(patch.PatchedCode, "const/4 v0, 0x0") {
		t.Fatalf("const 0 injection missing:\n%s", patch.PatchedCode)
	}
	if strings.Contains(patch.PatchedCode, "0x7fffffff") {
		t.Fatal("MAX_INT leaked into a zero-price patch")
	}
}

func TestPriceZeroBeatsNumericMaxOnAmbiguousNames(t *testing.T) {
	ss := NewStrategySelector()
	mi := priceZeroFixture()
	mi.MethodHeader = mi.RawBody[0]

	chosen := ss.SelectStrategy(mi, PatchModeResearch)
	if chosen == nil {
		t.Fatal("no strategy selected for ambiguous getGemCost")
	}
	if chosen.PatchType() != PatchReturnZero {
		t.Fatalf("on ambiguous getGemCost expected PriceZero (%s), got %T (%s)",
			PatchReturnZero, chosen, chosen.PatchType())
	}
}

func TestPriceZeroNotSelectedForBalanceGetters(t *testing.T) {
	ss := NewStrategySelector()
	mi := priceZeroFixture()
	mi.Name = "getGemBalance"
	mi.NameLower = "getgembalance"
	mi.FullSignature = "getGemBalance()I"
	mi.MethodHeader = mi.RawBody[0]
	mi.RawBody[0] = ".method public getGemBalance()I"

	chosen := ss.SelectStrategy(mi, PatchModeResearch)
	if chosen == nil {
		t.Fatal("no strategy selected for balance getter")
	}
	if chosen.PatchType() == PatchReturnZero {
		t.Fatal("balance getter must not be zeroed as a price")
	}
}
