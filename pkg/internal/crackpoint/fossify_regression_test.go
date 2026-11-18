package crackpoint

import "testing"

func TestCodecSignatureChecksAreNotTamperGates(t *testing.T) {
	syms := []SymbolRef{{Name: "VP8CheckSignature", Kind: SymbolExport}, {Name: "VP8LCheckSignature", Kind: SymbolExport}, {Name: "isProjected", Kind: SymbolMethod}}
	if got := NewFinder().FindCrackPointsInSymbols(syms, "renamed.so", PlatformNative); got.TotalFound != 0 {
		t.Fatalf("codec/UI symbols produced gates: %+v", got.CrackPoints)
	}
	syms = []SymbolRef{{Name: "checkSignature", Kind: SymbolExport}, {Name: "isPro", Kind: SymbolMethod}}
	if got := NewFinder().FindCrackPointsInSymbols(syms, "renamed.so", PlatformNative); got.TotalFound != 2 {
		t.Fatalf("real protection gates were lost: %+v", got.CrackPoints)
	}
}
