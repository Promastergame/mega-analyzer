package knownset

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func shaHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func build(t *testing.T, fpr float64, good, bad []string) BuildResult {
	t.Helper()
	b, err := NewBuilder(fpr)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range good {
		k, ok := KeySHA256(shaHex(g))
		if !ok || !b.AddGood(k) {
			t.Fatalf("good key %q rejected", g)
		}
	}
	for _, x := range bad {
		k, ok := KeySHA256(shaHex(x))
		if !ok || !b.AddBad(k) {
			t.Fatalf("bad key %q rejected", x)
		}
	}
	res, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestNoFalseNegatives(t *testing.T) {
	var good, bad []string
	for i := 0; i < 5000; i++ {
		good = append(good, fmt.Sprintf("good-%d", i))
	}
	for i := 0; i < 500; i++ {
		bad = append(bad, fmt.Sprintf("bad-%d", i))
	}
	bundle := build(t, 0.001, good, bad).Bundle
	for _, g := range good {
		if bundle.LookupSHA256(shaHex(g)) != KnownGood {
			t.Fatalf("known good %q missed", g)
		}
	}
	for _, x := range bad {
		if bundle.LookupSHA256(shaHex(x)) != KnownBad {
			t.Fatalf("known bad %q missed", x)
		}
	}
}

func TestEmpiricalFalsePositiveRateNearTarget(t *testing.T) {
	const n, probes = 20000, 200000
	var good []string
	for i := 0; i < n; i++ {
		good = append(good, fmt.Sprintf("g-%d", i))
	}
	bundle := build(t, 0.01, good, nil).Bundle
	hits := 0
	for i := 0; i < probes; i++ {
		if bundle.LookupSHA256(shaHex(fmt.Sprintf("never-added-%d", i))) == KnownGood {
			hits++
		}
	}
	rate := float64(hits) / probes
	if rate > 0.02 {
		t.Fatalf("observed false-positive rate %.4f is far above the 1%% target", rate)
	}
	if est := bundle.Stats().EstimatedFPR; est > 0.02 || est < 0.003 {
		t.Fatalf("estimated FPR %.4f is implausible for a 1%% target", est)
	}
}

func TestBadIsExactAndNeverFalsePositive(t *testing.T) {
	bundle := build(t, 0.5, nil, []string{"only-bad"}).Bundle // фильтр хорошего намеренно «дырявый»
	for i := 0; i < 20000; i++ {
		if bundle.LookupSHA256(shaHex(fmt.Sprintf("x-%d", i))) == KnownBad {
			t.Fatal("exact bad set produced a false positive")
		}
	}
}

func TestBadOverridesGoodAndConflictsAreCounted(t *testing.T) {
	res := build(t, 0.001, []string{"a", "b"}, []string{"b", "c"})
	if res.Conflicts != 1 {
		t.Fatalf("conflicts = %d", res.Conflicts)
	}
	if res.Bundle.LookupSHA256(shaHex("b")) != KnownBad {
		t.Fatal("bad must win over good")
	}
	if res.Bundle.LookupSHA256(shaHex("a")) != KnownGood {
		t.Fatal("a must stay good")
	}
}

func TestPURLCanonicalisationAgreesBetweenBuildAndLookup(t *testing.T) {
	b, _ := NewBuilder(0.0001)
	k, ok := KeyPURL("pkg:pypi/Foo_Bar@1.0?arch=x86#sub")
	if !ok || !b.AddBad(k) {
		t.Fatal("add failed")
	}
	bundle, _ := b.Build()
	for _, spelling := range []string{"pkg:pypi/foo-bar@1.0", "pkg:pypi/FOO_BAR@1.0", "pkg://pypi/foo-bar@1.0?x=y"} {
		if bundle.Bundle.LookupPURL(spelling) != KnownBad {
			t.Errorf("spelling %q must hit the same key", spelling)
		}
	}
	if bundle.Bundle.LookupPURL("pkg:pypi/foo-bar@1.1") != Unknown {
		t.Error("another version must not match")
	}
	if bundle.Bundle.LookupPURL("not a purl") != Unknown {
		t.Error("garbage must be Unknown, not an error or a hit")
	}
}

func TestNonCanonicalKeysAreRejectedByBuilder(t *testing.T) {
	b, _ := NewBuilder(0.01)
	for _, k := range []string{"", "abc", shaHex("x"), "SHA256:" + shaHex("x")} {
		if b.AddGood(k) || b.AddBad(k) {
			t.Errorf("non-canonical key %q accepted", k)
		}
	}
	if _, ok := KeySHA256("zz"); ok {
		t.Error("short hash accepted")
	}
	if _, ok := KeySHA256(strings.Repeat("g", 64)); ok {
		t.Error("non-hex hash accepted")
	}
	if k, ok := KeySHA256(strings.ToUpper(shaHex("x"))); !ok || k != "sha256:"+shaHex("x") {
		t.Error("uppercase hex must canonicalise to lowercase")
	}
}

func TestRoundTripThroughFile(t *testing.T) {
	res := build(t, 0.001, []string{"g1", "g2"}, []string{"b1"})
	path := filepath.Join(t.TempDir(), "set.mks")
	if err := res.Bundle.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.LookupSHA256(shaHex("g1")) != KnownGood || back.LookupSHA256(shaHex("b1")) != KnownBad || back.LookupSHA256(shaHex("zz")) != Unknown {
		t.Fatal("decoded bundle answers differently")
	}
	if s := back.Stats(); s.GoodKeys != 2 || s.BadKeys != 1 {
		t.Fatalf("stats: %+v", s)
	}
}

func TestCorruptionIsDetectedEverywhere(t *testing.T) {
	data := build(t, 0.001, []string{"g1", "g2", "g3"}, []string{"b1", "b2"}).Bundle.Encode()
	for _, pos := range []int{0, 5, 20, len(data) / 2, len(data) - 40, len(data) - 1} {
		bad := append([]byte(nil), data...)
		bad[pos] ^= 0x40
		if _, err := Decode(bad); err == nil {
			t.Errorf("flip at byte %d went unnoticed", pos)
		}
	}
	for _, cut := range []int{0, 3, 10, len(data) - 1, len(data) - 33} {
		if _, err := Decode(data[:cut]); err == nil {
			t.Errorf("truncation to %d bytes went unnoticed", cut)
		}
	}
}

func TestSchemeMismatchRefusesToOpen(t *testing.T) {
	data := build(t, 0.01, []string{"g"}, nil).Bundle.Encode()
	// Подменяем схему на другую той же длины и пересчитываем контрольную сумму:
	// файл целый, но ключи в нём построены по другим правилам.
	i := strings.Index(string(data), Scheme)
	forged := append([]byte(nil), data...)
	copy(forged[i:], strings.Repeat("X", len(Scheme)))
	sum := sha256.Sum256(forged[:len(forged)-32])
	copy(forged[len(forged)-32:], sum[:])
	_, err := Decode(forged)
	if err == nil || !strings.Contains(err.Error(), "scheme mismatch") {
		t.Fatalf("want scheme mismatch, got %v", err)
	}
}

func TestHostileHeadersDoNotPanicOrAllocateHugely(t *testing.T) {
	seed := build(t, 0.01, []string{"g"}, []string{"b"}).Bundle.Encode()
	for i := 4; i < len(seed)-32; i++ {
		mut := append([]byte(nil), seed...)
		mut[i] = 0xFF
		// Пересчитываем сумму, чтобы проверка дошла до разбора структуры.
		sum := sha256.Sum256(mut[:len(mut)-32])
		copy(mut[len(mut)-32:], sum[:])
		_, _ = Decode(mut) // главное — без паники и без гигантской аллокации
	}
}

func TestEmptyBundleIsUsable(t *testing.T) {
	b, _ := NewBuilder(0.01)
	res, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(res.Bundle.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if back.LookupSHA256(shaHex("x")) != Unknown {
		t.Fatal("empty bundle must answer Unknown")
	}
}

func TestBadFPRIsRejected(t *testing.T) {
	for _, f := range []float64{0, 1, -0.1, 2} {
		if _, err := NewBuilder(f); err == nil {
			t.Errorf("fpr %v accepted", f)
		}
	}
}
