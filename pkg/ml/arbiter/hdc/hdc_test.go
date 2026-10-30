package hdc

import "testing"

func TestSelfSim(t *testing.T) {
	v := Atom("foo")
	if got := v.Sim(v); got != 1.0 {
		t.Fatalf("self similarity must be 1, got %v", got)
	}
}

func TestAtomDeterministic(t *testing.T) {
	if d := Atom("abc").Hamming(Atom("abc")); d != 0 {
		t.Fatalf("same seed must yield same vector, hamming=%d", d)
	}
}

func TestBindInvertible(t *testing.T) {
	a, b := Atom("a"), Atom("b")
	if d := a.Bind(b).Bind(b).Hamming(a); d != 0 {
		t.Fatalf("bind must be invertible: (a^b)^b == a, hamming=%d", d)
	}
}

func TestBindSelfIsZero(t *testing.T) {
	a := Atom("anything")
	if d := a.Bind(a).Hamming(Vector{}); d != 0 {
		t.Fatalf("a^a must be the zero vector, hamming=%d", d)
	}
}

func TestHammingSymmetric(t *testing.T) {
	a, b := Atom("left"), Atom("right")
	if a.Hamming(b) != b.Hamming(a) {
		t.Fatal("hamming distance must be symmetric")
	}
}

func TestSimSymmetric(t *testing.T) {
	a, b := Atom("left"), Atom("right")
	if a.Sim(b) != b.Sim(a) {
		t.Fatal("similarity must be symmetric")
	}
}

func TestEmptyBundle(t *testing.T) {
	if d := Bundle().Hamming(Vector{}); d != 0 {
		t.Fatalf("empty bundle must be the zero vector, hamming=%d", d)
	}
}

func TestBundleResemblesMembers(t *testing.T) {
	a, b, c := Atom("x"), Atom("y"), Atom("z")
	bundle := Bundle(a, b, c)
	// Theoretical expectation for unrelated vectors is 0.5; a bundle must sit
	// clearly above that for each of its members.
	if bundle.Sim(a) < 0.55 {
		t.Fatalf("bundle should resemble member a: sim=%v", bundle.Sim(a))
	}
	if bundle.Sim(b) < 0.55 {
		t.Fatalf("bundle should resemble member b: sim=%v", bundle.Sim(b))
	}
	if bundle.Sim(c) < 0.55 {
		t.Fatalf("bundle should resemble member c: sim=%v", bundle.Sim(c))
	}
}

func TestUnrelatedNear50(t *testing.T) {
	// With D=2048 the spread is tight enough that unrelated atoms sit very
	// close to 0.5.
	s := Atom("alpha").Sim(Atom("omega"))
	if s < 0.45 || s > 0.55 {
		t.Fatalf("unrelated atoms should sit near 0.5, got %v", s)
	}
}

// TestEncodeOrderIndependent guards against map iteration order leaking into
// the encoding: the same features in a different insertion order must produce
// the exact same hypervector.
func TestEncodeOrderIndependent(t *testing.T) {
	f1 := map[string]string{"rule": "AWS_KEY", "lang": "smali"}
	f2 := map[string]string{"lang": "smali", "rule": "AWS_KEY"}
	if d := EncodeFeatures(f1).Hamming(EncodeFeatures(f2)); d != 0 {
		t.Fatalf("encoding must be order-independent, hamming=%d", d)
	}
}

// TestEncodeDeterministic re-encodes the same map many times. Because Go
// randomizes map iteration order per range, repeated runs exercise different
// orderings and must all collapse to the identical vector.
func TestEncodeDeterministic(t *testing.T) {
	f := map[string]string{
		"rule": "AWS_KEY",
		"lang": "smali",
		"sev":  "critical",
		"cls":  "crypto-weakness",
	}
	want := EncodeFeatures(f)
	for i := 0; i < 100; i++ {
		if d := want.Hamming(EncodeFeatures(f)); d != 0 {
			t.Fatalf("encoding must be deterministic across runs (iter %d), hamming=%d", i, d)
		}
	}
}

func TestEmptyFeatures(t *testing.T) {
	if d := EncodeFeatures(nil).Hamming(Vector{}); d != 0 {
		t.Fatalf("empty features must encode to the zero vector, hamming=%d", d)
	}
}
