package imagedec

import "testing"

// rotl4 and nibble swap are the same function, and so are xor-0xFF and
// complement. Both pairs would otherwise be found together, score identically,
// and resolve in whatever order the solver happened to try them.
func TestCanonicalCollapsesEquivalentTransforms(t *testing.T) {
	cases := []struct {
		in   Transform
		want Kind
	}{
		{Transform{Kind: KindRotate, N: 4}, KindNibble},
		{Transform{Kind: KindRotate, N: 12}, KindNibble},
		{Transform{Kind: KindXOR, Key: []byte{0xFF}}, KindNot},
		// Everything else must survive untouched.
		{Transform{Kind: KindRotate, N: 3}, KindRotate},
		{Transform{Kind: KindXOR, Key: []byte{0xFF, 0xFF}}, KindXOR},
		{Transform{Kind: KindXOR, Key: []byte{0x5A}}, KindXOR},
		{Transform{Kind: KindAdd, N: 4}, KindAdd},
		{Transform{Kind: KindReverse}, KindReverse},
	}
	for _, tc := range cases {
		if got := tc.in.Canonical(); got.Kind != tc.want {
			t.Errorf("%s canonicalised to %s, want kind %d", tc.in, got, tc.want)
		}
	}
}

// Canonicalisation must be a rename, never a behaviour change.
func TestCanonicalPreservesBehaviour(t *testing.T) {
	src := []byte{0x00, 0x12, 0x89, 0xFF, 0x5A, 0xA5, 0x0F, 0xF0, 0x34, 0x7E}
	for _, in := range []Transform{
		{Kind: KindRotate, N: 4},
		{Kind: KindRotate, N: 12},
		{Kind: KindXOR, Key: []byte{0xFF}},
		{Kind: KindRotate, N: 3},
		{Kind: KindAdd, N: 200},
	} {
		a := in.Apply(src)
		b := in.Canonical().Apply(src)
		if string(a) != string(b) {
			t.Errorf("%s -> %s changed the output: %x vs %x", in, in.Canonical(), a, b)
		}
	}
}
