package protocol

import (
	"testing"
)

// Review round: protobuf-first detection order, multi-field structural walk,
// majority-vote spec format.

// Two clean fields where the old order returned msgpack (0x08 is both
// field-1-varint tag and a positive fixint).
func TestReviewProtobufBeatsMsgpackPrefix(t *testing.T) {
	data := []byte{0x08, 0x96, 0x01, 0x12, 0x03, 'f', 'o', 'o'}
	if got := DetectFormat(data); got != FormatProtobuf {
		t.Errorf("two-field protobuf detected as %s", got)
	}
}

func TestReviewProtobufWalkRules(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"two varints", []byte{0x08, 0x01, 0x10, 0x02}, true},
		{"fixed32 + fixed64", []byte{0x0D, 1, 2, 3, 4, 0x11, 1, 2, 3, 4, 5, 6, 7, 8}, true},
		{"single field stays ambiguous", []byte{0x08, 0x10}, false},
		{"truncated tail after two fields still counts", []byte{0x08, 0x01, 0x10, 0x02, 0xF8}, true},
		{"corrupt wire mid-walk rejected", []byte{0x08, 0x01, 0x1F, 0x02}, false},
		{"groups rejected", []byte{0x0B, 0x01, 0x0C, 0x02}, false},
		{"field zero rejected", []byte{0x00, 0x01, 0x10, 0x02}, false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		if got := looksLikeProtobuf(tc.data); got != tc.want {
			t.Errorf("%s: looksLikeProtobuf = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestReviewDecodeVarint(t *testing.T) {
	if v, n := decodeVarint([]byte{0x96, 0x01}); v != 150 || n != 2 {
		t.Errorf("150 = (%d, %d)", v, n)
	}
	if _, n := decodeVarint([]byte{0x80}); n != 0 {
		t.Errorf("truncated varint should fail, got n=%d", n)
	}
	if _, n := decodeVarint([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}); n != 0 {
		t.Errorf("overlong varint should fail, got n=%d", n)
	}
	if _, n := decodeVarint(nil); n != 0 {
		t.Errorf("empty varint should fail, got n=%d", n)
	}
}

func TestReviewMajorityFormat(t *testing.T) {
	ps := NewProtocolSpec("Test")
	// JSON handshake first: the old latch locked the whole spec to JSON.
	ps.AddSample(1, "C2S", []byte(`{"hello":1}`))
	if ps.Format != FormatJSON {
		t.Fatalf("first sample should set JSON, got %s", ps.Format)
	}
	// Two protobuf messages outvote it.
	pb := []byte{0x08, 0x01, 0x10, 0x02}
	ps.AddSample(2, "C2S", pb)
	ps.AddSample(3, "C2S", pb)
	if ps.Format != FormatProtobuf {
		t.Errorf("majority protobuf should win, got %s", ps.Format)
	}
	// Tie keeps the incumbent deterministic.
	ps2 := NewProtocolSpec("Test")
	ps2.AddSample(1, "C2S", []byte(`{"hello":1}`))
	ps2.AddSample(2, "C2S", pb)
	if ps2.Format != FormatJSON {
		t.Errorf("tie should keep incumbent JSON, got %s", ps2.Format)
	}
}
