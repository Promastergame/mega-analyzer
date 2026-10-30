package netproxy

import (
	"bytes"
	"testing"
)

// FuzzUnmarshalMsgPack drives the decoder with arbitrary bytes. The decoder
// runs at the MITM periphery on attacker-controlled input, so the only
// acceptable outcomes are (value, nil) or (nil, error) — never a panic, a
// stack overflow, or an OOM. Go's fuzzer will explore malformed headers,
// truncated payloads, and pathological length fields.
func FuzzUnmarshalMsgPack(f *testing.F) {
	// Seed with valid encodings so the fuzzer starts from reachable states.
	seeds := []any{
		nil, true, false, int64(0), int64(-1), int64(1 << 40), "hello",
		[]any{int64(1), "two", true},
		map[string]any{"a": int64(1), "b": []any{"x"}},
	}
	for _, s := range seeds {
		if b, err := MarshalMsgPack(s); err == nil {
			f.Add(b)
		}
	}
	// A few raw adversarial headers.
	f.Add([]byte{0xdd, 0xff, 0xff, 0xff, 0xff}) // array32 claiming ~4B elements
	f.Add([]byte{0xdf, 0xff, 0xff, 0xff, 0xff}) // map32 claiming ~4B pairs
	f.Add([]byte{0xdb, 0x7f, 0xff, 0xff, 0xff}) // str32 claiming ~2GB

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic. Result is ignored; we only care that it terminates
		// cleanly with either a value or an error.
		_, _ = UnmarshalMsgPack(data)
	})
}

func TestUnmarshalMsgPack_DeepNestingRejected(t *testing.T) {
	// Build maxMsgPackDepth+5 nested single-element arrays: 0x91 repeated,
	// then a terminal nil (0xc0).
	var data []byte
	for i := 0; i < maxMsgPackDepth+5; i++ {
		data = append(data, 0x91) // fixarray length 1
	}
	data = append(data, 0xc0) // nil

	_, err := UnmarshalMsgPack(data)
	if err == nil {
		t.Fatalf("expected deep-nesting rejection, got nil error")
	}
}

func TestUnmarshalMsgPack_ArrayLengthAmplificationRejected(t *testing.T) {
	// array32 header claiming 100000 elements but only a few bytes follow.
	data := []byte{0xdd, 0x00, 0x01, 0x86, 0xa0, 0x01, 0x02} // len=100000, then 2 bytes
	_, err := UnmarshalMsgPack(data)
	if err == nil {
		t.Fatalf("expected length-vs-remaining rejection for array32, got nil")
	}
}

func TestUnmarshalMsgPack_MapLengthAmplificationRejected(t *testing.T) {
	// map32 header claiming 100000 pairs but only a couple of bytes follow.
	data := []byte{0xdf, 0x00, 0x01, 0x86, 0xa0, 0x01, 0x02}
	_, err := UnmarshalMsgPack(data)
	if err == nil {
		t.Fatalf("expected length-vs-remaining rejection for map32, got nil")
	}
}

func TestMarshalMsgPack_MapEncodingIsDeterministic(t *testing.T) {
	m := map[string]any{
		"zebra": int64(1), "apple": int64(2), "mango": int64(3),
		"kiwi": int64(4), "banana": int64(5),
	}
	first, err := MarshalMsgPack(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Encode many times; every result must be byte-identical (keys sorted).
	for i := 0; i < 50; i++ {
		got, err := MarshalMsgPack(m)
		if err != nil {
			t.Fatalf("marshal iteration %d: %v", i, err)
		}
		if !bytes.Equal(first, got) {
			t.Fatalf("map encoding is non-deterministic at iteration %d", i)
		}
	}
	// And it must still round-trip.
	back, err := UnmarshalMsgPack(first)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	bm, ok := back.(map[string]any)
	if !ok || len(bm) != len(m) {
		t.Fatalf("round-trip lost data: %v", back)
	}
}
