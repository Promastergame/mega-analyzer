package simdleb

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// encodeULEB128 produces the canonical ULEB128 encoding of v.
// Uses the standard byte-at-a-time emit loop; not optimized — the
// tests that drive the decoder ultimately cap out below 1ms.
func encodeULEB128(v uint32) []byte {
	var buf []byte
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v == 0 {
			buf = append(buf, b)
			return buf
		}
		buf = append(buf, b|0x80)
	}
}

func encodeBatch(values []uint32) []byte {
	var out []byte
	for _, v := range values {
		out = append(out, encodeULEB128(v)...)
	}
	return out
}

func TestDecodeMatchesGo_KnownValues(t *testing.T) {
	cases := [][]uint32{
		{0},
		{1},
		{0x7F},             // 1-byte boundary
		{0x80},             // 2-byte
		{0x3FFF},           // 2-byte boundary
		{0x4000},           // 3-byte
		{0x1FFFFF},         // 3-byte boundary
		{0x200000},         // 4-byte
		{0x0FFFFFFF},       // 4-byte boundary
		{0x10000000},       // 5-byte
		{0xFFFFFFFF},       // 5-byte max
		{0, 1, 2, 3, 4, 5}, // tiny stream
		{0, 0x7F, 0x80, 0x3FFF, 0x4000, 0xDEADBEEF},
	}

	for i, vals := range cases {
		buf := encodeBatch(vals)
		gotASM, nASM := Decode(buf, uint32(len(vals)))
		gotGo, nGo := DecodeGo(buf, uint32(len(vals)))

		if nASM != nGo {
			t.Fatalf("case %d: consumed bytes diverge: asm=%d go=%d (input=%v)", i, nASM, nGo, vals)
		}
		if len(gotASM) != len(gotGo) {
			t.Fatalf("case %d: result length diverges: asm=%d go=%d", i, len(gotASM), len(gotGo))
		}
		for j := range gotGo {
			if gotASM[j] != gotGo[j] {
				t.Fatalf("case %d, val %d: asm=%d go=%d (expected %d)", i, j, gotASM[j], gotGo[j], vals[j])
			}
		}
	}
}

func TestDecodeMatchesGo_RandomFuzz(t *testing.T) {
	// Pseudo-random fuzz against the Go reference. Seeded so failures
	// are reproducible without `-race -count=N` runs.
	rng := rand.New(rand.NewSource(1))

	for trial := 0; trial < 200; trial++ {
		count := rng.Intn(64) + 1
		values := make([]uint32, count)
		for i := range values {
			// Mix of small + huge values so we hit every byte length.
			switch rng.Intn(4) {
			case 0:
				values[i] = uint32(rng.Intn(0x80))
			case 1:
				values[i] = uint32(rng.Intn(0x4000))
			case 2:
				values[i] = uint32(rng.Intn(0x200000))
			default:
				values[i] = rng.Uint32()
			}
		}
		buf := encodeBatch(values)

		gotASM, nASM := Decode(buf, uint32(count))
		gotGo, nGo := DecodeGo(buf, uint32(count))

		if nASM != nGo || len(gotASM) != len(gotGo) {
			t.Fatalf("trial %d: shape diverges (asm=%d/%d go=%d/%d)",
				trial, nASM, len(gotASM), nGo, len(gotGo))
		}
		for i := range gotGo {
			if gotASM[i] != gotGo[i] {
				t.Fatalf("trial %d, val %d: asm=%d go=%d (input=%d)",
					trial, i, gotASM[i], gotGo[i], values[i])
			}
		}
	}
}

func TestDecodeTruncatedInput(t *testing.T) {
	// Encode 5 values, then trim mid-byte so the second value is
	// incomplete. Both decoders must agree on where they bailed out.
	values := []uint32{0x12, 0xCAFEBABE, 0x42, 0xDEADBEEF, 0x99}
	buf := encodeBatch(values)
	truncated := buf[:len(buf)-3]

	gotASM, nASM := Decode(truncated, uint32(len(values)))
	gotGo, nGo := DecodeGo(truncated, uint32(len(values)))

	if nASM != nGo {
		t.Fatalf("truncation consumed mismatch: asm=%d go=%d", nASM, nGo)
	}
	if len(gotASM) != len(gotGo) {
		t.Fatalf("truncation length mismatch: asm=%d go=%d", len(gotASM), len(gotGo))
	}
	for i := range gotGo {
		if gotASM[i] != gotGo[i] {
			t.Fatalf("truncation val %d: asm=%d go=%d", i, gotASM[i], gotGo[i])
		}
	}
}

func TestDecodeOverflowGuard(t *testing.T) {
	// 6 continuation bytes in a row → ULEB128 wider than 5 bytes →
	// both decoders must refuse and return early.
	buf := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}

	_, nASM := Decode(buf, 1)
	_, nGo := DecodeGo(buf, 1)

	if nASM != nGo {
		t.Fatalf("overflow consumed bytes diverge: asm=%d go=%d", nASM, nGo)
	}
}

func TestDecodeEmpty(t *testing.T) {
	_, n := Decode(nil, 5)
	if n != 0 {
		t.Fatalf("expected 0 consumed for nil input, got %d", n)
	}

	_, n = Decode([]byte{0x42}, 0)
	if n != 0 {
		t.Fatalf("expected 0 consumed for count=0, got %d", n)
	}
}

// ─── Benchmarks ─────────────────────────────────────────────────

func benchmarkBuffer(n int, seed int64) ([]byte, uint32) {
	rng := rand.New(rand.NewSource(seed))
	values := make([]uint32, n)
	for i := range values {
		values[i] = rng.Uint32() & 0xFFFFFF // 1–4 byte ULEB128 (typical DEX range)
	}
	return encodeBatch(values), uint32(n)
}

func BenchmarkDecodeASM(b *testing.B) {
	buf, count := benchmarkBuffer(4096, 7)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decode(buf, count)
	}
}

func BenchmarkDecodeGo(b *testing.B) {
	buf, count := benchmarkBuffer(4096, 7)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeGo(buf, count)
	}
}

// Sanity check that the encoder we use in tests is reversible when
// fed back through the standard library `binary.Uvarint`. This catches
// any encoder typo before it can mask a real decode bug.
func TestEncodeULEB128MatchesUvarint(t *testing.T) {
	for _, v := range []uint32{0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0xCAFEBABE, 0xFFFFFFFF} {
		buf := encodeULEB128(v)
		got, n := binary.Uvarint(buf)
		if n != len(buf) || got != uint64(v) {
			t.Fatalf("encodeULEB128(%d) → %x → uvarint=%d (n=%d)", v, buf, got, n)
		}
	}
}
