package netproxy

import (
	"encoding/binary"
	"testing"
)

// ─── encodeString helper ───────────────────────────────────────────────────

func TestEncodeString_Short_More(t *testing.T) {
	str := "hi"
	result := encodeString(str)
	if len(result) != 3 {
		t.Errorf("expected length 3, got %d", len(result))
	}
	if result[0] != (0xa0 | 2) {
		t.Errorf("expected fixstr header 0xa2, got 0x%x", result[0])
	}
}

func TestEncodeString_Empty_More(t *testing.T) {
	result := encodeString("")
	if len(result) != 1 {
		t.Errorf("expected length 1 for empty string, got %d", len(result))
	}
	if result[0] != 0xa0 {
		t.Errorf("expected 0xa0, got 0x%x", result[0])
	}
}

func TestEncodeString_Max31_More(t *testing.T) {
	str := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 31 chars
	result := encodeString(str)
	if result[0] != (0xa0 | 31) {
		t.Errorf("expected 0xbf (0xa0|31), got 0x%x", result[0])
	}
}

func TestEncodeString_Str8_More(t *testing.T) {
	str := string(make([]byte, 32))
	result := encodeString(str)
	if result[0] != 0xd9 {
		t.Errorf("expected str8 marker 0xd9, got 0x%x", result[0])
	}
	if result[1] != 32 {
		t.Errorf("expected length 32, got %d", result[1])
	}
}

func TestEncodeString_Str16_More(t *testing.T) {
	str := string(make([]byte, 256))
	result := encodeString(str)
	if result[0] != 0xda {
		t.Errorf("expected str16 marker 0xda, got 0x%x", result[0])
	}
	len16 := binary.BigEndian.Uint16(result[1:3])
	if len16 != 256 {
		t.Errorf("expected length 256, got %d", len16)
	}
}

func TestEncodeString_Str32_More(t *testing.T) {
	str := string(make([]byte, 65536))
	result := encodeString(str)
	if result[0] != 0xdb {
		t.Errorf("expected str32 marker 0xdb, got 0x%x", result[0])
	}
	len32 := binary.BigEndian.Uint32(result[1:5])
	if len32 != 65536 {
		t.Errorf("expected length 65536, got %d", len32)
	}
}

// ─── encodeBin helper ──────────────────────────────────────────────────────

func TestEncodeBin_Short_More(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	result := encodeBin(data)
	if result[0] != 0xc4 {
		t.Errorf("expected bin8 marker 0xc4, got 0x%x", result[0])
	}
	if result[1] != 3 {
		t.Errorf("expected length 3, got %d", result[1])
	}
}

func TestEncodeBin_Bin8Max_More(t *testing.T) {
	data := make([]byte, 255)
	result := encodeBin(data)
	if result[0] != 0xc4 {
		t.Errorf("expected bin8 marker, got 0x%x", result[0])
	}
	if result[1] != 255 {
		t.Errorf("expected length 255, got %d", result[1])
	}
}

func TestEncodeBin_Bin16_More(t *testing.T) {
	data := make([]byte, 256)
	result := encodeBin(data)
	if result[0] != 0xc5 {
		t.Errorf("expected bin16 marker 0xc5, got 0x%x", result[0])
	}
	len16 := binary.BigEndian.Uint16(result[1:3])
	if len16 != 256 {
		t.Errorf("expected length 256, got %d", len16)
	}
}

func TestEncodeBin_Bin32_More(t *testing.T) {
	data := make([]byte, 65536)
	result := encodeBin(data)
	if result[0] != 0xc6 {
		t.Errorf("expected bin32 marker 0xc6, got 0x%x", result[0])
	}
	len32 := binary.BigEndian.Uint32(result[1:5])
	if len32 != 65536 {
		t.Errorf("expected length 65536, got %d", len32)
	}
}

// ─── encodeMap helper ──────────────────────────────────────────────────────

func TestEncodeMap_Empty_More(t *testing.T) {
	m := map[string]any{}
	result, err := encodeMap(m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result[0] != 0x80 {
		t.Errorf("expected fixmap header 0x80, got 0x%x", result[0])
	}
}

func TestEncodeMap_Single_More(t *testing.T) {
	m := map[string]any{
		"key": "value",
	}
	result, err := encodeMap(m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should start with fixmap header or larger map header
	if result[0] < 0x80 || (result[0] > 0x8f && result[0] < 0xde) {
		t.Errorf("expected map header, got 0x%x", result[0])
	}
}

// ─── encodeFloat64 helper ──────────────────────────────────────────────────

func TestEncodeFloat64_Positive_More(t *testing.T) {
	f := 3.14159
	result := encodeFloat64(f)
	if result[0] != 0xcb {
		t.Errorf("expected float64 marker 0xcb, got 0x%x", result[0])
	}
	if len(result) != 9 {
		t.Errorf("expected length 9 (1 byte marker + 8 bytes), got %d", len(result))
	}
}

func TestEncodeFloat64_Negative_More(t *testing.T) {
	f := -2.71828
	result := encodeFloat64(f)
	if result[0] != 0xcb {
		t.Errorf("expected float64 marker 0xcb, got 0x%x", result[0])
	}
	if len(result) != 9 {
		t.Errorf("expected length 9, got %d", len(result))
	}
}

func TestEncodeFloat64_Zero_More(t *testing.T) {
	f := 0.0
	result := encodeFloat64(f)
	if len(result) != 9 {
		t.Errorf("expected length 9, got %d", len(result))
	}
}

// ─── encodeInt helper ────────────────────────────────────────────────────

func TestEncodeInt_FixintPositive_More(t *testing.T) {
	i := int64(10)
	result := encodeInt(i)
	if result[0] != 10 {
		t.Errorf("expected fixint 10, got %d", result[0])
	}
	if len(result) != 1 {
		t.Errorf("expected length 1, got %d", len(result))
	}
}

func TestEncodeInt_FixintZero_More(t *testing.T) {
	result := encodeInt(0)
	if result[0] != 0 {
		t.Errorf("expected fixint 0, got %d", result[0])
	}
}

func TestEncodeInt_FixintNegative_More(t *testing.T) {
	i := int64(-1)
	result := encodeInt(i)
	if result[0] != 0xff {
		t.Errorf("expected 0xff for -1, got 0x%x", result[0])
	}
}

func TestEncodeInt_Int8_More(t *testing.T) {
	i := int64(-33)
	result := encodeInt(i)
	if result[0] != 0xd0 {
		t.Errorf("expected int8 marker 0xd0, got 0x%x", result[0])
	}
	if len(result) != 2 {
		t.Errorf("expected length 2, got %d", len(result))
	}
}

func TestEncodeInt_Int16_More(t *testing.T) {
	i := int64(300)
	result := encodeInt(i)
	if result[0] != 0xd1 {
		t.Errorf("expected int16 marker 0xd1, got 0x%x", result[0])
	}
	if len(result) != 3 {
		t.Errorf("expected length 3, got %d", len(result))
	}
}

func TestEncodeInt_Int32_More(t *testing.T) {
	i := int64(100000)
	result := encodeInt(i)
	if result[0] != 0xd2 {
		t.Errorf("expected int32 marker 0xd2, got 0x%x", result[0])
	}
	if len(result) != 5 {
		t.Errorf("expected length 5, got %d", len(result))
	}
}

func TestEncodeInt_Int64_More(t *testing.T) {
	i := int64(9223372036854775807)
	result := encodeInt(i)
	if result[0] != 0xd3 {
		t.Errorf("expected int64 marker 0xd3, got 0x%x", result[0])
	}
	if len(result) != 9 {
		t.Errorf("expected length 9, got %d", len(result))
	}
}
