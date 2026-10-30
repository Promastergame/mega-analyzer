package netproxy

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestMsgPack_RoundTrip_Simple(t *testing.T) {
	cases := []struct {
		name string
		val  any
	}{
		{"nil", nil},
		{"true", true},
		{"false", false},
		{"zero", int64(0)},
		{"positive fixint", int64(42)},
		{"negative fixint", int64(-1)},
		{"int8", int64(-100)},
		{"int64 large", int64(1<<32 + 1)},
		{"float64", float64(3.14)},
		{"empty string", ""},
		{"short string", "hello"},
		{"empty slice", []byte{}},
		{"bytes", []byte{0x01, 0x02, 0x03}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			encoded, err := MarshalMsgPack(c.val)
			if err != nil {
				t.Fatalf("MarshalMsgPack(%v): %v", c.val, err)
			}
			decoded, err := UnmarshalMsgPack(encoded)
			if err != nil {
				t.Fatalf("UnmarshalMsgPack: %v (encoded: %x)", err, encoded)
			}
			switch exp := c.val.(type) {
			case nil:
				if decoded != nil {
					t.Errorf("nil round trip got %v", decoded)
				}
			case bool:
				if decoded != exp {
					t.Errorf("bool: got %v, want %v", decoded, exp)
				}
			case int64:
				if decoded != exp {
					t.Errorf("int64: got %v (%T), want %v", decoded, decoded, exp)
				}
			case float64:
				if math.Abs(decoded.(float64)-exp) > 1e-10 {
					t.Errorf("float64: got %v, want %v", decoded, exp)
				}
			case string:
				if decoded != exp {
					t.Errorf("string: got %q, want %q", decoded, exp)
				}
			}
		})
	}
}

func TestMsgPack_RoundTrip_Array(t *testing.T) {
	arr := []any{int64(1), "hello", true, nil}
	encoded, err := MarshalMsgPack(arr)
	if err != nil {
		t.Fatalf("MarshalMsgPack array: %v", err)
	}
	decoded, err := UnmarshalMsgPack(encoded)
	if err != nil {
		t.Fatalf("UnmarshalMsgPack array: %v", err)
	}
	result, ok := decoded.([]any)
	if !ok {
		t.Fatalf("expected []any, got %T", decoded)
	}
	if len(result) != 4 {
		t.Errorf("expected 4 elements, got %d", len(result))
	}
}

func TestMsgPack_RoundTrip_Map(t *testing.T) {
	m := map[string]any{
		"key1": int64(100),
		"key2": "value",
		"key3": false,
	}
	encoded, err := MarshalMsgPack(m)
	if err != nil {
		t.Fatalf("MarshalMsgPack map: %v", err)
	}
	decoded, err := UnmarshalMsgPack(encoded)
	if err != nil {
		t.Fatalf("UnmarshalMsgPack map: %v", err)
	}
	result, ok := decoded.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", decoded)
	}
	if len(result) != 3 {
		t.Errorf("expected 3 keys, got %d", len(result))
	}
	if result["key1"] != int64(100) {
		t.Errorf("key1 = %v, want 100", result["key1"])
	}
}

func TestUnmarshalMsgPack_Empty(t *testing.T) {
	_, err := UnmarshalMsgPack([]byte{})
	if err == nil {
		t.Error("empty data should error")
	}
}

func TestUnmarshalMsgPack_TrailingBytes(t *testing.T) {
	_, err := UnmarshalMsgPack([]byte{0xc3, 0xc3}) // true + extra byte
	if err == nil {
		t.Error("trailing bytes should error")
	}
}

func TestUnmarshalMsgPack_PositiveFixInt(t *testing.T) {
	v, err := UnmarshalMsgPack([]byte{0x7f}) // 127
	if err != nil {
		t.Fatalf("positive fixint: %v", err)
	}
	if v != int64(127) {
		t.Errorf("got %v, want 127", v)
	}
}

func TestUnmarshalMsgPack_NegativeFixInt(t *testing.T) {
	v, err := UnmarshalMsgPack([]byte{0xff}) // -1
	if err != nil {
		t.Fatalf("negative fixint: %v", err)
	}
	if v != int64(-1) {
		t.Errorf("got %v, want -1", v)
	}
}

func TestUnmarshalMsgPack_FixStr(t *testing.T) {
	// fixstr "hi" = 0xa2 'h' 'i'
	v, err := UnmarshalMsgPack([]byte{0xa2, 'h', 'i'})
	if err != nil {
		t.Fatalf("fixstr: %v", err)
	}
	if v != "hi" {
		t.Errorf("got %q, want 'hi'", v)
	}
}

func TestUnmarshalMsgPack_FixStr_Truncated(t *testing.T) {
	_, err := UnmarshalMsgPack([]byte{0xa3, 'h', 'i'}) // says 3 bytes but only 2
	if err == nil {
		t.Error("truncated fixstr should error")
	}
}

func TestUnmarshalMsgPack_Uint8(t *testing.T) {
	v, err := UnmarshalMsgPack([]byte{0xcc, 200})
	if err != nil {
		t.Fatalf("uint8: %v", err)
	}
	if v != int64(200) {
		t.Errorf("got %v, want 200", v)
	}
}

func TestUnmarshalMsgPack_Uint16(t *testing.T) {
	data := []byte{0xcd, 0x01, 0x00} // 256
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("uint16: %v", err)
	}
	if v != int64(256) {
		t.Errorf("got %v, want 256", v)
	}
}

func TestUnmarshalMsgPack_Uint32(t *testing.T) {
	data := []byte{0xce, 0, 0, 0x01, 0x00} // 256
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("uint32: %v", err)
	}
	if v != int64(256) {
		t.Errorf("got %v, want 256", v)
	}
}

func TestUnmarshalMsgPack_Uint64(t *testing.T) {
	data := make([]byte, 9)
	data[0] = 0xcf
	binary.BigEndian.PutUint64(data[1:], 12345678)
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("uint64: %v", err)
	}
	if v != int64(12345678) {
		t.Errorf("got %v, want 12345678", v)
	}
}

func TestUnmarshalMsgPack_Int8(t *testing.T) {
	v, err := UnmarshalMsgPack([]byte{0xd0, 0x80}) // -128
	if err != nil {
		t.Fatalf("int8: %v", err)
	}
	if v != int64(-128) {
		t.Errorf("got %v, want -128", v)
	}
}

func TestUnmarshalMsgPack_Int16(t *testing.T) {
	data := []byte{0xd1, 0xff, 0x00} // -256
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("int16: %v", err)
	}
	if v != int64(-256) {
		t.Errorf("got %v, want -256", v)
	}
}

func TestUnmarshalMsgPack_Int32(t *testing.T) {
	data := []byte{0xd2, 0xff, 0xff, 0xff, 0x00}
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("int32: %v", err)
	}
	_ = v
}

func TestUnmarshalMsgPack_Int64(t *testing.T) {
	data := make([]byte, 9)
	data[0] = 0xd3
	var negVal int64 = -12345
	binary.BigEndian.PutUint64(data[1:], uint64(negVal))
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("int64: %v", err)
	}
	if v != negVal {
		t.Errorf("got %v, want -12345", v)
	}
}

func TestUnmarshalMsgPack_Float32(t *testing.T) {
	data := make([]byte, 5)
	data[0] = 0xca
	binary.BigEndian.PutUint32(data[1:], math.Float32bits(3.14))
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("float32: %v", err)
	}
	_ = v.(float64)
}

func TestUnmarshalMsgPack_Float64(t *testing.T) {
	data := make([]byte, 9)
	data[0] = 0xcb
	binary.BigEndian.PutUint64(data[1:], math.Float64bits(3.14159))
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("float64: %v", err)
	}
	if math.Abs(v.(float64)-3.14159) > 1e-10 {
		t.Errorf("got %v, want 3.14159", v)
	}
}

func TestUnmarshalMsgPack_Str8(t *testing.T) {
	data := []byte{0xd9, 3, 'a', 'b', 'c'}
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("str8: %v", err)
	}
	if v != "abc" {
		t.Errorf("got %q, want abc", v)
	}
}

func TestUnmarshalMsgPack_Str16(t *testing.T) {
	msg := "hello world"
	data := make([]byte, 3+len(msg))
	data[0] = 0xda
	binary.BigEndian.PutUint16(data[1:], uint16(len(msg)))
	copy(data[3:], msg)
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("str16: %v", err)
	}
	if v != msg {
		t.Errorf("got %q, want %q", v, msg)
	}
}

func TestUnmarshalMsgPack_Str32(t *testing.T) {
	msg := "test"
	data := make([]byte, 5+len(msg))
	data[0] = 0xdb
	binary.BigEndian.PutUint32(data[1:], uint32(len(msg)))
	copy(data[5:], msg)
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("str32: %v", err)
	}
	if v != msg {
		t.Errorf("got %q, want %q", v, msg)
	}
}

func TestUnmarshalMsgPack_Bin8(t *testing.T) {
	data := []byte{0xc4, 3, 0xAA, 0xBB, 0xCC}
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("bin8: %v", err)
	}
	b := v.([]byte)
	if len(b) != 3 || b[0] != 0xAA {
		t.Errorf("bin8 wrong: %v", b)
	}
}

func TestUnmarshalMsgPack_Bin16(t *testing.T) {
	data := []byte{0xc5, 0x00, 0x02, 0x01, 0x02}
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("bin16: %v", err)
	}
	b := v.([]byte)
	if len(b) != 2 {
		t.Errorf("bin16 wrong len: %d", len(b))
	}
}

func TestUnmarshalMsgPack_Bin32(t *testing.T) {
	data := []byte{0xc6, 0x00, 0x00, 0x00, 0x02, 0x01, 0x02}
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("bin32: %v", err)
	}
	b := v.([]byte)
	if len(b) != 2 {
		t.Errorf("bin32 wrong len: %d", len(b))
	}
}

func TestUnmarshalMsgPack_Array16(t *testing.T) {
	// array16 with 2 items: [1, 2]
	data := []byte{0xdc, 0x00, 0x02, 0x01, 0x02}
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("array16: %v", err)
	}
	arr := v.([]any)
	if len(arr) != 2 {
		t.Errorf("array16 len = %d, want 2", len(arr))
	}
}

func TestUnmarshalMsgPack_Map16(t *testing.T) {
	// map16 with 1 entry: {"x": 1}
	// key: fixstr "x" = 0xa1 'x'
	// val: fixint 1 = 0x01
	data := []byte{0xde, 0x00, 0x01, 0xa1, 'x', 0x01}
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("map16: %v", err)
	}
	m := v.(map[string]any)
	if m["x"] != int64(1) {
		t.Errorf("map16 key 'x' = %v, want 1", m["x"])
	}
}

func TestUnmarshalMsgPack_Map32(t *testing.T) {
	// map32 with 1 entry: {"y": true}
	data := []byte{0xdf, 0x00, 0x00, 0x00, 0x01, 0xa1, 'y', 0xc3}
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("map32: %v", err)
	}
	m := v.(map[string]any)
	if m["y"] != true {
		t.Errorf("map32 key 'y' = %v, want true", m["y"])
	}
}

func TestUnmarshalMsgPack_Array32(t *testing.T) {
	// array32 with 1 item: [42]
	data := []byte{0xdd, 0x00, 0x00, 0x00, 0x01, 0x2a}
	v, err := UnmarshalMsgPack(data)
	if err != nil {
		t.Fatalf("array32: %v", err)
	}
	arr := v.([]any)
	if len(arr) != 1 || arr[0] != int64(42) {
		t.Errorf("array32: %v", arr)
	}
}

func TestUnmarshalMsgPack_Unsupported(t *testing.T) {
	// 0xc1 is a never-used/reserved byte
	_, err := UnmarshalMsgPack([]byte{0xc1})
	if err == nil {
		t.Error("unsupported byte should error")
	}
}

func TestMarshalMsgPack_UnsupportedType(t *testing.T) {
	_, err := MarshalMsgPack(struct{}{})
	if err == nil {
		t.Error("unsupported type should error")
	}
}

func TestMarshalMsgPack_LargeString(t *testing.T) {
	// String > 31 bytes needs str8/str16
	s := "this is a longer string that exceeds 31 characters easily"
	encoded, err := MarshalMsgPack(s)
	if err != nil {
		t.Fatalf("MarshalMsgPack large string: %v", err)
	}
	decoded, err := UnmarshalMsgPack(encoded)
	if err != nil {
		t.Fatalf("UnmarshalMsgPack large string: %v", err)
	}
	if decoded != s {
		t.Errorf("got %q, want %q", decoded, s)
	}
}

func TestMarshalMsgPack_NegativeInt(t *testing.T) {
	cases := []int64{-1, -32, -33, -128, -129, -32768, -1 << 31, -(1 << 31) - 1}
	for _, v := range cases {
		encoded, err := MarshalMsgPack(v)
		if err != nil {
			t.Errorf("MarshalMsgPack(%d): %v", v, err)
			continue
		}
		decoded, err := UnmarshalMsgPack(encoded)
		if err != nil {
			t.Errorf("UnmarshalMsgPack(%d): %v (encoded: %x)", v, err, encoded)
			continue
		}
		if decoded != v {
			t.Errorf("negative int %d round trip: got %v", v, decoded)
		}
	}
}

func TestMarshalMsgPack_IntSizes(t *testing.T) {
	// Cover different encoding branches for positive ints
	cases := []int64{0, 127, 128, 255, 256, 65535, 65536, 1<<31 - 1, 1 << 31}
	for _, v := range cases {
		encoded, err := MarshalMsgPack(v)
		if err != nil {
			t.Fatalf("MarshalMsgPack(%d): %v", v, err)
		}
		decoded, err := UnmarshalMsgPack(encoded)
		if err != nil {
			t.Fatalf("UnmarshalMsgPack(%d): %v", v, err)
		}
		if decoded != v {
			t.Errorf("int %d round trip: got %v", v, decoded)
		}
	}
}

func TestMarshalMsgPack_Int_Type(t *testing.T) {
	// Test int (not int64) input
	encoded, err := MarshalMsgPack(int(42))
	if err != nil {
		t.Fatalf("MarshalMsgPack(int): %v", err)
	}
	decoded, err := UnmarshalMsgPack(encoded)
	if err != nil {
		t.Fatalf("UnmarshalMsgPack(int): %v", err)
	}
	if decoded != int64(42) {
		t.Errorf("int: got %v, want 42", decoded)
	}
}

func TestMarshalMsgPack_Bytes(t *testing.T) {
	b := []byte{0x00, 0xFF, 0x42}
	encoded, err := MarshalMsgPack(b)
	if err != nil {
		t.Fatalf("MarshalMsgPack bytes: %v", err)
	}
	decoded, err := UnmarshalMsgPack(encoded)
	if err != nil {
		t.Fatalf("UnmarshalMsgPack bytes: %v", err)
	}
	result := decoded.([]byte)
	if len(result) != 3 || result[1] != 0xFF {
		t.Errorf("bytes round trip failed: %v", result)
	}
}

func TestMarshalMsgPack_NestedStructure(t *testing.T) {
	data := map[string]any{
		"users": []any{
			map[string]any{"name": "alice", "age": int64(30)},
			map[string]any{"name": "bob", "age": int64(25)},
		},
		"count": int64(2),
	}
	encoded, err := MarshalMsgPack(data)
	if err != nil {
		t.Fatalf("nested marshal: %v", err)
	}
	decoded, err := UnmarshalMsgPack(encoded)
	if err != nil {
		t.Fatalf("nested unmarshal: %v", err)
	}
	m := decoded.(map[string]any)
	if m["count"] != int64(2) {
		t.Errorf("nested count: %v", m["count"])
	}
}
