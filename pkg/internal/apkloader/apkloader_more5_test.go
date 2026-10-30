package apkloader

import (
	"testing"
)

// ─── DEXParser.IsLazyMode ──────────────────────────────────────────────────────

func TestDEXParser_IsLazyMode_Disabled(t *testing.T) {
	p := &DEXParser{lazyCode: false}
	if p.IsLazyMode() {
		t.Error("expected lazyCode=false")
	}
}

func TestDEXParser_IsLazyMode_Enabled_More(t *testing.T) {
	p := &DEXParser{lazyCode: true}
	if !p.IsLazyMode() {
		t.Error("expected lazyCode=true")
	}
}

// ─── isASCII helper function ───────────────────────────────────────────────────

func TestIsASCII_AllASCII_Text(t *testing.T) {
	if !isASCII([]byte("hello world")) {
		t.Error("expected ASCII for simple text")
	}
}

func TestIsASCII_WithNumbers_More(t *testing.T) {
	if !isASCII([]byte("test123")) {
		t.Error("expected ASCII for text with numbers")
	}
}

func TestIsASCII_WithSpecial_More(t *testing.T) {
	if !isASCII([]byte("foo@bar.com")) {
		t.Error("expected ASCII for email-like string")
	}
}

func TestIsASCII_Empty_More(t *testing.T) {
	if !isASCII([]byte{}) {
		t.Error("expected empty to be ASCII")
	}
}

func TestIsASCII_NonASCII_Bytes(t *testing.T) {
	if isASCII([]byte{0xFF, 0xFE}) {
		t.Error("expected non-ASCII bytes to fail")
	}
}

func TestIsASCII_HighByte_More(t *testing.T) {
	if isASCII([]byte("hello\x80world")) {
		t.Error("expected high byte to fail ASCII test")
	}
}

func TestIsASCII_OnlyHighBytes(t *testing.T) {
	if isASCII([]byte{0x80, 0x81, 0x82}) {
		t.Error("expected all high bytes to fail")
	}
}

func TestIsASCII_MixedWithControl(t *testing.T) {
	if !isASCII([]byte("hello\nworld")) {
		t.Error("expected control chars to be ASCII")
	}
}

func TestIsASCII_PrintableASCII(t *testing.T) {
	if !isASCII([]byte("!@#$%^&*()")) {
		t.Error("expected ASCII for printable symbols")
	}
}

// ─── DEXParser.GetMetrics (note: metrics are computed, not directly from counts)

func TestDEXParser_GetMetrics_Valid(t *testing.T) {
	p := &DEXParser{}
	metrics := p.GetMetrics()
	// Metrics returns a valid structure; values depend on internal state
	if metrics.ParseDuration < 0 {
		t.Error("expected non-negative duration")
	}
}

// ─── leU16 and leU32 helpers ───────────────────────────────────────────────────

func TestLeU16_Basic(t *testing.T) {
	data := []byte{0x12, 0x34}
	result := leU16(data, 0)
	if result != 0x3412 {
		t.Errorf("expected 0x3412, got 0x%x", result)
	}
}

func TestLeU16_MidBuffer(t *testing.T) {
	data := []byte{0xFF, 0xFF, 0x12, 0x34, 0xFF}
	result := leU16(data, 2)
	if result != 0x3412 {
		t.Errorf("expected 0x3412, got 0x%x", result)
	}
}

func TestLeU32_Basic(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56, 0x78}
	result := leU32(data, 0)
	if result != 0x78563412 {
		t.Errorf("expected 0x78563412, got 0x%x", result)
	}
}

func TestLeU32_MidBuffer(t *testing.T) {
	data := []byte{0xFF, 0xFF, 0x12, 0x34, 0x56, 0x78, 0xFF}
	result := leU32(data, 2)
	if result != 0x78563412 {
		t.Errorf("expected 0x78563412, got 0x%x", result)
	}
}

// ─── DEXParser bounds checking ─────────────────────────────────────────────────

func TestDEXParser_BoundsOK_Valid(t *testing.T) {
	p := &DEXParser{data: make([]byte, 1000)}
	if !p.boundsOK(0, 100) {
		t.Error("expected bounds check to pass for valid range")
	}
}

func TestDEXParser_BoundsOK_EndBoundary(t *testing.T) {
	p := &DEXParser{data: make([]byte, 1000)}
	if !p.boundsOK(900, 100) {
		t.Error("expected bounds check to pass at end boundary")
	}
}

func TestDEXParser_BoundsOK_Overflow(t *testing.T) {
	p := &DEXParser{data: make([]byte, 1000)}
	if p.boundsOK(900, 150) {
		t.Error("expected bounds check to fail on overflow")
	}
}

func TestDEXParser_BoundsOK_Empty(t *testing.T) {
	p := &DEXParser{data: make([]byte, 1000)}
	if !p.boundsOK(500, 0) {
		t.Error("expected bounds check to pass for zero size")
	}
}

func TestDEXParser_BoundsOK64_Valid(t *testing.T) {
	p := &DEXParser{data: make([]byte, 1000)}
	if !p.boundsOK64(0, 100) {
		t.Error("expected 64-bit bounds check to pass")
	}
}

func TestDEXParser_BoundsOK64_Large(t *testing.T) {
	p := &DEXParser{data: make([]byte, 1000000)}
	if !p.boundsOK64(0, uint64(1000000)) {
		t.Error("expected 64-bit bounds check to pass for exact size")
	}
}

func TestDEXParser_BoundsOK64_Overflow(t *testing.T) {
	p := &DEXParser{data: make([]byte, 1000)}
	if p.boundsOK64(999, 2) {
		t.Error("expected 64-bit bounds check to fail on overflow")
	}
}

// ─── Method/Field count consistency ────────────────────────────────────────────

func TestDEXParser_Counts_Consistency(t *testing.T) {
	methods := []*Method{
		{MethodName: "m1"},
		{MethodName: "m2"},
		{MethodName: "m3"},
	}
	fields := []*Field{
		{FieldName: "f1"},
		{FieldName: "f2"},
	}
	p := &DEXParser{
		methods: methods,
		fields:  fields,
	}
	if p.GetMethodCount() != 3 {
		t.Errorf("method count mismatch")
	}
	if p.GetFieldCount() != 2 {
		t.Errorf("field count mismatch")
	}
	if len(p.GetMethods()) != p.GetMethodCount() {
		t.Errorf("GetMethods length should match count")
	}
	if len(p.GetFields()) != p.GetFieldCount() {
		t.Errorf("GetFields length should match count")
	}
}
