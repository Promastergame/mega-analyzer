package apkloader

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════
// ТЕСТЫ ДЕКОДИРОВАНИЯ ИНСТРУКЦИЙ
// ═══════════════════════════════════════════

func TestDecodeInsn_NOP(t *testing.T) {
	insns := []uint16{0x0000}
	decoded, size := DecodeInsn(insns, 0, nil, nil)

	if decoded != "nop" {
		t.Errorf("got %q, want %q", decoded, "nop")
	}
	if size != 1 {
		t.Errorf("size = %d, want 1", size)
	}
}

func TestDecodeInsn_Return(t *testing.T) {
	tests := []struct {
		insns    []uint16
		expected string
	}{
		{[]uint16{0x000E}, "return-void"},
		{[]uint16{0x000F}, "return v0"},
		{[]uint16{0x010F}, "return v1"},
		{[]uint16{0x0011}, "return-object v0"},
	}

	for _, tt := range tests {
		decoded, _ := DecodeInsn(tt.insns, 0, nil, nil)
		if decoded != tt.expected {
			t.Errorf("got %q, want %q", decoded, tt.expected)
		}
	}
}

func TestDecodeInsn_Const4(t *testing.T) {
	// const/4 v0, 5
	insns := []uint16{0x5012} // opcode=0x12, vA=0, B=5
	decoded, size := DecodeInsn(insns, 0, nil, nil)

	if !strings.HasPrefix(decoded, "const/4") {
		t.Errorf("got %q, want const/4...", decoded)
	}
	if size != 1 {
		t.Errorf("size = %d, want 1", size)
	}
}

func TestDecodeInsn_Const16(t *testing.T) {
	// const/16 v0, 1000
	insns := []uint16{
		0x0013, // opcode=0x13, vAA=0
		0x03E8, // 1000
	}
	decoded, size := DecodeInsn(insns, 0, nil, nil)

	if decoded != "const/16 v0, 1000" {
		t.Errorf("got %q", decoded)
	}
	if size != 2 {
		t.Errorf("size = %d, want 2", size)
	}
}

func TestDecodeInsn_Move(t *testing.T) {
	// move v1, v2
	insns := []uint16{0x2101} // opcode=0x01, vA=1, vB=2
	decoded, _ := DecodeInsn(insns, 0, nil, nil)

	if decoded != "move v1, v2" {
		t.Errorf("got %q, want %q", decoded, "move v1, v2")
	}
}

func TestDecodeInsn_IfEq(t *testing.T) {
	// if-eq v0, v1, +10
	insns := []uint16{
		0x1032, // opcode=0x32, vA=0, vB=1
		0x000A, // offset=10
	}
	decoded, size := DecodeInsn(insns, 0, nil, nil)

	if decoded != "if-eq v0, v1, +10" {
		t.Errorf("got %q", decoded)
	}
	if size != 2 {
		t.Errorf("size = %d, want 2", size)
	}
}

func TestDecodeInsn_Goto(t *testing.T) {
	tests := []struct {
		name     string
		insns    []uint16
		expected string
		size     uint32
	}{
		{
			"goto +5",
			[]uint16{0x0528},
			"goto +5",
			1,
		},
		{
			"goto -10",
			[]uint16{0xF628}, // -10 в signed byte
			"goto -10",
			1,
		},
		{
			"goto/16 +1000",
			[]uint16{0x0029, 0x03E8},
			"goto/16 +1000",
			2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, size := DecodeInsn(tt.insns, 0, nil, nil)
			if decoded != tt.expected {
				t.Errorf("got %q, want %q", decoded, tt.expected)
			}
			if size != tt.size {
				t.Errorf("size = %d, want %d", size, tt.size)
			}
		})
	}
}

// ═══════════════════════════════════════════
// ТЕСТЫ INVOKE С РЕЗОЛВОМ
// ═══════════════════════════════════════════

func TestDecodeInsn_InvokeWithResolver(t *testing.T) {
	// invoke-virtual {v0}, method@0001
	insns := []uint16{
		0x106E, // opcode=0x6E, A=1 (1 arg),
		0x0001, // method_idx=1
		0x0000, // C=v0
	}

	// Создаём mock resolver
	resolver := &DEXParser{
		methods: []*Method{
			nil, // idx 0
			{ // idx 1
				ClassName:  "Ljava/lang/String;",
				MethodName: "length",
				ReturnType: "I",
				Parameters: nil,
			},
		},
	}

	decoded, _ := DecodeInsn(insns, 0, nil, resolver)

	expected := "invoke-virtual {v0}, Ljava/lang/String;->length()I"
	if decoded != expected {
		t.Errorf("got %q, want %q", decoded, expected)
	}
}

func TestDecodeInsn_InvokeWithoutResolver(t *testing.T) {
	insns := []uint16{0x106E, 0x0001, 0x0000}

	decoded, _ := DecodeInsn(insns, 0, nil, nil)

	// Без resolver должен быть fallback
	if !strings.Contains(decoded, "method@0001") {
		t.Errorf("got %q, expected method@0001", decoded)
	}
}

// ═══════════════════════════════════════════
// ТЕСТЫ PAYLOAD
// ═══════════════════════════════════════════

func TestDecodePackedSwitchPayload(t *testing.T) {
	// packed-switch с 3 targets, first_key=0
	insns := []uint16{
		0x0100,         // ident
		0x0003,         // size=3
		0x0000,         // first_key low
		0x0000,         // first_key high
		0x000A, 0x0000, // target 0: +10
		0x0014, 0x0000, // target 1: +20
		0x001E, 0x0000, // target 2: +30
	}

	decoded, size := decodePackedSwitchPayload(insns, 0)

	if !strings.Contains(decoded, ".packed-switch") {
		t.Errorf("missing .packed-switch: %q", decoded)
	}
	if !strings.Contains(decoded, "+10") {
		t.Errorf("missing target +10: %q", decoded)
	}
	if size != 10 { // 4 header + 3*2 targets
		t.Errorf("size = %d, want 10", size)
	}
}

func TestDecodeSparseSwitchPayload(t *testing.T) {
	// sparse-switch с 2 entries
	insns := []uint16{
		0x0200,         // ident
		0x0002,         // size=2
		0x0001, 0x0000, // key 0: 1
		0x0064, 0x0000, // key 1: 100
		0x000A, 0x0000, // target 0: +10
		0x0014, 0x0000, // target 1: +20
	}

	decoded, size := decodeSparseSwitchPayload(insns, 0)

	if !strings.Contains(decoded, ".sparse-switch") {
		t.Errorf("missing .sparse-switch: %q", decoded)
	}
	if !strings.Contains(decoded, "0x1 ->") {
		t.Errorf("missing key 1: %q", decoded)
	}
	if size != 10 { // 2 header + 2*2 keys + 2*2 targets
		t.Errorf("size = %d, want 10", size)
	}
}

func TestDecodeFillArrayPayload(t *testing.T) {
	// fill-array-data: 4 bytes per element, 2 elements
	insns := []uint16{
		0x0300,         // ident
		0x0004,         // element_width=4
		0x0002, 0x0000, // size=2
		0x1234, 0x5678, // element 0
		0xABCD, 0xEF01, // element 1
	}

	decoded, size := decodeFillArrayPayload(insns, 0)

	if !strings.Contains(decoded, ".array-data 4") {
		t.Errorf("missing .array-data 4: %q", decoded)
	}
	if !strings.Contains(decoded, "0x56781234") {
		t.Errorf("missing element value: %q", decoded)
	}
	if size != 8 { // 4 header + 4 data words
		t.Errorf("size = %d, want 8", size)
	}
}

// ═══════════════════════════════════════════
// ТЕСТЫ PAYLOAD SKIP
// ═══════════════════════════════════════════

func TestDecodeInsn_SkipsPayload(t *testing.T) {
	insns := []uint16{
		0x0000, // nop at 0
		0x0100, // payload ident at 1
		0x0001, // payload data
		0x0000,
		0x0000,
		0x000E, // return-void at 5
	}

	payloads := map[uint32]bool{1: true}

	// Позиция 0 — nop
	d0, s0 := DecodeInsn(insns, 0, payloads, nil)
	if d0 != "nop" {
		t.Errorf("pos 0: got %q", d0)
	}

	// Позиция 1 — payload, должен декодироваться как packed-switch
	d1, s1 := DecodeInsn(insns, 1, payloads, nil)
	if !strings.Contains(d1, ".packed-switch") {
		t.Errorf("pos 1: got %q, want payload", d1)
	}
	_ = s0
	_ = s1
}

// ═══════════════════════════════════════════
// ТЕСТЫ РЕЗОЛВА ССЫЛОК
// ═══════════════════════════════════════════

func TestResolveString(t *testing.T) {
	resolver := &DEXParser{
		strings: []string{"hello", "world"},
	}

	s := resolveString(0, resolver)
	if s != `"hello"` {
		t.Errorf("got %q", s)
	}

	s = resolveString(1, resolver)
	if s != `"world"` {
		t.Errorf("got %q", s)
	}

	// Out of bounds
	s = resolveString(999, resolver)
	if !strings.HasPrefix(s, "string@") {
		t.Errorf("got %q, want string@...", s)
	}

	// Nil resolver
	s = resolveString(0, nil)
	if !strings.HasPrefix(s, "string@") {
		t.Errorf("got %q", s)
	}
}

func TestResolveField(t *testing.T) {
	resolver := &DEXParser{
		fields: []*Field{
			{
				ClassName: "Lcom/test/Test;",
				FieldName: "value",
				TypeName:  "I",
			},
		},
	}

	f := resolveField(0, resolver)
	expected := "Lcom/test/Test;->value:I"
	if f != expected {
		t.Errorf("got %q, want %q", f, expected)
	}
}

func TestResolveMethod(t *testing.T) {
	resolver := &DEXParser{
		methods: []*Method{
			{
				ClassName:  "Ljava/io/PrintStream;",
				MethodName: "println",
				ReturnType: "V",
				Parameters: []string{"Ljava/lang/String;"},
			},
		},
	}

	m := resolveMethod(0, resolver)
	expected := "Ljava/io/PrintStream;->println(Ljava/lang/String;)V"
	if m != expected {
		t.Errorf("got %q, want %q", m, expected)
	}
}

// ═══════════════════════════════════════════
// БЕНЧМАРКИ
// ═══════════════════════════════════════════

func BenchmarkDecodeInsn_Simple(b *testing.B) {
	insns := []uint16{0x000E} // return-void

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeInsn(insns, 0, nil, nil)
	}
}

func BenchmarkDecodeInsn_Invoke(b *testing.B) {
	insns := []uint16{0x106E, 0x0001, 0x0000}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeInsn(insns, 0, nil, nil)
	}
}

func BenchmarkDecodeInsn_InvokeWithResolver(b *testing.B) {
	insns := []uint16{0x106E, 0x0001, 0x0000}
	resolver := &DEXParser{
		methods: []*Method{
			nil,
			{ClassName: "LA;", MethodName: "foo", ReturnType: "V"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeInsn(insns, 0, nil, resolver)
	}
}
