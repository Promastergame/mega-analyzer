package apkloader

import (
	"testing"
	"unsafe"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — Tests
// ═══════════════════════════════════════════════════════════════════════════════

// ── StringTable Tests ────────────────────────────────────────────────────────

func TestStringTable_BasicAccess(t *testing.T) {
	data := []byte("hello\x00world\x00test\x00")
	st := NewStringTable(3, data)

	st.SetEntry(0, 0, 5)  // "hello"
	st.SetEntry(1, 6, 5)  // "world"
	st.SetEntry(2, 12, 4) // "test"

	// GetView — zero-alloc
	view := st.GetView(0)
	if string(view) != "hello" {
		t.Errorf("GetView(0) = %q, want %q", view, "hello")
	}

	// GetCached — one alloc, then cached
	s := st.GetCached(1)
	if s != "world" {
		t.Errorf("GetCached(1) = %q, want %q", s, "world")
	}
	s2 := st.GetCached(1) // should hit cache
	if s2 != "world" {
		t.Errorf("GetCached(1) second call = %q, want %q", s2, "world")
	}

	// GetCloned — always fresh
	c := st.GetCloned(2)
	if c != "test" {
		t.Errorf("GetCloned(2) = %q, want %q", c, "test")
	}
}

func TestStringTable_OutOfBounds(t *testing.T) {
	st := NewStringTable(2, []byte("ab"))

	if view := st.GetView(99); view != nil {
		t.Errorf("GetView(99) should return nil, got %v", view)
	}
	if s := st.GetCached(99); s != "" {
		t.Errorf("GetCached(99) should return empty, got %q", s)
	}
}

func TestStringTable_EmptyEntry(t *testing.T) {
	st := NewStringTable(1, []byte("data"))
	st.SetEntry(0, 0, 0) // zero length

	if view := st.GetView(0); view != nil {
		t.Errorf("GetView of zero-length should return nil, got %v", view)
	}
	if s := st.GetCached(0); s != "" {
		t.Errorf("GetCached of zero-length should return empty, got %q", s)
	}
}

func TestStringTable_GetUnsafe(t *testing.T) {
	data := []byte("unsafe_string\x00")
	st := NewStringTable(1, data)
	st.SetEntry(0, 0, 13)

	s := st.GetUnsafe(0)
	if s != "unsafe_string" {
		t.Errorf("GetUnsafe(0) = %q, want %q", s, "unsafe_string")
	}
}

func TestStringTable_PrewarmRange(t *testing.T) {
	data := []byte("aaa\x00bbb\x00ccc\x00")
	st := NewStringTable(3, data)
	st.SetEntry(0, 0, 3)
	st.SetEntry(1, 4, 3)
	st.SetEntry(2, 8, 3)

	st.PrewarmRange(0, 3)

	// All should be cached now
	for i := uint32(0); i < 3; i++ {
		s := st.GetCached(i)
		if s == "" {
			t.Errorf("GetCached(%d) empty after prewarm", i)
		}
	}
}

// ── Arena Tests ──────────────────────────────────────────────────────────────

func TestArena_AllocAndReset(t *testing.T) {
	a := NewArena(4096)

	ptr1 := a.Alloc(64)
	if ptr1 == nil {
		t.Fatal("Alloc(64) returned nil")
	}

	ptr2 := a.Alloc(128)
	if ptr2 == nil {
		t.Fatal("Alloc(128) returned nil")
	}

	if a.Used() == 0 {
		t.Error("Used() should be > 0 after allocations")
	}

	a.Reset()
	if a.Used() != 0 {
		t.Errorf("Used() after Reset() = %d, want 0", a.Used())
	}
}

func TestArena_Exhaustion(t *testing.T) {
	a := NewArena(64) // tiny arena

	// This should succeed
	ptr := a.Alloc(32)
	if ptr == nil {
		t.Fatal("first Alloc should succeed")
	}

	// This should fail (not enough space)
	ptr2 := a.Alloc(64)
	if ptr2 != nil {
		t.Error("Alloc beyond capacity should return nil")
	}
}

func TestArena_AllocRawInsn(t *testing.T) {
	a := NewArena(defaultArenaSize)

	insn := a.AllocRawInsn()
	if insn == nil {
		t.Fatal("AllocRawInsn returned nil")
	}

	// Should be zero-initialized
	if insn.Op != 0 || insn.RegCount != 0 || insn.Imm != 0 {
		t.Error("AllocRawInsn should return zero-initialized struct")
	}

	insn.Op = 0x6E
	insn.Flags = FlagInvoke
	if !insn.IsInvoke() {
		t.Error("IsInvoke() should return true after setting flag")
	}
}

func TestArena_AllocRawInsnSlice(t *testing.T) {
	a := NewArena(defaultArenaSize)

	slice := a.AllocRawInsnSlice(100)
	if len(slice) != 100 {
		t.Errorf("AllocRawInsnSlice(100) len = %d, want 100", len(slice))
	}

	// Set one
	slice[50].Op = 0x0E
	slice[50].Flags = FlagReturn
	if !slice[50].IsReturn() {
		t.Error("slice[50].IsReturn() should be true")
	}
}

func TestArena_Pool(t *testing.T) {
	a := GetArena()
	if a == nil {
		t.Fatal("GetArena returned nil")
	}

	// Use it
	insn := a.AllocRawInsn()
	if insn == nil {
		t.Fatal("AllocRawInsn from pooled arena failed")
	}

	// Return it
	PutArena(a)

	// Get another (may be the same one, recycled)
	a2 := GetArena()
	if a2 == nil {
		t.Fatal("second GetArena returned nil")
	}
	if a2.Used() != 0 {
		t.Errorf("recycled arena Used() = %d, want 0", a2.Used())
	}
	PutArena(a2)
}

// ── RawInsn IR Tests ─────────────────────────────────────────────────────────

func TestRawInsn_Size(t *testing.T) {
	// RawInsn should be 32 bytes for cache-line friendliness
	size := unsafe.Sizeof(RawInsn{})
	// Allow up to 48 bytes due to alignment; 32 is ideal
	if size > 48 {
		t.Errorf("RawInsn size = %d bytes, want <= 48", size)
	}
	t.Logf("RawInsn size: %d bytes", size)
}

func TestRawInsn_Flags(t *testing.T) {
	insn := RawInsn{Flags: FlagBranch | FlagThrow}

	if !insn.IsBranch() {
		t.Error("IsBranch should be true")
	}
	if !insn.IsThrow() {
		t.Error("IsThrow should be true")
	}
	if insn.IsInvoke() {
		t.Error("IsInvoke should be false")
	}
	if insn.IsReturn() {
		t.Error("IsReturn should be false")
	}
}

func TestRawInsn_BranchTarget(t *testing.T) {
	insn := RawInsn{
		Offset: 10,
		Imm:    5,
		Flags:  FlagBranch,
	}
	if target := insn.BranchTarget(); target != 15 {
		t.Errorf("BranchTarget() = %d, want 15", target)
	}

	// Backward branch
	insn.Imm = -3
	if target := insn.BranchTarget(); target != 7 {
		t.Errorf("BranchTarget() backward = %d, want 7", target)
	}
}

// ── Decoder Tests ────────────────────────────────────────────────────────────

func TestDecodeMethodIR_Nop(t *testing.T) {
	insns := []uint16{0x0000} // nop
	result := DecodeMethodIR(insns, nil)

	if len(result) != 1 {
		t.Fatalf("expected 1 insn, got %d", len(result))
	}

	insn := result[0]
	if insn.Op != 0x00 {
		t.Errorf("Op = 0x%02x, want 0x00", insn.Op)
	}
	if insn.Size != 1 {
		t.Errorf("Size = %d, want 1", insn.Size)
	}
}

func TestDecodeMethodIR_ReturnVoid(t *testing.T) {
	insns := []uint16{0x000E} // return-void
	result := DecodeMethodIR(insns, nil)

	if len(result) != 1 {
		t.Fatalf("expected 1 insn, got %d", len(result))
	}
	if !result[0].IsReturn() {
		t.Error("return-void should have FlagReturn")
	}
}

func TestDecodeMethodIR_Const4(t *testing.T) {
	// const/4 v0, 1 → opcode=0x12, vA=0, literal=1
	insns := []uint16{0x1012} // nibble layout: [12] [10]
	result := DecodeMethodIR(insns, nil)

	if len(result) != 1 {
		t.Fatalf("expected 1 insn, got %d", len(result))
	}

	insn := result[0]
	if insn.Op != 0x12 {
		t.Errorf("Op = 0x%02x, want 0x12", insn.Op)
	}
	if !insn.IsConst() {
		t.Error("const/4 should have FlagConst")
	}
	if insn.Regs[0] != 0 {
		t.Errorf("Regs[0] = %d, want 0", insn.Regs[0])
	}
	if insn.Imm != 1 {
		t.Errorf("Imm = %d, want 1", insn.Imm)
	}
}

func TestDecodeMethodIR_IfEqz(t *testing.T) {
	// if-eqz v0, +3 → opcode=0x38
	insns := []uint16{0x0038, 0x0003}
	result := DecodeMethodIR(insns, nil)

	if len(result) != 1 {
		t.Fatalf("expected 1 insn, got %d", len(result))
	}

	insn := result[0]
	if insn.Op != 0x38 {
		t.Errorf("Op = 0x%02x, want 0x38", insn.Op)
	}
	if !insn.IsBranch() {
		t.Error("if-eqz should have FlagBranch")
	}
	if insn.Imm != 3 {
		t.Errorf("Imm = %d, want 3", insn.Imm)
	}
	if insn.BranchTarget() != 3 {
		t.Errorf("BranchTarget = %d, want 3", insn.BranchTarget())
	}
}

func TestDecodeMethodIR_InvokeVirtual(t *testing.T) {
	// invoke-virtual {v0, v1}, method@0x0042
	// 35c format: [A|G|op BBBB F|E|D|C]
	// A=2 (arg count), G=0, op=0x6E, BBBB=0x0042
	// C=0 (v0), D=1 (v1), E=0, F=0
	insns := []uint16{
		0x206E, // A=2, op=0x6E
		0x0042, // method@0x0042
		0x0010, // D=1, C=0
	}
	result := DecodeMethodIR(insns, nil)

	if len(result) != 1 {
		t.Fatalf("expected 1 insn, got %d", len(result))
	}

	insn := result[0]
	if insn.Op != 0x6E {
		t.Errorf("Op = 0x%02x, want 0x6E", insn.Op)
	}
	if !insn.IsInvoke() {
		t.Error("invoke-virtual should have FlagInvoke")
	}
	if insn.RefKind != RefMethod {
		t.Errorf("RefKind = %d, want RefMethod", insn.RefKind)
	}
	if insn.RefIdx != 0x0042 {
		t.Errorf("RefIdx = 0x%x, want 0x0042", insn.RefIdx)
	}
	if insn.RegCount != 2 {
		t.Errorf("RegCount = %d, want 2", insn.RegCount)
	}
}

func TestDecodeMethodIR_IgetObject(t *testing.T) {
	// iget-object v0, v1, field@0x0010
	// 22c format: B|A|op CCCC
	insns := []uint16{
		0x1054, // B=1, A=0, op=0x54
		0x0010, // field@0x0010
	}
	result := DecodeMethodIR(insns, nil)

	if len(result) != 1 {
		t.Fatalf("expected 1 insn, got %d", len(result))
	}

	insn := result[0]
	if insn.Op != 0x54 {
		t.Errorf("Op = 0x%02x, want 0x54", insn.Op)
	}
	if !insn.IsFieldOp() {
		t.Error("iget-object should have FlagFieldOp")
	}
	if insn.RefKind != RefField {
		t.Errorf("RefKind = %d, want RefField", insn.RefKind)
	}
}

func TestDecodeMethodIR_MultipleInstructions(t *testing.T) {
	insns := []uint16{
		0x0012, // const/4 v0, 0
		0x000E, // return-void
	}
	result := DecodeMethodIR(insns, nil)

	if len(result) != 2 {
		t.Fatalf("expected 2 insns, got %d", len(result))
	}
	if result[0].Op != 0x12 {
		t.Errorf("insn[0].Op = 0x%02x, want 0x12", result[0].Op)
	}
	if result[1].Op != 0x0E {
		t.Errorf("insn[1].Op = 0x%02x, want 0x0E", result[1].Op)
	}
}

func TestDecodeMethodIR_WithArena(t *testing.T) {
	arena := GetArena()
	defer PutArena(arena)

	insns := []uint16{0x0000, 0x000E} // nop, return-void
	result := DecodeMethodIR(insns, arena)

	if len(result) != 2 {
		t.Fatalf("expected 2 insns with arena, got %d", len(result))
	}
	if result[0].Op != 0x00 || result[1].Op != 0x0E {
		t.Error("arena-backed decoding produced wrong opcodes")
	}
}

func TestDecodeMethodIR_Empty(t *testing.T) {
	result := DecodeMethodIR(nil, nil)
	if result != nil {
		t.Errorf("empty insns should return nil, got %v", result)
	}
}

// ── Benchmarks ───────────────────────────────────────────────────────────────

func BenchmarkDecodeMethodIR_Small(b *testing.B) {
	// Simulate a small method: 10 instructions
	insns := []uint16{
		0x0012,         // const/4 v0, 0
		0x1312, 0x0001, // const/16 v3, 1
		0x0038, 0x0005, // if-eqz v0, +5
		0x206E, 0x0042, 0x0010, // invoke-virtual {v0, v1}, method@0x42
		0x000E, // return-void
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result := DecodeMethodIR(insns, nil)
		_ = result
	}
}

func BenchmarkDecodeMethodIR_WithArena(b *testing.B) {
	insns := []uint16{
		0x0012,
		0x1312, 0x0001,
		0x0038, 0x0005,
		0x206E, 0x0042, 0x0010,
		0x000E,
	}

	arena := GetArena()
	defer PutArena(arena)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		arena.Reset()
		result := DecodeMethodIR(insns, arena)
		_ = result
	}
}

func BenchmarkDecodeMethodIR_Large(b *testing.B) {
	// Simulate a large method: ~1000 instructions
	insns := make([]uint16, 0, 2000)
	for i := 0; i < 500; i++ {
		insns = append(insns, 0x0012)         // const/4
		insns = append(insns, 0x0038, 0x0002) // if-eqz
		insns = append(insns, 0x000E)         // return-void
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result := DecodeMethodIR(insns, nil)
		_ = result
	}
}

func BenchmarkStringTable_GetView(b *testing.B) {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = 'a'
	}
	st := NewStringTable(100, data)
	for i := uint32(0); i < 100; i++ {
		st.SetEntry(i, i*10, 9)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = st.GetView(uint32(i % 100))
	}
}

func BenchmarkStringTable_GetCached(b *testing.B) {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = 'a'
	}
	st := NewStringTable(100, data)
	for i := uint32(0); i < 100; i++ {
		st.SetEntry(i, i*10, 9)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = st.GetCached(uint32(i % 100))
	}
}

func BenchmarkArena_AllocRawInsn(b *testing.B) {
	a := NewArena(defaultArenaSize)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if a.Used() > a.Cap()-256 {
			a.Reset()
		}
		insn := a.AllocRawInsn()
		insn.Op = 0x6E
	}
}
