package apkloader

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// DEX BUILDER — fluent API для построения тестовых DEX
// ═══════════════════════════════════════════════════════════════

type dexBuilder struct {
	data []byte
}

func newDEXBuilder() *dexBuilder {
	d := make([]byte, dexHeaderSize)
	b := &dexBuilder{data: d}
	return b.
		setMagic("035").
		setFileSize(dexHeaderSize).
		setHeaderSize(dexHeaderSize).
		setEndianTag(dexEndianTag)
}

func (b *dexBuilder) setMagic(version string) *dexBuilder {
	copy(b.data[0:], "dex\n")
	copy(b.data[4:], version)
	b.data[7] = 0x00
	return b
}

func (b *dexBuilder) setFileSize(sz uint32) *dexBuilder {
	binary.LittleEndian.PutUint32(b.data[32:], sz)
	return b
}

func (b *dexBuilder) setHeaderSize(sz uint32) *dexBuilder {
	binary.LittleEndian.PutUint32(b.data[36:], sz)
	return b
}

func (b *dexBuilder) setEndianTag(tag uint32) *dexBuilder {
	binary.LittleEndian.PutUint32(b.data[40:], tag)
	return b
}

func (b *dexBuilder) setSection(sizeOff, offOff, count, offset uint32) *dexBuilder {
	binary.LittleEndian.PutUint32(b.data[sizeOff:], count)
	binary.LittleEndian.PutUint32(b.data[offOff:], offset)
	return b
}

func (b *dexBuilder) setStringIDs(count, off uint32) *dexBuilder {
	return b.setSection(56, 60, count, off)
}

func (b *dexBuilder) setTypeIDs(count, off uint32) *dexBuilder {
	return b.setSection(64, 68, count, off)
}

func (b *dexBuilder) grow(n int) *dexBuilder {
	b.data = append(b.data, make([]byte, n)...)
	return b
}

func (b *dexBuilder) updateFileSize() *dexBuilder {
	return b.setFileSize(uint32(len(b.data)))
}

func (b *dexBuilder) build() []byte {
	return b.data
}

// makeMinimalDEX создаёт минимальный валидный DEX-файл для тестов.
func makeMinimalDEX() []byte {
	return newDEXBuilder().build()
}

// ═══════════════════════════════════════════════════════════════
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ═══════════════════════════════════════════════════════════════

func requireError(t *testing.T, err error, desc string) {
	t.Helper()
	if err == nil {
		t.Errorf("expected error: %s", desc)
	}
}

func requireNoError(t *testing.T, err error, desc string) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error (%s): %v", desc, err)
	}
}

func requireErrorIs(t *testing.T, err, target error, desc string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %v for: %s", target, desc)
	}
	if !errors.Is(err, target) {
		t.Errorf("error %v does not wrap %v for: %s", err, target, desc)
	}
}

func assertEqual[T comparable](t *testing.T, got, want T, msg string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", msg, got, want)
	}
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ ЗАГОЛОВКА
// ═══════════════════════════════════════════════════════════════

func TestParseDEX_TooSmall(t *testing.T) {
	_, err := ParseDEXBytes([]byte("dex\n035"))
	requireErrorIs(t, err, errDexTooSmall, "too small")
}

func TestParseDEX_BadMagic(t *testing.T) {
	data := make([]byte, dexHeaderSize)
	copy(data, "notdex!!")
	_, err := ParseDEXBytes(data)
	requireErrorIs(t, err, errDexBadMagic, "bad magic")
}

func TestParseDEX_BadEndianTag(t *testing.T) {
	data := newDEXBuilder().setEndianTag(0xDEADBEEF).build()
	_, err := ParseDEXBytes(data)
	requireError(t, err, "bad endian tag")
}

func TestParseDEX_BadHeaderSize(t *testing.T) {
	data := newDEXBuilder().setHeaderSize(0x60).build()
	_, err := ParseDEXBytes(data)
	requireError(t, err, "bad header size")
}

func TestParseDEX_FileSizeExceedsData(t *testing.T) {
	data := newDEXBuilder().setFileSize(0x10000).build()
	_, err := ParseDEXBytes(data)
	requireError(t, err, "file size > data")
}

func TestParseDEX_FileSizeZero(t *testing.T) {
	data := newDEXBuilder().setFileSize(0).build()
	_, err := ParseDEXBytes(data)
	requireError(t, err, "zero file size")
}

func TestParseDEX_MinimalValid(t *testing.T) {
	data := newDEXBuilder().build()
	p, err := ParseDEXBytes(data)
	requireNoError(t, err, "minimal valid DEX")
	assertEqual(t, p.GetVersion(), "035", "version")
	assertEqual(t, p.GetClassCount(), 0, "class count")
	assertEqual(t, p.GetMethodCount(), 0, "method count")
}

func TestParseDEX_Versions(t *testing.T) {
	for _, ver := range []string{"035", "036", "037", "038", "039"} {
		ver := ver
		t.Run(ver, func(t *testing.T) {
			data := newDEXBuilder().setMagic(ver).build()
			p, err := ParseDEXBytes(data)
			requireNoError(t, err, "version "+ver)
			assertEqual(t, p.GetVersion(), ver, "version")
		})
	}
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ ВАЛИДАЦИИ СЕКЦИЙ
// ═══════════════════════════════════════════════════════════════

func TestParseDEX_OverlappingSections(t *testing.T) {
	b := newDEXBuilder().grow(0x100).updateFileSize()
	// string_ids и type_ids на одном offset → перекрытие
	b.setStringIDs(4, 0x80).setTypeIDs(4, 0x80)
	_, err := ParseDEXBytes(b.build())
	requireErrorIs(t, err, errSectionOverlap, "overlapping sections")
}

func TestParseDEX_SectionOutOfBounds(t *testing.T) {
	b := newDEXBuilder()
	b.setStringIDs(1000, 0x60) // далеко за пределами файла
	_, err := ParseDEXBytes(b.build())
	// OOM guard может сработать раньше чем bounds check
	if err == nil {
		t.Error("expected error for section OOB")
	}
	if !errors.Is(err, errSectionOOB) && !errors.Is(err, errCountTooLarge) {
		t.Errorf("expected errSectionOOB or errCountTooLarge, got: %v", err)
	}
}

func TestParseDEX_CountTooLarge(t *testing.T) {
	b := newDEXBuilder().grow(0x100).updateFileSize()
	// count = maxSectionItems+1 → должен отклониться
	b.setStringIDs(maxSectionItems+1, 0x80)
	_, err := ParseDEXBytes(b.build())
	requireErrorIs(t, err, errCountTooLarge, "count too large")
}

func TestParseDEX_CountOOMGuard(t *testing.T) {
	// count * minItemSize > len(data) → OOM guard
	b := newDEXBuilder().grow(0x100).updateFileSize()
	// fileSize = 0x170, count=1000 → 1000*1 > 0x170 → rejected
	b.setStringIDs(1000, 0x80)
	_, err := ParseDEXBytes(b.build())
	requireError(t, err, "OOM guard")
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ КОНТЕКСТА
// ═══════════════════════════════════════════════════════════════

func TestParseDEX_ContextAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	data := newDEXBuilder().build()
	_, err := ParseDEXBytesContext(ctx, data)
	// Маленький файл может успеть — проверяем что не паникует
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("unexpected error type: %v", err)
	}
}

func TestParseDEX_ContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)

	data := newDEXBuilder().build()
	_, _ = ParseDEXBytesContext(ctx, data) // не должно паниковать
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ ULEB128
// ═══════════════════════════════════════════════════════════════

func TestReadULEB128(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantVal uint32
		wantN   int
	}{
		{"zero", []byte{0x00}, 0, 1},
		{"one", []byte{0x01}, 1, 1},
		{"127", []byte{0x7F}, 127, 1},
		{"128", []byte{0x80, 0x01}, 128, 2},
		{"255", []byte{0xFF, 0x01}, 255, 2},
		{"256", []byte{0x80, 0x02}, 256, 2},
		{"16383", []byte{0xFF, 0x7F}, 16383, 2},
		{"16384", []byte{0x80, 0x80, 0x01}, 16384, 3},
		{"max_u32", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}, 0xFFFFFFFF, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &DEXParser{data: tt.data}
			val, n := p.readULEB128At(0)
			assertEqual(t, val, tt.wantVal, "value")
			assertEqual(t, n, tt.wantN, "bytes")
		})
	}
}

func TestReadULEB128_Overflow(t *testing.T) {
	// 6 байт — переполнение (макс 5)
	p := &DEXParser{data: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x01}}
	_, n := p.readULEB128At(0)
	assertEqual(t, n, 0, "overflow must return 0")
}

func TestReadULEB128_Truncated(t *testing.T) {
	// MSB установлен, но данные обрезаны
	p := &DEXParser{data: []byte{0x80}}
	_, n := p.readULEB128At(0)
	assertEqual(t, n, 0, "truncated must return 0")
}

func TestReadULEB128_OffsetBeyondData(t *testing.T) {
	p := &DEXParser{data: []byte{0x01}}
	_, n := p.readULEB128At(10) // offset > len
	assertEqual(t, n, 0, "OOB offset must return 0")
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ SLEB128
// ═══════════════════════════════════════════════════════════════

func TestReadSLEB128(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantVal int32
		wantN   int
	}{
		{"zero", []byte{0x00}, 0, 1},
		{"one", []byte{0x01}, 1, 1},
		{"minus_one", []byte{0x7F}, -1, 1},
		{"63", []byte{0x3F}, 63, 1},
		{"minus_64", []byte{0x40}, -64, 1},
		{"64", []byte{0xC0, 0x00}, 64, 2},
		{"minus_65", []byte{0xBF, 0x7F}, -65, 2},
		{"minus_128", []byte{0x80, 0x7F}, -128, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &DEXParser{data: tt.data}
			val, n := p.readSLEB128At(0)
			assertEqual(t, val, tt.wantVal, "value")
			assertEqual(t, n, tt.wantN, "bytes")
		})
	}
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ MUTF-8
// ═══════════════════════════════════════════════════════════════

func TestReadMUTF8_FastPathASCII(t *testing.T) {
	// Fast-path: чистый ASCII
	tests := []struct {
		name string
		str  string
	}{
		{"empty", ""},
		{"hello", "hello"},
		{"java_class", "Ljava/lang/String;"},
		{"method", "toString"},
		{"long", strings.Repeat("abcdefgh", 100)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data []byte
			// ULEB128 length
			l := len(tt.str)
			if l < 128 {
				data = append(data, byte(l))
			} else {
				data = append(data, byte(l&0x7F|0x80), byte(l>>7))
			}
			data = append(data, []byte(tt.str)...)
			data = append(data, 0x00)

			p := &DEXParser{data: data}
			got, err := p.readMUTF8(0)
			requireNoError(t, err, tt.name)
			assertEqual(t, got, tt.str, "string value")
			assertEqual(t, len(p.warnings), 0, "no warnings")
		})
	}
}

func TestReadMUTF8_SlowPathMultibyte(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			"mutf8_null",
			[]byte{0x01, 0xC0, 0x80, 0x00},
			"\x00",
		},
		{
			"cyrillic",
			[]byte{0x02, 0xD0, 0x90, 0xD0, 0x91, 0x00},
			"АБ",
		},
		{
			"checkmark",
			[]byte{0x01, 0xE2, 0x9C, 0x93, 0x00},
			"✓",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &DEXParser{data: tt.data}
			got, err := p.readMUTF8(0)
			requireNoError(t, err, tt.name)
			assertEqual(t, got, tt.want, "string")
		})
	}
}

func TestReadMUTF8_MissingTerminator(t *testing.T) {
	// null terminator заменён на 'X'
	data := []byte{0x03, 'a', 'b', 'c', 'X'}
	p := &DEXParser{data: data}
	got, _ := p.readMUTF8(0)
	assertEqual(t, got, "abc", "value")
	if len(p.warnings) == 0 {
		t.Error("expected warning for missing terminator")
	}
}

func TestReadMUTF8_PrematureNull(t *testing.T) {
	data := []byte{0x05, 'a', 'b', 0x00, 'c', 'd', 0x00}
	p := &DEXParser{data: data}
	got, _ := p.readMUTF8(0)
	assertEqual(t, got, "ab", "truncated at null")
	if len(p.warnings) == 0 {
		t.Error("expected warning for premature null")
	}
}

func TestReadMUTF8_TooLong(t *testing.T) {
	// ULEB128 для 2_000_000: 0x80 0x89 0x7A
	data := []byte{0x80, 0x89, 0x7A, 'x', 'x', 'x'}
	p := &DEXParser{data: data}
	_, err := p.readMUTF8(0)
	requireError(t, err, "string too long")
}

// TestReadMUTF8_TruncatedASCIINoPanic guards the fast-path bounds fix: the
// length header claims 10 ASCII units but only 3 bytes follow. Before the fix
// the fast-path sliced data[cursor:cursor+utf16Size] and panicked; now it must
// return the available bytes best-effort without crashing.
func TestReadMUTF8_TruncatedASCIINoPanic(t *testing.T) {
	// ULEB128 length = 10, then only "abc" (no terminator, buffer ends).
	data := []byte{0x0A, 'a', 'b', 'c'}
	p := &DEXParser{data: data}
	got, err := p.readMUTF8(0)
	if err != nil {
		t.Fatalf("unexpected error on truncated string: %v", err)
	}
	assertEqual(t, got, "abc", "best-effort truncated value")
}

func TestReadMUTF8_OutOfBounds(t *testing.T) {
	p := &DEXParser{data: []byte{}}
	_, err := p.readMUTF8(0)
	requireErrorIs(t, err, errOutOfBounds, "empty data")
}

func TestReadMUTF8_BadContinuationByte(t *testing.T) {
	// 2-byte sequence с неверным continuation byte
	data := []byte{0x01, 0xC2, 0x00 /* bad */, 0x00}
	p := &DEXParser{data: data}
	got, _ := p.readMUTF8(0) // не должно паниковать
	_ = got
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ BOUNDS
// ═══════════════════════════════════════════════════════════════

func TestBoundsOK(t *testing.T) {
	p := &DEXParser{data: make([]byte, 100)}
	tests := []struct {
		off, size uint32
		want      bool
	}{
		{0, 100, true},
		{0, 101, false},
		{99, 1, true},
		{99, 2, false},
		{100, 0, true},
		{100, 1, false},
		{0xFFFFFFFF, 1, false}, // overflow guard
		{0xFFFFFFFE, 2, false}, // overflow guard
	}
	for _, tt := range tests {
		got := p.boundsOK(tt.off, tt.size)
		if got != tt.want {
			t.Errorf("boundsOK(%d,%d)=%v want %v", tt.off, tt.size, got, tt.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ isASCII
// ═══════════════════════════════════════════════════════════════

func TestIsASCII(t *testing.T) {
	tests := []struct {
		data []byte
		want bool
	}{
		{[]byte("hello"), true},
		{[]byte("Ljava/lang/String;"), true},
		{[]byte{}, true},
		{[]byte{0x00}, false},        // null
		{[]byte{0x80}, false},        // multi-byte
		{[]byte("hel\xC0lo"), false}, // non-ASCII в середине
	}
	for _, tt := range tests {
		got := isASCII(tt.data)
		if got != tt.want {
			t.Errorf("isASCII(%q)=%v want %v", tt.data, got, tt.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ BUILDER POOL
// ═══════════════════════════════════════════════════════════════

func TestBuilderPool_ResetBeforePut(t *testing.T) {
	b := getBuilder()
	b.WriteString("some data")
	putBuilder(b) // должен сбросить перед помещением в пул

	b2 := getBuilder()
	defer putBuilder(b2)
	if b2.Len() != 0 {
		t.Errorf("builder from pool is not empty: len=%d", b2.Len())
	}
}

func TestBuilderPool_LargeBufNotReturned(t *testing.T) {
	b := getBuilder()
	b.Grow(100000)
	b.WriteString(strings.Repeat("x", 70000))
	putBuilder(b) // не должно паниковать, тихо выбрасывает
}

func TestBuilderPool_Concurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := getBuilder()
			b.WriteString("hello world")
			_ = b.String()
			putBuilder(b)
		}()
	}
	wg.Wait()
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ ПУБЛИЧНОГО API
// ═══════════════════════════════════════════════════════════════

func TestParserGetters(t *testing.T) {
	p := &DEXParser{
		version:  "039",
		strings:  []string{"hello", "", "world"},
		types:    []string{"Ljava/lang/String;"},
		methods:  []*Method{{MethodName: "test", ClassName: "LA;"}},
		fields:   []*Field{{FieldName: "value"}},
		classes:  []*ClassDef{{ClassName: "Lcom/test/Test;"}},
		warnings: []string{"w1"},
	}

	assertEqual(t, p.GetVersion(), "039", "version")
	assertEqual(t, p.GetStringCount(), 3, "string count")
	assertEqual(t, p.GetMethodCount(), 1, "method count")
	assertEqual(t, p.GetFieldCount(), 1, "field count")
	assertEqual(t, p.GetClassCount(), 1, "class count")
	assertEqual(t, p.GetWarningCount(), 1, "warning count")
	assertEqual(t, len(p.GetWarnings()), 1, "warnings slice len")

	strs := p.GetAllStrings()
	if len(strs) != 2 {
		t.Errorf("GetAllStrings len=%d want 2", len(strs))
	}
}

func TestFindClassByName(t *testing.T) {
	p := &DEXParser{
		classes: []*ClassDef{
			{ClassName: "Lcom/test/A;"},
			{ClassName: "Lcom/test/B;"},
			nil,
		},
	}

	c := p.FindClassByName("Lcom/test/B;")
	if c == nil {
		t.Fatal("FindClassByName returned nil")
	}
	assertEqual(t, c.ClassName, "Lcom/test/B;", "class name")
	if p.FindClassByName("Lnone;") != nil {
		t.Error("expected nil for unknown class")
	}
}

func TestFindClassByName_IndexBuiltOnce(t *testing.T) {
	p := &DEXParser{
		classes: []*ClassDef{{ClassName: "LA;"}},
	}
	// Вызываем несколько раз — индекс строится один раз
	for i := 0; i < 10; i++ {
		if p.FindClassByName("LA;") == nil {
			t.Errorf("call %d: FindClassByName returned nil", i)
		}
	}
}

func TestFindMethodsByClass(t *testing.T) {
	p := &DEXParser{
		methods: []*Method{
			{ClassName: "LA;", MethodName: "foo"},
			{ClassName: "LA;", MethodName: "bar"},
			{ClassName: "LB;", MethodName: "baz"},
		},
	}
	assertEqual(t, len(p.FindMethodsByClass("LA;")), 2, "methods of LA")
	assertEqual(t, len(p.FindMethodsByClass("LB;")), 1, "methods of LB")
	assertEqual(t, len(p.FindMethodsByClass("LC;")), 0, "methods of unknown")
}

func TestFindClassesBySuperClass(t *testing.T) {
	p := &DEXParser{
		classes: []*ClassDef{
			{ClassName: "LA;", SuperClass: "Ljava/lang/Object;"},
			{ClassName: "LB;", SuperClass: "Ljava/lang/Object;"},
			{ClassName: "LC;", SuperClass: "LA;"},
		},
	}
	assertEqual(t, len(p.FindClassesBySuperClass("Ljava/lang/Object;")), 2, "subclasses of Object")
	assertEqual(t, len(p.FindClassesBySuperClass("LA;")), 1, "subclasses of LA")
}

func TestFindClassesImplementing(t *testing.T) {
	p := &DEXParser{
		classes: []*ClassDef{
			{ClassName: "LA;", Interfaces: []string{"Ljava/io/Serializable;"}},
			{ClassName: "LB;", Interfaces: []string{"Ljava/io/Serializable;", "Ljava/lang/Runnable;"}},
			{ClassName: "LC;"},
		},
	}
	assertEqual(t, len(p.FindClassesImplementing("Ljava/io/Serializable;")), 2, "implementing Serializable")
	assertEqual(t, len(p.FindClassesImplementing("Ljava/lang/Runnable;")), 1, "implementing Runnable")
}

func TestFindStringBySubstring(t *testing.T) {
	p := &DEXParser{
		strings: []string{"hello world", "foo bar", "hello go"},
	}
	assertEqual(t, len(p.FindStringBySubstring("hello")), 2, "hello substrings")
	assertEqual(t, len(p.FindStringBySubstring("xyz")), 0, "no match")
}

func TestHasClass(t *testing.T) {
	p := &DEXParser{
		classes: []*ClassDef{{ClassName: "Lcom/test/A;"}},
	}
	if !p.HasClass("Lcom/test/A;") {
		t.Error("HasClass false for existing class")
	}
	if p.HasClass("Lcom/test/Z;") {
		t.Error("HasClass true for non-existent class")
	}
}

func TestStats(t *testing.T) {
	data := newDEXBuilder().build()
	p, err := ParseDEXBytes(data)
	requireNoError(t, err, "parse for stats")

	stats := p.Stats()
	if !strings.Contains(stats, "DEX v035") {
		t.Errorf("stats missing version: %s", stats)
	}
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ ПОТОКОБЕЗОПАСНОСТИ ПРЕДУПРЕЖДЕНИЙ
// ═══════════════════════════════════════════════════════════════

func TestWarnings_ThreadSafe(t *testing.T) {
	p := &DEXParser{
		data:     make([]byte, 1024),
		warnings: make([]string, 0),
	}

	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.warnf("warning %d", i)
		}()
	}
	wg.Wait()

	assertEqual(t, p.GetWarningCount(), n, "warning count")
	assertEqual(t, len(p.GetWarnings()), n, "warnings slice")
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ SENTINEL ERRORS
// ═══════════════════════════════════════════════════════════════

func TestSentinelErrors_Distinct(t *testing.T) {
	errs := []error{
		errDexTooSmall,
		errDexBadMagic,
		errOutOfBounds,
		errBadULEB128,
		errBadSLEB128,
		errDexNotFound,
		errUnknownFormat,
		errZipBomb,
		errSectionOverlap,
		errSectionOOB,
		errCountTooLarge,
	}
	for i := range errs {
		for j := range errs {
			if i != j && errors.Is(errs[i], errs[j]) {
				t.Errorf("errors[%d] and errors[%d] are not distinct: %v == %v",
					i, j, errs[i], errs[j])
			}
		}
	}
}

func TestLoaderError_Unwrap(t *testing.T) {
	le := &LoaderError{Op: "test", err: errOutOfBounds}
	if !errors.Is(le, errOutOfBounds) {
		t.Error("LoaderError.Unwrap not working")
	}
	if le.Error() != "test: "+errOutOfBounds.Error() {
		t.Errorf("unexpected Error(): %s", le.Error())
	}
}

// ═══════════════════════════════════════════════════════════════
// ТЕСТЫ leU16 / leU32
// ═══════════════════════════════════════════════════════════════

func TestLeU16(t *testing.T) {
	data := []byte{0x34, 0x12, 0x00, 0x00}
	assertEqual(t, leU16(data, 0), uint16(0x1234), "leU16")
}

func TestLeU32(t *testing.T) {
	data := []byte{0x78, 0x56, 0x34, 0x12}
	assertEqual(t, leU32(data, 0), uint32(0x12345678), "leU32")
}

// ═══════════════════════════════════════════════════════════════
// БЕНЧМАРКИ
// ═══════════════════════════════════════════════════════════════

func BenchmarkParseDEX_Minimal(b *testing.B) {
	data := newDEXBuilder().build()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseDEXBytes(data)
	}
}

func BenchmarkReadULEB128_1Byte(b *testing.B) {
	p := &DEXParser{data: []byte{0x7F}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.readULEB128At(0)
	}
}

func BenchmarkReadULEB128_5Bytes(b *testing.B) {
	p := &DEXParser{data: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.readULEB128At(0)
	}
}

func BenchmarkReadMUTF8_ASCII_FastPath(b *testing.B) {
	// Fast-path: ASCII строка
	str := "Ljava/lang/String;"
	data := append([]byte{byte(len(str))}, []byte(str)...)
	data = append(data, 0x00)
	p := &DEXParser{data: data}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p.readMUTF8(0)
	}
}

func BenchmarkReadMUTF8_Multibyte_SlowPath(b *testing.B) {
	// Slow-path: кириллица
	str := "Привет мир"
	data := append([]byte{byte(len([]rune(str)))}, []byte(str)...)
	data = append(data, 0x00)
	p := &DEXParser{data: data}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p.readMUTF8(0)
	}
}

func BenchmarkReadMUTF8_Long_ASCII(b *testing.B) {
	str := strings.Repeat("a", 1000)
	data := append([]byte{0xE8, 0x07}, []byte(str)...) // 1000 в ULEB128
	data = append(data, 0x00)
	p := &DEXParser{data: data}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p.readMUTF8(0)
	}
}

func BenchmarkFindClassByName_Hash(b *testing.B) {
	classes := make([]*ClassDef, 1000)
	for i := range classes {
		classes[i] = &ClassDef{ClassName: fmt.Sprintf("Lcom/test/Class%d;", i)}
	}
	p := &DEXParser{classes: classes}
	p.buildClassIndex()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p.FindClassByName("Lcom/test/Class500;")
	}
}

func BenchmarkFindClassByName_Linear(b *testing.B) {
	classes := make([]*ClassDef, 1000)
	for i := range classes {
		classes[i] = &ClassDef{ClassName: fmt.Sprintf("Lcom/test/Class%d;", i)}
	}
	target := "Lcom/test/Class500;"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, c := range classes {
			if c != nil && c.ClassName == target {
				break
			}
		}
	}
}

func BenchmarkLeU32_Binary(b *testing.B) {
	data := []byte{0x78, 0x56, 0x34, 0x12, 0x00}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = leU32(data, 0)
	}
}

func BenchmarkIsASCII_AllASCII(b *testing.B) {
	data := bytes.Repeat([]byte{'a'}, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isASCII(data)
	}
}
