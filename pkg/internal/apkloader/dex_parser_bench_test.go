package apkloader

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// BenchmarkParseStrings_Sequential — бенчмарк последовательного парсинга строк
func BenchmarkParseStrings_Sequential(b *testing.B) {
	// Создаём тестовый DEX с 10000 строк
	dex := createTestDEXWithStrings(10000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := ParseDEXBytes(dex)
		if err != nil {
			b.Fatalf("ParseDEXBytes failed: %v", err)
		}
		if len(p.strings) != 10000 {
			b.Fatalf("expected 10000 strings, got %d", len(p.strings))
		}
	}
}

// BenchmarkIsASCII — бенчмарк проверки ASCII
func BenchmarkIsASCII(b *testing.B) {
	// ASCII строка
	asciiData := bytes.Repeat([]byte("hello world"), 100)

	b.Run("ASCII", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = isASCII(asciiData)
		}
	})

	// Non-ASCII строка
	nonASCIIData := []byte("hello мир привет 世界")
	b.Run("NonASCII", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = isASCII(nonASCIIData)
		}
	})
}

// BenchmarkScanPayloads — бенчмарк сканирования payload инструкций
func BenchmarkScanPayloads(b *testing.B) {
	// Создаём code item с инструкциями
	code := &CodeItem{
		InsnsSize: 1000,
		Insns:     make([]uint16, 1000),
	}

	// Добавляем несколько payload инструкций
	code.Insns[100] = 0x26 // fill-array-data
	code.Insns[101] = 0x0010
	code.Insns[102] = 0x0000

	code.Insns[500] = 0x2B // packed-switch
	code.Insns[501] = 0x0020
	code.Insns[502] = 0x0000

	p := &DEXParser{
		data: make([]byte, 10000),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		code.PayloadOffsets = make(map[uint32]bool)
		p.scanPayloads(code)
	}
}

// BenchmarkReadMUTF8 — бенчмарк декодирования MUTF-8
func BenchmarkReadMUTF8(b *testing.B) {
	// Создаём простой DEX с одной строкой
	dex := createTestDEXWithSingleString("hello world")
	p, err := ParseDEXBytes(dex)
	if err != nil {
		b.Fatalf("ParseDEXBytes failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.strings[0]
	}
}

// createTestDEXWithStrings создаёт минимальный DEX с N строками
func createTestDEXWithStrings(count int) []byte {
	buf := new(bytes.Buffer)

	// Magic
	buf.WriteString("dex\n")
	// Version
	buf.WriteString("039")
	// Checksum (placeholder)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// SHA-1 (placeholder)
	buf.Write(make([]byte, 20))
	// File size (placeholder)
	binary.Write(buf, binary.LittleEndian, uint32(0x1000))
	// Header size
	binary.Write(buf, binary.LittleEndian, uint32(0x70))
	// Endian tag
	binary.Write(buf, binary.LittleEndian, uint32(0x12345678))
	// Link size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Link offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Map offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// String IDs size
	binary.Write(buf, binary.LittleEndian, uint32(count))
	// String IDs offset
	binary.Write(buf, binary.LittleEndian, uint32(0x70))
	// Type IDs size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Type IDs offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Proto IDs size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Proto IDs offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Field IDs size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Field IDs offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Method IDs size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Method IDs offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Class defs size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Class defs offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Data size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Data offset
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// String IDs (offsets to string data)
	stringDataOffset := uint32(0x70 + count*4)
	for i := 0; i < count; i++ {
		binary.Write(buf, binary.LittleEndian, stringDataOffset)
		stringDataOffset += 20 // approximate
	}

	// String data
	for i := 0; i < count; i++ {
		// ULEB128 size (5 bytes for "hello")
		buf.WriteByte(0x05)
		buf.WriteString("hello")
		buf.WriteByte(0x00) // null terminator
	}

	return buf.Bytes()
}

// createTestDEXWithSingleString создаёт DEX с одной строкой
func createTestDEXWithSingleString(s string) []byte {
	buf := new(bytes.Buffer)

	// Magic
	buf.WriteString("dex\n")
	// Version
	buf.WriteString("039")
	// Checksum
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// SHA-1
	buf.Write(make([]byte, 20))
	// File size
	binary.Write(buf, binary.LittleEndian, uint32(0x1000))
	// Header size
	binary.Write(buf, binary.LittleEndian, uint32(0x70))
	// Endian tag
	binary.Write(buf, binary.LittleEndian, uint32(0x12345678))
	// Link size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Link offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Map offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// String IDs size
	binary.Write(buf, binary.LittleEndian, uint32(1))
	// String IDs offset
	binary.Write(buf, binary.LittleEndian, uint32(0x70))
	// Type IDs size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Type IDs offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Proto IDs size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Proto IDs offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Field IDs size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Field IDs offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Method IDs size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Method IDs offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Class defs size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Class defs offset
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Data size
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Data offset
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// String ID (offset to string data)
	stringDataOffset := uint32(0x70 + 4)
	binary.Write(buf, binary.LittleEndian, stringDataOffset)

	// String data
	// ULEB128 size
	buf.WriteByte(byte(len(s)))
	buf.WriteString(s)
	buf.WriteByte(0x00) // null terminator

	return buf.Bytes()
}
