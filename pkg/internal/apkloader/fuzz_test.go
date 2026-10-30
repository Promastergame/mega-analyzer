//go:build go1.18
// +build go1.18

package apkloader

import (
	"testing"

	"mega-analyzer/pkg/internal/apkloader/axml"
)

// FuzzParseDEXBytes тестирует парсер на случайных данных
func FuzzParseDEXBytes(f *testing.F) {
	// Seed corpus
	f.Add([]byte("dex\n035\x00"))
	f.Add(newDEXBuilder().build())
	f.Add([]byte{})
	f.Add([]byte("notdex"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Не должен паниковать
		_, _ = ParseDEXBytes(data)
	})
}

// FuzzReadMUTF8 тестирует MUTF-8 декодер
func FuzzReadMUTF8(f *testing.F) {
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x05, 'h', 'e', 'l', 'l', 'o', 0x00})
	f.Add([]byte{0x01, 0xC0, 0x80, 0x00})
	f.Add([]byte{0xFF, 0xFF}) // invalid

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &DEXParser{data: data, warnings: []string{}}
		_, _ = p.readMUTF8(0)
	})
}

// FuzzReadULEB128 тестирует ULEB128 декодер
func FuzzReadULEB128(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0x7F})
	f.Add([]byte{0x80, 0x01})
	f.Add([]byte{0x80, 0x80, 0x80, 0x80, 0x80}) // too long

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &DEXParser{data: data}
		_, _ = p.readULEB128At(0)
	})
}

// FuzzDecodeInsn тестирует декодер инструкций
func FuzzDecodeInsn(f *testing.F) {
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x0E, 0x00})
	f.Add([]byte{0x6E, 0x10, 0x01, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			return
		}

		// Конвертируем в []uint16
		insns := make([]uint16, len(data)/2)
		for i := range insns {
			insns[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
		}

		_, _ = DecodeInsn(insns, 0, nil, nil)
	})
}

// FuzzAXMLDecode прогоняет бинарный AndroidManifest.xml через декодер.
// Паника здесь = краевой баг на недоверенном вводе (эти зависимости нашлись
// бы за минуты фаззинга — см. аудит, улучшение #1).
func FuzzAXMLDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("\x03\x00\x08\x00\x00\x00\x00\x00"))
	// Валидная внешняя шапка + чанк-мусор: раньше зависало на
	// hdrSize=0/chunkSize=0.
	f.Add([]byte("\x03\x00\x08\x00\x14\x00\x00\x00" +
		"\x03\x00\x00\x00\x00\x00\x00\x00"))
	// START_ELEMENT с attrSize=4: раньше паника index out of range.
	f.Add([]byte("\x03\x00\x08\x00\x40\x00\x00\x00" +
		"\x01\x00\x10\x00\x50\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x08\x00\x04\x00\x01\x00\x00\x00"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Не должен паниковать или зависать.
		_, _ = axml.Decode(data)
	})
}

// FuzzParseARSC фаззит resources.arsc: гигантские entryCount, комплексные
// entry-заголовки меньше 16 байт, library-каунты.
func FuzzParseARSC(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("\x02\x00\x0c\x00\x44\x00\x00\x00\x01\x00\x00\x00"))
	// type-chunk с entryCount=0xFFFFFFFF: раньше аллокация до 32 ГБ.
	f.Add([]byte("\x02\x00\x0c\x00\x2c\x00\x00\x00\x01\x00\x00\x00" +
		"\x02\x00\x0c\x00\x20\x00\x00\x00\x01\x01\x00\x00" +
		"\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = axml.ParseARSC(data)
	})
}

// FuzzHermes фаззит Hermes bytecode индекс (класс DoS на crafted bundle).
func FuzzHermes(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("\xc6\x1f\xbc\x03"))
	f.Add([]byte("\xc6\x1f\xbc\x03\x1e\x00\x00\x00"))

	f.Fuzz(func(t *testing.T, data []byte) {
		idx, err := ParseHermesBytecode(data)
		if err != nil || idx == nil {
			return
		}
		// Проход по строкам/функциям не должен паниковать.
		_ = idx.StringValues()
		for i := 0; i < 4 && i < 1000; i++ {
			_, _ = idx.DecodeFunction(uint32(i))
		}
	})
}
