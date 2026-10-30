package apkloader

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
)

var smaliBenchmarkText string

func BenchmarkResolveSmaliString(b *testing.B) {
	for _, value := range []string{"https://example.org/api/check", "line\nwith\t\"quotes\""} {
		b.Run(fmt.Sprintf("escaped=%t", bytes.ContainsAny([]byte(value), "\n\t\"")), func(b *testing.B) {
			p := &DEXParser{strings: []string{value}}
			b.ReportAllocs()
			for b.Loop() {
				smaliBenchmarkText = resolveString(0, p)
			}
		})
	}
}

func BenchmarkGenerateStringHeavyClassIR(b *testing.B) {
	p := &DEXParser{strings: []string{"https://example.org/api/check", "license_key"}}
	cls := &ClassDef{ClassName: "Lexample/License;", SuperClass: "Ljava/lang/Object;"}
	for i := 0; i < 32; i++ {
		code := &CodeItem{RegistersSize: 2}
		for j := 0; j < 16; j++ {
			code.Insns = append(code.Insns, 0x001a, uint16(j%2), 0x1112)
		}
		code.Insns = append(code.Insns, 0x0011)
		cls.DirectMethods = append(cls.DirectMethods, &EncodedMethod{
			Name: fmt.Sprintf("read%d", i), AccessFlags: 8, ReturnType: "Ljava/lang/String;", Code: code,
		})
	}
	b.ReportAllocs()
	for b.Loop() {
		smaliBenchmarkText = generateSmaliClass(cls, p)
	}
}

func BenchmarkSmaliCacheIO(b *testing.B) {
	dir := b.TempDir()
	h := openSmaliCacheDB(dir)
	for i := 0; i < 512; i++ {
		h.Put("dex", fmt.Sprintf("Lexample/C%d;", i), string(bytes.Repeat([]byte(".method public read()V\n.end method\n"), 64)))
	}
	if err := h.Save(0, 0); err != nil {
		b.Fatal(err)
	}
	b.Run("load", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			loaded := &smaliCacheDBHandle{path: filepath.Join(dir, nativeSmaliClassCacheDB), entries: map[string]SmaliCacheRecord{}}
			if err := loaded.load(); err != nil || len(loaded.entries) != len(h.entries) {
				b.Fatalf("load: %v, entries=%d", err, len(loaded.entries))
			}
		}
	})
	b.Run("save", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			h.Put("dex", "Lexample/C0;", h.entries[smaliCacheKey("dex", "Lexample/C0;")].Smali)
			if err := h.Save(0, 0); err != nil {
				b.Fatal(err)
			}
		}
	})
}
