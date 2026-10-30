package apkloader

import (
	"encoding/binary"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func peCoverageFixture(is64, delayed, legacy bool) []byte {
	b := make([]byte, 0x600)
	p16 := func(at int, v uint16) { binary.LittleEndian.PutUint16(b[at:], v) }
	p32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
	copy(b, "MZ")
	p32(0x3c, 0x80)
	copy(b[0x80:], "PE\x00\x00")
	p16(0x84, 0x14c)
	p16(0x86, 1)
	fixed, optSize := 96, 224
	p16(0x98, 0x10b)
	p32(0x98+28, 0x400000)
	if is64 {
		fixed, optSize = 112, 240
		p16(0x84, 0x8664)
		p16(0x98, 0x20b)
		binary.LittleEndian.PutUint64(b[0x98+24:], 0x140000000)
	}
	p16(0x94, uint16(optSize))
	p32(0x98+fixed-4, 16)
	p32(0x98+60, 0x200)
	s := 0x98 + optSize
	copy(b[s:], ".rdata")
	p32(s+8, 0x800) // virtual tail deliberately exceeds raw size
	p32(s+12, 0x1000)
	p32(s+16, 0x400)
	p32(s+20, 0x200)
	p32(s+36, 0x40000040)
	value := func(rva uint32) uint32 {
		if legacy {
			return rva + 0x400000
		}
		return rva
	}
	index, size := 1, uint32(40)
	if delayed {
		index, size = 13, 64
		if !legacy {
			p32(0x200, 1)
		}
		p32(0x204, value(0x1080))
		p32(0x20c, value(0x1040)) // IAT
		p32(0x210, value(0x1040)) // INT
	} else {
		p32(0x200, 0x1040)
		p32(0x20c, 0x1080)
		p32(0x210, 0x1040)
	}
	p32(0x98+fixed+index*8, 0x1000)
	p32(0x98+fixed+index*8+4, size)
	p32(0x240, value(0x10a0))
	copy(b[0x280:], "kernel32.dll\x00")
	copy(b[0x2a2:], "VirtualAllocEx\x00")
	return b
}

func TestPEImportCoverageIncludesLaterFirstThunkDescriptor(t *testing.T) {
	b := peCoverageFixture(true, false, false)
	p32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
	p32(0x98+112+12, 60)
	copy(b[0x2a2:], "Sleep\x00")
	p32(0x214+12, 0x1080)
	p32(0x214+16, 0x1060) // second descriptor has no OriginalFirstThunk
	p32(0x260, 0x10c0)
	copy(b[0x2c2:], "WriteProcessMemory\x00")
	r, ok := AnalyzeNativeGo(b)
	if !ok || r.Verdict == "parse-error" {
		t.Fatalf("fixture rejected: %+v", r)
	}
	if !slices.ContainsFunc(r.Findings, func(f NativeFinding) bool { return f.ID == "import-WriteProcessMemory" }) {
		t.Fatalf("later import missing from final report: %+v", r.Findings)
	}
}

func TestPEImportCoverageDelayLoad(t *testing.T) {
	for _, tc := range []struct {
		name              string
		is64, legacy, iat bool
	}{{"PE32 RVA", false, false, false}, {"PE32 VA", false, true, false},
		{"PE32+ RVA", true, false, false}, {"PE32+ IAT fallback", true, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			b := peCoverageFixture(tc.is64, true, tc.legacy)
			if tc.iat {
				binary.LittleEndian.PutUint32(b[0x210:], 0)
			}
			got := inspectPEImports(b)
			if !slices.Equal(got.Names, []string{"VirtualAllocEx"}) || got.Delayed != 1 || len(got.Warnings) != 0 {
				t.Fatalf("delay imports: %+v", got)
			}
			r, ok := AnalyzeNativeGo(b)
			if !ok || !slices.ContainsFunc(r.Findings, func(f NativeFinding) bool { return f.ID == "import-VirtualAllocEx" }) {
				t.Fatalf("delay import did not reach analyzer: %+v", r)
			}
		})
	}
}

func TestPEImportCoverageRejectsUnmappedAndTruncatedData(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]byte)
	}{
		{"64-bit value must not wrap into RVA", func(b []byte) {
			binary.LittleEndian.PutUint64(b[0x240:], 0x1000010a0)
		}},
		{"virtual tail is not file backing", func(b []byte) {
			binary.LittleEndian.PutUint64(b[0x240:], 0x1450)
			copy(b[0x652:], "VirtualAllocEx\x00")
		}},
		{"name cannot cross raw section end", func(b []byte) {
			binary.LittleEndian.PutUint64(b[0x240:], 0x13f8)
			copy(b[0x5fa:], "VirtualAllocEx\x00")
		}},
		{"directory cannot cross raw section end", func(b []byte) {
			binary.LittleEndian.PutUint32(b[0x98+112+12:], 0x420)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append(peCoverageFixture(true, false, false), make([]byte, 0x200)...)
			tc.edit(b)
			got := inspectPEImports(b)
			if len(got.Names) != 0 || len(got.Warnings) == 0 {
				t.Fatalf("unbacked import treated as evidence: %+v", got)
			}
			r, _ := AnalyzeNativeGo(b)
			if !slices.ContainsFunc(r.Findings, func(f NativeFinding) bool { return f.ID == "pe-imports-incomplete" }) {
				t.Fatal("incomplete coverage was not reported")
			}
		})
	}
}

func TestPEImportCoverageRespectsDirectoryCountAndSize(t *testing.T) {
	b := peCoverageFixture(true, false, false)
	binary.LittleEndian.PutUint32(b[0x98+108:], 0)
	if got := inspectPEImports(b); len(got.Names) != 0 || len(got.Warnings) != 0 {
		t.Fatalf("undeclared import directory read: %+v", got)
	}
	b = peCoverageFixture(true, false, false)
	binary.LittleEndian.PutUint32(b[0x98+112+12:], 20)
	got := inspectPEImports(b)
	if len(got.Names) != 1 || len(got.Warnings) == 0 {
		t.Fatalf("missing descriptor terminator not reported: %+v", got)
	}
}

func TestPEImportCoverageHeaderBackedImports(t *testing.T) {
	b := peCoverageFixture(true, false, false)
	// Extend SizeOfHeaders to include the fixture's tables, and remove sections.
	binary.LittleEndian.PutUint16(b[0x86:], 0)
	binary.LittleEndian.PutUint32(b[0x98+60:], 0x600)
	binary.LittleEndian.PutUint32(b[0x98+112+8:], 0x200)
	binary.LittleEndian.PutUint32(b[0x200:], 0x240)
	binary.LittleEndian.PutUint32(b[0x20c:], 0x280)
	binary.LittleEndian.PutUint32(b[0x210:], 0x240)
	binary.LittleEndian.PutUint64(b[0x240:], 0x2a0)
	if got := inspectPEImports(b); !slices.Equal(got.Names, []string{"VirtualAllocEx"}) || len(got.Warnings) != 0 {
		t.Fatalf("header-backed import: %+v", got)
	}
}

func TestPEImportCoverageSharedWorkLimit(t *testing.T) {
	b := append(peCoverageFixture(true, false, false), make([]byte, 0x3c00)...)
	binary.LittleEndian.PutUint32(b[0x98+240+8:], 0x4000)
	binary.LittleEndian.PutUint32(b[0x98+240+16:], 0x4000)
	// Repeated descriptors reference the same unterminated ordinal-only array.
	// It must consume one shared budget, not a fresh budget for every DLL.
	clear(b[0x200:])
	binary.LittleEndian.PutUint32(b[0x98+112+12:], 129*20)
	for d := 0; d < 128; d++ {
		at := 0x200 + d*20
		binary.LittleEndian.PutUint32(b[at:], 0x1b00)
		binary.LittleEndian.PutUint32(b[at+12:], 0x1a80)
	}
	copy(b[0xc80:], "k.dll\x00")
	for at := 0xd00; at < len(b); at += 8 {
		binary.LittleEndian.PutUint64(b[at:], 1<<63|1)
	}
	if got := inspectPEImports(b); !strings.Contains(strings.Join(got.Warnings, ";"), "work limit") {
		t.Fatalf("shared budget was not enforced: %+v", got)
	}
}

func FuzzPEImportCoverage(f *testing.F) {
	f.Add([]byte{})
	f.Add(peCoverageFixture(false, false, false))
	f.Add(peCoverageFixture(false, true, true))
	f.Add(peCoverageFixture(true, true, false))
	f.Fuzz(func(t *testing.T, data []byte) {
		result := inspectPEImports(data)
		if len(result.Names) > peMaxImportNames {
			t.Fatal("import budget exceeded")
		}
	})
}

func TestPEImportCoverageGoLinkedExecutable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("test executable is not PE on this host")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result := inspectPEImports(data)
	if len(result.Names) == 0 || len(result.Warnings) != 0 {
		t.Fatalf("Go-linked PE import coverage: %d names, warnings: %v", len(result.Names), result.Warnings)
	}
}
