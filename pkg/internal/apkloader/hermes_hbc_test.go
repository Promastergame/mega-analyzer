package apkloader

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseHermesBytecodeStructuralTables(t *testing.T) {
	stringsTable := []string{
		"main",
		"moduleA",
		"https://api.example.com/graphql",
		"NativeModules",
		"wss://socket.example.com/live",
	}
	data := buildTestHBC(t, 96, stringsTable)
	index, err := ParseHermesBytecode(data)
	if err != nil {
		t.Fatalf("ParseHermesBytecode: %v", err)
	}
	if index.Header.Version != 96 || index.Header.FunctionCount != 2 {
		t.Fatalf("unexpected header: %+v", index.Header)
	}
	if len(index.Strings) != len(stringsTable) {
		t.Fatalf("strings = %d, want %d", len(index.Strings), len(stringsTable))
	}
	if got, ok := index.StringByID(2); !ok || got.Value != stringsTable[2] {
		t.Fatalf("string 2 = %#v, %v", got, ok)
	}
	if len(index.Functions) != 2 || index.Functions[0].Name != "main" {
		t.Fatalf("unexpected functions: %#v", index.Functions)
	}
	if len(index.Modules) != 1 || index.Modules[0].Name != "moduleA" || index.Modules[0].FunctionIndex != 1 {
		t.Fatalf("unexpected modules: %#v", index.Modules)
	}

	instructions, err := index.DecodeFunction(0)
	if err != nil {
		t.Fatal(err)
	}
	foundString, foundCall := false, false
	for _, instruction := range instructions {
		for _, id := range instruction.StringRefs {
			if id == 2 {
				foundString = true
			}
		}
		for _, id := range instruction.FunctionRefs {
			if id == 1 {
				foundCall = true
			}
		}
	}
	if !foundString || !foundCall {
		t.Fatalf("lazy decode missing refs: string=%v call=%v instructions=%#v", foundString, foundCall, instructions)
	}
	edges := index.BuildFunctionGraph()
	if len(edges) != 1 || edges[0].Caller != 0 || edges[0].Callee != 1 {
		t.Fatalf("unexpected function graph: %#v", edges)
	}
}

func TestParseHermesBytecodeRejectsMalformedInput(t *testing.T) {
	if _, err := ParseHermesBytecode([]byte("not-hbc!")); !errors.Is(err, ErrNotHermes) {
		t.Fatalf("non-HBC error = %v", err)
	}
	if _, err := ParseHermesBytecode(HermesMagicLE); !errors.Is(err, ErrMalformedHermes) {
		t.Fatalf("truncated error = %v", err)
	}

	header := make([]byte, hermesHeaderSize)
	copy(header, HermesMagicLE)
	if _, err := ParseHermesBytecode(header); !errors.Is(err, ErrMalformedHermes) {
		t.Fatalf("zero-version error = %v", err)
	}
	binary.LittleEndian.PutUint32(header[8:12], 96)
	binary.LittleEndian.PutUint32(header[32:36], uint32(len(header)+10))
	if _, err := ParseHermesBytecode(header); !errors.Is(err, ErrMalformedHermes) {
		t.Fatalf("declared-length error = %v", err)
	}
}

func buildTestHBC(t *testing.T, version uint32, values []string) []byte {
	t.Helper()
	const functionCount = 2
	functionTableEnd := hermesHeaderSize + functionCount*hermesFunctionHeaderSize
	stringTableOffset := functionTableEnd
	storageOffset := stringTableOffset + len(values)*4
	storage := make([]byte, 0)
	entries := make([]uint32, len(values))
	for i, value := range values {
		if len(value) >= 0xff {
			t.Fatalf("test string too long")
		}
		entries[i] = uint32(len(value))<<24 | uint32(len(storage))<<1
		storage = append(storage, value...)
	}
	moduleOffset := align4(storageOffset + len(storage))
	// HBC v96: CallDirect r0, argc1, function1; LoadConstString r0, string2; Ret r0.
	code0 := []byte{82, 0, 1, 1, 0, 115, 0, 2, 0, 92, 0}
	code1 := []byte{0}
	code0Offset := moduleOffset + 8
	code1Offset := code0Offset + len(code0)
	fileLen := code1Offset + len(code1)
	data := make([]byte, fileLen)
	copy(data, HermesMagicLE)
	put32 := func(off int, value uint32) { binary.LittleEndian.PutUint32(data[off:off+4], value) }
	put32(8, version)
	put32(32, uint32(fileLen))
	put32(36, 0)
	put32(40, functionCount)
	put32(52, uint32(len(values)))
	put32(60, uint32(len(storage)))
	put32(96, 1)

	writeFunction := func(index, bytecodeOffset, bytecodeSize, nameID int) {
		base := hermesHeaderSize + index*hermesFunctionHeaderSize
		put32(base, uint32(bytecodeOffset)|1<<25)
		put32(base+4, uint32(bytecodeSize)|uint32(nameID)<<15)
		put32(base+8, 1<<25)
		put32(base+12, 0)
	}
	writeFunction(0, code0Offset, len(code0), 0)
	writeFunction(1, code1Offset, len(code1), 0)
	for i, entry := range entries {
		put32(stringTableOffset+i*4, entry)
	}
	copy(data[storageOffset:], storage)
	put32(moduleOffset, 1)
	put32(moduleOffset+4, 1)
	copy(data[code0Offset:], code0)
	copy(data[code1Offset:], code1)
	return data
}

// buildCompactHBC builds a minimal v98 HBC with 12-byte function
// headers and an explicit string-kind RLE, mirroring real bundles like
// Character.AI's index.android.bundle.
func buildCompactHBC(t *testing.T, version uint32, values []string) []byte {
	t.Helper()
	const legacyFuncSize = 12
	const functionCount = 1
	const kindCount = 1
	funcTableEnd := hermesHeaderSize + functionCount*legacyFuncSize
	kindsEnd := funcTableEnd + kindCount*4
	stringTableOffset := kindsEnd
	storageOffset := stringTableOffset + len(values)*4
	storage := make([]byte, 0)
	entries := make([]uint32, len(values))
	for i, value := range values {
		if len(value) >= 0xff {
			t.Fatalf("test string too long")
		}
		entries[i] = uint32(len(value))<<24 | uint32(len(storage))<<1
		storage = append(storage, value...)
	}
	fileLen := storageOffset + len(storage)
	data := make([]byte, fileLen)
	copy(data, HermesMagicLE)
	put32 := func(off int, value uint32) { binary.LittleEndian.PutUint32(data[off:off+4], value) }
	put32(8, version)
	put32(32, uint32(fileLen))
	put32(40, functionCount)
	put32(44, kindCount)
	put32(52, uint32(len(values)))
	put32(60, uint32(len(storage)))
	// HBC v98: offset|paramCount, size|nameID, frame|readCache|writeCache|flags.
	put32(hermesHeaderSize, 1<<25)
	put32(hermesHeaderSize+4, 0)
	put32(hermesHeaderSize+8, 1)
	// String-kind RLE: all strings, count == len(values).
	put32(funcTableEnd, uint32(len(values)))
	for i, entry := range entries {
		put32(stringTableOffset+i*4, entry)
	}
	copy(data[storageOffset:], storage)
	return data
}
