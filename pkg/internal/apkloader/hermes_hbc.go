package apkloader

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf16"
)

const (
	hermesHeaderSize            = 128
	hermesFunctionHeaderSize    = 16
	maxHermesFunctions          = 500_000
	maxHermesStrings            = 1_000_000
	maxHermesModules            = 500_000
	maxHermesDecodedStringBytes = 64 << 20
)

var (
	ErrNotHermes         = errors.New("not a Hermes bytecode file")
	ErrMalformedHermes   = errors.New("malformed Hermes bytecode")
	ErrUnsupportedHermes = errors.New("unsupported Hermes bytecode")
)

type hermesFunctionLayout uint8

const (
	hermesClassic hermesFunctionLayout = iota
	hermesCompact
	hermesTyped
)

type hermesVersionSpec struct {
	opcodes                              []hermesOpcode
	layout                               hermesFunctionLayout
	bigInt, functionSource, stringSwitch bool
}

// HermesHeader holds the fields of the explicitly supported HBC versions.
// Fields absent from a version stay zero; adjacent versions are never guessed.
type HermesHeader struct {
	Version                                                         uint32
	SourceHash                                                      [20]byte
	FileLength, GlobalCodeIndex, FunctionCount                      uint32
	StringKindCount, IdentifierCount, StringCount                   uint32
	OverflowStringCount, StringStorageSize                          uint32
	BigIntCount, BigIntStorageSize, RegExpCount, RegExpStorageSize  uint32
	ArrayBufferSize, ObjKeyBufferSize, ObjValueBufferSize           uint32
	LiteralValueBufferSize, ObjShapeTableCount, NumStringSwitchImms uint32
	SegmentID, CJSModuleCount, FunctionSourceCount, DebugInfoOffset uint32
	Options                                                         byte
}

type HermesString struct {
	ID               uint32
	Value            string
	UTF16            bool
	Offset, ByteSize uint32
}

type HermesFunction struct {
	Index, NameID                                          uint32
	Name                                                   string
	BytecodeOffset, BytecodeSize, InfoOffset, HeaderOffset uint32
	ParamCount, FrameSize, EnvironmentSize                 uint32
	Flags                                                  uint8
	Valid                                                  bool
	Overflow                                               bool
}

type HermesModule struct {
	Index, NameID, ModuleID uint32
	Name                    string
	FunctionIndex           uint32
	Static                  bool
}

// HermesIndex is immutable after parsing. Diagnostics describe incomplete
// structural coverage independently of instruction decoding.
type HermesIndex struct {
	Header          HermesHeader
	Strings         []HermesString
	Functions       []HermesFunction
	Modules         []HermesModule
	Diagnostics     []string
	DiagnosticCount int
	AnalysisStatus  string
	data            []byte
	order           binary.ByteOrder
	spec            hermesVersionSpec
}

func (h *HermesIndex) diagnose(message string) {
	h.AnalysisStatus = "partial"
	h.DiagnosticCount++
	if len(h.Diagnostics) < 64 {
		h.Diagnostics = append(h.Diagnostics, message)
	}
}

func HermesBytecodeVersion(data []byte) uint32 {
	if len(data) < 12 || !IsHermesBytecode(data) {
		return 0
	}
	if string(data[:8]) == string(HermesMagicBE) {
		return binary.BigEndian.Uint32(data[8:12])
	}
	return binary.LittleEndian.Uint32(data[8:12])
}

func ParseHermesBytecode(data []byte) (*HermesIndex, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("%w: truncated magic", ErrMalformedHermes)
	}
	var order binary.ByteOrder
	switch string(data[:8]) {
	case string(HermesMagicLE):
		order = binary.LittleEndian
	case string(HermesMagicBE):
		order = binary.BigEndian
	default:
		if isHermesDelta(data) {
			return nil, fmt.Errorf("%w: delta-prepared container", ErrUnsupportedHermes)
		}
		return nil, ErrNotHermes
	}
	if len(data) < hermesHeaderSize {
		return nil, fmt.Errorf("%w: header needs %d bytes, got %d", ErrMalformedHermes, hermesHeaderSize, len(data))
	}
	h := HermesHeader{Version: order.Uint32(data[8:12])}
	if h.Version == 0 {
		return nil, fmt.Errorf("%w: zero version", ErrMalformedHermes)
	}
	spec, supported := hermesVersions[h.Version]
	if !supported {
		return nil, fmt.Errorf("%w: version %d has no verified layout", ErrUnsupportedHermes, h.Version)
	}
	copy(h.SourceHash[:], data[12:32])
	at := 32
	read := func(dst *uint32) { *dst = order.Uint32(data[at : at+4]); at += 4 }
	for _, dst := range []*uint32{&h.FileLength, &h.GlobalCodeIndex, &h.FunctionCount,
		&h.StringKindCount, &h.IdentifierCount, &h.StringCount, &h.OverflowStringCount, &h.StringStorageSize} {
		read(dst)
	}
	if spec.bigInt {
		read(&h.BigIntCount)
		read(&h.BigIntStorageSize)
	}
	read(&h.RegExpCount)
	read(&h.RegExpStorageSize)
	if spec.layout == hermesClassic {
		read(&h.ArrayBufferSize)
		read(&h.ObjKeyBufferSize)
		read(&h.ObjValueBufferSize)
	} else {
		read(&h.LiteralValueBufferSize)
		read(&h.ObjKeyBufferSize)
		read(&h.ObjShapeTableCount)
	}
	if spec.stringSwitch {
		read(&h.NumStringSwitchImms)
	}
	read(&h.SegmentID)
	read(&h.CJSModuleCount)
	if spec.functionSource {
		read(&h.FunctionSourceCount)
	}
	read(&h.DebugInfoOffset)
	h.Options = data[at]
	if h.FileLength < hermesHeaderSize || uint64(h.FileLength) > uint64(len(data)) {
		return nil, fmt.Errorf("%w: declared length %d is invalid for input %d", ErrMalformedHermes, h.FileLength, len(data))
	}
	if h.FunctionCount > maxHermesFunctions || h.StringCount > maxHermesStrings || h.CJSModuleCount > maxHermesModules {
		return nil, fmt.Errorf("%w: structural table budget exceeded", ErrMalformedHermes)
	}
	fileEnd := int(h.FileLength)
	index := &HermesIndex{Header: h, data: data[:fileEnd], order: order, spec: spec, AnalysisStatus: "complete"}
	if order == binary.BigEndian {
		index.diagnose("big-endian instruction encoding is not verified; structural tables only")
	}
	if h.FunctionCount > 0 && h.GlobalCodeIndex >= h.FunctionCount {
		index.diagnose("global function index is out of bounds")
	}
	stride := 16
	if spec.layout != hermesClassic {
		stride = 12
	}
	offset, err := skipTable(hermesHeaderSize, h.FunctionCount, stride, fileEnd, "function")
	if err != nil {
		return nil, err
	}
	index.Functions = make([]HermesFunction, 0, h.FunctionCount)
	for i := uint32(0); i < h.FunctionCount; i++ {
		fn, err := index.readFunction(i, hermesHeaderSize+int(i)*stride)
		if err != nil {
			index.diagnose(err.Error())
		}
		index.Functions = append(index.Functions, fn)
	}
	kindsOffset := offset
	offset, err = skipTable(offset, h.StringKindCount, 4, fileEnd, "string-kind")
	if err != nil {
		return nil, err
	}
	if h.StringKindCount > 0 {
		var total, identifiers uint64
		for i := uint32(0); i < h.StringKindCount; i++ {
			value := order.Uint32(index.data[kindsOffset+int(i)*4:])
			count := uint64(value & 0x7fffffff)
			total += count
			if value>>31 != 0 {
				identifiers += count
			}
		}
		if total != uint64(h.StringCount) || identifiers != uint64(h.IdentifierCount) {
			index.diagnose("string-kind counts do not match string/identifier tables")
		}
	}
	offset, err = skipTable(offset, h.IdentifierCount, 4, fileEnd, "identifier-hash")
	if err != nil {
		return nil, err
	}
	stringTableOffset := offset
	offset, err = skipTable(offset, h.StringCount, 4, fileEnd, "string")
	if err != nil {
		return nil, err
	}
	overflowOffset := offset
	offset, err = skipTable(offset, h.OverflowStringCount, 8, fileEnd, "overflow-string")
	if err != nil {
		return nil, err
	}
	storageOffset := offset
	if !rangeFits(storageOffset, int(h.StringStorageSize), fileEnd) {
		return nil, fmt.Errorf("%w: string storage out of bounds", ErrMalformedHermes)
	}
	storage := index.data[storageOffset : storageOffset+int(h.StringStorageSize)]
	index.Strings = make([]HermesString, 0, h.StringCount)
	decodedBytes := 0
	for i := uint32(0); i < h.StringCount; i++ {
		raw := order.Uint32(index.data[stringTableOffset+int(i)*4:])
		isUTF16 := raw&1 != 0
		stringOffset, length := (raw>>1)&0x7fffff, raw>>24
		if length == 0xff {
			if stringOffset >= h.OverflowStringCount {
				index.diagnose(fmt.Sprintf("string %d has invalid overflow index", i))
				continue
			}
			base := overflowOffset + int(stringOffset)*8
			stringOffset = order.Uint32(index.data[base:])
			length = order.Uint32(index.data[base+4:])
		}
		byteLength := uint64(length)
		if isUTF16 {
			byteLength *= 2
		}
		if byteLength > uint64(len(storage)) || uint64(stringOffset)+byteLength > uint64(len(storage)) {
			index.diagnose(fmt.Sprintf("string %d range is out of bounds", i))
			continue
		}
		// UTF-16 can expand to three UTF-8 bytes per code unit.
		allocation := byteLength
		if isUTF16 {
			allocation = uint64(length) * 3
		}
		if allocation > uint64(maxHermesDecodedStringBytes-decodedBytes) {
			index.diagnose(fmt.Sprintf("decoded string budget reached after %d/%d entries", i, h.StringCount))
			break
		}
		rawString := storage[int(stringOffset):int(uint64(stringOffset)+byteLength)]
		value := string(rawString)
		if isUTF16 {
			value = decodeHermesUTF16(rawString, order)
		}
		decodedBytes += len(value)
		index.Strings = append(index.Strings, HermesString{ID: i, Value: value, UTF16: isUTF16, Offset: stringOffset, ByteSize: uint32(byteLength)})
	}
	tablesEnd, moduleErr := index.parseModuleTable(storageOffset + int(h.StringStorageSize))
	if moduleErr != nil {
		index.diagnose(moduleErr.Error())
	}
	for i := range index.Functions {
		fn := &index.Functions[i]
		if s, ok := index.StringByID(fn.NameID); ok {
			fn.Name = s.Value
		}
		if fn.Name == "" {
			fn.Name = fmt.Sprintf("function_%d", fn.Index)
		}
		if fn.Valid && fn.BytecodeSize > 0 && (int(fn.BytecodeOffset) < tablesEnd || moduleErr != nil) {
			fn.Valid = false
			index.diagnose(fmt.Sprintf("function %d bytecode overlaps structural tables or tables are incomplete", i))
		}
		if fn.Valid && fn.Overflow && int(fn.HeaderOffset) < tablesEnd {
			fn.Valid = false
			index.diagnose(fmt.Sprintf("function %d large header overlaps structural tables", i))
		}
	}
	return index, nil
}

func (h *HermesIndex) readFunction(id uint32, base int) (HermesFunction, error) {
	word := func(at int) uint32 { return h.order.Uint32(h.data[at : at+4]) }
	a, b, c := word(base), word(base+4), word(base+8)
	fn := HermesFunction{Index: id, BytecodeOffset: a & 0x01ffffff, ParamCount: a >> 25,
		BytecodeSize: b & 0x7fff, NameID: b >> 15, HeaderOffset: uint32(base)}
	switch h.spec.layout {
	case hermesClassic:
		fn.InfoOffset, fn.FrameSize = c&0x01ffffff, c>>25
		fn.EnvironmentSize, fn.Flags = uint32(h.data[base+12]), h.data[base+15]
	case hermesCompact:
		fn.FrameSize, fn.Flags = uint32(h.data[base+8]), h.data[base+11]
	case hermesTyped:
		fn.ParamCount, fn.BytecodeSize, fn.NameID = (a>>25)&0x1f, b&0x3fff, (b>>14)&0xff
		fn.FrameSize, fn.Flags = uint32(h.data[base+8]), h.data[base+11]
	}
	if fn.Flags&0x20 != 0 {
		fn.Overflow = true
		large := uint64(fn.NameID)<<16 | uint64(fn.BytecodeOffset)
		size := 23
		if h.spec.layout == hermesClassic {
			large = uint64(fn.InfoOffset)<<16 | uint64(fn.BytecodeOffset)
			size = 31
		}
		if h.spec.layout == hermesTyped {
			large = uint64(fn.NameID)<<24 | uint64(fn.BytecodeOffset)
			size = 36
		}
		if large > math.MaxUint32 || large < hermesHeaderSize || !rangeFits(int(large), size, len(h.data)) {
			return fn, fmt.Errorf("function %d large header is out of bounds", id)
		}
		base = int(large)
		fn.HeaderOffset = uint32(base)
		fn.BytecodeOffset, fn.ParamCount = word(base), word(base+4)
		switch h.spec.layout {
		case hermesClassic:
			fn.BytecodeSize, fn.NameID = word(base+8), word(base+12)
			fn.InfoOffset, fn.FrameSize, fn.EnvironmentSize = word(base+16), word(base+20), word(base+24)
			fn.Flags = h.data[base+30]
		case hermesCompact:
			fn.BytecodeSize, fn.NameID, fn.FrameSize = word(base+8), word(base+12), word(base+16)
			fn.Flags = h.data[base+22]
		case hermesTyped:
			fn.BytecodeSize, fn.NameID, fn.FrameSize = word(base+12), word(base+16), word(base+28)
			fn.Flags = h.data[base+35]
		}
		if fn.Flags&0x20 != 0 {
			return fn, fmt.Errorf("function %d has a recursively overflowed header", id)
		}
	}
	if fn.BytecodeSize > 0 && !rangeFits(int(fn.BytecodeOffset), int(fn.BytecodeSize), len(h.data)) {
		return fn, fmt.Errorf("function %d bytecode range is out of bounds", id)
	}
	fn.Valid = true
	return fn, nil
}

func (h *HermesIndex) StringByID(id uint32) (HermesString, bool) {
	if int(id) < len(h.Strings) && h.Strings[id].ID == id {
		return h.Strings[id], true
	}
	i := sort.Search(len(h.Strings), func(i int) bool { return h.Strings[i].ID >= id })
	if i < len(h.Strings) && h.Strings[i].ID == id {
		return h.Strings[i], true
	}
	return HermesString{}, false
}

func (h *HermesIndex) StringValues() []string {
	values := make([]string, 0, len(h.Strings))
	for _, s := range h.Strings {
		if s.Value != "" {
			values = append(values, s.Value)
		}
	}
	return values
}

func (h *HermesIndex) parseModuleTable(base int) (int, error) {
	advance := func(size uint64, name string) error {
		if size == 0 {
			return nil
		}
		base = align4(base)
		if size > uint64(len(h.data)) || !rangeFits(base, int(size), len(h.data)) {
			return fmt.Errorf("%s table/buffer is out of bounds", name)
		}
		base += int(size)
		return nil
	}
	header := h.Header
	steps := []struct {
		name string
		size uint64
	}{
		{"array/literal-value", uint64(header.ArrayBufferSize) + uint64(header.LiteralValueBufferSize)},
		{"object-key", uint64(header.ObjKeyBufferSize)},
		{"object-value/shape", uint64(header.ObjValueBufferSize) + uint64(header.ObjShapeTableCount)*8},
		{"bigint", uint64(header.BigIntCount) * 8}, {"bigint-storage", uint64(header.BigIntStorageSize)},
		{"regexp", uint64(header.RegExpCount) * 8}, {"regexp-storage", uint64(header.RegExpStorageSize)},
	}
	for _, step := range steps {
		if err := advance(step.size, step.name); err != nil {
			return base, err
		}
	}
	modulesBase := align4(base)
	if err := advance(uint64(header.CJSModuleCount)*8, "CJS module"); err != nil {
		return base, err
	}
	for i := uint32(0); i < header.CJSModuleCount; i++ {
		off := modulesBase + int(i)*8
		a, b := h.order.Uint32(h.data[off:]), h.order.Uint32(h.data[off+4:])
		if b >= header.FunctionCount {
			h.diagnose(fmt.Sprintf("module %d function index is out of bounds", i))
			continue
		}
		module := HermesModule{Index: i, NameID: math.MaxUint32, ModuleID: a, FunctionIndex: b, Static: header.Options&2 != 0}
		if !module.Static {
			name, ok := h.StringByID(a)
			if !ok {
				h.diagnose(fmt.Sprintf("module %d filename string is unavailable", i))
				continue
			}
			module.NameID, module.Name = a, name.Value
		}
		h.Modules = append(h.Modules, module)
	}
	if err := advance(uint64(header.FunctionSourceCount)*8, "function-source"); err != nil {
		return base, err
	}
	return base, nil
}

func decodeHermesUTF16(raw []byte, order binary.ByteOrder) string {
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = order.Uint16(raw[i*2 : i*2+2])
	}
	return string(utf16.Decode(units))
}

func skipTable(offset int, count uint32, width, limit int, name string) (int, error) {
	size, ok := checkedProduct(count, width, limit-offset)
	if !ok {
		return 0, fmt.Errorf("%w: %s table out of bounds", ErrMalformedHermes, name)
	}
	return offset + size, nil
}
func checkedProduct(count uint32, width, available int) (int, bool) {
	if width <= 0 || available < 0 || uint64(count) > uint64(available)/uint64(width) {
		return 0, false
	}
	return int(count) * width, true
}
func rangeFits(offset, size, limit int) bool {
	return offset >= 0 && size >= 0 && offset <= limit && size <= limit-offset
}
func align4(v int) int { return (v + 3) &^ 3 }
