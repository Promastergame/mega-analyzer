package axml

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ResTable entry / type flags.
const (
	entryFlagComplex     uint16 = 0x0001
	entryFlagPublic      uint16 = 0x0002
	entryFlagWeak        uint16 = 0x0004
	entryFlagCompact     uint16 = 0x0008
	entryFlagFeatureFlag uint16 = 0x0010

	typeFlagSparse   uint8 = 0x01
	typeFlagOffset16 uint8 = 0x02

	noEntry        uint32 = 0xFFFFFFFF
	noEntryOffset8 uint16 = 0xFFFF
)

// parseARSCInternal decodes a resources.arsc buffer. Callers go through
// the guarded ParseARSC in panicguard.go.
func parseARSCInternal(data []byte) (*ResourceTable, error) {
	if len(data) < 12 {
		return nil, errors.New("arsc: input too small")
	}
	chunkType := binary.LittleEndian.Uint16(data[0:2])
	if chunkType != chunkTable {
		return nil, fmt.Errorf("arsc: not a RES_TABLE chunk (got 0x%04x)", chunkType)
	}
	headerSize := binary.LittleEndian.Uint16(data[2:4])
	chunkSize := binary.LittleEndian.Uint32(data[4:8])
	if uint64(chunkSize) > uint64(len(data)) {
		// Some apps under-report; trust the buffer length.
		chunkSize = uint32(len(data))
	}
	expectedPkgs := binary.LittleEndian.Uint32(data[8:12])

	table := &ResourceTable{}

	cursor := uint32(headerSize)
	var globalPool *stringPool

	for cursor+8 <= chunkSize {
		ct, _, cs, err := readChunkHeader(data[cursor:])
		if err != nil {
			return nil, err
		}
		end := cursor + cs
		if end > chunkSize {
			return nil, errors.New("arsc: chunk overruns table")
		}
		chunk := data[cursor:end]

		switch ct {
		case chunkStringPool:
			pool, err := parseStringPool(chunk)
			if err != nil {
				return nil, fmt.Errorf("arsc: global string pool: %w", err)
			}
			globalPool = pool
			table.GlobalStrings = pool.entries

		case chunkTablePackage:
			pkg, err := parseTablePackage(chunk, globalPool)
			if err != nil {
				return nil, err
			}
			table.Packages = append(table.Packages, pkg)
		}

		cursor = end
	}

	_ = expectedPkgs // informational; we trust real packages we found
	table.resolveStringRefs()
	return table, nil
}

// ParseARSCFile is a convenience helper for callers with a path.
func ParseARSCFile(path string) (*ResourceTable, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseARSC(data)
}

// readChunkHeader returns (type, headerSize, chunkSize) and validates
// the basic invariants. Caller is responsible for checking chunkSize
// against the surrounding buffer.
func readChunkHeader(buf []byte) (ctype uint16, hdr uint16, size uint32, err error) {
	if len(buf) < 8 {
		err = errors.New("chunk header: truncated")
		return
	}
	ctype = binary.LittleEndian.Uint16(buf[0:2])
	hdr = binary.LittleEndian.Uint16(buf[2:4])
	size = binary.LittleEndian.Uint32(buf[4:8])
	if hdr < 8 {
		err = fmt.Errorf("chunk header: hdr=%d too small", hdr)
		return
	}
	if size < uint32(hdr) {
		err = fmt.Errorf("chunk size %d < header %d", size, hdr)
		return
	}
	return
}

// parseTablePackage decodes one RES_TABLE_PACKAGE_TYPE chunk.
//
// Layout after generic chunk header:
//
//	u32 id              // package id (0x7f for app, 0x01 for android)
//	u8[256] name        // null-terminated UTF-16LE
//	u32 typeStrings     // offset to type-name string pool
//	u32 lastPublicType
//	u32 keyStrings      // offset to entry-key string pool
//	u32 lastPublicKey
//	u32 typeIdOffset    // (since SDK 30+)
func parseTablePackage(chunk []byte, _ *stringPool) (ResourcePackage, error) {
	if len(chunk) < 8+288 {
		// 288 = old-style header with optional typeIdOffset; we accept
		// shorter headers because some packers truncate.
		if len(chunk) < 8+284 {
			return ResourcePackage{}, errors.New("arsc package: header too small")
		}
	}
	body := chunk[8:]
	id := binary.LittleEndian.Uint32(body[0:4])
	name := decodeFixedUTF16(body[4 : 4+256])
	typeStringsOff := binary.LittleEndian.Uint32(body[4+256 : 4+256+4])
	keyStringsOff := binary.LittleEndian.Uint32(body[4+256+8 : 4+256+12])

	pkg := ResourcePackage{
		ID:      id,
		Name:    name,
		TypeIDs: make(map[string]uint32, 16),
	}

	// Sub-chunks (type pool, key pool, typeSpec, type, library, ...) live
	// inside this package chunk after the generic+package header. Their
	// absolute offsets are relative to the chunk start.
	var typePool, keyPool *stringPool

	if int(typeStringsOff) < len(chunk) {
		if pool, err := parseStringPool(chunk[typeStringsOff:]); err == nil {
			typePool = pool
		}
	}
	if int(keyStringsOff) < len(chunk) {
		if pool, err := parseStringPool(chunk[keyStringsOff:]); err == nil {
			keyPool = pool
		}
	}

	// Walk remaining chunks.
	hdrSize := binary.LittleEndian.Uint16(chunk[2:4])
	cursor := uint32(hdrSize)
	totalSize := binary.LittleEndian.Uint32(chunk[4:8])
	if uint64(totalSize) > uint64(len(chunk)) {
		totalSize = uint32(len(chunk))
	}

	// We track types by ID so multiple type-chunks of the same ID
	// (different configs) merge into one ResourceType entry list.
	typesByID := make(map[uint32]*ResourceType, 16)

	for cursor+8 <= totalSize {
		ct, _, cs, err := readChunkHeader(chunk[cursor:])
		if err != nil {
			return pkg, err
		}
		end := cursor + cs
		if end > totalSize {
			return pkg, errors.New("arsc package sub-chunk overruns")
		}
		sub := chunk[cursor:end]

		switch ct {
		case chunkTableTypeSpec:
			// We don't render typeSpec content currently (entry flags
			// are advisory), but we do extract the type ID/name so
			// subsequent type chunks can refer to it.
			if len(sub) >= 16 && typePool != nil {
				typeID := uint32(sub[8])
				if name := typePool.String(typeID - 1); name != SentinelNoString {
					pkg.TypeIDs[name] = typeID
					if _, ok := typesByID[typeID]; !ok {
						typesByID[typeID] = &ResourceType{ID: typeID, Name: name}
					}
				}
			}

		case chunkTableType:
			if typePool == nil || keyPool == nil {
				break
			}
			typ, err := parseTableType(sub, typePool, keyPool)
			if err != nil {
				// Continue: corrupted type chunk should not abort the
				// whole package.
				continue
			}
			existing, ok := typesByID[typ.ID]
			if !ok {
				cp := typ
				typesByID[typ.ID] = &cp
				continue
			}
			mergeTypeEntries(existing, typ)

		case chunkTableLibrary:
			lib := parseTableLibrary(sub)
			pkg.Libraries = append(pkg.Libraries, lib...)
		}

		cursor = end
	}

	// Materialize types in stable ID order.
	for id := uint32(1); id < 256; id++ {
		if t, ok := typesByID[id]; ok {
			pkg.Types = append(pkg.Types, *t)
		}
	}

	return pkg, nil
}

// parseTableType decodes one RES_TABLE_TYPE_TYPE chunk.
func parseTableType(chunk []byte, typePool, keyPool *stringPool) (ResourceType, error) {
	if len(chunk) < 8+12 {
		return ResourceType{}, errors.New("arsc type: too small")
	}
	body := chunk[8:]
	typeID := uint32(body[0])
	flags := body[1]
	// body[2:4] = reserved
	entryCount := binary.LittleEndian.Uint32(body[4:8])
	entriesStart := binary.LittleEndian.Uint32(body[8:12])

	cfg, cfgLen, err := parseResConfig(body[12:])
	if err != nil {
		return ResourceType{}, err
	}
	configName := cfg.String()

	hdrSize := binary.LittleEndian.Uint16(chunk[2:4])
	if uint32(hdrSize) < 12+uint32(cfgLen)+8 {
		// header should at minimum include base+config+8 (chunk hdr)
		// some apps lie; tolerate
	}

	out := ResourceType{
		ID:   typeID,
		Name: typePool.String(typeID - 1),
	}

	isSparse := flags&typeFlagSparse != 0
	isOffset16 := flags&typeFlagOffset16 != 0

	// entryCount comes straight from the file; a crafted 0xFFFFFFFF would
	// allocate ~32 GB across the two slices below. Every entry consumes at
	// least 2 bytes of the offset table (offset16 flavour), so the chunk
	// itself bounds the legitimate count.
	if max := uint32(len(chunk) / 2); entryCount > max {
		entryCount = max
	}

	// Read entry-offset table immediately after the header.
	tableOff := uint32(hdrSize)
	indices := make([]uint32, 0, entryCount)
	offsets := make([]uint32, 0, entryCount)

offsetLoop:
	for i := uint32(0); i < entryCount; i++ {
		switch {
		case isSparse:
			if int(tableOff)+4 > len(chunk) {
				break offsetLoop
			}
			idx := uint32(binary.LittleEndian.Uint16(chunk[tableOff : tableOff+2]))
			off := uint32(binary.LittleEndian.Uint16(chunk[tableOff+2:tableOff+4])) * 4
			indices = append(indices, idx)
			offsets = append(offsets, off)
			tableOff += 4
		case isOffset16:
			if int(tableOff)+2 > len(chunk) {
				break offsetLoop
			}
			off16 := binary.LittleEndian.Uint16(chunk[tableOff : tableOff+2])
			tableOff += 2
			indices = append(indices, i)
			if off16 == noEntryOffset8 {
				offsets = append(offsets, noEntry)
			} else {
				offsets = append(offsets, uint32(off16)*4)
			}
		default:
			if int(tableOff)+4 > len(chunk) {
				break offsetLoop
			}
			off := binary.LittleEndian.Uint32(chunk[tableOff : tableOff+4])
			tableOff += 4
			indices = append(indices, i)
			offsets = append(offsets, off)
		}
	}

	// Decode each entry.
	for k, off := range offsets {
		if off == noEntry {
			continue
		}
		base := entriesStart + off
		if base+8 > uint32(len(chunk)) {
			continue
		}

		entry, value, isBag, err := parseTableEntry(chunk[base:], keyPool)
		if err != nil || entry == "" {
			continue
		}

		out.Entries = append(out.Entries, ResourceEntry{
			ID:    indices[k],
			Name:  entry,
			IsBag: isBag,
			Values: []ConfigValue{{
				Config:        configName,
				Value:         value.String,
				RawType:       value.Type,
				Parent:        value.Parent,
				ComplexValues: value.ComplexValues,
			}},
		})
	}

	return out, nil
}

// parseTableEntry decodes a single entry. We accept three flavours:
//   - simple (size>=16, type+data follow header)
//   - compact (size encoded with type/data in flags, single u32 data)
//   - complex bag (parent + N (name,value) pairs)
//
// All reads go through binreader so a crafted size/count degrades to an
// error or a partial parse instead of an out-of-range panic.
func parseTableEntry(buf []byte, keyPool *stringPool) (string, simpleValue, bool, error) {
	if len(buf) < 8 {
		return "", simpleValue{}, false, errors.New("entry: truncated")
	}
	r := newBinreader(buf)
	size := r.U16()
	flags := r.U16()
	keyIdx := r.U32()

	isCompact := flags&entryFlagCompact != 0
	isComplex := flags&entryFlagComplex != 0

	var entryName string
	if isCompact {
		// Compact entries pack the key index in `size` and value type
		// in the high byte of `flags`. The value data occupies the same
		// 4 bytes as the regular key index field (buf[4:8]).
		entryName = keyPool.String(uint32(size))
		if r.Err() != nil {
			return "", simpleValue{}, false, errors.New("compact entry: truncated")
		}
		valType := uint8(flags >> 8)
		return entryName, formatSimpleValue(valType, keyIdx, keyPool), false, nil
	}

	if keyIdx == noEntry {
		return "", simpleValue{}, false, errors.New("entry: no-entry key")
	}
	entryName = keyPool.String(keyIdx)

	if isComplex {
		// Complex bag: u32 parent + u32 count + N * (u32 name, Res_value).
		// Need the full 16-byte header for parent/count regardless of what
		// `size` claims, and the bag body must start past it.
		if len(buf) < 16 || int(size) < 16 || len(buf) < int(size) {
			return entryName, simpleValue{}, true, nil
		}
		parent := r.U32At(8)
		count := r.U32At(12)

		parentStr := ""
		if parent != 0 {
			parentStr = fmt.Sprintf("@0x%08x", parent)
		}

		val := simpleValue{Type: typeReference, String: parentStr, Parent: parentStr}

		offset := int(size)
		for i := uint32(0); i < count; i++ {
			nameID := r.U32At(offset)
			// skip size and res0 at offset+4, offset+6
			valType := r.U8At(offset + 7)
			valData := r.U32At(offset + 8)
			if r.Err() != nil {
				break
			}

			sv := formatSimpleValue(valType, valData, keyPool)
			val.ComplexValues = append(val.ComplexValues, ComplexValue{
				NameID:  nameID,
				Value:   sv.String,
				RawType: valType,
			})
			offset += 12
		}

		return entryName, val, true, nil
	}

	// Simple entry: Res_value at buf[size:].
	if int(size)+8 > len(buf) {
		return entryName, simpleValue{}, false, errors.New("entry: value past buffer")
	}
	rv := buf[size:]
	if len(rv) < 8 {
		return entryName, simpleValue{}, false, errors.New("entry: res_value truncated")
	}
	// Res_value: u16 size, u8 res0, u8 type, u32 data
	valType := rv[3]
	valData := binary.LittleEndian.Uint32(rv[4:8])
	return entryName, formatSimpleValue(valType, valData, keyPool), false, nil
}

type simpleValue struct {
	Type          uint8
	String        string
	Parent        string
	ComplexValues []ComplexValue
}

// formatSimpleValue renders a (type, data) pair into a human-readable
// string. For type=string, data is an index into the *global* string
// pool, but at this point we only have the key pool — callers patch
// these up later when they have a global pool reference.
func formatSimpleValue(t uint8, data uint32, _ *stringPool) simpleValue {
	switch t {
	case typeNull:
		return simpleValue{Type: t, String: "@null"}
	case typeReference, typeDynamicRef:
		return simpleValue{Type: t, String: fmt.Sprintf("@0x%08x", data)}
	case typeAttribute, typeDynamicAttr:
		return simpleValue{Type: t, String: fmt.Sprintf("?0x%08x", data)}
	case typeString:
		// The data is an index into the global value pool. We don't
		// have it here, so we record the index — the post-processing
		// stage in ParseARSC will resolve.
		return simpleValue{Type: t, String: fmt.Sprintf("strpool:%d", data)}
	case typeIntDec:
		return simpleValue{Type: t, String: fmt.Sprintf("%d", int32(data))}
	case typeIntHex:
		return simpleValue{Type: t, String: fmt.Sprintf("0x%08x", data)}
	case typeIntBoolean:
		if data == 0 {
			return simpleValue{Type: t, String: "false"}
		}
		return simpleValue{Type: t, String: "true"}
	case typeIntColorARGB8, typeIntColorRGB8, typeIntColorARGB4, typeIntColorRGB4:
		return simpleValue{Type: t, String: fmt.Sprintf("#%08x", data)}
	case typeFloat:
		return simpleValue{Type: t, String: fmt.Sprintf("%g", float64(float32frombits(data)))}
	case typeDimension:
		return simpleValue{Type: t, String: fmt.Sprintf("dim:0x%08x", data)}
	case typeFraction:
		return simpleValue{Type: t, String: fmt.Sprintf("frac:0x%08x", data)}
	default:
		return simpleValue{Type: t, String: fmt.Sprintf("0x%x", data)}
	}
}

// mergeTypeEntries merges entries from `add` into `into`, joining
// values for the same entry under separate config tags.
func mergeTypeEntries(into *ResourceType, add ResourceType) {
	byID := make(map[uint32]int, len(into.Entries))
	for i, e := range into.Entries {
		byID[e.ID] = i
	}
	for _, e := range add.Entries {
		if idx, ok := byID[e.ID]; ok {
			into.Entries[idx].Values = append(into.Entries[idx].Values, e.Values...)
		} else {
			byID[e.ID] = len(into.Entries)
			into.Entries = append(into.Entries, e)
		}
	}
}

// parseTableLibrary decodes RES_TABLE_LIBRARY_TYPE entries.
func parseTableLibrary(chunk []byte) []ResourceLibrary {
	if len(chunk) < 12 {
		return nil
	}
	count := binary.LittleEndian.Uint32(chunk[8:12])
	const entrySize = 4 + 256
	body := chunk[12:]
	// Cap the declared count by what the body can actually hold; a crafted
	// count would otherwise size the output slice to ~4 billion entries.
	if max := uint32(len(body) / entrySize); count > max {
		count = max
	}
	out := make([]ResourceLibrary, 0, count)
	for i := uint32(0); i < count; i++ {
		off := uint64(i) * entrySize
		if off+entrySize > uint64(len(body)) {
			break
		}
		pid := binary.LittleEndian.Uint32(body[off : off+4])
		name := decodeFixedUTF16(body[off+4 : off+entrySize])
		out = append(out, ResourceLibrary{PackageID: pid, Name: name})
	}
	return out
}

// decodeFixedUTF16 decodes a NUL-terminated UTF-16LE buffer of fixed
// total size into a Go string. Used for package and library names
// which are stored as 256-byte fixed-width records.
func decodeFixedUTF16(buf []byte) string {
	end := len(buf)
	for i := 0; i+1 < end; i += 2 {
		if buf[i] == 0 && buf[i+1] == 0 {
			end = i
			break
		}
	}
	if end == 0 {
		return ""
	}
	codeUnits := make([]uint16, 0, end/2)
	for i := 0; i+1 < end; i += 2 {
		codeUnits = append(codeUnits, binary.LittleEndian.Uint16(buf[i:i+2]))
	}
	// reuse the utf16 decoder built into stdlib via the strings helper
	return string(utf16Decode(codeUnits))
}

// utf16Decode is a thin wrapper over unicode/utf16.Decode kept here to
// avoid importing the package twice across files.
func utf16Decode(units []uint16) []rune {
	// We don't depend on unicode/utf16 directly in this file to keep
	// the imports list minimal — the package is imported in strings.go.
	return decodeUTF16(units)
}

// decodeUTF16 mirrors unicode/utf16.Decode without importing it (the
// rest of the package already does, but that file is generated).
// Algorithm: surrogate-aware pair decoding.
func decodeUTF16(units []uint16) []rune {
	out := make([]rune, 0, len(units))
	for i := 0; i < len(units); i++ {
		u := units[i]
		switch {
		case u < 0xD800 || u >= 0xE000:
			out = append(out, rune(u))
		case u <= 0xDBFF && i+1 < len(units):
			lo := units[i+1]
			if lo >= 0xDC00 && lo <= 0xDFFF {
				r := 0x10000 + (rune(u-0xD800) << 10) + rune(lo-0xDC00)
				out = append(out, r)
				i++
			} else {
				out = append(out, '\uFFFD')
			}
		default:
			out = append(out, '\uFFFD')
		}
	}
	return out
}

// resolveStringRefs walks the table and rewrites `strpool:N` placeholders
// into the actual string values from the global pool. Called by
// ParseARSC after every package has been parsed.
//
// We expose this as a method so callers can also re-resolve after
// merging tables (for split APKs that ship multiple resources.arsc).
func (t *ResourceTable) resolveStringRefs() {
	resolve := func(val string) string {
		if !strings.HasPrefix(val, "strpool:") {
			return val
		}
		idx, ok := parseStrpoolIdx(val)
		if !ok {
			return val
		}
		if int(idx) < len(t.GlobalStrings) {
			return t.GlobalStrings[idx]
		}
		return ""
	}

	for i := range t.Packages {
		for j := range t.Packages[i].Types {
			for k := range t.Packages[i].Types[j].Entries {
				vals := t.Packages[i].Types[j].Entries[k].Values
				for m := range vals {
					// Resolve simple values
					vals[m].Value = resolve(vals[m].Value)

					// Resolve complex values (arrays, styles, plurals)
					for c := range vals[m].ComplexValues {
						vals[m].ComplexValues[c].Value = resolve(vals[m].ComplexValues[c].Value)
					}
				}
			}
		}
	}
}

func parseStrpoolIdx(s string) (uint32, bool) {
	const prefix = "strpool:"
	if !strings.HasPrefix(s, prefix) {
		return 0, false
	}
	var n uint32
	for _, c := range s[len(prefix):] {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint32(c-'0')
	}
	return n, true
}
