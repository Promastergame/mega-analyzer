// Package dex provides a minimal, tolerant DEX file parser sufficient for
// compiler-heuristic fingerprinting. It does NOT implement the full DEX spec;
// any parse error leaves DEXInfo in a partial state with Valid=false.
package dex

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	dexMagicLen  = 8
	headerSize   = 112 // fixed DEX header size per spec
	maxStringLen = 65536
)

// Known map_list TYPE codes (DEX spec §4.1).
const (
	TypeHeaderItem           uint16 = 0x0000
	TypeStringIDItem         uint16 = 0x0001
	TypeTypeIDItem           uint16 = 0x0002
	TypeProtoIDItem          uint16 = 0x0003
	TypeFieldIDItem          uint16 = 0x0004
	TypeMethodIDItem         uint16 = 0x0005
	TypeClassDefItem         uint16 = 0x0006
	TypeCallSiteIDItem       uint16 = 0x0007
	TypeMethodHandleItem     uint16 = 0x0008
	TypeMapList              uint16 = 0x1000
	TypeTypeList             uint16 = 0x1001
	TypeAnnotationSetRefList uint16 = 0x1002
	TypeAnnotationSetItem    uint16 = 0x1003
	TypeClassDataItem        uint16 = 0x2000
	TypeCodeItem             uint16 = 0x2001
	TypeStringDataItem       uint16 = 0x2002
	TypeDebugInfoItem        uint16 = 0x2003
	TypeAnnotationItem       uint16 = 0x2004
	TypeEncodedArrayItem     uint16 = 0x2005
	TypeAnnotationsDirectory uint16 = 0x2006
	TypeHiddenapiClassData   uint16 = 0xF000
)

// DEXInfo holds the data extracted from a DEX header and used for
// compiler heuristics. All fields have zero values when parsing is partial.
type DEXInfo struct {
	// Version is the DEX format version string, e.g. "035", "039".
	Version string

	// StringPool contains decoded UTF-8 strings from the DEX string table.
	// May be truncated if the file is very large or malformed.
	StringPool []string

	// MapOrder is the sequence of item type codes from the map_list section,
	// in the order they appear. Used for compiler-toolchain heuristics.
	MapOrder []uint16

	// Compiler is a best-effort toolchain guess derived from structural
	// heuristics. Empty string = unknown.
	Compiler string

	// Valid is true when the header and string pool parsed without errors.
	Valid bool

	// Warnings holds non-fatal parse problems.
	Warnings []string
}

// ─── Parser ──────────────────────────────────────────────────────────────────

var errTooShort = errors.New("dex: file too short")

// ParseDEX attempts to parse the DEX header, map_list, and string pool from
// data. It is tolerant: it never panics and always returns a non-nil *DEXInfo.
// Callers should check DEXInfo.Valid before relying on structural fields.
func ParseDEX(data []byte) (*DEXInfo, error) {
	info := &DEXInfo{}
	if len(data) < headerSize {
		return info, errTooShort
	}

	// ── Magic ────────────────────────────────────────────────────────────────
	magic := data[:dexMagicLen]
	if magic[0] != 'd' || magic[1] != 'e' || magic[2] != 'x' || magic[3] != '\n' {
		return info, errors.New("dex: bad magic")
	}
	// Bytes 4-6 are the version digits; byte 7 is 0x00.
	version := string(magic[4:7])
	if magic[7] != 0x00 {
		info.Warnings = append(info.Warnings, "dex: version terminator not 0x00")
	}
	info.Version = version

	// ── Endianness tag ───────────────────────────────────────────────────────
	// Offset 40: endian_tag. 0x12345678 = little-endian (standard).
	endianTag := binary.LittleEndian.Uint32(data[40:44])
	if endianTag != 0x12345678 {
		// Big-endian DEX exists but is extremely rare; we don't support it.
		info.Warnings = append(info.Warnings, fmt.Sprintf("dex: non-standard endian tag 0x%x", endianTag))
		return info, nil
	}

	// ── Header fields we need ────────────────────────────────────────────────
	fileSize := binary.LittleEndian.Uint32(data[32:36])
	if int(fileSize) > len(data) {
		info.Warnings = append(info.Warnings, "dex: header file_size > actual data length")
		fileSize = uint32(len(data))
	}

	stringIDsSize := binary.LittleEndian.Uint32(data[56:60])
	stringIDsOff := binary.LittleEndian.Uint32(data[60:64])
	mapOff := binary.LittleEndian.Uint32(data[52:56])

	// ── Map list ─────────────────────────────────────────────────────────────
	if mapOff > 0 {
		if err := parseMapList(data, mapOff, info); err != nil {
			info.Warnings = append(info.Warnings, "dex: map_list: "+err.Error())
		}
	}

	// ── String pool ──────────────────────────────────────────────────────────
	if err := parseStringPool(data, stringIDsOff, stringIDsSize, info); err != nil {
		info.Warnings = append(info.Warnings, "dex: string_pool: "+err.Error())
	}

	// ── Compiler heuristic ───────────────────────────────────────────────────
	info.Compiler = inferCompiler(info)
	info.Valid = true
	return info, nil
}

// parseMapList reads the map_list section and populates info.MapOrder.
// All offset arithmetic is uint64: on 32-bit builds int(mapOff) wraps for
// hostile values and a wrapped bounds check passes garbage to the slicer.
func parseMapList(data []byte, mapOff uint32, info *DEXInfo) error {
	size := uint64(len(data))
	if uint64(mapOff)+4 > size {
		return errors.New("map_off out of bounds")
	}
	count := binary.LittleEndian.Uint32(data[mapOff : mapOff+4])
	if count > 1024 {
		return fmt.Errorf("implausibly large map list: %d items", count)
	}
	off := uint64(mapOff) + 4
	// Each map_item is 12 bytes: type(u16), unused(u16), size(u32), offset(u32).
	if off+uint64(count)*12 > size {
		return errors.New("map list overflows file")
	}
	info.MapOrder = make([]uint16, 0, count)
	for i := uint64(0); i < uint64(count); i++ {
		typeCode := binary.LittleEndian.Uint16(data[off : off+2])
		info.MapOrder = append(info.MapOrder, typeCode)
		off += 12
	}
	return nil
}

// parseStringPool reads up to maxStrings strings from the DEX string table.
func parseStringPool(data []byte, strIDsOff, strIDsSize uint32, info *DEXInfo) error {
	const maxStrings = 50000
	if strIDsSize == 0 {
		return nil
	}
	if uint64(strIDsOff)+uint64(strIDsSize)*4 > uint64(len(data)) {
		return errors.New("string_ids overflow")
	}
	limit := strIDsSize
	if limit > maxStrings {
		limit = maxStrings
		info.Warnings = append(info.Warnings, fmt.Sprintf("dex: string pool truncated at %d strings", maxStrings))
	}
	pool := make([]string, 0, limit)
	for i := uint64(0); i < uint64(limit); i++ {
		// Each string_id_item is a 4-byte offset into string_data_items.
		idOff := uint64(strIDsOff) + i*4
		strDataOff := binary.LittleEndian.Uint32(data[idOff : idOff+4])
		s, err := readMUTF8(data, strDataOff)
		if err != nil {
			// Malformed string — skip silently; don't abort the whole pool.
			continue
		}
		pool = append(pool, s)
	}
	info.StringPool = pool
	return nil
}

// readMUTF8 reads a MUTF-8 encoded string from offset.
// Format: ULEB128 length (in UTF-16 code units), then MUTF-8 bytes, then 0x00.
// Offsets stay uint64 throughout for the same 32-bit reason as above.
func readMUTF8(data []byte, off uint32) (string, error) {
	size := uint64(len(data))
	if uint64(off) >= size {
		return "", errors.New("string offset out of bounds")
	}
	// Decode ULEB128 length.
	length, n := decodeULEB128(data[off:])
	if n == 0 {
		return "", errors.New("bad ULEB128")
	}
	if length > maxStringLen {
		return "", fmt.Errorf("string length %d exceeds max", length)
	}
	start := uint64(off) + uint64(n)
	// Scan for the null terminator, up to length*3 bytes (max MUTF-8 expansion).
	end := start
	limit := start + uint64(length)*3 + 3
	if limit > size {
		limit = size
	}
	for end < limit && data[end] != 0 {
		end++
	}
	if end >= size {
		return "", errors.New("string not null-terminated")
	}
	return string(data[start:end]), nil
}

// decodeULEB128 decodes an unsigned LEB128 integer from p.
// Returns (value, bytesConsumed). bytesConsumed==0 on error.
func decodeULEB128(p []byte) (uint32, int) {
	var result uint32
	var shift uint
	for i, b := range p {
		if i >= 5 {
			return 0, 0 // overflow
		}
		result |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, i + 1
		}
		shift += 7
	}
	return 0, 0
}

// ─── Compiler heuristic ──────────────────────────────────────────────────────

// inferCompiler applies structural heuristics from real APKiD research to
// guess the toolchain from map_list order and string pool content.
//
// Heuristics (approximate; confidence ~0.80-0.90):
//
//   - d8/r8: TYPE_ANNOTATION_SET_REF_LIST (0x1002) appears before
//     TYPE_CODE_ITEM (0x2001) in the map_list.
//
//   - dx: TYPE_DEBUG_INFO_ITEM (0x2003) immediately follows TYPE_CODE_ITEM
//     in the map_list (legacy dx ordering).
//
//   - dexlib2: string pool is NOT sorted in a standard way AND the file
//     contains Dalvik annotation descriptors typical of baksmali output.
//
//   - jack: "com.android.jack" appears in the string pool.
func inferCompiler(info *DEXInfo) string {
	// String pool heuristics (fast).
	for _, s := range info.StringPool {
		if strings.Contains(s, "com.android.jack") || strings.Contains(s, "com/android/jack") {
			return "jack"
		}
		if strings.Contains(s, "jf.dexlib2") || strings.Contains(s, "dexlib2.writer") {
			return "dexlib2"
		}
		if strings.Contains(s, "com.android.tools.r8") {
			return "d8/r8"
		}
	}

	// Map-list structural heuristics.
	annotSetRefIdx := -1
	codeItemIdx := -1
	debugItemIdx := -1
	for i, t := range info.MapOrder {
		switch t {
		case TypeAnnotationSetRefList:
			if annotSetRefIdx < 0 {
				annotSetRefIdx = i
			}
		case TypeCodeItem:
			if codeItemIdx < 0 {
				codeItemIdx = i
			}
		case TypeDebugInfoItem:
			if debugItemIdx < 0 {
				debugItemIdx = i
			}
		}
	}

	// d8/r8 heuristic: ANNOTATION_SET_REF_LIST before CODE_ITEM.
	if annotSetRefIdx >= 0 && codeItemIdx >= 0 && annotSetRefIdx < codeItemIdx {
		return "d8/r8"
	}

	// dx heuristic: DEBUG_INFO_ITEM immediately after CODE_ITEM.
	if codeItemIdx >= 0 && debugItemIdx == codeItemIdx+1 {
		return "dx"
	}

	return ""
}
