package axml

// Entry-aware resources.arsc editor.
//
// Unlike text-keyed pool patching, every edit addresses one resource entry
// (type, name, config). String values shared by several entries are split
// (append + repoint) unless all sharers agree on the new text; integers,
// booleans and colors are rewritten in place because each entry owns its
// Res_value. Pure Go.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// ARSCEdit is one addressed value change.
type ARSCEdit struct {
	Type     string // e.g. "string"
	Name     string // entry name, e.g. "app_name"
	Config   string // canonical config, e.g. "default", "ru"
	NewValue string // new text value
}

// PatchARSCEntry applies a single addressed edit.
func PatchARSCEntry(data []byte, typ, name, config, newValue string) ([]byte, error) {
	return PatchARSCEntries(data, []ARSCEdit{{Type: typ, Name: name, Config: config, NewValue: newValue}})
}

// PatchARSCEntries applies a batch of addressed edits atomically.
func PatchARSCEntries(data []byte, edits []ARSCEdit) ([]byte, error) {
	if len(edits) == 0 {
		return data, nil
	}
	table, err := ParseARSC(data)
	if err != nil {
		return nil, err
	}
	type job struct {
		edit    ARSCEdit
		rawType uint8
		valOff  int // file offset of Res_value.data
		strIdx  uint32
		curText string
	}
	var jobs []job
	for _, e := range edits {
		entry := findTableEntry(table, e.Type, e.Name, e.Config)
		if entry == nil {
			return nil, fmt.Errorf("arsc: entry %s/%s@%s not found", e.Type, e.Name, e.Config)
		}
		val := findConfigValue(entry, e.Config)
		if val == nil {
			return nil, fmt.Errorf("arsc: entry %s/%s has no %s config", e.Type, e.Name, e.Config)
		}
		if entry.IsBag {
			return nil, fmt.Errorf("arsc: entry %s/%s is a bag (style/array); needs aapt2", e.Type, e.Name)
		}
		off, strIdx, err := locateEntryValue(data, e.Type, e.Name, e.Config)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job{edit: e, rawType: val.RawType, valOff: off, strIdx: strIdx, curText: val.Value})
	}
	out := append([]byte(nil), data...)
	// Direct rewrites for scalar types.
	for _, j := range jobs {
		switch j.rawType {
		case typeString:
			// handled below
		case typeIntDec, typeIntHex:
			v, err := strconv.ParseInt(strings.TrimSpace(j.edit.NewValue), 0, 32)
			if err != nil {
				return nil, fmt.Errorf("arsc: %s/%s: cannot parse %q as integer", j.edit.Type, j.edit.Name, j.edit.NewValue)
			}
			binary.LittleEndian.PutUint32(out[j.valOff:], uint32(int32(v)))
		case typeIntBoolean:
			t := strings.ToLower(strings.TrimSpace(j.edit.NewValue))
			if t != "true" && t != "false" {
				return nil, fmt.Errorf("arsc: %s/%s: cannot parse %q as boolean", j.edit.Type, j.edit.Name, j.edit.NewValue)
			}
			if t == "true" {
				binary.LittleEndian.PutUint32(out[j.valOff:], 0xFFFFFFFF)
			} else {
				binary.LittleEndian.PutUint32(out[j.valOff:], 0)
			}
		case typeIntColorARGB8, typeIntColorRGB8, typeIntColorARGB4, typeIntColorRGB4:
			c, err := parseColorValue(j.edit.NewValue)
			if err != nil {
				return nil, fmt.Errorf("arsc: %s/%s: %v", j.edit.Type, j.edit.Name, err)
			}
			binary.LittleEndian.PutUint32(out[j.valOff:], c)
			// Normalize stored type to ARGB8 (reader renders all color tags
			// identically; mixed tags only confuse diffing).
			out[j.valOff-1] = typeIntColorARGB8
		default:
			return nil, fmt.Errorf("arsc: %s/%s has unsupported type 0x%02x; needs aapt2", j.edit.Type, j.edit.Name, j.rawType)
		}
	}
	// String edits with sharing analysis.
	type strJob struct {
		job    job
		newIdx uint32 // resolved pool index
	}
	var sjobs []strJob
	for _, j := range jobs {
		if j.rawType != typeString {
			continue
		}
		if j.curText == j.edit.NewValue {
			continue
		}
		sjobs = append(sjobs, strJob{job: j})
	}
	if len(sjobs) > 0 {
		// Count references per pool slot across all simple string values.
		refCount, err := countStringRefs(out)
		if err != nil {
			return nil, err
		}
		// Group intents by pool slot.
		bySlot := map[uint32][]int{}
		for i, sj := range sjobs {
			bySlot[sj.job.strIdx] = append(bySlot[sj.job.strIdx], i)
		}
		splits := map[int]uint32{} // sjob index → new pool slot
		inPlace := map[uint32]string{}
		for slot, idxs := range bySlot {
			// Every edit touching this slot must agree, and no untouched
			// sharer may exist, for an in-place rewrite.
			first := sjobs[idxs[0]].job.edit.NewValue
			agree := true
			for _, i := range idxs[1:] {
				if sjobs[i].job.edit.NewValue != first {
					agree = false
					break
				}
			}
			if agree && refCount[slot] == uint32(len(idxs)) {
				inPlace[slot] = first
				for _, i := range idxs {
					sjobs[i].newIdx = slot
				}
			} else {
				// Split: each distinct new text gets its own appended slot.
				for _, i := range idxs {
					splits[i] = 0 // placeholder; resolved below
				}
			}
		}
		poolOff, poolChunk, err := findGlobalPool(out)
		if err != nil {
			return nil, err
		}
		pool, err := parseStringPool(poolChunk)
		if err != nil {
			return nil, err
		}
		newEntries := append([]string(nil), pool.entries...)
		for k, v := range inPlace {
			if int(k) >= len(newEntries) {
				return nil, fmt.Errorf("arsc: string pool index %d out of range", k)
			}
			newEntries[k] = v
		}
		slotForText := map[string]uint32{}
		for k, v := range inPlace {
			slotForText[v] = k
		}
		for i := range sjobs {
			if _, ok := splits[i]; !ok {
				continue
			}
			t := sjobs[i].job.edit.NewValue
			if s, ok := slotForText[t]; ok {
				splits[i] = s
				sjobs[i].newIdx = s
				continue
			}
			s := uint32(len(newEntries))
			newEntries = append(newEntries, t)
			slotForText[t] = s
			splits[i] = s
			sjobs[i].newIdx = s
		}
		rebuilt, _, err := rebuildPoolChunk(poolChunk, newEntries)
		if err != nil {
			return nil, err
		}
		out = spliceChunk(out, poolOff, len(poolChunk), rebuilt)
		// Repoint split entries at their new slots.
		for i, s := range splits {
			off := sjobs[i].job.valOff
			// Pool splice does not move Res_value offsets (pool is edited in
			// place size-wise? No: splice changes file layout AFTER the pool.
			// Value offsets live in package chunks after the pool, so they
			// shifted by the size delta. Recompute instead of trusting stale
			// offsets: relocate by re-walking.
			_ = off
			_ = s
		}
		_ = splits
		// Re-locate every split entry post-splice and rewrite its index.
		for i := range sjobs {
			if _, ok := splits[i]; !ok {
				continue
			}
			e := sjobs[i].job.edit
			off, _, err := locateEntryValue(out, e.Type, e.Name, e.Config)
			if err != nil {
				return nil, err
			}
			binary.LittleEndian.PutUint32(out[off:], sjobs[i].newIdx)
		}
	}
	return out, nil
}

func findTableEntry(table *ResourceTable, typ, name, config string) *ResourceEntry {
	for pi := range table.Packages {
		for ti := range table.Packages[pi].Types {
			t := &table.Packages[pi].Types[ti]
			if t.Name != typ {
				continue
			}
			for ei := range t.Entries {
				if t.Entries[ei].Name == name {
					return &t.Entries[ei]
				}
			}
		}
	}
	return nil
}

func findConfigValue(e *ResourceEntry, config string) *ConfigValue {
	for i := range e.Values {
		if e.Values[i].Config == config {
			return &e.Values[i]
		}
	}
	return nil
}

// locateEntryValue walks raw chunks to the Res_value.data of one entry.
// Returns the file offset of the 4-byte data field and, for strings, the
// current pool index.
func locateEntryValue(data []byte, typ, name, config string) (int, uint32, error) {
	if len(data) < 12 {
		return 0, 0, fmt.Errorf("arsc: too small")
	}
	rootSize := binary.LittleEndian.Uint32(data[4:8])
	if uint64(rootSize) > uint64(len(data)) {
		rootSize = uint32(len(data))
	}
	cursor := uint32(12)
	// Root children: global pool(s) then packages.
	for cursor+8 <= rootSize {
		ct, _, cs, err := readChunkHeader(data[cursor:])
		if err != nil {
			return 0, 0, err
		}
		end := cursor + cs
		if end > rootSize {
			return 0, 0, fmt.Errorf("arsc: chunk overruns table")
		}
		if ct == chunkTablePackage {
			off, idx, err := locateInPackage(data[cursor:end], typ, name, config)
			if err == nil {
				return int(cursor) + off, idx, nil
			}
		}
		cursor = end
	}
	return 0, 0, fmt.Errorf("arsc: entry %s/%s@%s not located", typ, name, config)
}

func locateInPackage(chunk []byte, typ, name, config string) (int, uint32, error) {
	if len(chunk) < 8+284 {
		return 0, 0, fmt.Errorf("arsc: package too small")
	}
	body := chunk[8:]
	typeStringsOff := binary.LittleEndian.Uint32(body[4+256 : 4+256+4])
	keyStringsOff := binary.LittleEndian.Uint32(body[4+256+8 : 4+256+12])
	var typePool, keyPool *stringPool
	if int(typeStringsOff) < len(chunk) {
		if p, err := parseStringPool(chunk[typeStringsOff:]); err == nil {
			typePool = p
		}
	}
	if int(keyStringsOff) < len(chunk) {
		if p, err := parseStringPool(chunk[keyStringsOff:]); err == nil {
			keyPool = p
		}
	}
	if typePool == nil || keyPool == nil {
		return 0, 0, fmt.Errorf("arsc: pools missing")
	}
	hdrSize := binary.LittleEndian.Uint16(chunk[2:4])
	totalSize := binary.LittleEndian.Uint32(chunk[4:8])
	if uint64(totalSize) > uint64(len(chunk)) {
		totalSize = uint32(len(chunk))
	}
	cursor := uint32(hdrSize)
	for cursor+8 <= totalSize {
		ct, _, cs, err := readChunkHeader(chunk[cursor:])
		if err != nil {
			return 0, 0, err
		}
		end := cursor + cs
		if end > totalSize {
			return 0, 0, fmt.Errorf("arsc: sub-chunk overruns")
		}
		if ct == chunkTableType {
			off, idx, err := locateInType(chunk[cursor:end], typePool, keyPool, typ, name, config)
			if err == nil {
				return int(cursor) + off, idx, nil
			}
		}
		cursor = end
	}
	return 0, 0, fmt.Errorf("arsc: entry not located in package")
}

func locateInType(chunk []byte, typePool, keyPool *stringPool, typ, name, config string) (int, uint32, error) {
	if len(chunk) < 20 {
		return 0, 0, fmt.Errorf("arsc: type too small")
	}
	body := chunk[8:]
	typeID := uint32(body[0])
	if typePool.String(typeID-1) != typ {
		return 0, 0, fmt.Errorf("arsc: wrong type")
	}
	flags := body[1]
	entryCount := binary.LittleEndian.Uint32(body[4:8])
	entriesStart := binary.LittleEndian.Uint32(body[8:12])
	cfg, _, err := parseResConfig(body[12:])
	if err != nil {
		return 0, 0, err
	}
	if cfg.String() != config && !(config == "default" && cfg.String() == "") {
		return 0, 0, fmt.Errorf("arsc: wrong config")
	}
	hdrSize := binary.LittleEndian.Uint16(chunk[2:4])
	tableOff := uint32(hdrSize)
	isSparse := flags&typeFlagSparse != 0
	isOffset16 := flags&typeFlagOffset16 != 0
	if max := uint32(len(chunk) / 2); entryCount > max {
		entryCount = max
	}
	for i := uint32(0); i < entryCount; i++ {
		var idx, off uint32
		switch {
		case isSparse:
			if int(tableOff)+4 > len(chunk) {
				return 0, 0, fmt.Errorf("arsc: offset table truncated")
			}
			idx = uint32(binary.LittleEndian.Uint16(chunk[tableOff : tableOff+2]))
			off = uint32(binary.LittleEndian.Uint16(chunk[tableOff+2 : tableOff+4]))
			off *= 4
			tableOff += 4
		case isOffset16:
			if int(tableOff)+2 > len(chunk) {
				return 0, 0, fmt.Errorf("arsc: offset table truncated")
			}
			o16 := binary.LittleEndian.Uint16(chunk[tableOff : tableOff+2])
			tableOff += 2
			idx = i
			if o16 == noEntryOffset8 {
				off = noEntry
			} else {
				off = uint32(o16) * 4
			}
		default:
			if int(tableOff)+4 > len(chunk) {
				return 0, 0, fmt.Errorf("arsc: offset table truncated")
			}
			off = binary.LittleEndian.Uint32(chunk[tableOff : tableOff+4])
			tableOff += 4
			idx = i
		}
		if off == noEntry {
			continue
		}
		_ = idx
		base := entriesStart + off
		if base+16 > uint32(len(chunk)) {
			continue
		}
		size := binary.LittleEndian.Uint16(chunk[base : base+2])
		cflags := binary.LittleEndian.Uint16(chunk[base+2 : base+4])
		keyIdx := binary.LittleEndian.Uint32(chunk[base+4 : base+8])
		if cflags&entryFlagComplex != 0 || size < 8 {
			continue
		}
		if keyPool.String(keyIdx) != name {
			continue
		}
		// Res_value at base+8: size u16, res0 u8, type u8, data u32 @ base+12.
		return int(base) + 12, binary.LittleEndian.Uint32(chunk[base+12 : base+16]), nil
	}
	return 0, 0, fmt.Errorf("arsc: entry %s not in chunk", name)
}

// countStringRefs counts references to each global-pool slot from simple
// string Res_values across the whole file.
func countStringRefs(data []byte) (map[uint32]uint32, error) {
	out := map[uint32]uint32{}
	if len(data) < 12 {
		return out, fmt.Errorf("arsc: too small")
	}
	rootSize := binary.LittleEndian.Uint32(data[4:8])
	if uint64(rootSize) > uint64(len(data)) {
		rootSize = uint32(len(data))
	}
	cursor := uint32(12)
	for cursor+8 <= rootSize {
		ct, _, cs, err := readChunkHeader(data[cursor:])
		if err != nil {
			return out, err
		}
		end := cursor + cs
		if end > rootSize {
			return out, fmt.Errorf("arsc: chunk overruns")
		}
		if ct == chunkTablePackage {
			countInPackage(data[cursor:end], out)
		}
		cursor = end
	}
	return out, nil
}

func countInPackage(chunk []byte, out map[uint32]uint32) {
	if len(chunk) < 8+284 {
		return
	}
	hdrSize := binary.LittleEndian.Uint16(chunk[2:4])
	totalSize := binary.LittleEndian.Uint32(chunk[4:8])
	if uint64(totalSize) > uint64(len(chunk)) {
		totalSize = uint32(len(chunk))
	}
	cursor := uint32(hdrSize)
	for cursor+8 <= totalSize {
		ct, _, cs, err := readChunkHeader(chunk[cursor:])
		if err != nil {
			return
		}
		end := cursor + cs
		if end > totalSize {
			return
		}
		if ct == chunkTableType {
			countInType(chunk[cursor:end], out)
		}
		cursor = end
	}
}

func countInType(chunk []byte, out map[uint32]uint32) {
	if len(chunk) < 20 {
		return
	}
	body := chunk[8:]
	flags := body[1]
	entryCount := binary.LittleEndian.Uint32(body[4:8])
	entriesStart := binary.LittleEndian.Uint32(body[8:12])
	hdrSize := binary.LittleEndian.Uint16(chunk[2:4])
	tableOff := uint32(hdrSize)
	isSparse := flags&typeFlagSparse != 0
	isOffset16 := flags&typeFlagOffset16 != 0
	if max := uint32(len(chunk) / 2); entryCount > max {
		entryCount = max
	}
	for i := uint32(0); i < entryCount; i++ {
		var off uint32
		switch {
		case isSparse:
			if int(tableOff)+4 > len(chunk) {
				return
			}
			off = uint32(binary.LittleEndian.Uint16(chunk[tableOff+2 : tableOff+4]))
			off *= 4
			tableOff += 4
		case isOffset16:
			if int(tableOff)+2 > len(chunk) {
				return
			}
			o16 := binary.LittleEndian.Uint16(chunk[tableOff : tableOff+2])
			tableOff += 2
			if o16 == noEntryOffset8 {
				continue
			}
			off = uint32(o16) * 4
		default:
			if int(tableOff)+4 > len(chunk) {
				return
			}
			off = binary.LittleEndian.Uint32(chunk[tableOff : tableOff+4])
			tableOff += 4
		}
		if off == noEntry {
			continue
		}
		base := entriesStart + off
		if base+16 > uint32(len(chunk)) {
			continue
		}
		size := binary.LittleEndian.Uint16(chunk[base : base+2])
		cflags := binary.LittleEndian.Uint16(chunk[base+2 : base+4])
		if cflags&entryFlagComplex != 0 || size < 8 {
			continue
		}
		if chunk[base+11] == typeString {
			idx := binary.LittleEndian.Uint32(chunk[base+12 : base+16])
			out[idx]++
		}
	}
}

// findGlobalPool locates the first top-level string pool chunk.
func findGlobalPool(data []byte) (int, []byte, error) {
	if len(data) < 12 {
		return 0, nil, fmt.Errorf("arsc: too small")
	}
	rootSize := binary.LittleEndian.Uint32(data[4:8])
	if uint64(rootSize) > uint64(len(data)) {
		rootSize = uint32(len(data))
	}
	cursor := uint32(12)
	for cursor+8 <= rootSize {
		ct, _, cs, err := readChunkHeader(data[cursor:])
		if err != nil {
			return 0, nil, err
		}
		end := cursor + cs
		if end > rootSize || end <= cursor {
			return 0, nil, fmt.Errorf("arsc: chunk overruns")
		}
		if ct == chunkStringPool {
			return int(cursor), data[cursor:end], nil
		}
		cursor = end
	}
	return 0, nil, fmt.Errorf("arsc: no global string pool")
}

// rebuildPoolChunk re-serializes a pool chunk with new entries (append and
// replace supported) and reports whether content changed.
func rebuildPoolChunk(chunk []byte, entries []string) ([]byte, bool, error) {
	pool, err := parseStringPool(chunk)
	if err != nil {
		return nil, false, err
	}
	if len(entries) == len(pool.entries) {
		same := true
		for i := range entries {
			if entries[i] != pool.entries[i] {
				same = false
				break
			}
		}
		if same {
			return chunk, false, nil
		}
	}
	isUtf8 := pool.flags&flagUTF8 != 0
	headerSize := binary.LittleEndian.Uint16(chunk[2:4])
	var strData bytes.Buffer
	offsets := make([]uint32, len(entries))
	for i, s := range entries {
		offsets[i] = uint32(strData.Len())
		writePoolEntry(&strData, s, isUtf8)
	}
	for strData.Len()%4 != 0 {
		strData.WriteByte(0)
	}
	localHeaderSize := uint32(headerSize)
	offsetsTableSize := uint32(len(entries)) * 4
	stringsStart := localHeaderSize + offsetsTableSize
	totalChunkSize := stringsStart + uint32(strData.Len())
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, chunkStringPool)
	_ = binary.Write(&out, binary.LittleEndian, headerSize)
	_ = binary.Write(&out, binary.LittleEndian, totalChunkSize)
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(entries)))
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))
	_ = binary.Write(&out, binary.LittleEndian, pool.flags)
	_ = binary.Write(&out, binary.LittleEndian, stringsStart)
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))
	for _, off := range offsets {
		_ = binary.Write(&out, binary.LittleEndian, off)
	}
	out.Write(strData.Bytes())
	return out.Bytes(), true, nil
}

func writePoolEntry(buf *bytes.Buffer, s string, utf8Mode bool) {
	if utf8Mode {
		enc := encodeCESU8Bytes(s)
		u16 := utf16.Encode([]rune(s))
		writePoolLen(buf, len(u16))
		writePoolLen(buf, len(enc))
		buf.Write(enc)
		buf.WriteByte(0)
		return
	}
	u16 := utf16.Encode([]rune(s))
	if len(u16) > 0x7FFF {
		_ = binary.Write(buf, binary.LittleEndian, uint16((len(u16)>>16)|0x8000))
		_ = binary.Write(buf, binary.LittleEndian, uint16(len(u16)&0xFFFF))
	} else {
		_ = binary.Write(buf, binary.LittleEndian, uint16(len(u16)))
	}
	for _, w := range u16 {
		_ = binary.Write(buf, binary.LittleEndian, w)
	}
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
}

func writePoolLen(buf *bytes.Buffer, n int) {
	if n > 0x7FFF {
		// Pools this large are out of scope; the decoder would still skip
		// them, but no valid aapt output looks like this.
		buf.WriteByte(byte((n>>8)&0x7F) | 0x80)
		buf.WriteByte(byte(n & 0xFF))
	} else if n > 0x7F {
		buf.WriteByte(byte((n>>8)&0x7F) | 0x80)
		buf.WriteByte(byte(n & 0xFF))
	} else {
		buf.WriteByte(byte(n))
	}
}

// spliceChunk replaces [off:off+oldLen) with repl and fixes the root size.
func spliceChunk(data []byte, off, oldLen int, repl []byte) []byte {
	out := make([]byte, 0, len(data)-oldLen+len(repl))
	out = append(out, data[:off]...)
	out = append(out, repl...)
	out = append(out, data[off+oldLen:]...)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)))
	return out
}

func parseColorValue(s string) (uint32, error) {
	return parseColor(s)
}
