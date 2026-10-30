package apkloader

// DEX file layout: ids, data blobs, map list, header.
//
// Pure Go; offsets are 4-byte aligned throughout.

import (
	"crypto/sha1"
	"fmt"
	"hash/adler32"
	"sort"
)

// DEX map-list type codes.
const (
	mapHeader        = 0x0000
	mapStringID      = 0x0001
	mapTypeID        = 0x0002
	mapProtoID       = 0x0003
	mapFieldID       = 0x0004
	mapMethodID      = 0x0005
	mapClassDef      = 0x0006
	mapCallSiteID    = 0x0007
	mapMethodHandle  = 0x0008
	mapMapList       = 0x1000
	mapTypeList      = 0x1001
	mapSetRefList    = 0x1002
	mapSet           = 0x1003
	mapClassData     = 0x2000
	mapCode          = 0x2001
	mapStringData    = 0x2002
	mapAnnotation    = 0x2004
	mapEncodedArray  = 0x2005
	mapAnnoDirectory = 0x2006
)

// dexVersionForAPI maps smali --api levels to DEX versions.
func dexVersionForAPI(api int) string {
	switch {
	case api >= 28:
		return "039"
	case api >= 26:
		return "038"
	default:
		return "035"
	}
}

// assembleDex writes one DEX file from finalized pools + classes.
func assembleDex(pools *asmPools, classes []*asmClass, apiLevel int) ([]byte, error) {
	if len(pools.methods) > 65536 {
		return nil, fmt.Errorf("method refs %d exceed single-DEX limit 65536: split smali into smali_classesN", len(pools.methods))
	}
	if len(pools.fields) > 65536 {
		return nil, fmt.Errorf("field refs %d exceed single-DEX limit 65536: split smali into smali_classesN", len(pools.fields))
	}
	if len(pools.types) > 65536 {
		return nil, fmt.Errorf("type refs %d exceed single-DEX limit 65536", len(pools.types))
	}
	w := &dexOut{pools: pools}
	if err := w.writeAll(classes, dexVersionForAPI(apiLevel)); err != nil {
		return nil, err
	}
	return w.buf, nil
}

type dexOut struct {
	pools *asmPools
	buf   []byte
}

func (w *dexOut) align() {
	for len(w.buf)%4 != 0 {
		w.buf = append(w.buf, 0)
	}
}

func (w *dexOut) off() uint32 { return uint32(len(w.buf)) }

type mapEntry struct {
	typ  uint16
	size uint32
	off  uint32
}

func (w *dexOut) writeAll(classes []*asmClass, version string) error {
	// Reserve header.
	w.buf = make([]byte, 0x70)

	stringIDsOff := w.off()
	for range w.pools.strings {
		dexPutU32(&w.buf, 0)
	}
	stringIDsPatch := stringIDsOff

	typeIDsOff := w.off()
	for range w.pools.types {
		dexPutU32(&w.buf, 0)
	}
	protoIDsOff := w.off()
	for range w.pools.protos {
		dexPutU32(&w.buf, 0)
		dexPutU32(&w.buf, 0)
		dexPutU32(&w.buf, 0)
	}
	fieldIDsOff := w.off()
	for range w.pools.fields {
		dexPutU32(&w.buf, 0)
		dexPutU32(&w.buf, 0)
	}
	methodIDsOff := w.off()
	for range w.pools.methods {
		dexPutU32(&w.buf, 0)
		dexPutU32(&w.buf, 0)
	}
	classDefsOff := w.off()
	classDefsPatch := make([]int, len(classes))
	for i := range classes {
		classDefsPatch[i] = len(w.buf)
		for k := 0; k < 8; k++ {
			dexPutU32(&w.buf, 0)
		}
	}
	callSiteIDsOff := uint32(0)
	if len(w.pools.callSites) > 0 {
		callSiteIDsOff = w.off()
		for range w.pools.callSites {
			dexPutU32(&w.buf, 0)
		}
	}
	methodHandleOff := uint32(0)
	if len(w.pools.handles) > 0 {
		methodHandleOff = w.off()
		for range w.pools.handles {
			dexPutU32(&w.buf, 0)
			dexPutU32(&w.buf, 0)
		}
	}
	dataOff := w.off()

	var maps []mapEntry
	maps = append(maps, mapEntry{mapHeader, 1, 0})
	if len(w.pools.strings) > 0 {
		maps = append(maps, mapEntry{mapStringID, uint32(len(w.pools.strings)), stringIDsOff})
	}
	if len(w.pools.types) > 0 {
		maps = append(maps, mapEntry{mapTypeID, uint32(len(w.pools.types)), typeIDsOff})
	}
	if len(w.pools.protos) > 0 {
		maps = append(maps, mapEntry{mapProtoID, uint32(len(w.pools.protos)), protoIDsOff})
	}
	if len(w.pools.fields) > 0 {
		maps = append(maps, mapEntry{mapFieldID, uint32(len(w.pools.fields)), fieldIDsOff})
	}
	if len(w.pools.methods) > 0 {
		maps = append(maps, mapEntry{mapMethodID, uint32(len(w.pools.methods)), methodIDsOff})
	}
	if len(classes) > 0 {
		maps = append(maps, mapEntry{mapClassDef, uint32(len(classes)), classDefsOff})
	}
	if len(w.pools.callSites) > 0 {
		maps = append(maps, mapEntry{mapCallSiteID, uint32(len(w.pools.callSites)), callSiteIDsOff})
	}
	if len(w.pools.handles) > 0 {
		maps = append(maps, mapEntry{mapMethodHandle, uint32(len(w.pools.handles)), methodHandleOff})
	}

	// ── Data blobs ──
	typeListOffs := map[string]uint32{} // key: joined type idxs
	writeTypeList := func(idxs []uint32) uint32 {
		if len(idxs) == 0 {
			return 0
		}
		key := fmt.Sprint(idxs)
		if o, ok := typeListOffs[key]; ok {
			return o
		}
		w.align()
		o := w.off()
		dexPutU32(&w.buf, uint32(len(idxs)))
		for _, t := range idxs {
			dexPutU16(&w.buf, uint16(t))
		}
		typeListOffs[key] = o
		maps = append(maps, mapEntry{mapTypeList, 1, o})
		return o
	}

	// String data.
	stringDataOffs := make([]uint32, len(w.pools.strings))
	for i, s := range w.pools.strings {
		stringDataOffs[i] = w.off()
		dexPutUleb(&w.buf, uint32(utf16Len(s)))
		w.buf = append(w.buf, encodeMUTF8(s)...)
		w.buf = append(w.buf, 0)
		maps = append(maps, mapEntry{mapStringData, 1, stringDataOffs[i]})
	}
	for i, o := range stringDataOffs {
		dexPutU32At(w.buf, int(stringIDsPatch)+i*4, o)
	}

	// Type lists for protos + interfaces (deduped).
	protoParamOffs := make([]uint32, len(w.pools.protos))
	for i, pr := range w.pools.protos {
		var idxs []uint32
		for _, t := range pr.params {
			idxs = append(idxs, w.pools.typeIndex[t])
		}
		protoParamOffs[i] = writeTypeList(idxs)
	}
	ifaceOffs := make([]uint32, len(classes))
	for ci, c := range classes {
		ifaceOffs[ci] = writeTypeList(c.ifaces)
	}

	// Code items first (class_data needs their offsets).
	type methodSlot struct {
		mo  *asmMethodOut
		off uint32
	}
	slots := []*methodSlot{}
	for _, c := range classes {
		for _, m := range c.directM {
			if m.code != nil {
				off, err := w.writeCodeItem(m.code, w.pools)
				if err != nil {
					return err
				}
				maps = append(maps, mapEntry{mapCode, 1, off})
				slots = append(slots, &methodSlot{mo: m, off: off})
			}
		}
		for _, m := range c.virtualM {
			if m.code != nil {
				off, err := w.writeCodeItem(m.code, w.pools)
				if err != nil {
					return err
				}
				maps = append(maps, mapEntry{mapCode, 1, off})
				slots = append(slots, &methodSlot{mo: m, off: off})
			}
		}
	}
	codeOffByMethod := map[*asmMethodOut]uint32{}
	for _, s := range slots {
		codeOffByMethod[s.mo] = s.off
	}

	// Class data with real code offsets.
	for _, c := range classes {
		off := w.off()
		var b []byte
		dexPutUleb(&b, uint32(len(c.staticF)))
		dexPutUleb(&b, uint32(len(c.instanceF)))
		dexPutUleb(&b, uint32(len(c.directM)))
		dexPutUleb(&b, uint32(len(c.virtualM)))
		prev := uint32(0)
		for _, f := range c.staticF {
			dexPutUleb(&b, f.idx-prev)
			prev = f.idx
			dexPutUleb(&b, f.acc)
		}
		prev = 0
		for _, f := range c.instanceF {
			dexPutUleb(&b, f.idx-prev)
			prev = f.idx
			dexPutUleb(&b, f.acc)
		}
		prev = 0
		for _, m := range c.directM {
			dexPutUleb(&b, m.idx-prev)
			prev = m.idx
			dexPutUleb(&b, m.acc)
			dexPutUleb(&b, codeOffByMethod[m])
		}
		prev = 0
		for _, m := range c.virtualM {
			dexPutUleb(&b, m.idx-prev)
			prev = m.idx
			dexPutUleb(&b, m.acc)
			dexPutUleb(&b, codeOffByMethod[m])
		}
		w.buf = append(w.buf, b...)
		maps = append(maps, mapEntry{mapClassData, 1, off})
		c.classDataOff = off
	}

	// Annotations are written in strict phases (items, then sets, then
	// ref-lists, then directories) so each map-list section stays contiguous.
	type setJob struct {
		anns  []DEXAnnotation
		set   *uint32
		items []uint32
	}
	var setJobs []*setJob
	addSets := func(anns []DEXAnnotation, dst *uint32) {
		setJobs = append(setJobs, &setJob{anns: anns, set: dst})
	}
	for _, c := range classes {
		addSets(c.classAnn, &c.classSetOff)
		for _, f := range c.staticF {
			addSets(f.ann, &f.setOff)
		}
		for _, f := range c.instanceF {
			addSets(f.ann, &f.setOff)
		}
		for _, m := range c.directM {
			addSets(m.ann, &m.setOff)
			m.paramSetOffs = make(paramOffs, len(m.params))
			for pi := range m.params {
				addSets(m.params[pi], m.paramSetOffs.ensure(pi))
			}
		}
		for _, m := range c.virtualM {
			addSets(m.ann, &m.setOff)
			m.paramSetOffs = make(paramOffs, len(m.params))
			for pi := range m.params {
				addSets(m.params[pi], m.paramSetOffs.ensure(pi))
			}
		}
	}
	// Sort each set by type for determinism.
	for _, j := range setJobs {
		cp := append([]DEXAnnotation(nil), j.anns...)
		sort.Slice(cp, func(a, b int) bool {
			return w.pools.typeIndex[cp[a].Type] < w.pools.typeIndex[cp[b].Type]
		})
		j.anns = cp
	}
	// Phase 1: items (contiguous).
	nAnnoItems := 0
	firstAnnoItem := uint32(0)
	for _, j := range setJobs {
		for _, a := range j.anns {
			off := w.off()
			if nAnnoItems == 0 {
				firstAnnoItem = off
			}
			w.buf = append(w.buf, a.Visibility)
			var ab []byte
			writeEncodedAnnotation(&ab, w.pools, &a)
			w.buf = append(w.buf, ab...)
			j.items = append(j.items, off)
			nAnnoItems++
		}
	}
	if nAnnoItems > 0 {
		maps = append(maps, mapEntry{mapAnnotation, uint32(nAnnoItems), firstAnnoItem})
	}
	// Phase 2: sets (contiguous).
	nSets := 0
	firstSet := uint32(0)
	for _, j := range setJobs {
		if len(j.items) == 0 {
			continue
		}
		w.align()
		*j.set = w.off()
		if nSets == 0 {
			firstSet = *j.set
		}
		dexPutU32(&w.buf, uint32(len(j.items)))
		for _, o := range j.items {
			dexPutU32(&w.buf, o)
		}
		nSets++
	}
	if nSets > 0 {
		maps = append(maps, mapEntry{mapSet, uint32(nSets), firstSet})
	}
	// Phase 3: param ref-lists (contiguous), only when non-empty.
	nRefLists := 0
	firstRefList := uint32(0)
	for _, c := range classes {
		for _, m := range append(append([]*asmMethodOut(nil), c.directM...), c.virtualM...) {
			if len(m.params) == 0 {
				continue
			}
			any := false
			for pi := range m.params {
				if pi < len(m.paramSetOffs) && m.paramSetOffs[pi] != 0 {
					any = true
					break
				}
			}
			if !any {
				continue
			}
			w.align()
			m.paramListOff = w.off()
			if nRefLists == 0 {
				firstRefList = m.paramListOff
			}
			dexPutU32(&w.buf, uint32(len(m.params)))
			for pi := range m.params {
				var o uint32
				if pi < len(m.paramSetOffs) {
					o = m.paramSetOffs[pi]
				}
				dexPutU32(&w.buf, o)
			}
			nRefLists++
		}
	}
	if nRefLists > 0 {
		maps = append(maps, mapEntry{mapSetRefList, uint32(nRefLists), firstRefList})
	}
	// Directories form one contiguous section, followed by encoded arrays.
	for _, c := range classes {
		if c.classSetOff != 0 || hasFieldSets(c) || hasMethodSets(c) || hasParamSets(c) {
			w.align()
			c.annoDirOff = w.off()
			type annotationEntry struct{ index, offset uint32 }
			var fields, methods, params []annotationEntry
			for _, f := range append(append([]*asmFieldOut(nil), c.staticF...), c.instanceF...) {
				if f.setOff != 0 {
					fields = append(fields, annotationEntry{f.idx, f.setOff})
				}
			}
			for _, m := range append(append([]*asmMethodOut(nil), c.directM...), c.virtualM...) {
				if m.setOff != 0 {
					methods = append(methods, annotationEntry{m.idx, m.setOff})
				}
				if m.paramListOff != 0 {
					params = append(params, annotationEntry{m.idx, m.paramListOff})
				}
			}
			// All four header words precede the three sorted entry arrays.
			dexPutU32(&w.buf, c.classSetOff)
			dexPutU32(&w.buf, uint32(len(fields)))
			dexPutU32(&w.buf, uint32(len(methods)))
			dexPutU32(&w.buf, uint32(len(params)))
			for _, entries := range [][]annotationEntry{fields, methods, params} {
				sort.Slice(entries, func(i, j int) bool { return entries[i].index < entries[j].index })
				for _, entry := range entries {
					dexPutU32(&w.buf, entry.index)
					dexPutU32(&w.buf, entry.offset)
				}
			}
			maps = append(maps, mapEntry{mapAnnoDirectory, 1, c.annoDirOff})
		}
	}
	for _, c := range classes {
		// Static values.
		if len(c.staticVals) > 0 {
			c.staticValsOff = w.off()
			var b []byte
			dexPutUleb(&b, uint32(len(c.staticVals)))
			for _, v := range c.staticVals {
				if err := writeEncodedValue(&b, w.pools, v); err != nil {
					return err
				}
			}
			w.buf = append(w.buf, b...)
			maps = append(maps, mapEntry{mapEncodedArray, 1, c.staticValsOff})
		}
	}

	// Call sites (encoded arrays) + call_site_ids patch.
	for i, cs := range w.pools.callSites {
		off := w.off()
		var b []byte
		dexPutUleb(&b, uint32(len(cs)))
		for _, v := range cs {
			if err := writeEncodedValue(&b, w.pools, v); err != nil {
				return err
			}
		}
		w.buf = append(w.buf, b...)
		maps = append(maps, mapEntry{mapEncodedArray, 1, off})
		dexPutU32At(w.buf, int(callSiteIDsOff)+i*4, off)
	}

	// Patch ids.
	for i, t := range w.pools.types {
		dexPutU32At(w.buf, int(typeIDsOff)+i*4, w.pools.strIndex[t])
	}
	for i, pr := range w.pools.protos {
		base := int(protoIDsOff) + i*12
		dexPutU32At(w.buf, base, w.pools.strIndex[pr.shorty])
		dexPutU32At(w.buf, base+4, w.pools.typeIndex[pr.ret])
		dexPutU32At(w.buf, base+8, protoParamOffs[i])
	}
	for i, f := range w.pools.fields {
		base := int(fieldIDsOff) + i*8
		// class_idx u16, type_idx u16, name_idx u32.
		w.buf[base] = byte(w.pools.typeIndex[f.cls])
		w.buf[base+1] = byte(w.pools.typeIndex[f.cls] >> 8)
		w.buf[base+2] = byte(w.pools.typeIndex[f.typ])
		w.buf[base+3] = byte(w.pools.typeIndex[f.typ] >> 8)
		dexPutU32At(w.buf, base+4, w.pools.strIndex[f.name])
	}
	for i, m := range w.pools.methods {
		base := int(methodIDsOff) + i*8
		w.buf[base] = byte(w.pools.typeIndex[m.cls])
		w.buf[base+1] = byte(w.pools.typeIndex[m.cls] >> 8)
		pidx := w.pools.protoIndex[protoKey(m.ret, m.params)]
		w.buf[base+2] = byte(pidx)
		w.buf[base+3] = byte(pidx >> 8)
		dexPutU32At(w.buf, base+4, w.pools.strIndex[m.name])
	}
	for i, h := range w.pools.handles {
		base := int(methodHandleOff) + i*8
		w.buf[base] = byte(h.Kind)
		w.buf[base+1] = 0
		w.buf[base+2] = 0
		w.buf[base+3] = 0
		w.buf[base+4] = byte(h.Target)
		w.buf[base+5] = byte(h.Target >> 8)
		w.buf[base+6] = 0
		w.buf[base+7] = 0
	}

	// Patch class defs.
	for ci, c := range classes {
		base := classDefsPatch[ci]
		dexPutU32At(w.buf, base, c.typeIdx)
		dexPutU32At(w.buf, base+4, c.file.Access)
		super := uint32(0xFFFFFFFF)
		if c.file.Super != "" || c.file.Class == "Ljava/lang/Object;" {
			if c.file.Class == "Ljava/lang/Object;" && c.file.Super == "" {
				super = 0xFFFFFFFF
			} else {
				super = c.superIdx
			}
		} else {
			super = c.superIdx
		}
		dexPutU32At(w.buf, base+8, super)
		dexPutU32At(w.buf, base+12, ifaceOffs[ci])
		src := uint32(0xFFFFFFFF)
		if c.hasSource {
			src = c.sourceIdx
		}
		dexPutU32At(w.buf, base+16, src)
		dexPutU32At(w.buf, base+20, c.annoDirOff)
		dexPutU32At(w.buf, base+24, c.classDataOff)
		dexPutU32At(w.buf, base+28, c.staticValsOff)
	}

	// Map list.
	w.align()
	mapOff := w.off()
	dexPutU32(&w.buf, uint32(len(maps)+1))
	allMaps := append(maps, mapEntry{mapMapList, 1, mapOff})
	// Count items per type for size fields of section entries.
	byType := map[uint16][]mapEntry{}
	for _, me := range allMaps {
		byType[me.typ] = append(byType[me.typ], me)
	}
	// Rebuild: one entry per type with total size; offset = first.
	var ordered []mapEntry
	for _, typ := range sortedMapTypes(byType) {
		es := byType[typ]
		var count uint32
		for _, entry := range es {
			count += entry.size
		}
		ordered = append(ordered, mapEntry{typ, count, es[0].off})
	}
	// The DEX format requires map entries in ascending file-offset order.
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].off < ordered[j].off })
	// Rewrite count.
	dexPutU32At(w.buf, int(mapOff), uint32(len(ordered)))
	for _, me := range ordered {
		dexPutU16(&w.buf, me.typ)
		dexPutU16(&w.buf, 0)
		dexPutU32(&w.buf, me.size)
		dexPutU32(&w.buf, me.off)
	}

	// Header.
	emptyOffset := func(count int, offset uint32) uint32 {
		if count == 0 {
			return 0
		}
		return offset
	}
	dataSize := uint32(len(w.buf)) - dataOff
	magic := []byte("dex\n" + version + "\x00")
	copy(w.buf[0:], magic)
	dexPutU32At(w.buf, 32, uint32(len(w.buf)))
	dexPutU32At(w.buf, 36, 0x70)
	dexPutU32At(w.buf, 40, 0x12345678)
	dexPutU32At(w.buf, 52, mapOff)
	dexPutU32At(w.buf, 56, uint32(len(w.pools.strings)))
	dexPutU32At(w.buf, 60, emptyOffset(len(w.pools.strings), stringIDsOff))
	dexPutU32At(w.buf, 64, uint32(len(w.pools.types)))
	dexPutU32At(w.buf, 68, emptyOffset(len(w.pools.types), typeIDsOff))
	dexPutU32At(w.buf, 72, uint32(len(w.pools.protos)))
	dexPutU32At(w.buf, 76, emptyOffset(len(w.pools.protos), protoIDsOff))
	dexPutU32At(w.buf, 80, uint32(len(w.pools.fields)))
	dexPutU32At(w.buf, 84, emptyOffset(len(w.pools.fields), fieldIDsOff))
	dexPutU32At(w.buf, 88, uint32(len(w.pools.methods)))
	dexPutU32At(w.buf, 92, emptyOffset(len(w.pools.methods), methodIDsOff))
	dexPutU32At(w.buf, 96, uint32(len(classes)))
	dexPutU32At(w.buf, 100, emptyOffset(len(classes), classDefsOff))
	dexPutU32At(w.buf, 104, dataSize)
	dexPutU32At(w.buf, 108, dataOff)
	// Signature (SHA-1 over [32:]) then checksum (adler32 over [12:]).
	sig := sha1.Sum(w.buf[32:])
	copy(w.buf[12:32], sig[:])
	sum := adler32.Checksum(w.buf[12:])
	dexPutU32At(w.buf, 8, sum)
	return nil
}

func dexPutU32At(buf []byte, pos int, v uint32) {
	buf[pos] = byte(v)
	buf[pos+1] = byte(v >> 8)
	buf[pos+2] = byte(v >> 16)
	buf[pos+3] = byte(v >> 24)
}

// writeCodeItem writes one code_item; returns its offset.
func (w *dexOut) writeCodeItem(code *asmMethodCode, pools *asmPools) (uint32, error) {
	w.align()
	off := w.off()
	dexPutU16(&w.buf, code.registers)
	dexPutU16(&w.buf, code.insSize)
	dexPutU16(&w.buf, code.outsSize)
	dexPutU16(&w.buf, uint16(len(code.tries)))
	dexPutU32(&w.buf, 0) // debug_info_off
	dexPutU32(&w.buf, uint32(len(code.units)))
	for _, u := range code.units {
		dexPutU16(&w.buf, u)
	}
	if len(code.units)%2 == 1 {
		dexPutU16(&w.buf, 0)
	}
	// Build handler list with dedup. handler_off is a byte offset into the
	// encoded_catch_handler_list (past the list-size uleb), not a sequence
	// index: encode each unique sequence separately, then lay them out.
	var seqs [][]*asmHandler
	seqIndex := map[string]int{}
	trySeq := make([]int, len(code.tries))
	for ti, t := range code.tries {
		key := ""
		for _, h := range t.handlers {
			key += fmt.Sprintf("%s@%d|", h.typeName, h.addr)
		}
		si, ok := seqIndex[key]
		if !ok {
			si = len(seqs)
			seqs = append(seqs, t.handlers)
			seqIndex[key] = si
		}
		trySeq[ti] = si
	}
	seqBytes := make([][]byte, len(seqs))
	for si, seq := range seqs {
		var b []byte
		typed := 0
		hasCatchAll := false
		for _, h := range seq {
			if h.catchAll {
				hasCatchAll = true
			} else {
				typed++
			}
		}
		if hasCatchAll {
			dexPutSleb(&b, -int32(typed))
		} else {
			dexPutSleb(&b, int32(typed))
		}
		for _, h := range seq {
			if h.catchAll {
				continue
			}
			dexPutUleb(&b, pools.typeIndex[h.typeName])
			dexPutUleb(&b, h.addr)
		}
		for _, h := range seq {
			if h.catchAll {
				dexPutUleb(&b, h.addr)
				break
			}
		}
		seqBytes[si] = b
	}
	var sizeUleb []byte
	dexPutUleb(&sizeUleb, uint32(len(seqs)))
	seqOff := make([]uint16, len(seqs))
	ho := uint32(len(sizeUleb))
	for si, b := range seqBytes {
		seqOff[si] = uint16(ho)
		ho += uint32(len(b))
	}
	for ti, t := range code.tries {
		dexPutU32(&w.buf, t.start)
		dexPutU16(&w.buf, uint16(t.count))
		dexPutU16(&w.buf, seqOff[trySeq[ti]])
	}
	if len(seqs) > 0 {
		w.buf = append(w.buf, sizeUleb...)
		for _, b := range seqBytes {
			w.buf = append(w.buf, b...)
		}
	}
	return off, nil
}

func sortedMapTypes(byType map[uint16][]mapEntry) []uint16 {
	out := make([]uint16, 0, len(byType))
	for t := range byType {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
