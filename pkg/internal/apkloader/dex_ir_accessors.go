package apkloader

// ═══════════════════════════════════════════════════════════════
// DEX IR ADAPTER SUPPORT — additive public index accessors
// ═══════════════════════════════════════════════════════════════
//
// These accessors expose the resolved id-tables (strings, types,
// field_ids, method_ids, proto_ids) by raw index so that the shared
// typed IR package (pkg/internal/dexir) can resolve instruction
// references without a smali text round-trip.
//
// All accessors are read-only and safe for concurrent use after Parse
// completes. Out-of-range indexes yield zero values / nil.

// GetStringByIndex returns the resolved string at string_ids[idx],
// or "" if idx is out of range. The returned string may reference
// mmap'd data — it is only valid while the parser (and its mmap
// mapping) is alive.
func (p *DEXParser) GetStringByIndex(idx uint32) string {
	if p == nil || idx >= uint32(len(p.strings)) {
		return ""
	}
	return p.strings[idx]
}

// GetTypeByIndex returns the type descriptor at type_ids[idx],
// or "" if idx is out of range.
func (p *DEXParser) GetTypeByIndex(idx uint32) string {
	if p == nil || idx >= uint32(len(p.types)) {
		return ""
	}
	return p.types[idx]
}

// GetFieldByID returns the parsed field_ids entry at idx, or nil if
// idx is out of range.
func (p *DEXParser) GetFieldByID(idx uint32) *Field {
	if p == nil || idx >= uint32(len(p.fields)) {
		return nil
	}
	return p.fields[idx]
}

// GetMethodByID returns the parsed method_ids entry at idx, or nil if
// idx is out of range.
func (p *DEXParser) GetMethodByID(idx uint32) *Method {
	if p == nil || idx >= uint32(len(p.methods)) {
		return nil
	}
	return p.methods[idx]
}

// GetProtoByID returns the parsed proto_ids entry at idx, or nil if
// idx is out of range.
func (p *DEXParser) GetProtoByID(idx uint32) *Proto {
	if p == nil || idx >= uint32(len(p.protos)) {
		return nil
	}
	return p.protos[idx]
}

// GetClassByDescriptor returns the ClassDef with the given type
// descriptor (e.g. "Lcom/example/Foo;"), or nil when not found.
// Builds the lazy class index on first use.
func (p *DEXParser) GetClassByDescriptor(desc string) *ClassDef {
	if p == nil || desc == "" {
		return nil
	}
	p.buildClassIndex()
	return p.classIndex[desc]
}

// GenerateSmaliClass renders a class as smali text using the same
// generator the extraction pipeline uses. Exported so the typed-IR
// round-trip tests (and future adapters) can produce the text form
// without duplicating the emitter.
func GenerateSmaliClass(class *ClassDef, parser *DEXParser) []byte {
	return generateSmaliClassBytes(class, parser)
}
