package axml

// Native AXML encoder: edited text XML + original binary → new binary.
//
// Strategy is overlay, not recompile: the original binary DOM stays
// authoritative for structure, namespaces and resource IDs; the edited text
// supplies new element/attribute values. Unchanged attributes keep their
// exact (type, data) bytes, so references, dimensions and styles survive
// without aapt2. Anything the overlay cannot represent (new references
// without a resource table, unparseable typed values, structural renames it
// cannot key on) is a hard error, never a silent downgrade.
//
// Pure Go; no external processes.

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// ── DOM ──────────────────────────────────────────────────────────────────────

// DomAttr is one attribute with its binary identity.
type DomAttr struct {
	NS    string // namespace URI, "" when none
	Name  string // local name
	ResID uint32 // resource map ID, 0 when none
	Type  uint8  // Res_value type tag
	Data  uint32 // raw value data
	Str   string // string value when Type == typeString
}

// DomElem is one element.
type DomElem struct {
	Name  string
	Attrs []DomAttr
	Kids  []*DomElem
}

// DomDoc is a document with root-level namespace declarations.
type DomDoc struct {
	NS   [][2]string // prefix, uri (first declaration wins per prefix)
	Root *DomElem
}

// ── Binary → DOM ─────────────────────────────────────────────────────────────

type domBuilder struct {
	pool    *stringPool
	resMap  []uint32
	nsStack []map[uint32]string // uri idx → prefix, scoped
	nsSeen  [][2]string
	root    *DomElem
	stack   []*DomElem
}

func ParseBinaryAXML(data []byte) (*DomDoc, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("axml: input too small")
	}
	if binary.LittleEndian.Uint16(data[0:2]) != chunkXML {
		return nil, fmt.Errorf("axml: not an XML chunk")
	}
	total := binary.LittleEndian.Uint32(data[4:8])
	if uint64(total) > uint64(len(data)) {
		total = uint32(len(data))
	}
	b := &domBuilder{}
	cursor := uint32(8)
	for cursor+8 <= total {
		ct := binary.LittleEndian.Uint16(data[cursor : cursor+2])
		hs := binary.LittleEndian.Uint16(data[cursor+2 : cursor+4])
		cs := binary.LittleEndian.Uint32(data[cursor+4 : cursor+8])
		if hs < 8 || cs < 8 || cs < uint32(hs) || cs > maxChunkBytes {
			return nil, fmt.Errorf("axml: bad chunk size %d at 0x%x", cs, cursor)
		}
		end := uint64(cursor) + uint64(cs)
		if end <= uint64(cursor) || end > uint64(len(data)) {
			return nil, fmt.Errorf("axml: chunk overruns buffer at 0x%x", cursor)
		}
		chunk := data[cursor:end]
		if err := b.visit(ct, chunk); err != nil {
			return nil, err
		}
		cursor = uint32(end)
	}
	if b.root == nil {
		return nil, fmt.Errorf("axml: no root element")
	}
	return &DomDoc{NS: b.nsSeen, Root: b.root}, nil
}

func (b *domBuilder) visit(ct uint16, chunk []byte) error {
	switch ct {
	case chunkStringPool:
		pool, err := parseStringPool(chunk)
		if err != nil {
			return err
		}
		b.pool = pool
	case chunkXMLResourceMap:
		payload := chunk[8:]
		b.resMap = make([]uint32, len(payload)/4)
		for i := range b.resMap {
			b.resMap[i] = binary.LittleEndian.Uint32(payload[i*4:])
		}
	case chunkXMLStartNS:
		if len(chunk) < 24 {
			return fmt.Errorf("axml: truncated namespace chunk")
		}
		prefix := binary.LittleEndian.Uint32(chunk[16:20])
		uri := binary.LittleEndian.Uint32(chunk[20:24])
		top := map[uint32]string{}
		if len(b.nsStack) > 0 {
			for k, v := range b.nsStack[len(b.nsStack)-1] {
				top[k] = v
			}
		}
		top[uri] = b.pool.String(prefix)
		b.nsStack = append(b.nsStack, top)
		ps, us := b.pool.String(prefix), b.pool.String(uri)
		if ps != SentinelNoString && us != SentinelNoString && ps != "" {
			found := false
			for _, seen := range b.nsSeen {
				if seen[0] == ps {
					found = true
					break
				}
			}
			if !found {
				b.nsSeen = append(b.nsSeen, [2]string{ps, us})
			}
		}
	case chunkXMLEndNS:
		if len(b.nsStack) > 0 {
			b.nsStack = b.nsStack[:len(b.nsStack)-1]
		}
	case chunkXMLStartElement:
		el, err := b.startElement(chunk)
		if err != nil {
			return err
		}
		if len(b.stack) == 0 {
			b.root = el
		} else {
			parent := b.stack[len(b.stack)-1]
			parent.Kids = append(parent.Kids, el)
		}
		b.stack = append(b.stack, el)
	case chunkXMLEndElement:
		if len(b.stack) > 0 {
			b.stack = b.stack[:len(b.stack)-1]
		}
	case chunkXMLCData:
		// Character data is not used by manifests/layouts we rewrite; drop
		// it loudly rather than misplace it.
		return fmt.Errorf("axml: CDATA sections are not supported by the overlay encoder")
	}
	return nil
}

func (b *domBuilder) resIDFor(nameIdx uint32) uint32 {
	if int(nameIdx) < len(b.resMap) {
		return b.resMap[nameIdx]
	}
	return 0
}

func (b *domBuilder) startElement(chunk []byte) (*DomElem, error) {
	body := chunk[8:]
	if len(body) < 22 {
		return nil, fmt.Errorf("axml: truncated start element")
	}
	nsIdx := binary.LittleEndian.Uint32(body[8:12])
	nameIdx := binary.LittleEndian.Uint32(body[12:16])
	attrStart := uint64(binary.LittleEndian.Uint16(body[16:18]))
	attrSize := binary.LittleEndian.Uint16(body[18:20])
	attrCount := binary.LittleEndian.Uint16(body[20:22])
	if attrCount > maxAttributesPerNode {
		return nil, fmt.Errorf("axml: refusing %d attrs", attrCount)
	}
	if attrSize == 0 {
		attrSize = 20
	}
	if attrSize < 20 {
		return nil, fmt.Errorf("axml: attribute size %d too small", attrSize)
	}
	base := uint64(8) + attrStart
	end := base + uint64(attrCount)*uint64(attrSize)
	if end > uint64(len(body)) {
		return nil, fmt.Errorf("axml: attributes overrun chunk")
	}
	el := &DomElem{Name: b.pool.String(nameIdx)}
	_ = nsIdx
	for i := uint16(0); i < attrCount; i++ {
		raw := body[base+uint64(i)*uint64(attrSize):]
		aNS := binary.LittleEndian.Uint32(raw[0:4])
		aName := binary.LittleEndian.Uint32(raw[4:8])
		aStr := binary.LittleEndian.Uint32(raw[8:12])
		aType := raw[15]
		aData := binary.LittleEndian.Uint32(raw[16:20])
		nsURI := ""
		if b.pool.Has(aNS) {
			nsURI = b.pool.String(aNS)
		}
		name := b.pool.String(aName)
		if name == "" || name == SentinelNoString {
			if id := b.resIDFor(aName); id != 0 {
				if n, ok := resourceID[id]; ok {
					name = n
				}
			}
			if name == "" || name == SentinelNoString {
				name = fmt.Sprintf("attr_0x%08x", b.resIDFor(aName))
			}
		}
		attr := DomAttr{NS: nsURI, Name: name, ResID: b.resIDFor(aName), Type: aType, Data: aData}
		if aType == typeString && b.pool.Has(aStr) {
			attr.Str = b.pool.String(aStr)
		}
		el.Attrs = append(el.Attrs, attr)
	}
	return el, nil
}

// ── Text → DOM ───────────────────────────────────────────────────────────────

type textAttr struct {
	ns    string
	name  string
	value string
}

func ParseTextAXML(text []byte) (*DomDoc, error) {
	dec := xml.NewDecoder(bytes.NewReader(text))
	dec.Strict = true
	doc := &DomDoc{}
	var stack []*DomElem
	nsScope := []map[string]string{{}}
	seenPrefix := map[string]bool{}
	pushScope := func() { nsScope = append(nsScope, map[string]string{}) }
	popScope := func() { nsScope = nsScope[:len(nsScope)-1] }
	lookup := func(prefix string) string {
		for i := len(nsScope) - 1; i >= 0; i-- {
			if u, ok := nsScope[i][prefix]; ok {
				return u
			}
		}
		return ""
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("axml: malformed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) == 0 && doc.Root != nil {
				return nil, fmt.Errorf("axml: multiple root elements")
			}
			if t.Name.Space != "" {
				return nil, fmt.Errorf("axml: namespaced elements are not supported: %s", t.Name.Local)
			}
			pushScope()
			var attrs []textAttr
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" {
					nsScope[len(nsScope)-1][a.Name.Local] = a.Value
					if !seenPrefix[a.Name.Local] {
						seenPrefix[a.Name.Local] = true
						doc.NS = append(doc.NS, [2]string{a.Name.Local, a.Value})
					}
					continue
				}
				if a.Name.Space == "" && a.Name.Local == "xmlns" {
					continue
				}
				uri := ""
				if a.Name.Space != "" {
					// encoding/xml Token() resolves prefixes to namespace URIs,
					// while RawToken() keeps them as written. Accept both so
					// "android:name" and its resolved form keep working.
					if a.Name.Space == androidNS || strings.Contains(a.Name.Space, "://") {
						uri = a.Name.Space
					} else {
						uri = lookup(a.Name.Space)
						if uri == "" {
							if a.Name.Space == "android" {
								uri = androidNS
							} else {
								return nil, fmt.Errorf("axml: unbound prefix %q", a.Name.Space)
							}
						}
					}
				}
				attrs = append(attrs, textAttr{ns: uri, name: a.Name.Local, value: a.Value})
			}
			// Element namespace: encoding/xml puts prefix in Space.
			elemNS := ""
			elemName := t.Name.Local
			if t.Name.Space != "" {
				elemNS = lookup(t.Name.Space)
				_ = elemNS
			}
			el := &DomElem{Name: elemName}
			for _, a := range attrs {
				el.Attrs = append(el.Attrs, DomAttr{NS: a.ns, Name: a.name, Str: a.value, Type: 0xFF})
			}
			if len(stack) == 0 {
				doc.Root = el
			} else {
				parent := stack[len(stack)-1]
				parent.Kids = append(parent.Kids, el)
			}
			stack = append(stack, el)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			popScope()
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return nil, fmt.Errorf("axml: character data is not supported by the overlay encoder")
			}
		}
	}
	if doc.Root == nil {
		return nil, fmt.Errorf("axml: no root element in text")
	}
	// Ensure the android namespace is known even when the text relies on it
	// without declaring (decoder output always declares it; be lenient).
	hasAndroid := false
	for _, ns := range doc.NS {
		if ns[1] == androidNS {
			hasAndroid = true
		}
	}
	if !hasAndroid {
		doc.NS = append(doc.NS, [2]string{"android", androidNS})
	}
	return doc, nil
}

// SameAXMLSemantics reports whether binary and text describe the same
// document (tags, attributes and values). Used to skip no-op re-encodes.
func SameAXMLSemantics(binData, textData []byte) bool {
	binDoc, err := ParseBinaryAXML(binData)
	if err != nil {
		return false
	}
	textDoc, err := ParseTextAXML(textData)
	if err != nil {
		return false
	}
	return domEqual(binDoc.Root, textDoc.Root)
}

func domEqual(a, b *DomElem) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Name != b.Name || len(a.Attrs) != len(b.Attrs) || len(a.Kids) != len(b.Kids) {
		return false
	}
	byID := map[string]string{}
	for _, at := range a.Attrs {
		byID[at.NS+"\x00"+at.Name] = attrText(at)
	}
	for _, bt := range b.Attrs {
		av, ok := byID[bt.NS+"\x00"+bt.Name]
		if !ok || av != attrText(bt) {
			return false
		}
	}
	for i := range a.Kids {
		if !domEqual(a.Kids[i], b.Kids[i]) {
			return false
		}
	}
	return true
}

// ── Overlay ──────────────────────────────────────────────────────────────────

// OverlayAXML merges edited text onto the original binary. table may be nil;
// it is only needed to resolve new @type/name and ?attr/name references.
func OverlayAXML(origBin, editedText []byte, table *ResourceTable) ([]byte, error) {
	orig, err := ParseBinaryAXML(origBin)
	if err != nil {
		return nil, err
	}
	text, err := ParseTextAXML(editedText)
	if err != nil {
		return nil, err
	}
	merged, err := overlayElem(orig.Root, text.Root, table, "/"+orig.Root.Name, orig.Root.Name == "manifest")
	if err != nil {
		return nil, err
	}
	doc := &DomDoc{Root: merged}
	doc.NS = mergeNamespaces(orig.NS, text.NS)
	return EncodeDomAXML(doc)
}

func mergeNamespaces(a, b [][2]string) [][2]string {
	out := append([][2]string(nil), a...)
	seen := map[string]bool{}
	for _, ns := range a {
		seen[ns[0]] = true
	}
	for _, ns := range b {
		if !seen[ns[0]] {
			seen[ns[0]] = true
			out = append(out, ns)
		}
	}
	return out
}

func matchKey(el *DomElem) string {
	for _, a := range el.Attrs {
		if (a.NS == androidNS || a.NS == "") && a.Name == "name" {
			v := attrText(a)
			if v != "" {
				return el.Name + "\x00" + v
			}
		}
	}
	return el.Name
}

func attrText(a DomAttr) string {
	if a.Type == typeString || a.Type == 0xFF {
		return a.Str
	}
	return renderTypedValue(a.Type, a.Data, a.Str)
}

func overlayElem(orig, edited *DomElem, table *ResourceTable, path string, manifestMode bool) (*DomElem, error) {
	if orig.Name != edited.Name {
		return nil, fmt.Errorf("axml: element rename %s -> %s at %s is not supported; keep tag names stable", orig.Name, edited.Name, path)
	}
	out := &DomElem{Name: orig.Name}
	// Index originals by key; edited order wins for output.
	type slot struct {
		orig *DomElem
		used bool
	}
	byKey := map[string][]*slot{}
	for _, k := range orig.Kids {
		key := matchKey(k)
		byKey[key] = append(byKey[key], &slot{orig: k})
	}
	for _, ek := range edited.Kids {
		key := matchKey(ek)
		var o *DomElem
		if slots, ok := byKey[key]; ok {
			for _, s := range slots {
				if !s.used {
					s.used = true
					o = s.orig
					break
				}
			}
		}
		if o == nil {
			// Brand-new element: build from text with table resolution.
			nb, err := buildNewElem(ek, table, path+"/"+ek.Name, manifestMode)
			if err != nil {
				return nil, err
			}
			out.Kids = append(out.Kids, nb)
			continue
		}
		mk, err := overlayElem(o, ek, table, path+"/"+ek.Name, manifestMode)
		if err != nil {
			return nil, err
		}
		out.Kids = append(out.Kids, mk)
	}
	// Attributes: edited wins; deletions respected.
	origByID := map[string]*DomAttr{}
	for i := range orig.Attrs {
		a := &orig.Attrs[i]
		origByID[a.NS+"\x00"+a.Name] = a
	}
	seen := map[string]bool{}
	for _, ea := range edited.Attrs {
		id := ea.NS + "\x00" + ea.Name
		seen[id] = true
		oa, ok := origByID[id]
		if !ok {
			na, err := buildNewAttr(ea, table, path)
			if err != nil {
				return nil, fmt.Errorf("axml: %s @%s: %v", path, ea.Name, err)
			}
			out.Attrs = append(out.Attrs, na)
			continue
		}
		na, err := mergeAttr(*oa, ea.Str, table, path)
		if err != nil {
			return nil, fmt.Errorf("axml: %s @%s: %v", path, ea.Name, err)
		}
		out.Attrs = append(out.Attrs, na)
	}
	// Keep original-only attributes? No: the text is the user's intent and
	// our own decoder emits every attribute, so absence means deletion.
	_ = seen
	return out, nil
}

// mergeAttr reconciles one attribute. Unchanged text keeps binary bytes
// verbatim (references included); changed text is coerced by original type.
func mergeAttr(oa DomAttr, newText string, table *ResourceTable, path string) (DomAttr, error) {
	if attrText(oa) == newText {
		return oa, nil
	}
	// A source XML may retain named enums/references after its first native
	// compilation (e.g. match_parent instead of -1). Reuse the same schema
	// on subsequent overlays, preserving the existing resource ID.
	if oa.NS == androidNS {
		if spec, ok := nativeAndroidAttrs[oa.Name]; ok {
			if value, err := nativeAttributeValue(newText, spec, table); err == nil {
				value.NS, value.Name, value.ResID = oa.NS, oa.Name, oa.ResID
				if oa.Type == typeDynamicRef && value.Type == typeReference {
					value.Type = typeDynamicRef
				}
				if oa.Type == typeDynamicAttr && value.Type == typeAttribute {
					value.Type = typeDynamicAttr
				}
				return value, nil
			}
		}
	}
	na := DomAttr{NS: oa.NS, Name: oa.Name, ResID: oa.ResID}
	switch oa.Type {
	case typeString:
		na.Type, na.Data, na.Str = typeString, 0, newText
		return na, nil
	case typeIntDec, typeIntHex:
		v, err := strconv.ParseInt(strings.TrimSpace(newText), 0, 32)
		if err != nil {
			return na, fmt.Errorf("cannot parse %q as integer", newText)
		}
		na.Type, na.Data = oa.Type, uint32(int32(v))
		return na, nil
	case typeIntBoolean:
		t := strings.ToLower(strings.TrimSpace(newText))
		if t == "true" {
			na.Type, na.Data = typeIntBoolean, 0xFFFFFFFF
			return na, nil
		}
		if t == "false" {
			na.Type, na.Data = typeIntBoolean, 0
			return na, nil
		}
		return na, fmt.Errorf("cannot parse %q as boolean", newText)
	case typeFloat:
		f, err := strconv.ParseFloat(strings.TrimSpace(newText), 32)
		if err != nil {
			return na, fmt.Errorf("cannot parse %q as float", newText)
		}
		na.Type, na.Data = typeFloat, math.Float32bits(float32(f))
		return na, nil
	case typeIntColorARGB8, typeIntColorRGB8, typeIntColorARGB4, typeIntColorRGB4:
		c, err := parseColor(newText)
		if err != nil {
			return na, err
		}
		na.Type, na.Data = typeIntColorARGB8, c
		return na, nil
	case typeDimension, typeFraction:
		kind := "dimension"
		if oa.Type == typeFraction {
			kind = "fraction"
		}
		c, err := nativeComplex(newText, kind == "fraction")
		if err != nil {
			return na, err
		}
		na.Type, na.Data = oa.Type, c
		return na, nil
	case typeReference, typeDynamicRef, typeAttribute, typeDynamicAttr:
		id, err := resolveReference(newText, table)
		if err != nil {
			return na, err
		}
		na.Type, na.Data = oa.Type, id
		return na, nil
	case typeNull:
		if strings.TrimSpace(newText) == "" {
			na.Type = typeNull
			return na, nil
		}
		na.Type, na.Data, na.Str = typeString, 0, newText
		return na, nil
	default:
		// Unknown typed values: only accept identical text (handled above),
		// anything else becomes a string rather than corrupt bytes.
		na.Type, na.Data, na.Str = typeString, 0, newText
		return na, nil
	}
}

// buildNewAttr types a brand-new attribute from its text.
func buildNewAttr(ea DomAttr, table *ResourceTable, path string) (DomAttr, error) {
	na := DomAttr{NS: ea.NS, Name: ea.Name, ResID: lookupResID(ea.NS, ea.Name)}
	if ea.NS == androidNS {
		if spec, ok := nativeAndroidAttrs[ea.Name]; ok {
			value, err := nativeAttributeValue(ea.Str, spec, table)
			value.NS, value.Name, value.ResID = ea.NS, ea.Name, spec.ID
			return value, err
		}
	}
	t := strings.TrimSpace(ea.Str)
	if strings.HasPrefix(t, "@") || strings.HasPrefix(t, "?") {
		id, isAttr, err := resolveReferenceFull(t, table)
		if err != nil {
			return na, err
		}
		if isAttr {
			na.Type, na.Data = typeAttribute, id
		} else {
			na.Type, na.Data = typeReference, id
		}
		return na, nil
	}
	if t == "true" || t == "false" {
		na.Type = typeIntBoolean
		if t == "true" {
			na.Data = 0xFFFFFFFF
		}
		return na, nil
	}
	if v, err := strconv.ParseInt(t, 0, 32); err == nil && isKnownIntAttr(ea.Name) {
		na.Type, na.Data = typeIntDec, uint32(int32(v))
		return na, nil
	}
	if strings.HasPrefix(t, "#") {
		if c, err := parseColor(t); err == nil {
			na.Type, na.Data = typeIntColorARGB8, c
			return na, nil
		}
	}
	na.Type, na.Data, na.Str = typeString, 0, ea.Str
	return na, nil
}

// overlayManifestElems lists manifest tags the overlay encoder can append.
// <permission>, <permission-group> and <permission-tree> definitions are
// intentionally absent: the structured mapper does not track them yet, so
// accepting them would silently diverge the binary from the parsed manifest.
// Needs aapt2 or mapper support first.
var overlayManifestElems = map[string]bool{
	"manifest": true, "uses-sdk": true, "uses-permission": true,
	"uses-permission-sdk-23": true, "uses-feature": true, "application": true,
	"activity": true, "activity-alias": true, "service": true,
	"receiver": true, "provider": true, "intent-filter": true,
	"action": true, "category": true, "data": true, "meta-data": true,
	"uses-library": true, "supports-screens": true, "compatible-screens": true,
	"supports-gl-texture": true, "grant-uri-permission": true,
	"path-permission": true, "property": true,
}

// buildNewElem builds a brand-new element subtree from text.
func buildNewElem(ek *DomElem, table *ResourceTable, path string, manifestMode bool) (*DomElem, error) {
	if manifestMode && !overlayManifestElems[ek.Name] {
		return nil, fmt.Errorf("axml: element <%s> at %s is not supported by the overlay encoder; keep tag names stable", ek.Name, path)
	}
	out := &DomElem{Name: ek.Name}
	for _, ea := range ek.Attrs {
		na, err := buildNewAttr(ea, table, path)
		if err != nil {
			return nil, err
		}
		out.Attrs = append(out.Attrs, na)
	}
	for _, k := range ek.Kids {
		nk, err := buildNewElem(k, table, path+"/"+k.Name, manifestMode)
		if err != nil {
			return nil, err
		}
		out.Kids = append(out.Kids, nk)
	}
	return out, nil
}
