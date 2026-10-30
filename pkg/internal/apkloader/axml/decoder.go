package axml

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// XML namespace used for android:* attributes.
const androidNS = "http://schemas.android.com/apk/res/android"

// resourceID is the on-disk attribute identifier mapped to a public
// android.* attribute name. We carry only the small subset relevant
// for manifest analysis. Values come from Android's public
// `android.R.attr` IDs (stable across versions).
//
// The set is intentionally narrow: missing IDs degrade gracefully to
// "attrXXXXXXXX" hex form, which is fine for unknown vendor attrs.
// resourceID maps known android attribute resource IDs to public attribute names.
// Values are taken from the public `android.R.attr` constants (these IDs are
// part of Android's stable public API since 1.0).
//
// Coverage is intentionally narrow: only manifest-relevant attributes.
// Unknown IDs degrade to "attr_XXXXXXXX" hex form, which is fine for
// vendor attrs we never display anyway.
var resourceID = map[uint32]string{
	// Core attributes (0x010100xx)
	0x01010000: "theme",
	0x01010001: "label",
	0x01010002: "icon",
	0x01010003: "name",
	0x01010004: "manageSpaceActivity",
	0x01010005: "allowClearUserData",
	0x01010006: "permission",
	0x01010007: "readPermission",
	0x01010008: "writePermission",
	0x01010009: "protectionLevel",
	0x0101000a: "permissionGroup",
	0x0101000b: "sharedUserId",
	0x0101000c: "hasCode",
	0x0101000d: "persistent",
	0x0101000e: "enabled",
	0x0101000f: "debuggable",
	0x01010010: "exported",
	0x01010011: "process",
	0x01010012: "taskAffinity",
	0x01010013: "multiprocess",
	0x01010014: "finishOnTaskLaunch",
	0x01010015: "clearTaskOnLaunch",
	0x01010016: "stateNotNeeded",
	0x01010017: "excludeFromRecents",
	0x01010018: "authorities",
	0x01010019: "syncable",
	0x0101001a: "initOrder",
	0x0101001b: "grantUriPermissions",
	0x0101001c: "priority",
	0x0101001d: "launchMode",
	0x0101001e: "screenOrientation",
	0x0101001f: "configChanges",
	0x01010020: "description",
	0x01010021: "targetPackage",
	0x01010022: "handleProfiling",
	0x01010023: "functionalTest",
	0x01010024: "value",
	0x01010025: "resource",
	0x01010026: "mimeType",
	0x01010027: "scheme",
	0x01010028: "host",
	0x01010029: "port",
	0x0101002a: "path",
	0x0101002b: "pathPrefix",
	0x0101002c: "pathPattern",
	0x0101002d: "action",
	// Feature/SDK attributes
	0x01010202: "configure",
	0x0101020c: "versionCode",
	0x0101021b: "versionName",
	0x01010264: "glEsVersion",
	0x01010270: "windowSoftInputMode",
	0x010102b8: "screenSize",
	0x010102bd: "required",
	0x010102c9: "reqFiveWayNav",
	0x010102d3: "installLocation",
	// SDK 11+
	0x01010354: "allowBackup",
	0x010103a0: "uiOptions",
	0x010103e7: "logo",
	0x010103e8: "minResizeWidth",
	0x010103e9: "minResizeHeight",
	0x010103f3: "compileSdkVersion",
	0x010104d3: "isolatedProcess",
	0x010104d6: "supportsRtl",
	0x010104ea: "extractNativeLibs",
	0x010104ee: "autoVerify",
	0x01010540: "fullBackupContent",
	0x01010571: "minSdkVersion",
	0x01010572: "targetSdkVersion",
	0x01010573: "maxSdkVersion",
	0x01010578: "networkSecurityConfig",
	0x01010579: "usesCleartextTraffic",
	0x0101057c: "fullBackupOnly",
	0x01010592: "dataExtractionRules",
}

// Decoder is the entry point for AndroidManifest.xml parsing.
type Decoder struct {
	data       []byte
	pool       *stringPool
	resMap     []uint32
	nsPrefixes map[uint32]uint32 // uri-idx → prefix-idx (root snapshot)
	nsStack    *namespaceStack
}

// decodeAXML parses an AXML buffer and returns a structured Manifest plus
// the rendered plaintext XML. Callers go through the guarded Decode in
// panicguard.go.
func decodeAXML(data []byte) (*Manifest, error) {
	if len(data) < 8 {
		return nil, errors.New("axml: input too small")
	}
	d := &Decoder{
		data:       data,
		nsPrefixes: make(map[uint32]uint32, 4),
		nsStack:    newNamespaceStack(),
	}
	return d.decode()
}

func (d *Decoder) decode() (*Manifest, error) {
	hdr := binary.LittleEndian.Uint16(d.data[0:2])
	if hdr != chunkXML {
		return nil, fmt.Errorf("axml: not an XML chunk (type=0x%04x)", hdr)
	}

	// total file size
	totalSize := binary.LittleEndian.Uint32(d.data[4:8])
	if uint64(totalSize) > uint64(len(d.data)) {
		// trust the buffer length; some packers under-report size
		totalSize = uint32(len(d.data))
	}

	cursor := uint32(8) // past outer chunk header
	manifest := &Manifest{
		MetaData: make(map[string]string, 8),
	}

	var (
		xmlBuf   strings.Builder
		stack    []string // open-element names for depth tracking
		curComp  *Component
		curList  *[]Component
		inFilter bool
		curFilt  *IntentFilter
	)

	xmlBuf.Grow(len(d.data))
	xmlBuf.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	xmlBuf.WriteByte('\n')

	for cursor+8 <= totalSize {
		chunkType := binary.LittleEndian.Uint16(d.data[cursor : cursor+2])
		hdrSize := binary.LittleEndian.Uint16(d.data[cursor+2 : cursor+4])
		chunkSize := binary.LittleEndian.Uint32(d.data[cursor+4 : cursor+8])

		// hdrSize/chunkSize must both cover the 8-byte generic header and
		// chunkSize must advance the cursor; otherwise a crafted
		// hdrSize=0/chunkSize=0 chunk would loop forever.
		if hdrSize < 8 || chunkSize < 8 || chunkSize < uint32(hdrSize) || chunkSize > maxChunkBytes {
			return nil, fmt.Errorf("axml: bad chunk size %d (hdr %d) at 0x%x", chunkSize, hdrSize, cursor)
		}
		end := uint64(cursor) + uint64(chunkSize)
		if end <= uint64(cursor) || end > uint64(len(d.data)) {
			return nil, fmt.Errorf("axml: chunk overruns buffer at 0x%x", cursor)
		}

		chunk := d.data[cursor:end]

		switch chunkType {
		case chunkStringPool:
			pool, err := parseStringPool(chunk)
			if err != nil {
				return nil, err
			}
			d.pool = pool

		case chunkXMLResourceMap:
			// payload is u32[] of resource IDs, one per pool entry up to
			// payload length; we keep the full slice for attribute lookup
			payload := chunk[8:]
			n := len(payload) / 4
			d.resMap = make([]uint32, n)
			for i := 0; i < n; i++ {
				d.resMap[i] = binary.LittleEndian.Uint32(payload[i*4 : i*4+4])
			}

		case chunkXMLStartNS:
			// chunk[8:16] holds line/comment, then prefix-idx, uri-idx
			if len(chunk) >= 24 {
				prefix := binary.LittleEndian.Uint32(chunk[16:20])
				uri := binary.LittleEndian.Uint32(chunk[20:24])
				d.nsPrefixes[uri] = prefix
				d.nsStack.pushNamespace(prefix, uri)
			}

		case chunkXMLEndNS:
			d.nsStack.popNamespace()

		case chunkXMLStartElement:
			name, attrs, err := d.parseStartElement(chunk)
			if err != nil {
				return nil, err
			}
			if len(stack) >= maxNestingDepth {
				return nil, errors.New("axml: nesting depth exceeded")
			}
			stack = append(stack, name)
			d.nsStack.enterElement()

			indent := strings.Repeat("  ", len(stack)-1)
			xmlBuf.WriteString(indent)
			xmlBuf.WriteByte('<')
			xmlBuf.WriteString(name)

			if len(stack) == 1 {
				// On the root element, materialize all namespaces that
				// are currently in scope. Minifiers strip xmlns:android
				// from manifests routinely; we re-inject the standard
				// android URI as a fallback because every consumer
				// expects to find it.
				written := false
				for _, pair := range d.nsStack.activeURIs() {
					prefix := d.pool.String(pair[0])
					uri := d.pool.String(pair[1])
					if prefix == SentinelNoString || uri == SentinelNoString || prefix == "" {
						continue
					}
					xmlBuf.WriteString(` xmlns:`)
					xmlBuf.WriteString(prefix)
					xmlBuf.WriteString(`="`)
					xmlBuf.WriteString(escapeXML(uri))
					xmlBuf.WriteByte('"')
					if uri == androidNS {
						written = true
					}
				}
				if !written && name == "manifest" {
					xmlBuf.WriteString(` xmlns:android="`)
					xmlBuf.WriteString(androidNS)
					xmlBuf.WriteByte('"')
				}
			}

			d.applyAttrsToManifest(name, attrs, manifest, &curComp, &curList, &inFilter, &curFilt)

			for _, a := range attrs {
				xmlBuf.WriteByte(' ')
				if a.Namespace == androidNS {
					xmlBuf.WriteString("android:")
				} else if a.Namespace != "" {
					// Try to resolve a non-android namespace prefix
					// from the current scope. Falls back to no prefix
					// when the minifier nuked the declaration.
					if prefix := d.lookupPrefix(a.Namespace); prefix != "" {
						xmlBuf.WriteString(prefix)
						xmlBuf.WriteByte(':')
					}
				}
				xmlBuf.WriteString(a.Name)
				xmlBuf.WriteString(`="`)
				xmlBuf.WriteString(escapeXML(a.Value))
				xmlBuf.WriteByte('"')
			}
			xmlBuf.WriteString(">\n")

		case chunkXMLEndElement:
			if len(stack) == 0 {
				continue
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			d.nsStack.leaveElement()
			indent := strings.Repeat("  ", len(stack))
			xmlBuf.WriteString(indent)
			xmlBuf.WriteString("</")
			xmlBuf.WriteString(top)
			xmlBuf.WriteString(">\n")

			d.finalizeElement(top, manifest, &curComp, &curList, &inFilter, &curFilt)

		case chunkXMLCData:
			// usually unused in manifests; skip

		case chunkNull:
			// padding — advance

		default:
			// unknown chunk; skip
		}

		cursor = uint32(end)
	}

	manifest.XMLBytes = []byte(xmlBuf.String())
	return manifest, nil
}

// parsedAttr is the attribute view emitted by parseStartElement.
type parsedAttr struct {
	Namespace string
	Name      string
	Value     string
	RawType   uint8
	RawData   uint32
}

// parseStartElement decodes a RES_XML_START_ELEMENT_TYPE chunk.
//
// Layout after the 16-byte node header (lineNumber, comment, ns, name):
//
//	u32 attributeStart  // offset from chunk-after-header
//	u16 attributeSize   // 0x14 in current AXML
//	u16 attributeCount
//	u16 idIndex / classIndex / styleIndex (1-based, 0 = none)
//	... attributeCount * Res_XML_attribute (each = 5 u32 = 20 bytes) ...
func (d *Decoder) parseStartElement(chunk []byte) (string, []parsedAttr, error) {
	if len(chunk) < 8+16+12 {
		return "", nil, errors.New("axml: start element too small")
	}

	// node header (16 bytes after generic chunk header)
	body := chunk[8:]
	nameIdx := binary.LittleEndian.Uint32(body[12:16])

	// Element layout starting at body[16]:
	//   u16 attrStart (offset from body[8] = namespace index)
	//   u16 attrSize  (typically 20, room for vendor extensions)
	//   u16 attrCount
	//   u16 idIndex / classIndex / styleIndex
	// Note: attrStart is relative to the namespace index field, NOT
	// relative to the body or chunk. Misreading this as u32 leads to
	// astronomical offsets and bogus "bad chunk size" errors.
	attrStart := uint64(binary.LittleEndian.Uint16(body[16:18]))
	attrSize := binary.LittleEndian.Uint16(body[18:20])
	attrCount := binary.LittleEndian.Uint16(body[20:22])

	if attrCount > maxAttributesPerNode {
		return "", nil, fmt.Errorf("axml: refusing %d attrs", attrCount)
	}
	if attrSize == 0 {
		attrSize = 20
	}
	// Attribute records are indexed with fixed u32 reads up to raw[16:20];
	// anything smaller than 20 bytes would panic on those slices.
	if attrSize < 20 {
		return "", nil, fmt.Errorf("axml: attribute size %d too small", attrSize)
	}

	// attrStart is the offset from body[8] (start of namespace index)
	base := uint64(8) + attrStart
	end := base + uint64(attrCount)*uint64(attrSize)
	if end > uint64(len(body)) {
		return "", nil, errors.New("axml: attributes overrun chunk")
	}

	attrs := make([]parsedAttr, 0, attrCount)
	for i := uint16(0); i < attrCount; i++ {
		off := base + uint64(i)*uint64(attrSize)
		raw := body[off : off+uint64(attrSize)]
		nsIdx := binary.LittleEndian.Uint32(raw[0:4])
		nIdx := binary.LittleEndian.Uint32(raw[4:8])
		strIdx := binary.LittleEndian.Uint32(raw[8:12])
		// raw[12:16] is value size + zero
		valType := raw[15]
		valData := binary.LittleEndian.Uint32(raw[16:20])

		nsURI := ""
		if d.pool.Has(nsIdx) {
			nsURI = d.pool.String(nsIdx)
		}
		attrName := d.attrName(nIdx)
		attrValue := d.formatAttrValue(valType, valData, strIdx)

		attrs = append(attrs, parsedAttr{
			Namespace: nsURI,
			Name:      attrName,
			Value:     attrValue,
			RawType:   valType,
			RawData:   valData,
		})
	}

	return d.pool.String(nameIdx), attrs, nil
}

// lookupPrefix resolves a namespace URI to its current prefix string,
// or "" if no in-scope declaration matches. Walks the runtime stack
// rather than the root snapshot so we still see redeclarations.
func (d *Decoder) lookupPrefix(uri string) string {
	if d.pool == nil || uri == "" {
		return ""
	}
	for _, pair := range d.nsStack.activeURIs() {
		if d.pool.String(pair[1]) == uri {
			s := d.pool.String(pair[0])
			if s == SentinelNoString {
				return ""
			}
			return s
		}
	}
	return ""
}

// attrName resolves a name index. AXML attributes from the public
// android.* namespace are typically empty strings in the pool — the
// real identifier lives in the resource map. We probe both sources.
func (d *Decoder) attrName(idx uint32) string {
	if d.pool.Has(idx) {
		s := d.pool.String(idx)
		if s != "" {
			return s
		}
	}
	if int(idx) < len(d.resMap) {
		id := d.resMap[idx]
		if name, ok := resourceID[id]; ok {
			return name
		}
		return fmt.Sprintf("attr_%08x", id)
	}
	return SentinelNoString
}

// formatAttrValue prints a Res_value tuple in the same convention
// aapt uses for `aapt dump xmltree`-style output.
func (d *Decoder) formatAttrValue(t uint8, data uint32, strIdx uint32) string {
	switch t {
	case typeNull:
		return ""
	case typeReference, typeDynamicRef:
		return fmt.Sprintf("@0x%08x", data)
	case typeAttribute, typeDynamicAttr:
		return fmt.Sprintf("?0x%08x", data)
	case typeString:
		if d.pool.Has(strIdx) {
			return d.pool.String(strIdx)
		}
		return ""
	case typeFloat:
		return strconv.FormatFloat(float64(uint32ToFloat(data)), 'g', -1, 32)
	case typeIntDec:
		return strconv.FormatInt(int64(int32(data)), 10)
	case typeIntHex:
		return fmt.Sprintf("0x%08x", data)
	case typeIntBoolean:
		if data == 0 {
			return "false"
		}
		return "true"
	case typeIntColorARGB8, typeIntColorRGB8, typeIntColorARGB4, typeIntColorRGB4:
		return fmt.Sprintf("#%08x", data)
	default:
		return fmt.Sprintf("0x%x", data)
	}
}

// applyAttrsToManifest is the heuristic mapper that promotes a flat
// attribute stream into the structured Manifest. Element handling is
// table-driven: only manifest-relevant tags trigger state changes.
func (d *Decoder) applyAttrsToManifest(
	tag string,
	attrs []parsedAttr,
	m *Manifest,
	curComp **Component,
	curList **[]Component,
	inFilter *bool,
	curFilt **IntentFilter,
) {
	switch tag {
	case "manifest":
		for _, a := range attrs {
			switch a.Name {
			case "package":
				m.Package = a.Value
			case "versionCode":
				if v, err := strconv.ParseUint(a.Value, 0, 32); err == nil {
					m.VersionCode = uint32(v)
				}
			case "versionName":
				m.VersionName = a.Value
			case "sharedUserId":
				m.SharedUserID = a.Value
			case "compileSdkVersion":
				if v, err := strconv.ParseUint(a.Value, 0, 32); err == nil {
					m.CompileSDK = uint32(v)
				}
			}
		}

	case "uses-sdk":
		for _, a := range attrs {
			switch a.Name {
			case "minSdkVersion":
				if v, err := strconv.ParseUint(a.Value, 0, 32); err == nil {
					m.MinSDK = uint32(v)
				}
			case "targetSdkVersion":
				if v, err := strconv.ParseUint(a.Value, 0, 32); err == nil {
					m.TargetSDK = uint32(v)
				}
			}
		}

	case "uses-permission":
		if name := lookupAttr(attrs, "name"); name != "" {
			m.Permissions = append(m.Permissions, name)
		}
	case "uses-permission-sdk-23":
		if name := lookupAttr(attrs, "name"); name != "" {
			m.OptionalPerms = append(m.OptionalPerms, name)
		}

	case "uses-feature":
		req := true
		if v := lookupAttr(attrs, "required"); v == "false" {
			req = false
		}
		if name := lookupAttr(attrs, "name"); name != "" {
			m.UsesFeatures = append(m.UsesFeatures, FeatureInfo{Name: name, Required: req})
		}

	case "application":
		for _, a := range attrs {
			switch a.Name {
			case "name":
				m.Application.Name = a.Value
			case "label":
				m.Application.Label = a.Value
			case "icon":
				m.Application.Icon = a.Value
			case "theme":
				m.Application.Theme = a.Value
			case "debuggable":
				m.Application.Debuggable = parseManifestBool(a.Value)
			case "allowBackup":
				value := parseManifestBool(a.Value)
				m.Application.AllowBackup = value
				m.Application.AllowBackupDeclared = &value
			case "usesCleartextTraffic":
				value := parseManifestBool(a.Value)
				m.Application.UsesCleartext = value
				m.Application.CleartextDeclared = &value
			case "networkSecurityConfig":
				m.Application.NetworkSecCfg = a.Value
			case "fullBackupContent", "fullBackupContent_v1":
				m.Application.FullBackupContent = a.Value
			case "dataExtractionRules":
				m.Application.DataExtractionRules = a.Value
			case "fullBackupOnly":
				value := parseManifestBool(a.Value)
				m.Application.FullBackupOnly = &value
			case "process":
				m.Application.Process = a.Value
			case "extractNativeLibs":
				m.Application.ExtractNativeLibs = parseManifestBool(a.Value)
			case "hasCode":
				m.Application.HasCode = parseManifestBool(a.Value)
			}
		}

	case "activity", "activity-alias":
		*curList = &m.Activities
		*curComp = newComponent(attrs)
	case "service":
		*curList = &m.Services
		*curComp = newComponent(attrs)
	case "receiver":
		*curList = &m.Receivers
		*curComp = newComponent(attrs)
	case "provider":
		*curList = &m.Providers
		*curComp = newComponent(attrs)
		(*curComp).Authorities = lookupAttr(attrs, "authorities")

	case "intent-filter":
		if *curComp != nil {
			*inFilter = true
			*curFilt = &IntentFilter{}
			// android:autoVerify (App Links) is declared on the filter but
			// Android applies verification per activity, so lift it onto the
			// component. A single true declaration wins over later false ones.
			if v := lookupAttrOpt(attrs, "autoVerify"); v != nil {
				b := parseManifestBool(*v)
				if b || (*curComp).AutoVerify == nil {
					(*curComp).AutoVerify = &b
				}
			}
		}
	case "action":
		if *inFilter && *curFilt != nil {
			if v := lookupAttr(attrs, "name"); v != "" {
				(*curFilt).Actions = append((*curFilt).Actions, v)
			}
		}
	case "category":
		if *inFilter && *curFilt != nil {
			if v := lookupAttr(attrs, "name"); v != "" {
				(*curFilt).Categories = append((*curFilt).Categories, v)
			}
		}
	case "data":
		if *inFilter && *curFilt != nil {
			if s := lookupAttr(attrs, "scheme"); s != "" {
				(*curFilt).DataScheme = append((*curFilt).DataScheme, s)
			}
			if h := lookupAttr(attrs, "host"); h != "" {
				(*curFilt).DataHost = append((*curFilt).DataHost, h)
			}
		}

	case "meta-data":
		k := lookupAttr(attrs, "name")
		v := lookupAttr(attrs, "value")
		if v == "" {
			v = lookupAttr(attrs, "resource")
		}
		if k != "" {
			m.MetaData[k] = v
		}
	}
}

// finalizeElement closes the current state at end-element boundaries.
func (d *Decoder) finalizeElement(
	tag string,
	m *Manifest,
	curComp **Component,
	curList **[]Component,
	inFilter *bool,
	curFilt **IntentFilter,
) {
	switch tag {
	case "intent-filter":
		if *curComp != nil && *curFilt != nil {
			(*curComp).IntentFilts = append((*curComp).IntentFilts, **curFilt)
		}
		*inFilter = false
		*curFilt = nil
	case "activity", "activity-alias", "service", "receiver", "provider":
		if *curComp != nil && *curList != nil {
			**curList = append(**curList, **curComp)
		}
		*curComp = nil
		*curList = nil
	}
	_ = m
}

func newComponent(attrs []parsedAttr) *Component {
	c := &Component{
		Name:            lookupAttr(attrs, "name"),
		Permission:      lookupAttr(attrs, "permission"),
		ReadPermission:  lookupAttr(attrs, "readPermission"),
		WritePermission: lookupAttr(attrs, "writePermission"),
		Process:         lookupAttr(attrs, "process"),
		LaunchMode:      lookupAttr(attrs, "launchMode"),
		TaskAffinity:    lookupAttr(attrs, "taskAffinity"),
	}
	if v := lookupAttrOpt(attrs, "exported"); v != nil {
		b := parseManifestBool(*v)
		c.Exported = &b
	}
	if v := lookupAttrOpt(attrs, "enabled"); v != nil {
		b := parseManifestBool(*v)
		c.Enabled = &b
	}
	if v := lookupAttrOpt(attrs, "grantUriPermissions"); v != nil {
		b := parseManifestBool(*v)
		c.GrantUriPermissions = &b
	}
	return c
}

func parseManifestBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "0xffffffff":
		return true
	default:
		return false
	}
}

func lookupAttr(attrs []parsedAttr, name string) string {
	for _, a := range attrs {
		if a.Name == name {
			return a.Value
		}
	}
	return ""
}

func lookupAttrOpt(attrs []parsedAttr, name string) *string {
	for _, a := range attrs {
		if a.Name == name {
			v := a.Value
			return &v
		}
	}
	return nil
}

func uint32ToFloat(b uint32) float32 {
	// inline math.Float32frombits to avoid importing math here
	return float32frombits(b)
}

// float32frombits is a copy of math.Float32frombits — duplicated so
// this package stays std-only with no transitive imports beyond strconv.
func float32frombits(b uint32) float32 {
	return *(*float32)(unsafePointerCast(&b))
}

func escapeXML(s string) string {
	if !needsEscape(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func needsEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&', '<', '>', '"', '\'':
			return true
		}
	}
	return false
}
