package axml

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// CompiledResources contains new binary resources and file resources to copy.
// Source files are never changed; callers can stage an APK before publication.
type CompiledResources struct {
	Binary  map[string][]byte
	Copy    []string
	Symbols string
}

type nativeResource struct {
	typ, name string
	id        uint32
	values    map[string]nativeResourceValue
}
type nativeResourceValue struct {
	config []byte
	text   string
	file   bool
}
type nativeResourceCompiler struct {
	resources map[string]*nativeResource
	public    map[string]uint32
	xml       map[string][]byte
	result    CompiledResources
}

// CompileResourceDirectory supports scalar values, IDs and file resources with
// common locale, density, orientation, night, screen-size and API qualifiers.
// Complex bags, custom attrs, styled strings and nine-patches are rejected.
// Public IDs, when supplied in public.xml, are retained exactly.
func CompileResourceDirectory(ctx context.Context, sourceDir string) (*CompiledResources, error) {
	c := &nativeResourceCompiler{resources: map[string]*nativeResource{}, public: map[string]uint32{}, xml: map[string][]byte{}, result: CompiledResources{Binary: map[string][]byte{}}}
	manifest, err := os.ReadFile(filepath.Join(sourceDir, "AndroidManifest.xml"))
	if err != nil {
		return nil, err
	}
	doc, err := ParseTextAXML(manifest)
	if err != nil {
		return nil, fmt.Errorf("AndroidManifest.xml: %w", err)
	}
	if doc.Root.Name != "manifest" {
		return nil, fmt.Errorf("AndroidManifest.xml: root must be <manifest>")
	}
	pkg := ""
	for _, a := range doc.Root.Attrs {
		if a.NS == "" && a.Name == "package" {
			pkg = a.Str
		}
	}
	c.xml["AndroidManifest.xml"] = manifest
	resDir := filepath.Join(sourceDir, "res")
	err = filepath.WalkDir(resDir, func(path string, de os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			if path == resDir && os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if path == resDir {
			return nil
		}
		if strings.HasPrefix(de.Name(), ".") {
			if de.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if de.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("resource symlinks are not supported: %s", path)
		}
		rel, _ := filepath.Rel(resDir, path)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if de.IsDir() {
			if len(parts) > 1 {
				return fmt.Errorf("nested resource directory %s is not supported", rel)
			}
			return nil
		}
		if len(parts) != 2 {
			return fmt.Errorf("resource %s must be inside a resource-type directory", rel)
		}
		folder := strings.SplitN(parts[0], "-", 2)
		typ := folder[0]
		qual := ""
		if len(folder) > 1 {
			qual = folder[1]
		}
		config, err := nativeConfig(qual)
		if err != nil {
			return fmt.Errorf("res/%s: %w", rel, err)
		}
		if typ == "values" {
			if !strings.HasSuffix(parts[1], ".xml") {
				return fmt.Errorf("res/%s: values input must be XML", rel)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return c.readValues(data, config, "res/"+filepath.ToSlash(rel))
		}
		switch typ {
		case "raw", "drawable", "mipmap", "layout", "xml", "menu", "anim", "animator", "font":
		default:
			return fmt.Errorf("res/%s: unsupported resource type %q", rel, typ)
		}
		if strings.HasSuffix(strings.ToLower(parts[1]), ".9.png") {
			return fmt.Errorf("res/%s: native nine-patch compilation is not supported", rel)
		}
		name := strings.TrimSuffix(parts[1], filepath.Ext(parts[1]))
		zipPath := "res/" + filepath.ToSlash(rel)
		if err := c.add(typ, name, nativeResourceValue{config: config, text: zipPath, file: true}); err != nil {
			return fmt.Errorf("%s: %w", zipPath, err)
		}
		if strings.EqualFold(filepath.Ext(parts[1]), ".xml") && typ != "raw" {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if IsBinaryXML(data) {
				return fmt.Errorf("%s: compiled XML requires its original resource table", zipPath)
			}
			c.xml[zipPath] = data
		} else {
			c.result.Copy = append(c.result.Copy, zipPath)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// @+id declarations are collected before any references are linked.
	for _, path := range sortedNativeKeys(c.xml) {
		d, err := ParseTextAXML(c.xml[path])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		var visit func(*DomElem) error
		visit = func(e *DomElem) error {
			for _, a := range e.Attrs {
				if strings.HasPrefix(a.Str, "@+id/") {
					name := strings.TrimPrefix(a.Str, "@+id/")
					if _, exists := c.resources["id/"+name]; !exists {
						cfg, _ := nativeConfig("")
						if err := c.add("id", name, nativeResourceValue{config: cfg}); err != nil {
							return err
						}
					}
				}
			}
			for _, k := range e.Kids {
				if err := visit(k); err != nil {
					return err
				}
			}
			return nil
		}
		if err := visit(d.Root); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if len(c.resources) > 0 && (pkg == "" || len(utf16.Encode([]rune(pkg))) > 127) {
		return nil, fmt.Errorf("a package name of 1–127 UTF-16 characters is required to compile resources")
	}
	table, err := c.assignIDs(pkg)
	if err != nil {
		return nil, err
	}
	for _, path := range sortedNativeKeys(c.xml) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		bin, err := CompileTextAXML(c.xml[path], table)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		c.result.Binary[path] = bin
	}
	if len(c.resources) > 0 {
		bin, err := c.encodeTable(pkg, table)
		if err != nil {
			return nil, err
		}
		c.result.Binary["resources.arsc"] = bin
	}
	sort.Strings(c.result.Copy)
	return &c.result, nil
}

func sortedNativeKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func nativeResourceName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}
func (c *nativeResourceCompiler) add(typ, name string, v nativeResourceValue) error {
	if !nativeResourceName(name) {
		return fmt.Errorf("unsupported resource name %q (use letters, digits and underscores)", name)
	}
	key := typ + "/" + name
	r := c.resources[key]
	if r == nil {
		r = &nativeResource{typ: typ, name: name, values: map[string]nativeResourceValue{}}
		c.resources[key] = r
	}
	cfgKey := string(v.config)
	if _, exists := r.values[cfgKey]; exists {
		return fmt.Errorf("duplicate resource %s in the same configuration", key)
	}
	r.values[cfgKey] = v
	return nil
}

func (c *nativeResourceCompiler) readValues(data, config []byte, path string) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	root := false
	closed := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		switch el := tok.(type) {
		case xml.StartElement:
			if !root {
				if el.Name.Local != "resources" || el.Name.Space != "" {
					return fmt.Errorf("%s: expected <resources>", path)
				}
				root = true
				continue
			}
			if closed || el.Name.Space != "" {
				return fmt.Errorf("%s: invalid resource document", path)
			}
			name, typ, id, format := "", el.Name.Local, "", ""
			for _, a := range el.Attr {
				switch a.Name.Local {
				case "name":
					name = a.Value
				case "type":
					if typ == "item" || typ == "public" {
						format = a.Value
					}
				case "id":
					id = a.Value
				case "translatable", "formatted":
				default:
					return fmt.Errorf("%s: unsupported attribute %s on <%s>", path, a.Name.Local, el.Name.Local)
				}
			}
			if typ == "public" {
				if format == "" || name == "" {
					return fmt.Errorf("%s: public resource needs type and name", path)
				}
				n, err := strconv.ParseUint(id, 0, 32)
				if err != nil || n>>24 != 0x7f || (n>>16)&0xff == 0 {
					return fmt.Errorf("%s: invalid public ID %q", path, id)
				}
				key := format + "/" + name
				if _, exists := c.public[key]; exists {
					return fmt.Errorf("%s: duplicate public declaration %s", path, key)
				}
				c.public[key] = uint32(n)
				var content string
				if err := dec.DecodeElement(&content, &el); err != nil {
					return err
				}
				continue
			}
			if typ == "item" {
				typ = format
			}
			switch typ {
			case "string", "bool", "integer", "color", "dimen", "fraction", "id":
			default:
				return fmt.Errorf("%s: native compiler does not support <%s>; styles, arrays, plurals and custom attrs require a full resource compiler", path, typ)
			}
			var text strings.Builder
			for {
				token, err := dec.Token()
				if err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
				switch t := token.(type) {
				case xml.CharData:
					text.Write(t)
				case xml.Comment:
				case xml.EndElement:
					goto valueDone
				default:
					return fmt.Errorf("%s: styled/nested values are not supported for %s/%s", path, typ, name)
				}
			}
		valueDone:
			value := strings.TrimSpace(text.String())
			if typ == "string" {
				var err error
				value, err = nativeStringValue(value)
				if err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
			}
			if err := c.add(typ, name, nativeResourceValue{config: config, text: value}); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		case xml.EndElement:
			closed = true
		case xml.CharData:
			if strings.TrimSpace(string(el)) != "" {
				return fmt.Errorf("%s: text outside a resource", path)
			}
		}
	}
	if !root || !closed {
		return fmt.Errorf("%s: incomplete resources document", path)
	}
	return nil
}

func nativeStringValue(s string) (string, error) {
	quoted := len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"'
	if quoted {
		s = s[1 : len(s)-1]
	} else {
		s = strings.Join(strings.Fields(s), " ")
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out.WriteByte(s[i])
			continue
		}
		i++
		if i >= len(s) {
			return "", fmt.Errorf("trailing backslash in string resource")
		}
		switch s[i] {
		case 'n':
			out.WriteByte('\n')
		case 't':
			out.WriteByte('\t')
		case '\\', '\'', '"':
			out.WriteByte(s[i])
		case '@', '?':
			if out.Len() == 0 {
				out.WriteByte('\\')
			}
			out.WriteByte(s[i])
		case 'u':
			if i+4 >= len(s) {
				return "", fmt.Errorf("truncated Unicode escape")
			}
			n, err := strconv.ParseUint(s[i+1:i+5], 16, 16)
			if err != nil || n >= 0xd800 && n <= 0xdfff {
				return "", fmt.Errorf("unsupported Unicode escape; write the Unicode character directly")
			}
			out.WriteRune(rune(n))
			i += 4
		default:
			return "", fmt.Errorf("unsupported string escape \\%c", s[i])
		}
	}
	return out.String(), nil
}

func (c *nativeResourceCompiler) assignIDs(pkg string) (*ResourceTable, error) {
	typeIDs := map[string]uint32{}
	usedTypes := map[uint32]string{}
	used := map[uint32]string{}
	for key, id := range c.public {
		r := c.resources[key]
		if r == nil {
			return nil, fmt.Errorf("public resource %s has no definition", key)
		}
		tid := (id >> 16) & 0xff
		if old := typeIDs[r.typ]; old != 0 && old != tid {
			return nil, fmt.Errorf("conflicting public type IDs for %s", r.typ)
		}
		if old := usedTypes[tid]; old != "" && old != r.typ {
			return nil, fmt.Errorf("public type ID 0x%x reused by %s and %s", tid, old, r.typ)
		}
		if old := used[id]; old != "" {
			return nil, fmt.Errorf("public ID 0x%08x reused by %s and %s", id, old, key)
		}
		r.id = id
		typeIDs[r.typ] = tid
		usedTypes[tid] = r.typ
		used[id] = key
	}
	keys := sortedNativeKeys(c.resources)
	for _, key := range keys {
		r := c.resources[key]
		if typeIDs[r.typ] == 0 {
			var id uint32 = 1
			for usedTypes[id] != "" && id < 256 {
				id++
			}
			if id >= 256 {
				return nil, fmt.Errorf("too many resource types")
			}
			typeIDs[r.typ] = id
			usedTypes[id] = r.typ
		}
	}
	p := ResourcePackage{ID: 0x7f, Name: pkg, TypeIDs: typeIDs}
	var symbols strings.Builder
	for tid := uint32(1); tid < 256; tid++ {
		typ := usedTypes[tid]
		if typ == "" {
			continue
		}
		rt := ResourceType{ID: tid, Name: typ}
		var next uint32
		for _, key := range keys {
			r := c.resources[key]
			if r.typ != typ {
				continue
			}
			if r.id == 0 {
				for next < 65536 && used[0x7f000000|tid<<16|next] != "" {
					next++
				}
				if next >= 65536 {
					return nil, fmt.Errorf("too many %s resources", typ)
				}
				r.id = 0x7f000000 | tid<<16 | next
				used[r.id] = key
				next++
			}
			rt.Entries = append(rt.Entries, ResourceEntry{ID: r.id & 0xffff, Name: r.name})
			fmt.Fprintf(&symbols, "int %s %s 0x%08x\n", typ, r.name, r.id)
		}
		sort.Slice(rt.Entries, func(i, j int) bool { return rt.Entries[i].ID < rt.Entries[j].ID })
		p.Types = append(p.Types, rt)
	}
	c.result.Symbols = symbols.String()
	return &ResourceTable{Packages: []ResourcePackage{p}}, nil
}

func (c *nativeResourceCompiler) encodeTable(pkg string, table *ResourceTable) ([]byte, error) {
	global := &poolBuilder{index: map[string]uint32{}}
	types := &poolBuilder{index: map[string]uint32{}}
	keys := &poolBuilder{index: map[string]uint32{}}
	var chunks bytes.Buffer
	for _, rt := range table.Packages[0].Types {
		for uint32(len(types.items))+1 < rt.ID {
			types.add(fmt.Sprintf("unused_%d", len(types.items)+1))
		}
		types.add(rt.Name)
		count := rt.Entries[len(rt.Entries)-1].ID + 1
		spec := make([]byte, 16+4*count)
		nativeChunkHeader(spec, chunkTableTypeSpec, 16)
		spec[8] = byte(rt.ID)
		binary.LittleEndian.PutUint32(spec[12:], count)
		configs := map[string][]byte{}
		for _, e := range rt.Entries {
			r := c.resources[rt.Name+"/"+e.Name]
			keys.add(r.name)
			binary.LittleEndian.PutUint32(spec[16+e.ID*4:], 0x40000000)
			for k, v := range r.values {
				configs[k] = v.config
			}
		}
		chunks.Write(spec)
		for _, cfgKey := range sortedNativeKeys(configs) {
			cfg := configs[cfgKey]
			headerSize := 20 + len(cfg)
			start := headerSize + int(count)*4
			b := make([]byte, start)
			b[8] = byte(rt.ID)
			binary.LittleEndian.PutUint32(b[12:], count)
			binary.LittleEndian.PutUint32(b[16:], uint32(start))
			copy(b[20:], cfg)
			for i := uint32(0); i < count; i++ {
				binary.LittleEndian.PutUint32(b[headerSize+int(i)*4:], 0xffffffff)
			}
			for _, e := range rt.Entries {
				r := c.resources[rt.Name+"/"+e.Name]
				v, ok := r.values[cfgKey]
				if !ok {
					continue
				}
				var value DomAttr
				var err error
				if v.file {
					value = DomAttr{Type: typeString, Str: v.text}
				} else if r.typ == "id" {
					if v.text != "" {
						return nil, fmt.Errorf("id/%s cannot have a value", r.name)
					}
					value = DomAttr{Type: typeIntBoolean}
				} else {
					formats := map[string]string{"string": "string", "bool": "boolean", "integer": "integer", "color": "color", "dimen": "dimension", "fraction": "fraction"}
					value, err = nativeAttributeValue(v.text, nativeAttrSpec{Format: formats[r.typ]}, table)
				}
				if err != nil {
					return nil, fmt.Errorf("%s/%s: %w", r.typ, r.name, err)
				}
				if value.Type == typeString {
					if len(encodeCESU8Bytes(value.Str)) > 32767 {
						return nil, fmt.Errorf("%s/%s: string too large for native UTF-8 pool", r.typ, r.name)
					}
					value.Data = global.add(value.Str)
				}
				offset := len(b) - start
				binary.LittleEndian.PutUint32(b[headerSize+int(e.ID)*4:], uint32(offset))
				entry := make([]byte, 16)
				binary.LittleEndian.PutUint16(entry, 8)
				binary.LittleEndian.PutUint32(entry[4:], keys.index[r.name])
				binary.LittleEndian.PutUint16(entry[8:], 8)
				entry[11] = value.Type
				binary.LittleEndian.PutUint32(entry[12:], value.Data)
				b = append(b, entry...)
			}
			nativeChunkHeader(b, chunkTableType, uint16(headerSize))
			chunks.Write(b)
		}
	}
	tp, kp := types.build(), keys.build()
	p := make([]byte, 288)
	binary.LittleEndian.PutUint32(p[8:], 0x7f)
	for i, v := range utf16.Encode([]rune(pkg)) {
		binary.LittleEndian.PutUint16(p[12+i*2:], v)
	}
	binary.LittleEndian.PutUint32(p[268:], 288)
	binary.LittleEndian.PutUint32(p[272:], uint32(len(types.items)))
	binary.LittleEndian.PutUint32(p[276:], uint32(288+len(tp)))
	binary.LittleEndian.PutUint32(p[280:], uint32(len(keys.items)))
	p = append(p, tp...)
	p = append(p, kp...)
	p = append(p, chunks.Bytes()...)
	nativeChunkHeader(p, chunkTablePackage, 288)
	out := make([]byte, 12)
	binary.LittleEndian.PutUint32(out[8:], 1)
	out = append(out, global.build()...)
	out = append(out, p...)
	nativeChunkHeader(out, chunkTable, 12)
	return out, nil
}

func nativeChunkHeader(b []byte, typ, header uint16) {
	binary.LittleEndian.PutUint16(b, typ)
	binary.LittleEndian.PutUint16(b[2:], header)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
}

func nativeConfig(qual string) ([]byte, error) {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b, 64)
	if qual == "" {
		return b, nil
	}
	seen := map[string]bool{}
	for _, q := range strings.Split(qual, "-") {
		key := ""
		set16 := func(off int, n uint64) { binary.LittleEndian.PutUint16(b[off:], uint16(n)) }
		switch {
		case len(q) == 2 && q[0] >= 'a' && q[0] <= 'z' && q[1] >= 'a' && q[1] <= 'z':
			key = "locale"
			copy(b[8:], q)
		case len(q) == 3 && q[0] == 'r' && q[1] >= 'A' && q[1] <= 'Z' && q[2] >= 'A' && q[2] <= 'Z':
			key = "region"
			if !seen["locale"] {
				return nil, fmt.Errorf("region qualifier requires a language")
			}
			copy(b[10:], q[1:])
		case q == "land" || q == "port":
			key = "orientation"
			b[12] = 1
			if q == "land" {
				b[12] = 2
			}
		case q == "night" || q == "notnight":
			key = "night"
			b[29] = 0x10
			if q == "night" {
				b[29] = 0x20
			}
		case q == "ldpi" || q == "mdpi" || q == "tvdpi" || q == "hdpi" || q == "xhdpi" || q == "xxhdpi" || q == "xxxhdpi" || q == "nodpi" || q == "anydpi":
			key = "density"
			set16(14, map[string]uint64{"ldpi": 120, "mdpi": 160, "tvdpi": 213, "hdpi": 240, "xhdpi": 320, "xxhdpi": 480, "xxxhdpi": 640, "nodpi": 65535, "anydpi": 65534}[q])
		case strings.HasPrefix(q, "v"):
			key = "sdk"
			n, err := strconv.ParseUint(q[1:], 10, 16)
			if err != nil || n == 0 {
				return nil, fmt.Errorf("invalid API qualifier %q", q)
			}
			set16(24, n)
		case strings.HasSuffix(q, "dp") && (strings.HasPrefix(q, "sw") || strings.HasPrefix(q, "w") || strings.HasPrefix(q, "h")):
			prefix, off := "w", 32
			if strings.HasPrefix(q, "sw") {
				prefix, off = "sw", 30
			} else if strings.HasPrefix(q, "h") {
				prefix, off = "h", 34
			}
			key = prefix
			n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(q, prefix), "dp"), 10, 16)
			if err != nil || n == 0 {
				return nil, fmt.Errorf("invalid screen qualifier %q", q)
			}
			set16(off, n)
		default:
			return nil, fmt.Errorf("native resource qualifier %q is not supported", q)
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate %s resource qualifier", key)
		}
		seen[key] = true
	}
	return b, nil
}
