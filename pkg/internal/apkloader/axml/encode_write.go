package axml

// Binary serializer for the overlay DOM.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// EncodeDomAXML serializes a merged DOM into binary AXML.
func EncodeDomAXML(doc *DomDoc) ([]byte, error) {
	if doc == nil || doc.Root == nil {
		return nil, fmt.Errorf("axml: nothing to encode")
	}
	p := &poolBuilder{index: map[string]uint32{}}
	for _, ns := range doc.NS {
		p.add(ns[0])
		p.add(ns[1])
	}
	collectDocStrings(p, doc.Root)
	poolChunk := p.build()
	resMap := make([]uint32, len(p.items))
	for i := range resMap {
		resMap[i] = 0
	}
	// Resource map must cover every attribute-name index.
	markRes := func(name string, id uint32) {
		if id == 0 {
			return
		}
		idx, ok := p.index[name]
		if !ok {
			return
		}
		resMap[idx] = id
	}
	var walkRes func(el *DomElem)
	walkRes = func(el *DomElem) {
		for _, a := range el.Attrs {
			markRes(a.Name, a.ResID)
		}
		for _, k := range el.Kids {
			walkRes(k)
		}
	}
	walkRes(doc.Root)

	var body bytes.Buffer
	body.Write(poolChunk)
	body.Write(buildResMap(resMap))
	// Namespace declarations at root scope.
	for _, ns := range doc.NS {
		body.Write(buildNSChunk(chunkXMLStartNS, p.index[ns[0]], p.index[ns[1]]))
	}
	if err := writeElem(&body, p, doc.Root); err != nil {
		return nil, err
	}
	for i := len(doc.NS) - 1; i >= 0; i-- {
		ns := doc.NS[i]
		body.Write(buildNSChunk(chunkXMLEndNS, p.index[ns[0]], p.index[ns[1]]))
	}
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, chunkXML)
	_ = binary.Write(&out, binary.LittleEndian, uint16(8))
	_ = binary.Write(&out, binary.LittleEndian, uint32(8+body.Len()))
	out.Write(body.Bytes())
	return out.Bytes(), nil
}

func collectDocStrings(p *poolBuilder, el *DomElem) {
	p.add(el.Name)
	for _, a := range el.Attrs {
		if a.NS != "" {
			p.add(a.NS)
		}
		p.add(a.Name)
		if a.Type == typeString {
			p.add(a.Str)
		}
	}
	for _, k := range el.Kids {
		collectDocStrings(p, k)
	}
}

func writeElem(body *bytes.Buffer, p *poolBuilder, el *DomElem) error {
	nameIdx, ok := p.index[el.Name]
	if !ok {
		return fmt.Errorf("axml: string %q missing from pool", el.Name)
	}
	attrBase := uint32(36)
	_ = attrBase
	chunkSize := uint32(36 + 20*len(el.Attrs))
	var chunk bytes.Buffer
	_ = binary.Write(&chunk, binary.LittleEndian, chunkXMLStartElement)
	_ = binary.Write(&chunk, binary.LittleEndian, uint16(16))
	_ = binary.Write(&chunk, binary.LittleEndian, chunkSize)
	_ = binary.Write(&chunk, binary.LittleEndian, uint32(0))          // line
	_ = binary.Write(&chunk, binary.LittleEndian, uint32(0xFFFFFFFF)) // comment
	_ = binary.Write(&chunk, binary.LittleEndian, uint32(0xFFFFFFFF)) // ns
	_ = binary.Write(&chunk, binary.LittleEndian, nameIdx)
	_ = binary.Write(&chunk, binary.LittleEndian, uint16(20)) // attrStart
	_ = binary.Write(&chunk, binary.LittleEndian, uint16(20)) // attrSize
	_ = binary.Write(&chunk, binary.LittleEndian, uint16(len(el.Attrs)))
	var idIndex, classIndex, styleIndex uint16
	for i, a := range el.Attrs {
		if a.NS == androidNS && a.Name == "id" {
			idIndex = uint16(i + 1)
		}
		if a.NS == "" && a.Name == "class" {
			classIndex = uint16(i + 1)
		}
		if a.NS == "" && a.Name == "style" {
			styleIndex = uint16(i + 1)
		}
	}
	_ = binary.Write(&chunk, binary.LittleEndian, idIndex)
	_ = binary.Write(&chunk, binary.LittleEndian, classIndex)
	_ = binary.Write(&chunk, binary.LittleEndian, styleIndex)
	for _, a := range el.Attrs {
		nsIdx := uint32(0xFFFFFFFF)
		if a.NS != "" {
			ni, ok := p.index[a.NS]
			if !ok {
				return fmt.Errorf("axml: namespace %q missing from pool", a.NS)
			}
			nsIdx = ni
		}
		nIdx, ok := p.index[a.Name]
		if !ok {
			return fmt.Errorf("axml: attr name %q missing from pool", a.Name)
		}
		strIdx := uint32(0xFFFFFFFF)
		data := a.Data
		if a.Type == typeString {
			si, ok := p.index[a.Str]
			if !ok {
				return fmt.Errorf("axml: string value missing from pool")
			}
			strIdx, data = si, si
		}
		_ = binary.Write(&chunk, binary.LittleEndian, nsIdx)
		_ = binary.Write(&chunk, binary.LittleEndian, nIdx)
		_ = binary.Write(&chunk, binary.LittleEndian, strIdx)
		_ = binary.Write(&chunk, binary.LittleEndian, uint16(8)) // value size
		_ = binary.Write(&chunk, binary.LittleEndian, uint8(0))  // res0
		_ = binary.Write(&chunk, binary.LittleEndian, a.Type)
		_ = binary.Write(&chunk, binary.LittleEndian, data)
	}
	body.Write(chunk.Bytes())
	for _, k := range el.Kids {
		if err := writeElem(body, p, k); err != nil {
			return err
		}
	}
	var end bytes.Buffer
	_ = binary.Write(&end, binary.LittleEndian, chunkXMLEndElement)
	_ = binary.Write(&end, binary.LittleEndian, uint16(16))
	_ = binary.Write(&end, binary.LittleEndian, uint32(24))
	_ = binary.Write(&end, binary.LittleEndian, uint32(0))
	_ = binary.Write(&end, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&end, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&end, binary.LittleEndian, nameIdx)
	body.Write(end.Bytes())
	return nil
}

func buildNSChunk(typ uint16, prefix, uri uint32) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, typ)
	_ = binary.Write(&b, binary.LittleEndian, uint16(16))
	_ = binary.Write(&b, binary.LittleEndian, uint32(24))
	_ = binary.Write(&b, binary.LittleEndian, uint32(0))
	_ = binary.Write(&b, binary.LittleEndian, uint32(0xFFFFFFFF))
	_ = binary.Write(&b, binary.LittleEndian, prefix)
	_ = binary.Write(&b, binary.LittleEndian, uri)
	return b.Bytes()
}

func buildResMap(ids []uint32) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, chunkXMLResourceMap)
	_ = binary.Write(&b, binary.LittleEndian, uint16(8))
	_ = binary.Write(&b, binary.LittleEndian, uint32(8+4*len(ids)))
	for _, id := range ids {
		_ = binary.Write(&b, binary.LittleEndian, id)
	}
	return b.Bytes()
}

// poolBuilder assigns pool indices in first-use order.
type poolBuilder struct {
	items []string
	index map[string]uint32
}

func (p *poolBuilder) add(s string) uint32 {
	if i, ok := p.index[s]; ok {
		return i
	}
	i := uint32(len(p.items))
	p.items = append(p.items, s)
	p.index[s] = i
	return i
}

func (p *poolBuilder) build() []byte {
	var data bytes.Buffer
	offsets := make([]uint32, len(p.items))
	for i, s := range p.items {
		offsets[i] = uint32(data.Len())
		enc := encodeCESU8Bytes(s)
		u16 := utf16.Encode([]rune(s))
		writeLen(&data, len(u16))
		writeLen(&data, len(enc))
		data.Write(enc)
		data.WriteByte(0)
	}
	for data.Len()%4 != 0 {
		data.WriteByte(0)
	}
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, chunkStringPool)
	_ = binary.Write(&out, binary.LittleEndian, uint16(28))
	stringsStart := uint32(28 + 4*len(p.items))
	_ = binary.Write(&out, binary.LittleEndian, uint32(28+4*len(p.items)+data.Len()))
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(p.items)))
	_ = binary.Write(&out, binary.LittleEndian, uint32(0)) // styles
	_ = binary.Write(&out, binary.LittleEndian, flagUTF8)
	_ = binary.Write(&out, binary.LittleEndian, stringsStart)
	_ = binary.Write(&out, binary.LittleEndian, uint32(0)) // stylesStart
	for _, o := range offsets {
		_ = binary.Write(&out, binary.LittleEndian, o)
	}
	out.Write(data.Bytes())
	return out.Bytes()
}

func writeLen(b *bytes.Buffer, n int) {
	if n > 0x7F {
		b.WriteByte(byte((n>>8)&0x7F) | 0x80)
		b.WriteByte(byte(n & 0xFF))
	} else {
		b.WriteByte(byte(n))
	}
}

// encodeCESU8Bytes encodes s the way Android resource pools do: astral
// characters become UTF-16 surrogate pairs, each half UTF-8 encoded.
func encodeCESU8Bytes(s string) []byte {
	var out []byte
	for _, r := range s {
		switch {
		case r < 0x80:
			out = append(out, byte(r))
		case r < 0x800:
			out = append(out, byte(0xC0|(r>>6)), byte(0x80|(r&0x3F)))
		case r < 0x10000:
			out = append(out, byte(0xE0|(r>>12)), byte(0x80|((r>>6)&0x3F)), byte(0x80|(r&0x3F)))
		default:
			r1, r2 := utf16.EncodeRune(r)
			for _, sr := range []rune{r1, r2} {
				out = append(out, byte(0xE0|(sr>>12)), byte(0x80|((sr>>6)&0x3F)), byte(0x80|(sr&0x3F)))
			}
		}
	}
	return out
}
