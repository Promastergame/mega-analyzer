package axml

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// AXML chunk size cheat-sheet (used to verify the fixture below):
//   generic chunk header                                = 8 bytes
//   RES_XML_node header (line, comment)                 = 8 bytes
//   RES_XML_namespaceExt (prefix, uri)                  = 8 bytes
//   RES_XML_attrExt (ns, name, 6 * u16)                 = 20 bytes
//   RES_XML_attribute (ns, name, raw, size, res0, type, data) = 20 bytes
//   RES_XML_endElementExt (ns, name)                    = 8 bytes
//
// Therefore:
//   StartNamespace / EndNamespace chunk size = 8 + 8 + 8  = 24
//   StartElement chunk size                  = 8 + 8 + 20 + N*20
//   EndElement chunk size                    = 8 + 8 + 8  = 24

const (
	chunkHdrSize  = 8
	nodeHdrSize   = 8
	nsExtSize     = 8
	attrExtSize   = 20
	attrSize      = 20
	endExtSize    = 8
	nsChunkSize   = chunkHdrSize + nodeHdrSize + nsExtSize  // 24
	endElemChunk  = chunkHdrSize + nodeHdrSize + endExtSize // 24
	headerNodeAll = chunkHdrSize + nodeHdrSize              // 16
)

func startElemSize(attrs int) uint32 {
	return uint32(chunkHdrSize + nodeHdrSize + attrExtSize + attrs*attrSize)
}

// buildMinimalAXML constructs a tiny but valid AXML buffer with one
// <manifest package="com.example"><uses-permission name="..."/></manifest>
// element. Used as a controlled fixture so the decoder is exercised
// end-to-end without depending on a real APK.
func buildMinimalAXML(t *testing.T) []byte {
	t.Helper()

	strs := []string{
		"manifest",                    // 0 - element name
		"uses-permission",             // 1 - element name
		"package",                     // 2 - attr name (no resID)
		"name",                        // 3 - attr name (with resID)
		"com.example",                 // 4 - package value
		"android.permission.INTERNET", // 5 - permission value
		"http://schemas.android.com/apk/res/android", // 6 - ns uri
		"android", // 7 - ns prefix
	}

	// String pool body: each entry has utf-16 char count + utf-8 byte
	// count + payload + NUL. We pad to 4-byte alignment afterwards.
	var sbuf bytes.Buffer
	offsets := make([]uint32, len(strs))
	for i, s := range strs {
		offsets[i] = uint32(sbuf.Len())
		sbuf.WriteByte(byte(len(s))) // utf-16 char count
		sbuf.WriteByte(byte(len(s))) // utf-8 byte count
		sbuf.WriteString(s)
		sbuf.WriteByte(0)
	}
	for sbuf.Len()%4 != 0 {
		sbuf.WriteByte(0)
	}

	const poolHeaderSize = 28 // 8 chunk hdr + 20 pool-specific
	stringsStart := uint32(poolHeaderSize + len(offsets)*4)

	stringPool := new(bytes.Buffer)
	binary.Write(stringPool, binary.LittleEndian, chunkStringPool)
	binary.Write(stringPool, binary.LittleEndian, uint16(28))
	chunkSizePos := stringPool.Len()
	binary.Write(stringPool, binary.LittleEndian, uint32(0))
	binary.Write(stringPool, binary.LittleEndian, uint32(len(strs)))
	binary.Write(stringPool, binary.LittleEndian, uint32(0))
	binary.Write(stringPool, binary.LittleEndian, flagUTF8)
	binary.Write(stringPool, binary.LittleEndian, stringsStart)
	binary.Write(stringPool, binary.LittleEndian, uint32(0))
	for _, off := range offsets {
		binary.Write(stringPool, binary.LittleEndian, off)
	}
	stringPool.Write(sbuf.Bytes())
	for stringPool.Len()%4 != 0 {
		stringPool.WriteByte(0)
	}
	chunkBytes := stringPool.Bytes()
	binary.LittleEndian.PutUint32(chunkBytes[chunkSizePos:], uint32(stringPool.Len()))

	// Resource map: 4 entries
	resMap := new(bytes.Buffer)
	binary.Write(resMap, binary.LittleEndian, chunkXMLResourceMap)
	binary.Write(resMap, binary.LittleEndian, uint16(8))
	binary.Write(resMap, binary.LittleEndian, uint32(8+4*4))
	binary.Write(resMap, binary.LittleEndian, uint32(0))
	binary.Write(resMap, binary.LittleEndian, uint32(0))
	binary.Write(resMap, binary.LittleEndian, uint32(0))
	binary.Write(resMap, binary.LittleEndian, uint32(0x01010003))

	writeNodeHeader := func(buf *bytes.Buffer) {
		binary.Write(buf, binary.LittleEndian, uint32(1))
		binary.Write(buf, binary.LittleEndian, uint32(0xFFFFFFFF))
	}

	// StartNamespace: android -> http://schemas...
	startNS := new(bytes.Buffer)
	binary.Write(startNS, binary.LittleEndian, chunkXMLStartNS)
	binary.Write(startNS, binary.LittleEndian, uint16(headerNodeAll))
	binary.Write(startNS, binary.LittleEndian, uint32(nsChunkSize))
	writeNodeHeader(startNS)
	binary.Write(startNS, binary.LittleEndian, uint32(7))
	binary.Write(startNS, binary.LittleEndian, uint32(6))

	// StartElement: manifest with package="com.example"
	startManifest := new(bytes.Buffer)
	binary.Write(startManifest, binary.LittleEndian, chunkXMLStartElement)
	binary.Write(startManifest, binary.LittleEndian, uint16(headerNodeAll))
	binary.Write(startManifest, binary.LittleEndian, startElemSize(1))
	writeNodeHeader(startManifest)
	binary.Write(startManifest, binary.LittleEndian, uint32(0xFFFFFFFF))  // ns
	binary.Write(startManifest, binary.LittleEndian, uint32(0))           // name = "manifest"
	binary.Write(startManifest, binary.LittleEndian, uint16(attrExtSize)) // attrStart
	binary.Write(startManifest, binary.LittleEndian, uint16(attrSize))    // attrSize
	binary.Write(startManifest, binary.LittleEndian, uint16(1))           // attrCount
	binary.Write(startManifest, binary.LittleEndian, uint16(0))           // idIndex
	binary.Write(startManifest, binary.LittleEndian, uint16(0))           // classIndex
	binary.Write(startManifest, binary.LittleEndian, uint16(0))           // styleIndex
	// Attribute: package="com.example"
	binary.Write(startManifest, binary.LittleEndian, uint32(0xFFFFFFFF)) // ns
	binary.Write(startManifest, binary.LittleEndian, uint32(2))          // name = "package"
	binary.Write(startManifest, binary.LittleEndian, uint32(4))          // raw value = "com.example"
	binary.Write(startManifest, binary.LittleEndian, uint16(8))          // value size
	startManifest.WriteByte(0)                                           // res0
	startManifest.WriteByte(typeString)                                  // value type
	binary.Write(startManifest, binary.LittleEndian, uint32(4))          // value data

	// StartElement: uses-permission android:name="android.permission.INTERNET"
	startPerm := new(bytes.Buffer)
	binary.Write(startPerm, binary.LittleEndian, chunkXMLStartElement)
	binary.Write(startPerm, binary.LittleEndian, uint16(headerNodeAll))
	binary.Write(startPerm, binary.LittleEndian, startElemSize(1))
	writeNodeHeader(startPerm)
	binary.Write(startPerm, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(startPerm, binary.LittleEndian, uint32(1))
	binary.Write(startPerm, binary.LittleEndian, uint16(attrExtSize))
	binary.Write(startPerm, binary.LittleEndian, uint16(attrSize))
	binary.Write(startPerm, binary.LittleEndian, uint16(1))
	binary.Write(startPerm, binary.LittleEndian, uint16(0))
	binary.Write(startPerm, binary.LittleEndian, uint16(0))
	binary.Write(startPerm, binary.LittleEndian, uint16(0))
	binary.Write(startPerm, binary.LittleEndian, uint32(6)) // ns uri idx
	binary.Write(startPerm, binary.LittleEndian, uint32(3)) // name (resID 0x01010003)
	binary.Write(startPerm, binary.LittleEndian, uint32(5)) // raw = perm value
	binary.Write(startPerm, binary.LittleEndian, uint16(8))
	startPerm.WriteByte(0)
	startPerm.WriteByte(typeString)
	binary.Write(startPerm, binary.LittleEndian, uint32(5))

	endPerm := buildEndElement(0xFFFFFFFF, 1)
	endManifest := buildEndElement(0xFFFFFFFF, 0)

	endNS := new(bytes.Buffer)
	binary.Write(endNS, binary.LittleEndian, chunkXMLEndNS)
	binary.Write(endNS, binary.LittleEndian, uint16(headerNodeAll))
	binary.Write(endNS, binary.LittleEndian, uint32(nsChunkSize))
	writeNodeHeader(endNS)
	binary.Write(endNS, binary.LittleEndian, uint32(7))
	binary.Write(endNS, binary.LittleEndian, uint32(6))

	body := new(bytes.Buffer)
	body.Write(stringPool.Bytes())
	body.Write(resMap.Bytes())
	body.Write(startNS.Bytes())
	body.Write(startManifest.Bytes())
	body.Write(startPerm.Bytes())
	body.Write(endPerm)
	body.Write(endManifest)
	body.Write(endNS.Bytes())

	out := new(bytes.Buffer)
	binary.Write(out, binary.LittleEndian, chunkXML)
	binary.Write(out, binary.LittleEndian, uint16(8))
	binary.Write(out, binary.LittleEndian, uint32(8+body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

func buildEndElement(ns, name uint32) []byte {
	b := new(bytes.Buffer)
	binary.Write(b, binary.LittleEndian, chunkXMLEndElement)
	binary.Write(b, binary.LittleEndian, uint16(headerNodeAll))
	binary.Write(b, binary.LittleEndian, uint32(endElemChunk))
	binary.Write(b, binary.LittleEndian, uint32(1))
	binary.Write(b, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(b, binary.LittleEndian, ns)
	binary.Write(b, binary.LittleEndian, name)
	return b.Bytes()
}

func TestDecode_MinimalManifest(t *testing.T) {
	data := buildMinimalAXML(t)

	if !IsBinaryXML(data) {
		t.Fatal("IsBinaryXML returned false on built fixture")
	}

	m, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if m.Package != "com.example" {
		t.Errorf("package=%q, want com.example", m.Package)
	}
	if len(m.Permissions) != 1 || m.Permissions[0] != "android.permission.INTERNET" {
		t.Errorf("permissions=%v", m.Permissions)
	}
	if !strings.Contains(string(m.XMLBytes), `package="com.example"`) {
		t.Errorf("rendered XML missing package attribute:\n%s", m.XMLBytes)
	}
	if !strings.Contains(string(m.XMLBytes), `android:name="android.permission.INTERNET"`) {
		t.Errorf("rendered XML missing permission attribute:\n%s", m.XMLBytes)
	}
}

func TestDecode_RejectsTooSmall(t *testing.T) {
	if _, err := Decode([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error on too-small input")
	}
}

func TestDecode_RejectsWrongMagic(t *testing.T) {
	bad := []byte{0xFF, 0xFF, 0, 0, 0, 0, 0, 0}
	if _, err := Decode(bad); err == nil {
		t.Fatal("expected error on non-XML magic")
	}
}

func TestCESU8Decode_SupplementaryCodepoint(t *testing.T) {
	// U+1F600 (😀) encoded as CESU-8 surrogate pair:
	//   high D83D = ED A0 BD
	//   low  DE00 = ED B8 80
	cesu := []byte{0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80}
	got := decodeAndroidUTF8(cesu)
	want := "\U0001F600"
	if got != want {
		t.Errorf("decoded %q (%v), want %q", got, []rune(got), want)
	}
}

func TestCESU8Decode_AsciiFastPath(t *testing.T) {
	got := decodeAndroidUTF8([]byte("hello"))
	if got != "hello" {
		t.Errorf("got %q, want hello", got)
	}
}
