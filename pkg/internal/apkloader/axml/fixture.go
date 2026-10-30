package axml

import (
	"bytes"
	"encoding/binary"
)

// MinimalManifestXML returns a tiny, valid binary Android manifest.
//
// The fixture is intentionally synthetic: it contains only the strings and
// chunks needed to represent:
//
//	<manifest package="com.example">
//	  <uses-permission android:name="android.permission.INTERNET"/>
//	</manifest>
//
// Tests use it as a controlled input instead of depending on a real APK.
func MinimalManifestXML() []byte {
	strs := []string{
		"manifest",
		"uses-permission",
		"package",
		"name",
		"com.example",
		"android.permission.INTERNET",
		"http://schemas.android.com/apk/res/android",
		"android",
	}

	var stringData bytes.Buffer
	offsets := make([]uint32, len(strs))
	for index, value := range strs {
		offsets[index] = uint32(stringData.Len())
		stringData.WriteByte(byte(len(value)))
		stringData.WriteByte(byte(len(value)))
		stringData.WriteString(value)
		stringData.WriteByte(0)
	}
	for stringData.Len()%4 != 0 {
		stringData.WriteByte(0)
	}

	const poolHeaderSize = 28
	stringsStart := uint32(poolHeaderSize + len(offsets)*4)
	stringPool := new(bytes.Buffer)
	binary.Write(stringPool, binary.LittleEndian, chunkStringPool)
	binary.Write(stringPool, binary.LittleEndian, uint16(poolHeaderSize))
	chunkSizeOffset := stringPool.Len()
	binary.Write(stringPool, binary.LittleEndian, uint32(0))
	binary.Write(stringPool, binary.LittleEndian, uint32(len(strs)))
	binary.Write(stringPool, binary.LittleEndian, uint32(0))
	binary.Write(stringPool, binary.LittleEndian, flagUTF8)
	binary.Write(stringPool, binary.LittleEndian, stringsStart)
	binary.Write(stringPool, binary.LittleEndian, uint32(0))
	for _, offset := range offsets {
		binary.Write(stringPool, binary.LittleEndian, offset)
	}
	stringPool.Write(stringData.Bytes())
	for stringPool.Len()%4 != 0 {
		stringPool.WriteByte(0)
	}
	chunkBytes := stringPool.Bytes()
	binary.LittleEndian.PutUint32(chunkBytes[chunkSizeOffset:], uint32(stringPool.Len()))

	resourceMap := new(bytes.Buffer)
	binary.Write(resourceMap, binary.LittleEndian, chunkXMLResourceMap)
	binary.Write(resourceMap, binary.LittleEndian, uint16(8))
	binary.Write(resourceMap, binary.LittleEndian, uint32(8+4*4))
	binary.Write(resourceMap, binary.LittleEndian, uint32(0))
	binary.Write(resourceMap, binary.LittleEndian, uint32(0))
	binary.Write(resourceMap, binary.LittleEndian, uint32(0))
	binary.Write(resourceMap, binary.LittleEndian, uint32(0x01010003))

	writeNodeHeader := func(buffer *bytes.Buffer) {
		binary.Write(buffer, binary.LittleEndian, uint32(1))
		binary.Write(buffer, binary.LittleEndian, uint32(0xFFFFFFFF))
	}

	startNamespace := new(bytes.Buffer)
	binary.Write(startNamespace, binary.LittleEndian, chunkXMLStartNS)
	binary.Write(startNamespace, binary.LittleEndian, uint16(16))
	binary.Write(startNamespace, binary.LittleEndian, uint32(24))
	writeNodeHeader(startNamespace)
	binary.Write(startNamespace, binary.LittleEndian, uint32(7))
	binary.Write(startNamespace, binary.LittleEndian, uint32(6))

	startManifest := new(bytes.Buffer)
	binary.Write(startManifest, binary.LittleEndian, chunkXMLStartElement)
	binary.Write(startManifest, binary.LittleEndian, uint16(16))
	binary.Write(startManifest, binary.LittleEndian, uint32(56))
	writeNodeHeader(startManifest)
	binary.Write(startManifest, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(startManifest, binary.LittleEndian, uint32(0))
	binary.Write(startManifest, binary.LittleEndian, uint16(20))
	binary.Write(startManifest, binary.LittleEndian, uint16(20))
	binary.Write(startManifest, binary.LittleEndian, uint16(1))
	binary.Write(startManifest, binary.LittleEndian, uint16(0))
	binary.Write(startManifest, binary.LittleEndian, uint16(0))
	binary.Write(startManifest, binary.LittleEndian, uint16(0))
	binary.Write(startManifest, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(startManifest, binary.LittleEndian, uint32(2))
	binary.Write(startManifest, binary.LittleEndian, uint32(4))
	binary.Write(startManifest, binary.LittleEndian, uint16(8))
	startManifest.WriteByte(0)
	startManifest.WriteByte(typeString)
	binary.Write(startManifest, binary.LittleEndian, uint32(4))

	startPermission := new(bytes.Buffer)
	binary.Write(startPermission, binary.LittleEndian, chunkXMLStartElement)
	binary.Write(startPermission, binary.LittleEndian, uint16(16))
	binary.Write(startPermission, binary.LittleEndian, uint32(56))
	writeNodeHeader(startPermission)
	binary.Write(startPermission, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(startPermission, binary.LittleEndian, uint32(1))
	binary.Write(startPermission, binary.LittleEndian, uint16(20))
	binary.Write(startPermission, binary.LittleEndian, uint16(20))
	binary.Write(startPermission, binary.LittleEndian, uint16(1))
	binary.Write(startPermission, binary.LittleEndian, uint16(0))
	binary.Write(startPermission, binary.LittleEndian, uint16(0))
	binary.Write(startPermission, binary.LittleEndian, uint16(0))
	binary.Write(startPermission, binary.LittleEndian, uint32(6))
	binary.Write(startPermission, binary.LittleEndian, uint32(3))
	binary.Write(startPermission, binary.LittleEndian, uint32(5))
	binary.Write(startPermission, binary.LittleEndian, uint16(8))
	startPermission.WriteByte(0)
	startPermission.WriteByte(typeString)
	binary.Write(startPermission, binary.LittleEndian, uint32(5))

	endPermission := buildFixtureEndElement(0xFFFFFFFF, 1)
	endManifest := buildFixtureEndElement(0xFFFFFFFF, 0)

	endNamespace := new(bytes.Buffer)
	binary.Write(endNamespace, binary.LittleEndian, chunkXMLEndNS)
	binary.Write(endNamespace, binary.LittleEndian, uint16(16))
	binary.Write(endNamespace, binary.LittleEndian, uint32(24))
	writeNodeHeader(endNamespace)
	binary.Write(endNamespace, binary.LittleEndian, uint32(7))
	binary.Write(endNamespace, binary.LittleEndian, uint32(6))

	body := new(bytes.Buffer)
	body.Write(stringPool.Bytes())
	body.Write(resourceMap.Bytes())
	body.Write(startNamespace.Bytes())
	body.Write(startManifest.Bytes())
	body.Write(startPermission.Bytes())
	body.Write(endPermission)
	body.Write(endManifest)
	body.Write(endNamespace.Bytes())

	output := new(bytes.Buffer)
	binary.Write(output, binary.LittleEndian, chunkXML)
	binary.Write(output, binary.LittleEndian, uint16(8))
	binary.Write(output, binary.LittleEndian, uint32(8+body.Len()))
	output.Write(body.Bytes())
	return output.Bytes()
}

func buildFixtureEndElement(namespace, name uint32) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.LittleEndian, chunkXMLEndElement)
	binary.Write(buffer, binary.LittleEndian, uint16(16))
	binary.Write(buffer, binary.LittleEndian, uint32(24))
	binary.Write(buffer, binary.LittleEndian, uint32(1))
	binary.Write(buffer, binary.LittleEndian, uint32(0xFFFFFFFF))
	binary.Write(buffer, binary.LittleEndian, namespace)
	binary.Write(buffer, binary.LittleEndian, name)
	return buffer.Bytes()
}

// MinimalARSC returns the smallest valid resources.arsc buffer.
func MinimalARSC() []byte {
	pool := new(bytes.Buffer)
	binary.Write(pool, binary.LittleEndian, chunkStringPool)
	binary.Write(pool, binary.LittleEndian, uint16(28))
	binary.Write(pool, binary.LittleEndian, uint32(28))
	binary.Write(pool, binary.LittleEndian, uint32(0))
	binary.Write(pool, binary.LittleEndian, uint32(0))
	binary.Write(pool, binary.LittleEndian, flagUTF8)
	binary.Write(pool, binary.LittleEndian, uint32(28))
	binary.Write(pool, binary.LittleEndian, uint32(0))

	output := make([]byte, 12+pool.Len())
	binary.LittleEndian.PutUint16(output[0:2], chunkTable)
	binary.LittleEndian.PutUint16(output[2:4], 12)
	binary.LittleEndian.PutUint32(output[4:8], uint32(len(output)))
	binary.LittleEndian.PutUint32(output[8:12], 0)
	copy(output[12:], pool.Bytes())
	return output
}
