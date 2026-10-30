package axml

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf16"
)

// PatchStringPool replaces exact string matches in a RES_STRING_POOL chunk
// inside an AXML or ARSC binary file and returns the patched file data.
func PatchStringPool(data []byte, replacements map[string]string) ([]byte, error) {
	if len(data) < 16 || len(replacements) == 0 {
		return data, nil
	}

	rootHeaderSize := binary.LittleEndian.Uint16(data[2:4])
	rootChunkSize := binary.LittleEndian.Uint32(data[4:8])

	// Locate the first RES_STRING_POOL chunk
	poolOffset := int(rootHeaderSize)
	if poolOffset+8 > len(data) {
		return data, errors.New("truncated root chunk")
	}

	for poolOffset+8 <= len(data) {
		chunkType := binary.LittleEndian.Uint16(data[poolOffset : poolOffset+2])
		chunkSize := binary.LittleEndian.Uint32(data[poolOffset+4 : poolOffset+8])
		if chunkSize < 8 || poolOffset+int(chunkSize) > len(data) {
			break
		}

		if chunkType == chunkStringPool {
			// Found the string pool
			oldPoolBytes := data[poolOffset : poolOffset+int(chunkSize)]
			newPoolBytes, modified, err := patchSingleStringPool(oldPoolBytes, replacements)
			if err != nil {
				return nil, fmt.Errorf("patch string pool: %w", err)
			}
			if !modified {
				return data, nil
			}

			// Reconstruct root buffer
			var out bytes.Buffer
			out.Write(data[:poolOffset])
			out.Write(newPoolBytes)
			out.Write(data[poolOffset+int(chunkSize):])

			res := out.Bytes()
			// Update root chunk size
			delta := int32(len(newPoolBytes)) - int32(chunkSize)
			newRootSize := uint32(int32(rootChunkSize) + delta)
			if newRootSize <= uint32(len(res)) {
				binary.LittleEndian.PutUint32(res[4:8], uint32(len(res)))
			}

			return res, nil
		}

		poolOffset += int(chunkSize)
	}

	return data, nil
}

func patchSingleStringPool(chunk []byte, replacements map[string]string) ([]byte, bool, error) {
	pool, err := parseStringPool(chunk)
	if err != nil {
		return nil, false, err
	}

	modified := false
	newEntries := make([]string, len(pool.entries))
	for i, s := range pool.entries {
		if repl, ok := replacements[s]; ok && repl != s {
			newEntries[i] = repl
			modified = true
		} else {
			newEntries[i] = s
		}
	}

	if !modified {
		return chunk, false, nil
	}

	// Re-serialize string pool chunk
	isUtf8 := pool.flags&flagUTF8 != 0

	headerSize := binary.LittleEndian.Uint16(chunk[2:4])
	flags := pool.flags
	stringCount := uint32(len(newEntries))

	// Re-encode string payloads and compute offsets
	var strData bytes.Buffer
	offsets := make([]uint32, stringCount)

	for i, s := range newEntries {
		offsets[i] = uint32(strData.Len())

		if isUtf8 {
			u16 := utf16.Encode([]rune(s))
			u8 := []byte(s)

			// 1. UTF-16 char length (1 or 2 bytes)
			u16Len := len(u16)
			if u16Len > 0x7F {
				strData.WriteByte(byte((u16Len >> 8) | 0x80))
				strData.WriteByte(byte(u16Len & 0xFF))
			} else {
				strData.WriteByte(byte(u16Len))
			}

			// 2. UTF-8 byte length (1 or 2 bytes)
			u8Len := len(u8)
			if u8Len > 0x7F {
				strData.WriteByte(byte((u8Len >> 8) | 0x80))
				strData.WriteByte(byte(u8Len & 0xFF))
			} else {
				strData.WriteByte(byte(u8Len))
			}

			// 3. UTF-8 payload + null terminator
			strData.Write(u8)
			strData.WriteByte(0)
		} else {
			u16 := utf16.Encode([]rune(s))
			u16Len := len(u16)

			// 1. Length prefix (2 or 4 bytes)
			if u16Len > 0x7FFF {
				hi := uint16((u16Len >> 16) | 0x8000)
				lo := uint16(u16Len & 0xFFFF)
				_ = binary.Write(&strData, binary.LittleEndian, hi)
				_ = binary.Write(&strData, binary.LittleEndian, lo)
			} else {
				_ = binary.Write(&strData, binary.LittleEndian, uint16(u16Len))
			}

			// 2. UTF-16 words + 2-byte null terminator
			for _, w := range u16 {
				_ = binary.Write(&strData, binary.LittleEndian, w)
			}
			_ = binary.Write(&strData, binary.LittleEndian, uint16(0))
		}
	}

	// 4-byte align the string data
	for strData.Len()%4 != 0 {
		strData.WriteByte(0)
	}

	// Compute styles start and total chunk size
	localHeaderSize := uint32(headerSize)
	offsetsTableSize := stringCount * 4
	stringsStart := localHeaderSize + offsetsTableSize
	stylesStart := uint32(0) // styles stripped / 0

	totalChunkSize := stringsStart + uint32(strData.Len())

	var out bytes.Buffer
	// Chunk header
	_ = binary.Write(&out, binary.LittleEndian, chunkStringPool)
	_ = binary.Write(&out, binary.LittleEndian, headerSize)
	_ = binary.Write(&out, binary.LittleEndian, totalChunkSize)

	// String pool header
	_ = binary.Write(&out, binary.LittleEndian, stringCount)
	_ = binary.Write(&out, binary.LittleEndian, uint32(0)) // styleCount
	_ = binary.Write(&out, binary.LittleEndian, flags)
	_ = binary.Write(&out, binary.LittleEndian, stringsStart)
	_ = binary.Write(&out, binary.LittleEndian, stylesStart)

	// Offsets table
	for _, off := range offsets {
		_ = binary.Write(&out, binary.LittleEndian, off)
	}

	// String data
	out.Write(strData.Bytes())

	return out.Bytes(), true, nil
}

// PatchARSCAndAXMLFiles scans a source directory and updates resources.arsc and AndroidManifest.xml.bin
// in-place using the provided replacements map.
func PatchARSCAndAXMLFiles(sourceDir string, replacements map[string]string) error {
	if len(replacements) == 0 {
		return nil
	}

	// 1. Patch resources.arsc
	arscPath := filepath.Join(sourceDir, "resources.arsc")
	if data, err := os.ReadFile(arscPath); err == nil {
		if patched, err := PatchStringPool(data, replacements); err == nil && len(patched) > 0 {
			_ = os.WriteFile(arscPath, patched, 0644)
		}
	}

	// 2. Patch AndroidManifest.xml.bin
	manifestBin := filepath.Join(sourceDir, "AndroidManifest.xml.bin")
	if data, err := os.ReadFile(manifestBin); err == nil {
		if patched, err := PatchStringPool(data, replacements); err == nil && len(patched) > 0 {
			_ = os.WriteFile(manifestBin, patched, 0644)
		}
	}

	return nil
}
