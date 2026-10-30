package media

// This file isolates the OFFENSIVE payload-injection utilities that used to
// live in the shipped forensic API (patcher.go). They fabricate malicious
// polyglot/steganographic files, which is not part of legitimate analysis, so
// they are confined to the test build (files ending in _test.go are never
// compiled into the production package or any importing binary).
//
// They remain here only to generate fixtures for regression tests such as
// TestBugFix_PNGInjectPayload.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// InjectPayload attempts to inject a string payload into the file without breaking it.
// TEST-ONLY offensive utility; not part of the forensic API.
func InjectPayload(data []byte, format MediaType, payload string) PatchResult {
	if len(data) == 0 {
		return PatchResult{Success: false, Message: "Empty file", Data: data}
	}

	payloadBytes := []byte(payload)

	// JPEG: inject into COM (Comment) marker 0xFF 0xFE after SOI
	if format == TypeJPEG && len(data) >= 2 && data[0] == 0xFF && data[1] == 0xD8 {
		var patchedData []byte
		patchedData = append(patchedData, data[0:2]...)

		// COM Marker
		patchedData = append(patchedData, 0xFF, 0xFE)
		length := len(payloadBytes) + 2
		patchedData = append(patchedData, byte(length>>8), byte(length&0xFF))
		patchedData = append(patchedData, payloadBytes...)

		// Rest of the file
		patchedData = append(patchedData, data[2:]...)
		return PatchResult{Success: true, Message: "Injected payload into JPEG COM marker", Data: patchedData}
	}

	// PNG: inject a proper tEXt chunk after IHDR
	if format == TypePNG && len(data) >= 8 && string(data[0:8]) == "\x89PNG\r\n\x1a\n" {
		ihdrIdx := bytes.Index(data, []byte("IHDR"))
		if ihdrIdx != -1 && ihdrIdx+17 < len(data) {
			ihdrEnd := ihdrIdx + 17 // IHDR: 4 len + 4 type + 13 data + 4 CRC

			// Build tEXt chunk: "MEGA\0" + payload
			keyword := []byte("MEGA")
			chunkData := append(keyword, 0x00)
			chunkData = append(chunkData, payloadBytes...)

			var chunk []byte
			// Length (big-endian)
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(chunkData)))
			chunk = append(chunk, lenBuf...)
			// Type
			chunk = append(chunk, "tEXt"...)
			// Data
			chunk = append(chunk, chunkData...)
			// CRC32 over type + data
			checksum := crc32.ChecksumIEEE(append([]byte("tEXt"), chunkData...))
			crcBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(crcBuf, checksum)
			chunk = append(chunk, crcBuf...)

			var patchedData []byte
			patchedData = append(patchedData, data[:ihdrEnd]...)
			patchedData = append(patchedData, chunk...)
			patchedData = append(patchedData, data[ihdrEnd:]...)

			return PatchResult{Success: true, Message: "Injected payload into PNG tEXt chunk", Data: patchedData}
		}
	}

	// Fallback: append as steganography overlay
	return HideStego(data, format, payloadBytes)
}

// HideStego appends data to the end of the file (Steganography).
// TEST-ONLY offensive utility; not part of the forensic API.
func HideStego(data []byte, format MediaType, payload []byte) PatchResult {
	if len(data) == 0 {
		return PatchResult{Success: false, Message: "Empty file", Data: data}
	}

	patchedData := make([]byte, len(data))
	copy(patchedData, data)

	magicMarker := []byte("!!MEGA_STEGO!!")
	patchedData = append(patchedData, magicMarker...)
	patchedData = append(patchedData, payload...)
	patchedData = append(patchedData, magicMarker...)

	return PatchResult{
		Success: true,
		Message: fmt.Sprintf("Appended %d bytes of steganography data to EOF", len(payload)),
		Data:    patchedData,
	}
}
