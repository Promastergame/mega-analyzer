package media

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"io"
)

// ─── Full PNG chunk walk ─────────────────────────────────────────────────────
//
// One structural walk over every PNG chunk that builds several outputs at
// once (avoids re-walking the chunk list once per feature): the full
// offset/type/size/CRC table forensics wants to see, decoded tEXt/zTXt/iTXt
// text, the iCCP color profile, the eXIf payload (feeds the same TIFF path
// JPEG uses), and whatever bytes sit after IEND (overlay/polyglot data).

// maxPNGChunksRecorded bounds the chunk table against a pathological file
// with an enormous number of tiny ancillary chunks.
const maxPNGChunksRecorded = 2000

type pngWalkResult struct {
	Chunks       []PNGChunkView
	TextChunks   map[string]string
	ICC          *ICCProfileInfo
	EXIFChunk    []byte
	IENDOffset   int // -1 if IEND was never found
	TrailingData []byte
	Truncated    bool // true if chunk recording stopped early (maxPNGChunksRecorded hit)
}

func walkPNGChunks(data []byte) pngWalkResult {
	result := pngWalkResult{
		TextChunks: make(map[string]string),
		IENDOffset: -1,
	}
	if len(data) < 8 {
		return result
	}

	pos := 8
	for pos+8 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		typ := string(data[pos+4 : pos+8])
		dataStart := pos + 8
		if length < 0 || dataStart+length+4 > len(data) {
			break // truncated chunk - stop, don't guess
		}
		chunkData := data[dataStart : dataStart+length]
		storedCRC := binary.BigEndian.Uint32(data[dataStart+length : dataStart+length+4])
		computedCRC := crc32.ChecksumIEEE(append([]byte(typ), chunkData...))

		if len(result.Chunks) < maxPNGChunksRecorded {
			result.Chunks = append(result.Chunks, PNGChunkView{
				Offset:   pos,
				Type:     typ,
				Size:     length,
				CRCValid: storedCRC == computedCRC,
			})
		} else {
			result.Truncated = true
		}

		switch typ {
		case "eXIf":
			if result.EXIFChunk == nil {
				result.EXIFChunk = append([]byte(nil), chunkData...)
			}
		case "tEXt":
			parsePNGtEXt(chunkData, result.TextChunks)
		case "zTXt":
			parsePNGzTXt(chunkData, result.TextChunks)
		case "iTXt":
			parsePNGiTXt(chunkData, result.TextChunks)
		case "iCCP":
			if result.ICC == nil {
				result.ICC = parsePNGiCCP(chunkData)
			}
		case "IEND":
			result.IENDOffset = pos
			trailingStart := dataStart + length + 4
			if trailingStart < len(data) {
				result.TrailingData = data[trailingStart:]
			}
			return result
		}

		pos = dataStart + length + 4
	}

	return result
}

// parsePNGtEXt decodes a tEXt chunk: "keyword\0text", both Latin-1.
func parsePNGtEXt(chunkData []byte, out map[string]string) {
	nul := bytes.IndexByte(chunkData, 0)
	if nul < 0 {
		return
	}
	keyword := string(chunkData[:nul])
	text := string(chunkData[nul+1:])
	if keyword != "" {
		out[keyword] = text
	}
}

// parsePNGzTXt decodes a zTXt chunk: "keyword\0 compressionMethod(1) zlibdata".
func parsePNGzTXt(chunkData []byte, out map[string]string) {
	nul := bytes.IndexByte(chunkData, 0)
	if nul < 0 || nul+2 > len(chunkData) {
		return
	}
	keyword := string(chunkData[:nul])
	// PNG spec: only compression method 0 (zlib/deflate) is defined.
	if chunkData[nul+1] != 0x00 {
		return
	}
	compressed := chunkData[nul+2:]
	text, ok := zlibDecompressCapped(compressed)
	if !ok || keyword == "" {
		return
	}
	out[keyword] = text
}

// parsePNGiTXt decodes an iTXt chunk:
// "keyword\0 compressionFlag(1) compressionMethod(1) languageTag\0 translatedKeyword\0 text"
func parsePNGiTXt(chunkData []byte, out map[string]string) {
	nul1 := bytes.IndexByte(chunkData, 0)
	if nul1 < 0 || nul1+3 > len(chunkData) {
		return
	}
	keyword := string(chunkData[:nul1])
	compressionFlag := chunkData[nul1+1]
	rest := chunkData[nul1+3:]

	nul2 := bytes.IndexByte(rest, 0)
	if nul2 < 0 {
		return
	}
	rest = rest[nul2+1:]

	nul3 := bytes.IndexByte(rest, 0)
	if nul3 < 0 {
		return
	}
	translatedKeyword := string(rest[:nul3])
	textData := rest[nul3+1:]

	var text string
	if compressionFlag == 1 {
		decoded, ok := zlibDecompressCapped(textData)
		if !ok {
			return
		}
		text = decoded
	} else {
		text = string(textData)
	}

	key := translatedKeyword
	if key == "" {
		key = keyword
	}
	if key != "" {
		out[key] = text
	}
}

// parsePNGiCCP decodes an iCCP chunk ("profileName\0 compressionMethod(1)
// zlibdata") and parses the fixed 128-byte ICC.1 profile header.
func parsePNGiCCP(chunkData []byte) *ICCProfileInfo {
	nul := bytes.IndexByte(chunkData, 0)
	if nul < 0 || nul+2 > len(chunkData) {
		return nil
	}
	profileName := string(chunkData[:nul])
	compressed := chunkData[nul+2:]

	decoded, ok := zlibDecompressCappedBytes(compressed)
	if !ok || len(decoded) < 128 {
		return nil
	}

	return &ICCProfileInfo{
		ProfileSize:        int(binary.BigEndian.Uint32(decoded[0:4])),
		DeviceClass:        cleanICCString(decoded[12:16]),
		ColorSpace:         cleanICCString(decoded[16:20]),
		PCS:                cleanICCString(decoded[20:24]),
		ProfileDescription: profileName,
	}
}

func cleanICCString(b []byte) string {
	end := len(b)
	for end > 0 && (b[end-1] == 0 || b[end-1] == ' ') {
		end--
	}
	return string(b[:end])
}

// zlibDecompressCapped decompresses a zlib stream with a hard output-size
// cap (zlib-bomb defense) and its own panic recovery (malformed zlib
// streams can panic in rare corrupt cases). Returns ok=false on any error,
// including hitting the cap.
func zlibDecompressCapped(compressed []byte) (text string, ok bool) {
	b, ok := zlibDecompressCappedBytes(compressed)
	if !ok {
		return "", false
	}
	return string(b), true
}

func zlibDecompressCappedBytes(compressed []byte) (out []byte, ok bool) {
	defer func() {
		if recover() != nil {
			out, ok = nil, false
		}
	}()

	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, false
	}
	defer r.Close()

	limited := io.LimitReader(r, maxDecompressedChunkBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, false
	}
	if len(data) > maxDecompressedChunkBytes {
		return nil, false // hit the cap - treat as unusable rather than truncating silently
	}
	return data, true
}
