package media

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ─── ICO ──────────────────────────────────────────────────────────────────
//
// ICO header (ICONDIR): reserved(2)=0, type(2) 1=icon/2=cursor, count(2),
// followed by `count` 16-byte ICONDIRENTRY records: width(1, 0 means 256),
// height(1, 0 means 256), colorCount(1), reserved(1), planes(2), bitCount(2),
// bytesInRes(4), imageOffset(4).

type ICOEntryView struct {
	Width     int
	Height    int
	BitDepth  int
	SizeBytes int
}

// parseICOInfo reads the ICONDIR/ICONDIRENTRY structure and returns each
// embedded image's declared dimensions/depth/size. Bounds-checked throughout
// since this walks untrusted input; caps entry count to guard against a
// corrupt/hostile count field.
func parseICOInfo(data []byte) (entries []ICOEntryView, ok bool) {
	if len(data) < 6 {
		return nil, false
	}
	reserved := binary.LittleEndian.Uint16(data[0:2])
	typ := binary.LittleEndian.Uint16(data[2:4])
	count := binary.LittleEndian.Uint16(data[4:6])
	if reserved != 0 || (typ != 1 && typ != 2) {
		return nil, false
	}
	if count == 0 || count > 256 {
		return nil, false
	}

	base := 6
	for i := 0; i < int(count); i++ {
		off := base + i*16
		if off+16 > len(data) {
			break
		}
		w := int(data[off])
		if w == 0 {
			w = 256
		}
		h := int(data[off+1])
		if h == 0 {
			h = 256
		}
		bitCount := int(binary.LittleEndian.Uint16(data[off+6 : off+8]))
		bytesInRes := int(binary.LittleEndian.Uint32(data[off+8 : off+12]))

		entries = append(entries, ICOEntryView{
			Width:     w,
			Height:    h,
			BitDepth:  bitCount,
			SizeBytes: bytesInRes,
		})
	}

	return entries, len(entries) > 0
}

// summarizeICOEntries renders a compact "N (16x16@32bit, 32x32@32bit, ...)"
// style string for the flat Fields map, matching the existing curated-field
// display convention rather than building a dedicated ICO table for what is
// usually just a handful of entries.
func summarizeICOEntries(entries []ICOEntryView) string {
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, fmt.Sprintf("%dx%d@%dbit", e.Width, e.Height, e.BitDepth))
	}
	return fmt.Sprintf("%d (%s)", len(entries), strings.Join(parts, ", "))
}
