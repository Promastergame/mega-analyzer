package media

// MediaMetadata is the full, structured forensic metadata extracted from an
// image file - everything extractMediaMetadataFull recovers, beyond the flat
// Fields map that feeds the existing "Recovered Metadata" report list.
type MediaMetadata struct {
	// Fields holds the existing curated single-value metadata (Camera_Make,
	// GPS_Coordinates, Screenshot_Likely, ...) - unchanged shape/behavior from
	// before this struct existed, still the source for Classification.RecoveredData.
	Fields map[string]string `json:"fields,omitempty"`

	// AllTags is the full generic EXIF dump (IFD0 + Exif SubIFD + GPS IFD,
	// and for WEBP/PNG the same when an eXIf/EXIF chunk is present) - every
	// tag the file carries, recognized or not.
	AllTags []TiffTagView `json:"all_tags,omitempty"`

	// XMP holds parsed common Dublin-Core/Exif/tiff/photoshop XMP fields.
	XMP map[string]string `json:"xmp,omitempty"`
	// XMPRaw is the raw XMP XML packet, capped to xmpRawCap bytes.
	XMPRaw string `json:"xmp_raw,omitempty"`

	// PNGChunks is the full ordered PNG chunk table (PNG only).
	PNGChunks []PNGChunkView `json:"png_chunks,omitempty"`
	// PNGTextChunks holds decoded tEXt/zTXt/iTXt keyword -> text (PNG only).
	PNGTextChunks map[string]string `json:"png_text_chunks,omitempty"`

	// ICCProfile is non-nil when an ICC color profile chunk (PNG iCCP) was
	// found and its header parsed successfully.
	ICCProfile *ICCProfileInfo `json:"icc_profile,omitempty"`

	// Thumbnail holds the raw bytes of an embedded EXIF thumbnail (IFD1),
	// when present. Excluded from JSON (see ThumbnailSizeBytes) so a
	// generic JSON export doesn't silently balloon with embedded images;
	// the HTML report reads this field directly, in-process.
	Thumbnail          []byte `json:"-"`
	ThumbnailMime      string `json:"thumbnail_mime,omitempty"`
	ThumbnailSizeBytes int    `json:"thumbnail_size_bytes,omitempty"`

	// TrailingData is non-nil when bytes were found after the file's
	// logical end (PNG IEND / JPEG EOI) - a classic overlay/polyglot/
	// steganography signal.
	TrailingData *TrailingDataInfo `json:"trailing_data,omitempty"`
}

// PNGChunkView is one row of the full PNG chunk table: every chunk in the
// file, in order, with its CRC-32 validation status.
type PNGChunkView struct {
	Offset   int    `json:"offset"`
	Type     string `json:"type"`
	Size     int    `json:"size"`
	CRCValid bool   `json:"crc_valid"`
}

// ICCProfileInfo summarizes the fixed 128-byte ICC profile header (ICC.1
// spec) found in a PNG iCCP chunk.
type ICCProfileInfo struct {
	ProfileSize        int    `json:"profile_size"`
	ColorSpace         string `json:"color_space"`
	PCS                string `json:"pcs"`
	DeviceClass        string `json:"device_class"`
	ProfileDescription string `json:"profile_description"`
}

// TrailingDataInfo describes bytes found after a file's logical end.
type TrailingDataInfo struct {
	Offset         int    `json:"offset"`
	Size           int    `json:"size"`
	DetectedFormat string `json:"detected_format,omitempty"` // "" if unrecognized
}

// xmpRawCap / maxDecompressedChunkBytes bound how much of a single embedded
// blob this package will hold in memory / echo back in a report, so a
// hostile file (huge XMP packet, zlib bomb inside a PNG text chunk) can't
// turn a metadata scan into a memory/response-size DoS.
const (
	xmpRawCap                 = 8 * 1024
	maxDecompressedChunkBytes = 1024 * 1024
)
