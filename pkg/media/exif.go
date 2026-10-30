package media

// exif.go — layout map (code moved, no logic change).
//
// The former 2200-line exif.go is now split by responsibility:
//   exif_warn.go       — mediaWarning, warnBag, safeStage
//   exif_tiff.go       — TIFF/EXIF primitives, parseIFD, parseTIFFDoc
//   exif_jpeg.go       — JPEG marker walker, APP1 EXIF, SOF frame, EOI
//   exif_png.go        — PNG header (IHDR/CgBI); chunk walk is in pngchunks.go
//   exif_format.go     — sniffFormat + RAW/TIFF/BMP/GIF/HEIC/AVIF detection
//   exif_fields.go     — exposure/GPS/timestamps/thumbnail/editing
//   exif_screenshot.go — screenshot heuristic
//   exif_extract.go    — extractCuratedEXIF + extractMediaMetadataFull
//
// Depends on exif_tags.go for TiffType, IFDKind, TagID, payloadOf,
// sanitizeText, DumpAllTags and TiffTagView.
