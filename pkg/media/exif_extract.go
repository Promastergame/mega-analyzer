package media

import (
	"bytes"
	"fmt"
	"strings"
)

// curated extraction + public entry points.
//
// Split from exif.go: exact code move, no logic changes.

// --- Curated extraction -----------------------------------------------------

// exifExtractOutcome is the shared result of walking one TIFF buffer,
// regardless of which container it came from.
type exifExtractOutcome struct {
	Fields          map[string]string
	AllTags         []TiffTagView
	Thumbnail       []byte
	HasCameraExif   bool
	CaptureEvidence int // count of independent proofs of an actual exposure
	Software        string
	UserComment     string
	EditSignals     []string
	Warnings        []mediaWarning
}

func extractCuratedEXIF(tiffBuf []byte) exifExtractOutcome {
	return extractCuratedEXIFCtx(tiffBuf, 0, 0, false, nil)
}

// extractCuratedEXIFCtx additionally receives the real frame size, which is
// what makes the resize/crop detection possible.
func extractCuratedEXIFCtx(tiffBuf []byte, actualW, actualH int, hasDims bool, w *warnBag) exifExtractOutcome {
	out := exifExtractOutcome{Fields: make(map[string]string)}
	if len(tiffBuf) == 0 {
		return out
	}
	if w == nil {
		w = &warnBag{}
	}

	doc, ok := parseTIFFDoc(tiffBuf, w)
	if !ok {
		out.Warnings = w.list
		return out
	}
	t := doc.File
	result := out.Fields

	setText := func(key string, ifd map[uint16]tiffEntry, tag uint16) string {
		e, present := ifd[tag]
		if !present {
			return ""
		}
		v, an := t.asciiWarn(e)
		if v == "" {
			return ""
		}
		result[key] = v
		if an&(AnomalyBidiControl|AnomalyNonPrintable|AnomalyInvalidUTF8|AnomalyEmbeddedNUL) != 0 {
			// Hostile text in a metadata field is a finding, not a nuisance.
			w.add("exif.text", "suspicious_characters", int64(e.valOffset),
				fmt.Sprintf("%s: %s", key, an))
		}
		return v
	}

	if v := setText("Camera_Make", doc.IFD0, tagMake); v != "" {
		out.HasCameraExif = true
	}
	if v := setText("Camera_Model", doc.IFD0, tagModel); v != "" {
		out.HasCameraExif = true
	}
	out.Software = setText("Software", doc.IFD0, tagSoftware)
	setText("Host_Computer", doc.IFD0, tagHostComputer)
	setText("Artist", doc.IFD0, tagArtist)
	setText("Copyright", doc.IFD0, tagCopyright)

	orientation := 0
	if e, present := doc.IFD0[tagOrientation]; present {
		if v, ok2 := t.uint(e); ok2 {
			orientation = int(v)
			result["Orientation"] = orientationLabel(orientation)
		}
	}

	// Identity fields: the whole point of a forensic dump, and none of them
	// were being extracted.
	setText("Camera_Owner", doc.Exif, tagCameraOwner)
	setText("Body_Serial", doc.Exif, tagBodySerial)
	setText("Lens_Make", doc.Exif, tagLensMake)
	setText("Lens_Serial", doc.Exif, tagLensSerial)
	setText("Image_Unique_ID", doc.Exif, tagImageUniqueID)
	if v := setText("Lens_Model", doc.Exif, tagLensModel); v != "" {
		out.HasCameraExif = true
	}

	// UserComment needs the charset-prefix decoder, which is where the iOS
	// screenshot marker lives.
	if e, present := doc.Exif[tagUserComment]; present {
		if s, _ := formatTiffValue(t, IFDExif, tagUserComment, e); s != "" && !strings.HasPrefix(s, "<") {
			out.UserComment = s
			result["User_Comment"] = s
		}
	}
	// XPComment is UTF-16 and carries the same marker on Windows.
	if e, present := doc.IFD0[tagXPComment]; present {
		if s, _ := formatTiffValue(t, IFD0, tagXPComment, e); s != "" && !strings.HasPrefix(s, "<") {
			result["XP_Comment"] = s
			if out.UserComment == "" {
				out.UserComment = s
			}
		}
	}

	// Timestamps
	rawDate := func(ifd map[uint16]tiffEntry, tag uint16) string {
		e, present := ifd[tag]
		if !present {
			return ""
		}
		v := t.ascii(e)
		if isPlaceholderDate(v) {
			if v != "" {
				w.add("exif.date", "placeholder_value", int64(e.valOffset), fmt.Sprintf("%q", v))
			}
			return ""
		}
		return v
	}
	dateOrig := rawDate(doc.Exif, tagDateTimeOrig)
	dateModified := rawDate(doc.IFD0, tagDateTime)
	dateDigitized := rawDate(doc.Exif, tagDateTimeDigit)

	dateTaken := dateOrig
	if dateTaken == "" {
		dateTaken = dateDigitized
	}
	if dateTaken == "" {
		dateTaken = dateModified
	}
	if dateTaken != "" {
		result["Date_Taken"] = exifTimestamp(t, doc.Exif, dateTaken)
	}
	if dateModified != "" {
		result["Date_Modified"] = dateModified
	}

	if settings := cameraSettings(t, doc.Exif); settings != "" {
		result["Camera_Settings"] = settings
	}

	// Capture evidence: independent optical parameters, not Make/Model.
	for _, tag := range []uint16{tagExposureTime, tagFNumber, tagFocalLength, tagShutterSpeedVal, tagApertureValue} {
		if e, ok := doc.Exif[tag]; ok {
			if v, ok2 := t.rational(e); ok2 && v > 0 {
				out.CaptureEvidence++
			}
		}
	}
	if _, _, ok := exifISO(t, doc.Exif); ok {
		out.CaptureEvidence++
	}
	if dateOrig != "" {
		out.CaptureEvidence++
	}

	// GPS
	if lat, lon, ok2 := gpsCoordinates(t, doc.GPS); ok2 {
		result["GPS_Coordinates"] = fmt.Sprintf("%.6f, %.6f", lat, lon)
		if alt, ok3 := gpsAltitude(t, doc.GPS); ok3 {
			result["GPS_Altitude"] = fmt.Sprintf("%.1f m", alt)
		}
		// GPSProcessingMethod distinguishes a real satellite fix from a
		// cell-tower estimate from a location a human typed in by hand.
		if e, present := doc.GPS[tagGPSProcMethod]; present {
			if s, _ := formatTiffValue(t, IFDGPS, tagGPSProcMethod, e); s != "" && !strings.HasPrefix(s, "<") {
				result["GPS_Method"] = s
				if strings.Contains(strings.ToUpper(s), "MANUAL") {
					w.add("gps", "manually_entered_location", -1, s)
				}
			}
		}
		if e, present := doc.GPS[tagGPSHPosError]; present {
			if v, ok3 := t.rational(e); ok3 && v > 0 {
				result["GPS_Accuracy"] = fmt.Sprintf("%.1f m", v)
			}
		}
		if e, present := doc.GPS[tagGPSImgDir]; present {
			if v, ok3 := t.rational(e); ok3 {
				result["GPS_Direction"] = fmt.Sprintf("%.0f\u00B0 %s", v,
					gpsRef(t, doc.GPS, tagGPSImgDirRef, "T"))
			}
		}
		// GPSDateStamp is UTC. A different calendar day from the local
		// DateTimeOriginal is possible near midnight, but a different month is
		// not: that means the GPS block was transplanted.
		if e, present := doc.GPS[tagGPSDateStamp]; present {
			if gd := t.ascii(e); !isPlaceholderDate(gd) {
				result["GPS_Date"] = gd
				if len(gd) >= 7 && len(dateOrig) >= 7 && gd[:7] != dateOrig[:7] {
					w.add("gps", "date_disagrees_with_capture", -1,
						fmt.Sprintf("GPS %s vs capture %s", gd, dateOrig))
				}
			}
		}
	}

	// Displayed dimensions differ from stored ones for orientations 5-8.
	if hasDims && actualW > 0 && actualH > 0 {
		if orientationSwapsAxes(orientation) {
			result["Display_Dimensions"] = fmt.Sprintf("%dx%d", actualH, actualW)
		}
	}

	out.EditSignals = detectEditing(t, doc, actualW, actualH, hasDims, out.Software, dateModified, dateOrig)

	// Full tag dump. IFD1 and the Interop IFD were previously parsed (or not
	// parsed at all) and never dumped, so the thumbnail's own metadata - the
	// place where a re-saved file most often disagrees with itself - was
	// invisible.
	allTags := make([]TiffTagView, 0, len(doc.IFD0)+len(doc.Exif)+len(doc.GPS)+len(doc.Interop)+len(doc.IFD1))
	allTags = append(allTags, DumpAllTags(t, IFD0, doc.IFD0)...)
	allTags = append(allTags, DumpAllTags(t, IFDExif, doc.Exif)...)
	allTags = append(allTags, DumpAllTags(t, IFDGPS, doc.GPS)...)
	allTags = append(allTags, DumpAllTags(t, IFDInterop, doc.Interop)...)
	allTags = append(allTags, DumpAllTags(t, IFD1, doc.IFD1)...)
	out.AllTags = allTags

	out.Thumbnail = extractThumbnail(t, doc.IFD1, actualW, actualH)
	out.Warnings = w.list
	return out
}

// applyExifOutcome folds one TIFF extraction into the result.
//
// This exists because the JPEG branch used to copy the thumbnail into the
// metadata and the PNG and WEBP branches silently discarded it, even though
// all three carry the identical TIFF structure. Identical inputs must not
// produce different outputs depending on which container they arrived in.
func applyExifOutcome(meta *MediaMetadata, out exifExtractOutcome, state *extractState) {
	mergeStrings(meta.Fields, out.Fields)
	if len(out.AllTags) > 0 {
		meta.AllTags = out.AllTags
	}
	if len(out.Thumbnail) > 0 {
		meta.Thumbnail = out.Thumbnail
		meta.ThumbnailMime = "image/jpeg"
		meta.ThumbnailSizeBytes = len(out.Thumbnail)
	}
	state.hasCameraExif = state.hasCameraExif || out.HasCameraExif
	if out.CaptureEvidence > state.captureEvidence {
		state.captureEvidence = out.CaptureEvidence
	}
	if out.Software != "" {
		state.software = append(state.software, out.Software)
	}
	if out.UserComment != "" {
		state.userComment = out.UserComment
	}
	state.editSignals = append(state.editSignals, out.EditSignals...)
}

// extractState is the cross-branch scratch space that the old code kept in a
// pile of loose local variables.
type extractState struct {
	width, height   int
	hasDims         bool
	dimsSource      string
	hasCameraExif   bool
	captureEvidence int
	software        []string
	userComment     string
	editSignals     []string
	pngChunkNames   []string
	pngDPI          int
}

// sameTIFFFamily reports whether two formats are the same TIFF container
// seen at different refinement levels. A .cr2 holding a TIFF header is not
// an attack; flagging TIFF->RAW as Format_Mismatch would cry wolf on every
// legitimate RAW file.
func sameTIFFFamily(a, b MediaType) bool {
	family := func(t MediaType) bool {
		return t == TypeTIFF || t == TypeDNG || t == TypeRAW
	}
	return family(a) && family(b)
}

// tiffPayloadForRAW returns the TIFF byte range inside a RAW file. Most
// vendor RAWs ARE a TIFF file; Fuji RAF prefixes it with a 16-byte
// "FUJIFILMCCD-RAW " magic plus a header, so the TIFF starts a little later.
func tiffPayloadForRAW(data []byte) []byte {
	if len(data) >= 16 && string(data[0:16]) == "FUJIFILMCCD-RAW " {
		limit := 4096
		if len(data) < limit {
			limit = len(data)
		}
		for i := 16; i+4 <= limit; i++ {
			if isTIFFHeader(data[i:]) {
				return data[i:]
			}
		}
	}
	return data
}

// --- Public entry points ----------------------------------------------------

// extractMediaMetadata returns just the flat curated field set.
func extractMediaMetadata(data []byte, format MediaType, filename string) map[string]string {
	return extractMediaMetadataFull(data, format, filename).Fields
}

// extractMediaMetadataFull is the main forensic metadata entry point: EXIF
// (curated fields, full generic tag dump, embedded thumbnail), XMP, PNG
// text/ICC chunks and the chunk table, trailing/overlay data, editing
// signals and the screenshot verdict.
//
// Containers: JPEG, PNG, WEBP, GIF, BMP, TIFF/DNG/RAW (TIFF-based RAWs reuse
// the same TIFF path), HEIC/AVIF/CR3 (ISO-BMFF stills via parseBMFFStill),
// ICO, SVG, plus dims-only PSD/JXL. TIFF-family refinement (TIFF<->DNG<->RAW)
// is not a mismatch: it is the same container seen with/without the filename.
//
// Every sub-extraction is independently panic-guarded, so one malformed
// sub-structure cannot blank out an otherwise successful pass - but unlike
// before, a recovered panic is RECORDED rather than swallowed. Fields
// Parse_Warnings and Parse_Warning_Count are the debugging surface and the
// fuzzing oracle at the same time.
func extractMediaMetadataFull(data []byte, format MediaType, filename string) MediaMetadata {
	meta := MediaMetadata{Fields: make(map[string]string)}
	w := &warnBag{}
	st := &extractState{}

	// Never trust the caller's format. When it comes from a filename
	// extension, a JPEG named .png produced empty metadata and no
	// explanation - and extension/content disagreement is both a common
	// upload attack and a finding in its own right.
	if detected, ok := sniffFormatWithName(data, filename); ok {
		if detected != format {
			if sameTIFFFamily(detected, format) {
				// Same TIFF container, refined by extension/tags
				// (TIFF vs DNG vs vendor RAW): adopt without a
				// mismatch alert; the branch records Format_Note.
				format = detected
			} else {
				w.add("format", "declared_vs_detected_mismatch", 0,
					fmt.Sprintf("declared %v, content %v", format, detected))
				meta.Fields["Format_Mismatch"] = fmt.Sprintf(
					"declared %v but content is %v", format, detected)
				format = detected
			}
		}
	} else if len(data) > 0 {
		w.add("format", "unrecognized_magic", 0, "")
	}

	switch format {
	case TypeJPEG:
		var frame jpegFrame
		safeStage(w, "jpeg.frame", func() {
			frame = parseJPEGFrame(data, w)
			st.width, st.height, st.hasDims = frame.Width, frame.Height, frame.HasDims
			st.dimsSource = "jpeg:SOF"
			if frame.Progressive {
				meta.Fields["JPEG_Mode"] = "progressive"
			} else if frame.Width > 0 {
				meta.Fields["JPEG_Mode"] = "baseline"
			}
			if frame.Arithmetic {
				w.add("jpeg.frame", "arithmetic_coding", -1, "")
			}
			if frame.Subsampling != "" {
				meta.Fields["JPEG_Subsampling"] = frame.Subsampling
			}
		})
		safeStage(w, "jpeg.exif", func() {
			tiffBuf := findJPEGExifTIFFWarn(data, w)
			if len(tiffBuf) == 0 {
				return
			}
			applyExifOutcome(&meta, extractCuratedEXIFCtx(tiffBuf, st.width, st.height, st.hasDims, w), st)
		})
		safeStage(w, "jpeg.comment", func() {
			// The COM segment is where gd-jpeg (PHP resize), GIMP, ffmpeg and
			// Facebook's FBMD marker live. It was not read at all.
			walkJPEG(data, nil, func(s jpegSeg) bool {
				if s.Marker != 0xFE || len(s.Payload) == 0 {
					return true
				}
				if c, _ := sanitizeText(truncateRunes(s.Payload, maxCuratedTextBytes)); c != "" {
					meta.Fields["JPEG_Comment"] = c
					st.software = append(st.software, c)
				}
				return false
			})
		})
		safeStage(w, "jpeg.xmp", func() {
			if xmpRaw := findJPEGXMP(data); xmpRaw != nil {
				if fields, ok := parseXMP(xmpRaw); ok && len(fields) > 0 {
					meta.XMP = fields
					// capXMPRaw returns a fresh truncated string, so no subslice
					// of a large upload is retained by the cached struct.
					meta.XMPRaw = capXMPRaw(xmpRaw)
					if tool, ok := fields["xmp:CreatorTool"]; ok {
						st.software = append(st.software, tool)
					}
				}
			}
		})
		safeStage(w, "jpeg.trailing", func() {
			// Uses the marker walker, so this is the TOP-LEVEL EOI. A plain
			// search for FF D9 finds the embedded thumbnail's EOI inside APP1
			// and reports the rest of the file as hidden payload.
			eoi, trailing, ok := jpegTopLevelEOI(data, w)
			if !ok || len(trailing) == 0 {
				return
			}
			meta.TrailingData = &TrailingDataInfo{
				Offset:         eoi + 2,
				Size:           len(trailing),
				DetectedFormat: identifyTrailingFormat(trailing),
			}
			// Motion photos are the overwhelmingly common cause of trailing
			// bytes on phone images. Without this the detector cries "hidden
			// payload" on every other photo taken with a Pixel or a Galaxy.
			switch {
			case bytes.Contains(trailing, []byte("ftyp")):
				meta.Fields["Motion_Photo"] = fmt.Sprintf(
					"embedded video at offset %d, %d bytes", eoi+2, len(trailing))
			case bytes.HasPrefix(trailing, []byte("SEFH")) || bytes.Contains(trailing, []byte("SEFT")):
				meta.Fields["Motion_Photo"] = "Samsung Extended Format trailer"
			}
		})

	case TypePNG:
		var hdr pngHeader
		safeStage(w, "png.header", func() {
			hdr = parsePNGHeader(data, w)
			st.width, st.height, st.hasDims = hdr.Width, hdr.Height, hdr.HasDims
			st.dimsSource = "png:IHDR"
			if hdr.HasDims {
				meta.Fields["PNG_Bit_Depth"] = fmt.Sprintf("%d", hdr.BitDepth)
				meta.Fields["PNG_Color_Type"] = fmt.Sprintf("%d", hdr.ColorType)
				if hdr.Interlace != 0 {
					meta.Fields["PNG_Interlaced"] = "yes"
				}
			}
			if hdr.AppleCgBI {
				meta.Fields["PNG_Variant"] = "Apple CgBI (non-standard)"
				st.pngChunkNames = append(st.pngChunkNames, "CgBI")
			}
			// A decompression bomb declares an enormous canvas in a tiny file.
			if hdr.HasDims && len(data) > 0 {
				pixels := int64(hdr.Width) * int64(hdr.Height)
				if pixels/int64(len(data)) > 100000 {
					w.add("png.header", "suspicious_pixel_ratio", 0,
						fmt.Sprintf("%d pixels in %d bytes", pixels, len(data)))
					meta.Fields["Suspicious_Pixel_Ratio"] = fmt.Sprintf(
						"%dx%d declared in a %d byte file", hdr.Width, hdr.Height, len(data))
				}
			}
		})
		safeStage(w, "png.chunks", func() {
			walk := walkPNGChunks(data)
			meta.PNGChunks = walk.Chunks
			if len(walk.TextChunks) > 0 {
				meta.PNGTextChunks = walk.TextChunks
			}
			meta.ICCProfile = walk.ICC

			if walk.EXIFChunk != nil {
				applyExifOutcome(&meta,
					extractCuratedEXIFCtx(walk.EXIFChunk, st.width, st.height, st.hasDims, w), st)
			}

			// Capture tools write their name into tEXt/iTXt, not into EXIF.
			// The screenshot heuristic could not previously see any of this.
			for _, key := range []string{"Software", "Comment", "Description", "Source", "Title"} {
				if v, ok := walk.TextChunks[key]; ok && v != "" {
					st.software = append(st.software, v)
				}
			}
			// A1111 / ComfyUI / NovelAI leave their generation payload here.
			for _, key := range []string{"parameters", "prompt", "workflow", "Comment"} {
				if v, ok := walk.TextChunks[key]; ok && v != "" {
					meta.Fields["AI_Generated_Likely"] = fmt.Sprintf(
						"PNG text chunk %q present (diffusion-tool metadata)", key)
					break
				}
			}

			if xmpText, present := walk.TextChunks["XML:com.adobe.xmp"]; present {
				if fields, ok := parseXMP([]byte(xmpText)); ok && len(fields) > 0 {
					meta.XMP = fields
					meta.XMPRaw = capXMPRaw([]byte(xmpText))
					if tool, ok := fields["xmp:CreatorTool"]; ok {
						st.software = append(st.software, tool)
					}
				}
			}

			if walk.IENDOffset != -1 && len(walk.TrailingData) > 0 {
				meta.TrailingData = &TrailingDataInfo{
					Offset:         walk.IENDOffset + 8 + 4, // past IEND's [len][type][crc]
					Size:           len(walk.TrailingData),
					DetectedFormat: identifyTrailingFormat(walk.TrailingData),
				}
			}
		})

	case TypeWEBP:
		safeStage(w, "webp", func() {
			info, ok := parseWEBPInfo(data)
			if !ok {
				w.add("webp", "unparseable", 0, "")
				return
			}
			if info.HasDims {
				st.width, st.height, st.hasDims = info.Width, info.Height, true
				st.dimsSource = "webp:VP8X"
			}
			if info.EXIFChunk != nil {
				applyExifOutcome(&meta,
					extractCuratedEXIFCtx(info.EXIFChunk, st.width, st.height, st.hasDims, w), st)
			}
			if info.XMPChunk != nil {
				if fields, ok := parseXMP(info.XMPChunk); ok && len(fields) > 0 {
					meta.XMP = fields
					meta.XMPRaw = capXMPRaw(info.XMPChunk)
				}
			}
		})

	case TypeGIF:
		safeStage(w, "gif.dims", func() {
			if gw, gh, ok := parseGIFDims(data); ok {
				st.width, st.height, st.hasDims = gw, gh, true
				st.dimsSource = "gif:LSD"
				meta.Fields["GIF_Version"] = string(data[0:6])
			} else {
				w.add("gif.header", "unparseable", 0, "")
			}
		})
		safeStage(w, "gif.trailing", func() {
			if trailing := gifTrailing(data); len(trailing) > 0 {
				meta.TrailingData = &TrailingDataInfo{
					Offset:         len(data) - len(trailing),
					Size:           len(trailing),
					DetectedFormat: identifyTrailingFormat(trailing),
				}
			}
		})

	case TypeBMP:
		safeStage(w, "bmp.dims", func() {
			bw, bh, bpp, ok := parseBMPDims(data)
			if !ok {
				w.add("bmp.header", "unparseable", 0, "")
				return
			}
			st.width, st.height, st.hasDims = bw, bh, true
			st.dimsSource = "bmp:infoheader"
			if bpp > 0 {
				meta.Fields["BMP_Bit_Depth"] = fmt.Sprintf("%d", bpp)
			}
			if declared, ok := bmpDeclaredSize(data); ok {
				switch {
				case len(data) > declared:
					meta.TrailingData = &TrailingDataInfo{
						Offset:         declared,
						Size:           len(data) - declared,
						DetectedFormat: identifyTrailingFormat(data[declared:]),
					}
				case len(data) < declared:
					w.add("bmp.header", "truncated_file", 0,
						fmt.Sprintf("header claims %d bytes, have %d", declared, len(data)))
				}
			}
		})

	case TypeTIFF, TypeDNG, TypeRAW:
		safeStage(w, "tiff.exif", func() {
			// Canon CR3 ("crx " brand) is ISO-BMFF, not TIFF: route it to
			// the BMFF still path instead of feeding ftyp bytes to the
			// TIFF parser.
			if _, isBMFF := bmffBrand(data); isBMFF {
				info, ok := parseBMFFStill(data)
				if !ok {
					w.add("bmff", "unparseable", 0, "")
					return
				}
				if info.HasDims {
					st.width, st.height, st.hasDims = info.Width, info.Height, true
					st.dimsSource = "bmff:ispe"
				}
				meta.Fields["Container_Brand"] = info.Brand
				if variant, note := identifyTIFFVariant(data, filename); note != "" {
					_ = variant
					meta.Fields["Format_Note"] = note
				} else if info.Brand == "crx " {
					meta.Fields["Format_Note"] = "Canon CR3 (ISO-BMFF RAW)"
				}
				if info.EXIF != nil {
					applyExifOutcome(&meta,
						extractCuratedEXIFCtx(info.EXIF, st.width, st.height, st.hasDims, w), st)
				}
				if info.XMP != nil {
					if fields, ok := parseXMP(info.XMP); ok && len(fields) > 0 {
						meta.XMP = fields
						meta.XMPRaw = capXMPRaw(info.XMP)
					}
				}
				return
			}
			if variant, note := identifyTIFFVariant(data, filename); note != "" {
				meta.Fields["Format_Note"] = note
				_ = variant
			}
			if tw, th, ok := parseTIFFDims(data); ok {
				st.width, st.height, st.hasDims = tw, th, true
				st.dimsSource = "tiff:IFD0"
			}
			payload := tiffPayloadForRAW(data)
			applyExifOutcome(&meta,
				extractCuratedEXIFCtx(payload, st.width, st.height, st.hasDims, w), st)
		})

	case TypeHEIC, TypeAVIF:
		safeStage(w, "bmff", func() {
			info, ok := parseBMFFStill(data)
			if !ok {
				w.add("bmff", "unparseable", 0, "")
				return
			}
			if info.HasDims {
				st.width, st.height, st.hasDims = info.Width, info.Height, true
				st.dimsSource = "bmff:ispe"
			}
			if info.Brand != "" {
				meta.Fields["Container_Brand"] = info.Brand
			}
			if info.EXIF != nil {
				applyExifOutcome(&meta,
					extractCuratedEXIFCtx(info.EXIF, st.width, st.height, st.hasDims, w), st)
			}
			if info.XMP != nil {
				if fields, ok := parseXMP(info.XMP); ok && len(fields) > 0 {
					meta.XMP = fields
					meta.XMPRaw = capXMPRaw(info.XMP)
				}
			}
		})

	case TypePSD:
		safeStage(w, "psd.dims", func() {
			if pw, ph, ok := parsePSDDims(data); ok {
				st.width, st.height, st.hasDims = pw, ph, true
				st.dimsSource = "psd:header"
			} else {
				w.add("psd.header", "unparseable", 0, "")
			}
		})

	case TypeJXL:
		safeStage(w, "jxl", func() {
			if brand, ok := bmffBrand(data); ok {
				meta.Fields["Container_Brand"] = brand
			}
			meta.Fields["Format_Note"] = "JPEG XL; dimensions/EXIF not decoded"
			w.add("jxl", "dims_unsupported", 0, "")
		})

	case TypeICO:
		safeStage(w, "ico", func() {
			if entries, ok := parseICOInfo(data); ok {
				meta.Fields["ICO_Entries"] = summarizeICOEntries(entries)
			} else {
				w.add("ico", "unparseable", 0, "")
			}
		})

	case TypeSVG:
		safeStage(w, "svg", func() {
			mergeStrings(meta.Fields, parseSVGInfo(data))
		})

	default:
		w.add("format", "unsupported", 0, fmt.Sprintf("%v", format))
	}

	// One exit path. The old code returned early for ICO and SVG, which
	// skipped Image_Dimensions and would have skipped the warnings too, and
	// left the consumer unable to tell "no dimensions found" apart from "this
	// format does not carry dimensions".
	if st.hasDims {
		meta.Fields["Image_Dimensions"] = fmt.Sprintf("%dx%d", st.width, st.height)
		if st.dimsSource != "" {
			meta.Fields["Dimensions_Source"] = st.dimsSource
		}
	}

	if len(st.editSignals) > 0 {
		meta.Fields["Edited_Signals"] = strings.Join(st.editSignals, "; ")
	}

	if format == TypeJPEG || format == TypePNG || format == TypeWEBP ||
		format == TypeGIF || format == TypeBMP ||
		format == TypeTIFF || format == TypeDNG || format == TypeRAW ||
		format == TypeHEIC || format == TypeAVIF {
		safeStage(w, "screenshot", func() {
			v := detectScreenshotV2(screenshotInput{
				Filename:        filename,
				Format:          format,
				Width:           st.width,
				Height:          st.height,
				HasDims:         st.hasDims,
				CaptureEvidence: st.captureEvidence,
				Software:        st.software,
				UserComment:     st.userComment,
				PNGChunkNames:   st.pngChunkNames,
				PNGDPI:          st.pngDPI,
			})
			if reason := v.reason(); reason != "" {
				meta.Fields["Screenshot_Likely"] = reason
				meta.Fields["Screenshot_Confidence"] = v.Confidence
			}
		})
	}

	if s := w.summary(); s != "" {
		meta.Fields["Parse_Warnings"] = s
		meta.Fields["Parse_Warning_Count"] = fmt.Sprintf("%d", len(w.list)+w.dropped)
	}

	return meta
}

func mergeStrings(dst, src map[string]string) {
	for k, v := range src {
		dst[k] = v
	}
}
