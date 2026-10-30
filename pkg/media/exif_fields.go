package media

import (
	"bytes"
	"fmt"
	"math"
	"strings"
)

// curated field formatting: exposure, GPS, timestamps, thumbnail, editing.
//
// Split from exif.go: exact code move, no logic changes.

// --- Field formatting -------------------------------------------------------

func orientationLabel(v int) string {
	switch v {
	case 1:
		return "Normal"
	case 2:
		return "Mirrored horizontal"
	case 3:
		return "Rotated 180\u00B0"
	case 4:
		return "Mirrored vertical"
	case 5:
		return "Mirrored horizontal, rotated 270\u00B0 CW"
	case 6:
		return "Rotated 90\u00B0 CW"
	case 7:
		return "Mirrored horizontal, rotated 90\u00B0 CW"
	case 8:
		return "Rotated 270\u00B0 CW"
	default:
		return fmt.Sprintf("Unknown (%d)", v)
	}
}

// orientationSwapsAxes reports whether the stored pixel dimensions must be
// swapped to get displayed dimensions.
func orientationSwapsAxes(v int) bool { return v >= 5 && v <= 8 }

// formatExposure prints the exposure the way a camera does.
//
// The old "1/%.0fs" applied to everything below 1 second turned 0.6 s into
// "1/2s" and 0.7 s into "1/1s". Using the stored numerator/denominator avoids
// reconstructing a fraction from a float at all.
func formatExposure(r exifRational) string {
	v, ok := r.float()
	if !ok || v <= 0 {
		return ""
	}
	if v >= 0.25 {
		return strings.TrimSuffix(fmt.Sprintf("%.1f", v), ".0") + "s"
	}
	if r.Num > 0 && r.Den > 0 && r.Num != 1 {
		// 10/2500 is the same exposure as 1/250; normalize for display.
		return fmt.Sprintf("1/%.0fs", 1/v)
	}
	if r.Num == 1 && r.Den > 0 {
		return fmt.Sprintf("1/%ds", r.Den)
	}
	return fmt.Sprintf("1/%.0fs", 1/v)
}

// formatFNumber keeps two decimals when the first one loses information:
// f/1.75 lenses exist and "%.1f" reported them as f/1.8.
func formatFNumber(v float64) string {
	if math.Abs(v*10-math.Round(v*10)) < 0.01 {
		return fmt.Sprintf("f/%.1f", v)
	}
	return fmt.Sprintf("f/%.2f", v)
}

// apexToFNumber converts ApertureValue (APEX) to an f-number: F = 2^(Av/2).
func apexToFNumber(av float64) (float64, bool) {
	if av < 0 || av > 30 {
		return 0, false
	}
	v := math.Pow(2, av/2)
	if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
		return 0, false
	}
	return v, true
}

// apexToExposure converts ShutterSpeedValue (APEX, SRATIONAL) to seconds:
// t = 2^(-Tv).
func apexToExposure(tv float64) (float64, bool) {
	if tv < -20 || tv > 30 {
		return 0, false
	}
	v := math.Pow(2, -tv)
	if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
		return 0, false
	}
	return v, true
}

// exifISO resolves ISO across the three tags that carry it.
//
// ISOSpeedRatings == 65535 is a sentinel meaning "the real value is in
// ISOSpeed (0x8833)", which newer Sony and Canon bodies rely on; reading only
// 0x8827 loses ISO entirely on those files.
func exifISO(t *tiffFile, exif map[uint16]tiffEntry) (uint64, string, bool) {
	if e, ok := exif[tagISOSpeedRatings]; ok {
		if v, ok2 := t.uint(e); ok2 && v > 0 && v != 65535 {
			return v, "exif:0x8827", true
		}
	}
	for _, c := range []struct {
		tag uint16
		src string
	}{{tagISOSpeed, "exif:0x8833"}, {tagRecommendedEI, "exif:0x8832"}} {
		if e, ok := exif[c.tag]; ok {
			if v, ok2 := t.uint(e); ok2 && v > 0 {
				return v, c.src, true
			}
		}
	}
	return 0, "", false
}

func cameraSettings(t *tiffFile, exifIFD map[uint16]tiffEntry) string {
	var parts []string

	if r, ok := t.rationalRaw(exifIFD[tagFNumber]); ok {
		if v, ok2 := r.float(); ok2 && v > 0 {
			parts = append(parts, formatFNumber(v))
		}
	} else if e, ok := exifIFD[tagApertureValue]; ok {
		// FNumber is frequently written as 0/0; APEX ApertureValue is the
		// documented fallback and was being ignored.
		if av, ok2 := t.rational(e); ok2 {
			if v, ok3 := apexToFNumber(av); ok3 {
				parts = append(parts, formatFNumber(v)+" (from APEX)")
			}
		}
	}

	if r, ok := t.rationalRaw(exifIFD[tagExposureTime]); ok {
		if s := formatExposure(r); s != "" {
			parts = append(parts, s)
		}
	} else if e, ok := exifIFD[tagShutterSpeedVal]; ok {
		if tv, ok2 := t.srational(e); ok2 {
			if v, ok3 := apexToExposure(tv); ok3 {
				parts = append(parts, formatExposure(exifRational{Num: 1, Den: int64(math.Round(1 / v))})+" (from APEX)")
			}
		}
	}

	if v, _, ok := exifISO(t, exifIFD); ok {
		parts = append(parts, fmt.Sprintf("ISO %d", v))
	}

	if e, ok := exifIFD[tagFocalLength]; ok {
		if v, ok2 := t.rational(e); ok2 && v > 0 {
			s := fmt.Sprintf("%.1fmm", v)
			if e35, ok3 := exifIFD[tagFocalLength35]; ok3 {
				if v35, ok4 := t.uint(e35); ok4 && v35 > 0 {
					s += fmt.Sprintf(" (%dmm eq.)", v35)
				}
			}
			parts = append(parts, s)
		}
	}

	if e, ok := exifIFD[tagExposureBias]; ok {
		// ExposureBias is SRATIONAL, which the old code could not read at all.
		// 0 EV is a real value, so it is only omitted when the tag is absent.
		if v, ok2 := t.srational(e); ok2 {
			parts = append(parts, fmt.Sprintf("%+.1f EV", v))
		}
	}

	if e, ok := exifIFD[tagFlash]; ok {
		if v, ok2 := t.uint(e); ok2 {
			if v&0x01 != 0 {
				parts = append(parts, "flash fired")
			} else {
				parts = append(parts, "no flash")
			}
		}
	}

	return strings.Join(parts, ", ")
}

// --- GPS --------------------------------------------------------------------

func dmsToDecimal(dms [3]float64, ref string) float64 {
	v := dms[0] + dms[1]/60.0 + dms[2]/3600.0
	// Refs appear as "S", "s" and occasionally "South"; the old exact
	// comparison against "S"/"W" silently produced a mirrored location.
	switch strings.ToUpper(strings.TrimSpace(ref)) {
	case "S", "SOUTH", "W", "WEST":
		v = -v
	}
	return v
}

func gpsRef(t *tiffFile, gps map[uint16]tiffEntry, tag uint16, def string) string {
	if e, ok := gps[tag]; ok {
		if v := t.ascii(e); v != "" {
			return v
		}
	}
	return def
}

func gpsCoordinates(t *tiffFile, gpsIFD map[uint16]tiffEntry) (lat, lon float64, ok bool) {
	latE, ok1 := gpsIFD[tagGPSLat]
	lonE, ok2 := gpsIFD[tagGPSLon]
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	latDMS, ok3 := t.gpsDMS(latE)
	lonDMS, ok4 := t.gpsDMS(lonE)
	if !ok3 || !ok4 {
		t.warn.add("gps", "unreadable_coordinates", -1, "")
		return 0, 0, false
	}

	lat = dmsToDecimal(latDMS, gpsRef(t, gpsIFD, tagGPSLatRef, "N"))
	lon = dmsToDecimal(lonDMS, gpsRef(t, gpsIFD, tagGPSLonRef, "E"))

	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		t.warn.add("gps", "coordinates_out_of_range", -1, fmt.Sprintf("%f,%f", lat, lon))
		return 0, 0, false
	}
	// Exactly (0,0) is Null Island: a very common firmware placeholder, not a
	// location in the Gulf of Guinea.
	if lat == 0 && lon == 0 {
		t.warn.add("gps", "null_island_placeholder", -1, "")
		return 0, 0, false
	}
	return lat, lon, true
}

func gpsAltitude(t *tiffFile, gpsIFD map[uint16]tiffEntry) (float64, bool) {
	e, ok := gpsIFD[tagGPSAlt]
	if !ok {
		return 0, false
	}
	v, ok2 := t.rational(e)
	if !ok2 {
		return 0, false
	}
	if refE, present := gpsIFD[tagGPSAltRef]; present {
		if ref, ok3 := t.uint(refE); ok3 && ref == 1 {
			v = -v
		}
	}
	return v, true
}

// --- Timestamps -------------------------------------------------------------

// exifPlaceholderDates are the standard "field present but unset" values that
// the old code handed back as a real Date_Taken.
var exifPlaceholderDates = map[string]bool{
	"0000:00:00 00:00:00": true,
	"    :  :     :  :  ": true,
	"0000:00:00":          true,
	"1970:01:01 00:00:00": true, // epoch: almost always an unset clock
}

func isPlaceholderDate(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || exifPlaceholderDates[s] || exifPlaceholderDates[trimmed] {
		return true
	}
	// "0000:00:00..." in any variant, and any value with no digits at all.
	if strings.HasPrefix(trimmed, "0000:00:00") {
		return true
	}
	return strings.IndexFunc(trimmed, func(r rune) bool { return r >= '1' && r <= '9' }) < 0
}

// exifTimestamp assembles a full timestamp from DateTimeOriginal plus the
// sub-second and UTC-offset tags, which the old code did not read.
func exifTimestamp(t *tiffFile, exif map[uint16]tiffEntry, base string) string {
	if base == "" {
		return ""
	}
	out := base
	if e, ok := exif[tagSubSecTimeOrig]; ok {
		if frac := strings.TrimSpace(t.ascii(e)); frac != "" && strings.Trim(frac, "0") != "" {
			out += "." + frac
		}
	}
	if e, ok := exif[tagOffsetTimeOrig]; ok {
		// OffsetTimeOriginal is the only tag that makes DateTimeOriginal an
		// unambiguous instant; without it the timestamp is wall-clock local
		// time with no zone at all.
		off := strings.TrimSpace(t.ascii(e))
		if len(off) >= 3 && (off[0] == '+' || off[0] == '-') {
			out += " " + off
		}
	}
	return out
}

// --- Thumbnail --------------------------------------------------------------

// extractThumbnail reads the embedded JPEG preview referenced by IFD1.
//
// Beyond the original bounds check and SOI check this also requires a
// terminating EOI and rejects a "thumbnail" that is not smaller than the main
// image: a preview larger than the image it previews is a transplanted or
// hidden picture, not a thumbnail.
func extractThumbnail(t *tiffFile, ifd1 map[uint16]tiffEntry, mainW, mainH int) []byte {
	offE, present := ifd1[tagThumbOffset]
	if !present {
		return nil
	}
	lenE, present := ifd1[tagThumbLength]
	if !present {
		return nil
	}
	off, ok1 := t.uint(offE)
	length, ok2 := t.uint(lenE)
	if !ok1 || !ok2 || length == 0 {
		return nil
	}
	if length > maxThumbnailBytes {
		t.warn.add("thumbnail", "length_over_cap", int64(off), fmt.Sprintf("%d bytes", length))
		return nil
	}
	raw, ok := t.slice(off, length)
	if !ok {
		t.warn.add("thumbnail", "out_of_bounds", int64(off), fmt.Sprintf("%d bytes", length))
		return nil
	}
	if len(raw) < 4 || raw[0] != 0xFF || raw[1] != 0xD8 {
		t.warn.add("thumbnail", "not_a_jpeg", int64(off), "missing SOI")
		return nil
	}
	if raw[len(raw)-2] != 0xFF || raw[len(raw)-1] != 0xD9 {
		// Truncated or padded preview: keep it, but say so.
		t.warn.add("thumbnail", "missing_eoi", int64(off), "")
	}
	if tw, th, ok := findJPEGDimensions(raw); ok && mainW > 0 && mainH > 0 {
		if tw > mainW || th > mainH {
			t.warn.add("thumbnail", "larger_than_main_image", int64(off),
				fmt.Sprintf("%dx%d vs %dx%d", tw, th, mainW, mainH))
		}
	}
	// Clone: the returned slice outlives the call, and holding a subslice pins
	// the entire input file in memory.
	return bytes.Clone(raw)
}

// --- Editing detection ------------------------------------------------------

// editorSoftwareMarkers maps a lowercase Software substring to a display name.
var editorSoftwareMarkers = []struct{ marker, name string }{
	{"adobe photoshop", "Adobe Photoshop"},
	{"photoshop", "Adobe Photoshop"},
	{"lightroom", "Adobe Lightroom"},
	{"camera raw", "Adobe Camera Raw"},
	{"gimp", "GIMP"},
	{"snapseed", "Snapseed"},
	{"pixelmator", "Pixelmator"},
	{"affinity", "Affinity Photo"},
	{"canva", "Canva"},
	{"picsart", "PicsArt"},
	{"lunapic", "LunaPic"},
	{"imagemagick", "ImageMagick"},
	{"paint.net", "Paint.NET"},
	{"pillow", "Python Pillow"},
	{"capture one", "Capture One"},
	{"darktable", "darktable"},
	{"rawtherapee", "RawTherapee"},
	{"luminar", "Luminar"},
	{"vsco", "VSCO"},
	{"facetune", "Facetune"},
	{"remini", "Remini"},
}

// detectEditing is the highest-value-per-line check in this file: it compares
// what the camera recorded against what the file actually contains.
func detectEditing(t *tiffFile, doc tiffDoc, actualW, actualH int, hasDims bool, software, dateTime, dateTimeOrig string) []string {
	var signals []string

	// PixelXDimension/PixelYDimension are what the camera wrote at capture.
	// Disagreement with the real frame size means the image was resized or
	// cropped afterwards.
	if hasDims && actualW > 0 && actualH > 0 {
		px, okx := doc.Exif[tagPixelXDimension]
		py, oky := doc.Exif[tagPixelYDimension]
		if okx && oky {
			vx, ok1 := t.uint(px)
			vy, ok2 := t.uint(py)
			if ok1 && ok2 && vx > 0 && vy > 0 {
				sameWay := int(vx) == actualW && int(vy) == actualH
				swapped := int(vx) == actualH && int(vy) == actualW
				if !sameWay && !swapped {
					signals = append(signals, fmt.Sprintf(
						"EXIF records %dx%d but the frame is %dx%d (resized or cropped)",
						vx, vy, actualW, actualH))
				}
			}
		}
	}

	// DateTime is "last modified"; DateTimeOriginal is "captured".
	if dateTime != "" && dateTimeOrig != "" && dateTime != dateTimeOrig &&
		!isPlaceholderDate(dateTime) && !isPlaceholderDate(dateTimeOrig) {
		signals = append(signals, fmt.Sprintf(
			"DateTime %q differs from DateTimeOriginal %q (file was re-saved)", dateTime, dateTimeOrig))
	}

	lower := strings.ToLower(software)
	for _, m := range editorSoftwareMarkers {
		if strings.Contains(lower, m.marker) {
			signals = append(signals, "Software tag names an editor: "+m.name)
			break
		}
	}

	return signals
}
