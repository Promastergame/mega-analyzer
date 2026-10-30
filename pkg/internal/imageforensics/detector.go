package imageforensics

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTOR — high-level entry point
//
// Analyze takes raw image bytes plus the file extension (best-effort) and
// returns a Report. The function never panics: every parser uses
// `defer recover()`, and any lower-level failure degrades to verdict
// VerdictSuspicious without leaking information.
// ═══════════════════════════════════════════════════════════════════════════════

// Report aggregates signals for a single image.
type Report struct {
	Verdict          string
	Reasons          []string // human-readable explanations attached to Verdict
	MimeMismatch     bool
	Truncated        bool
	TrailingData     int
	PolyglotSignals  []string
	SuspiciousChunks []string
	BadCRC           []string
	EXIF             map[string]string
	Width            int
	Height           int
	Entropy          float64
	DetectedMime     string
	DeclaredMime     string
}

// Analyze inspects the byte slice and returns forensic signals.
func Analyze(data []byte, ext string) (rep Report) {
	defer func() {
		if r := recover(); r != nil {
			// Keep results, but force verdict to suspicious.
			rep.Verdict = VerdictSuspicious
			rep.Reasons = appendReason(rep.Reasons, "internal parser failure")
		}
	}()

	rep.Entropy = Shannon(data)
	rep.DetectedMime = SniffMime(data)
	rep.DeclaredMime = MimeFromExt(ext)

	if rep.DeclaredMime != "" && !MimesCompatible(rep.DetectedMime, rep.DeclaredMime) {
		rep.MimeMismatch = true
	}

	// Format-specific parsers.
	switch rep.DetectedMime {
	case "image/png":
		info := ParsePNG(data)
		rep.Width = info.Width
		rep.Height = info.Height
		rep.SuspiciousChunks = info.SuspiciousChunks
		rep.BadCRC = info.BadCRC
		rep.TrailingData = len(info.TrailingData)
		if rep.TrailingData > 0 {
			rep.PolyglotSignals = polyglotFormats(info.TrailingData)
		}
	case "image/jpeg":
		info := ParseJPEG(data)
		rep.Width = info.Width
		rep.Height = info.Height
		rep.TrailingData = len(info.TrailingData)
		if rep.TrailingData > 0 {
			rep.PolyglotSignals = polyglotFormats(info.TrailingData)
		}
	case "image/gif":
		info := ParseGIF(data)
		rep.Width = info.Width
		rep.Height = info.Height
		rep.TrailingData = len(info.TrailingData)
		if rep.TrailingData > 0 {
			rep.PolyglotSignals = polyglotFormats(info.TrailingData)
		}
		if info.SuspiciousComment {
			rep.SuspiciousChunks = append(rep.SuspiciousChunks, "GIF.comment")
		}
	case "image/webp":
		info := ParseWEBP(data)
		rep.TrailingData = len(info.TrailingData)
		rep.Truncated = info.Truncated
		if rep.TrailingData > 0 {
			rep.PolyglotSignals = polyglotFormats(info.TrailingData)
		}
	}

	// EXIF (JPEG only at the moment).
	if rep.DetectedMime == "image/jpeg" {
		// Find APP1 inside the JPEG header window.
		if exifBytes := findEXIFAppSegment(data); len(exifBytes) > 0 {
			rep.EXIF = ParseEXIF(exifBytes)
		}
	}

	rep.Verdict, rep.Reasons = computeVerdict(rep)
	return rep
}

// computeVerdict applies the signal table from plan.md §5 and returns
// (verdict, reasons). Reasons are ordered by severity contribution.
func computeVerdict(rep Report) (string, []string) {
	reasons := make([]string, 0, 4)

	// Collect every relevant fact first — UI shows all of them.
	if rep.MimeMismatch {
		reasons = appendReason(reasons,
			fmt.Sprintf("file extension does not match detected MIME (%s vs %s)",
				rep.DeclaredMime, rep.DetectedMime))
	}
	if rep.Truncated {
		reasons = appendReason(reasons, "declared payload size exceeds actual file size")
	}
	if rep.TrailingData > 0 {
		reasons = appendReason(reasons,
			fmt.Sprintf("%d bytes of trailing data found after image stream", rep.TrailingData))
	}
	for _, fmtName := range rep.PolyglotSignals {
		reasons = appendReason(reasons,
			fmt.Sprintf("%s header found in trailing data", fmtName))
	}
	for _, ctype := range rep.SuspiciousChunks {
		reasons = appendReason(reasons,
			fmt.Sprintf("oversized %s chunk", ctype))
	}
	for _, ctype := range rep.BadCRC {
		reasons = appendReason(reasons,
			fmt.Sprintf("CRC mismatch in %s chunk", ctype))
	}
	if suspectEXIF(rep.EXIF) {
		reasons = appendReason(reasons, "GPS EXIF present without camera Make")
	}

	hasArchiveOrExe := false
	for _, fmtName := range rep.PolyglotSignals {
		switch fmtName {
		case "PE", "ELF", "DEX", "ZIP", "RAR", "7z":
			hasArchiveOrExe = true
		}
	}
	mimeIsAppPayload := strings.HasPrefix(rep.DetectedMime, "application/") &&
		rep.DetectedMime != "application/octet-stream"

	switch {
	// Strongest: extension says image but content is itself an executable / archive.
	case rep.MimeMismatch && mimeIsAppPayload:
		return VerdictPotentiallyUnsafe, reasons

	// Polyglot + MIME mismatch is a stronger composite signal than polyglot alone.
	case len(rep.PolyglotSignals) > 0 && rep.MimeMismatch:
		return VerdictPotentiallyUnsafe, reasons

	case len(rep.PolyglotSignals) > 0 && hasArchiveOrExe:
		return VerdictPossibleEmbedded, reasons

	case rep.TrailingData > 1024 && rep.Entropy > 7.95:
		return VerdictSuspicious, reasons

	case rep.TrailingData > 0:
		return VerdictPossibleEmbedded, reasons

	case len(rep.SuspiciousChunks) > 0 || len(rep.BadCRC) > 0:
		return VerdictSuspicious, reasons

	case rep.Truncated:
		return VerdictUnusualStructure, reasons

	case rep.MimeMismatch:
		return VerdictUnusualStructure, reasons

	case suspectEXIF(rep.EXIF):
		return VerdictUnusualStructure, reasons

	default:
		// No reasons -> drop the empty slice so it serialises cleanly.
		if len(reasons) == 0 {
			return VerdictOK, nil
		}
		return VerdictOK, reasons
	}
}

func appendReason(reasons []string, r string) []string {
	for _, existing := range reasons {
		if existing == r {
			return reasons
		}
	}
	return append(reasons, r)
}

func suspectEXIF(exif map[string]string) bool {
	if len(exif) == 0 {
		return false
	}
	makeField := strings.TrimSpace(exif["Make"])
	software := strings.TrimSpace(exif["Software"])
	// Camera EXIF without Make is unusual; Software set without Make is
	// fine on its own but the combination of GPS + missing Make is worth
	// flagging.
	if exif["GPSIFD"] != "" && makeField == "" {
		return true
	}
	if makeField != "" && software != "" && strings.EqualFold(makeField, software) {
		return true
	}
	return false
}

func polyglotFormats(trailing []byte) []string {
	sigs := FindPolyglot(trailing)
	if len(sigs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(sigs))
	out := make([]string, 0, len(sigs))
	for _, s := range sigs {
		if _, ok := seen[s.Format]; ok {
			continue
		}
		seen[s.Format] = struct{}{}
		out = append(out, s.Format)
	}
	return out
}

// findEXIFAppSegment locates the APP1 EXIF segment inside a JPEG and
// returns just its payload (without the APP1 marker / length).
func findEXIFAppSegment(data []byte) []byte {
	defer func() { notePanic("imageforensics.detector", recover()) }()

	if len(data) < 4 {
		return nil
	}
	pos := 2
	for pos+4 < len(data) {
		if data[pos] != 0xFF {
			return nil
		}
		marker := data[pos+1]
		if marker == 0xD8 || (marker >= 0xD0 && marker <= 0xD7) {
			pos += 2
			continue
		}
		if marker == 0xD9 || marker == 0xDA {
			return nil
		}
		length := int(data[pos+2])<<8 | int(data[pos+3])
		if length < 2 || pos+2+length > len(data) {
			return nil
		}
		if marker == 0xE1 && length > 8 {
			payload := data[pos+4 : pos+2+length]
			if len(payload) >= 6 && string(payload[:4]) == "Exif" {
				return payload
			}
		}
		pos += 2 + length
	}
	return nil
}
