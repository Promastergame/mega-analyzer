package report

import (
	"encoding/base64"
	"fmt"
	"html"
	"sort"
	"strings"

	"mega-analyzer/pkg/media"
)

// iconForMediaFormat maps a media.MediaType string (jpeg, png, mp4, wav, pdf, apk, ...)
// to the closest available sprite icon.
func iconForMediaFormat(format string) string {
	switch strings.ToLower(format) {
	case "jpeg", "png", "gif", "webp", "bmp":
		return icon("image")
	case "mp4", "webm", "avi", "mov":
		return icon("video")
	case "wav", "mp3", "ogg", "flac":
		return icon("audio")
	case "pdf":
		return icon("file-text")
	case "dex":
		return icon("file-code")
	case "zip", "apk":
		return icon("package")
	default:
		return icon("file")
	}
}

// iconForRegionType picks a representative icon for a detected embedded-region
// signal name (e.g. "privacy_leak", "high_entropy", "suspicious_payload").
func iconForRegionType(typ string) string {
	t := strings.ToLower(typ)
	switch {
	case strings.Contains(t, "gps") || strings.Contains(t, "location"):
		return icon("map-pin")
	case strings.Contains(t, "privacy"):
		return icon("shield")
	case strings.Contains(t, "url") || strings.Contains(t, "link"):
		return icon("link")
	case strings.Contains(t, "entropy"):
		return icon("chart-bar")
	case strings.Contains(t, "payload") || strings.Contains(t, "exploit"):
		return icon("alert-triangle")
	case strings.Contains(t, "apk") || strings.Contains(t, "dex") || strings.Contains(t, "zip"):
		return icon("package")
	default:
		return icon("alert-circle")
	}
}

// iconForRecoveredKey picks a representative icon for a recovered-metadata key
// (e.g. "gps_latitude", "device_model", "url").
func iconForRecoveredKey(key string) string {
	k := strings.ToLower(key)
	switch {
	case strings.Contains(k, "gps") || strings.Contains(k, "lat") || strings.Contains(k, "lon"):
		return icon("map-pin")
	case strings.Contains(k, "url") || strings.Contains(k, "link"):
		return icon("link")
	case strings.Contains(k, "time") || strings.Contains(k, "date"):
		return icon("clock")
	case strings.Contains(k, "camera") || strings.Contains(k, "lens") || strings.Contains(k, "settings"):
		return icon("camera")
	case strings.Contains(k, "screenshot"):
		return icon("device-mobile")
	case strings.Contains(k, "dimension"):
		return icon("image")
	default:
		return icon("info-circle")
	}
}

// buildMediaForensicsSection generates the HTML for Media/Polyglot anomalies.
func (r *HTMLReporter) buildMediaForensicsSection(sb htmlWriter, view HTMLReportView) {
	if len(view.Report.MediaReports) == 0 {
		return
	}

	sb.WriteString(`<section class="section" id="media-forensics">`)
	sb.WriteString(fmt.Sprintf(`<h2 class="section-title">%s <span>Media Forensics & Steganography</span></h2>`, icon("camera")))
	sb.WriteString(`<p class="section-desc">Analysis of embedded threats, polyglots, and recovered data in media files (Images, Audio, PDF)</p>`)

	sb.WriteString(`<div class="media-container">`)

	for _, md := range view.Report.MediaReports {
		sb.WriteString(fmt.Sprintf(`<div class="media-card border-%s">`, md.SeverityClass))

		// Header
		sb.WriteString(`<div class="media-header">`)
		sb.WriteString(fmt.Sprintf(`<span class="badge badge-%s">%s Score %d/100</span>`, md.SeverityClass, iconForRiskClass(md.SeverityClass), md.RiskScore))
		sb.WriteString(fmt.Sprintf(`<span class="media-path mono">%s</span>`, html.EscapeString(md.Path)))
		sb.WriteString(`</div>`)

		// Polyglot Info
		if md.IsPolyglot {
			sb.WriteString(`<div class="media-polyglot">`)
			sb.WriteString(fmt.Sprintf(`<span class="polyglot-primary">%s Primary Format: %s</span>`, iconForMediaFormat(md.PrimaryFormat), strings.ToUpper(md.PrimaryFormat)))
			if len(md.HiddenFormats) > 0 {
				sb.WriteString(`<span class="polyglot-hidden-label">Hidden Formats:</span>`)
				for _, hf := range md.HiddenFormats {
					sb.WriteString(fmt.Sprintf(`<span class="polyglot-hidden">%s %s</span>`, iconForMediaFormat(hf), html.EscapeString(strings.ToUpper(hf))))
				}
			}
			sb.WriteString(`</div>`)
		}

		// Embedded Regions
		if len(md.Regions) > 0 {
			sb.WriteString(`<div class="media-regions">`)
			sb.WriteString(fmt.Sprintf(`<div class="regions-title">%s Detected Embedded Regions</div>`, icon("crosshair")))
			sb.WriteString(`<table class="mc-hardening"><thead><tr><th>Offset</th><th>Size</th><th>Type</th><th>Severity</th><th>Why flagged</th></tr></thead><tbody>`)
			for _, reg := range md.Regions {
				why := reg.Reason
				if why == "" {
					why = "-"
				}
				sb.WriteString(fmt.Sprintf(`<tr><td class="mono">%s</td><td>%s</td><td class="media-region-type">%s %s</td><td><span class="text-%s">%.2f</span></td><td style="font-size:12px; color:#94a3b8; max-width:420px;">%s</td></tr>`,
					reg.Offset, humanSize(int64(reg.Size)), iconForRegionType(reg.Type), html.EscapeString(reg.Type), reg.SeverityClass, reg.Severity, html.EscapeString(why)))
			}
			sb.WriteString(`</tbody></table>`)
			sb.WriteString(`</div>`)
		}

		// Recovered Data
		if len(md.RecoveredData) > 0 {
			sb.WriteString(`<div class="media-recovered">`)
			sb.WriteString(fmt.Sprintf(`<div class="recovered-title">%s Recovered Metadata</div>`, icon("database")))
			sb.WriteString(`<ul class="recovered-list">`)
			keys := make([]string, 0, len(md.RecoveredData))
			for key := range md.RecoveredData {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				sb.WriteString(fmt.Sprintf(`<li>%s<strong>%s:</strong> <span class="mono">%s</span></li>`,
					iconForRecoveredKey(key), html.EscapeString(key), html.EscapeString(md.RecoveredData[key])))
			}
			sb.WriteString(`</ul>`)
			sb.WriteString(`</div>`)
		}

		// Extended forensic detail (full EXIF dump, XMP, PNG chunk table,
		// ICC profile, embedded thumbnail, trailing/overlay data) - present
		// even for files that scored 0 risk, since a full metadata picture
		// (e.g. "which camera took this") is useful on its own.
		if md.Extra != nil {
			writeMediaThumbnail(sb, md.Extra)
			writeMediaTrailingData(sb, md.Extra)
			writeMediaICCProfile(sb, md.Extra)
			writeMediaXMP(sb, md.Extra)
			writeMediaAllTags(sb, md.Extra)
			writeMediaPNGChunks(sb, md.Extra)
		}

		sb.WriteString(`</div>`) // end media-card
	}

	sb.WriteString(`</div></section>`)
}

// writeMediaThumbnail renders the embedded EXIF thumbnail (IFD1), if any, as
// an inline base64 data URI - encoded here at render time, never stored
// pre-encoded, so the size cap on the raw bytes (see media.maxThumbnailBytes)
// is what actually bounds memory/report size.
func writeMediaThumbnail(sb htmlWriter, extra *media.MediaMetadata) {
	if len(extra.Thumbnail) == 0 {
		return
	}
	mime := extra.ThumbnailMime
	if mime == "" {
		mime = "image/jpeg"
	}
	dataURI := "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(extra.Thumbnail)
	sb.WriteString(`<div class="media-thumb">`)
	sb.WriteString(fmt.Sprintf(`<img src="%s" alt="Embedded EXIF thumbnail" loading="lazy" />`, dataURI))
	sb.WriteString(fmt.Sprintf(`<span class="media-thumb-caption">%s Embedded thumbnail (%s)</span>`, icon("image"), humanSize(int64(extra.ThumbnailSizeBytes))))
	sb.WriteString(`</div>`)
}

// writeMediaTrailingData flags bytes found after the file's logical end
// (PNG IEND / JPEG EOI) - a classic overlay/polyglot/steganography signal,
// surfaced whether or not it was already reflected in HiddenFormats.
func writeMediaTrailingData(sb htmlWriter, extra *media.MediaMetadata) {
	td := extra.TrailingData
	if td == nil {
		return
	}
	sb.WriteString(`<div class="media-trailing">`)
	if td.DetectedFormat != "" {
		sb.WriteString(fmt.Sprintf(`%s <strong>Trailing data detected:</strong> %s bytes after logical end (offset 0x%x), identified as <span class="mono">%s</span>`,
			icon("alert-triangle"), humanSize(int64(td.Size)), td.Offset, html.EscapeString(td.DetectedFormat)))
	} else {
		sb.WriteString(fmt.Sprintf(`%s <strong>Trailing data detected:</strong> %s bytes after logical end (offset 0x%x), format not recognized`,
			icon("alert-circle"), humanSize(int64(td.Size)), td.Offset))
	}
	sb.WriteString(`</div>`)
}

// writeMediaICCProfile renders a one-line summary of an embedded ICC color
// profile (PNG iCCP), when its header was parsed successfully.
func writeMediaICCProfile(sb htmlWriter, extra *media.MediaMetadata) {
	icc := extra.ICCProfile
	if icc == nil {
		return
	}
	sb.WriteString(`<div class="media-icc">`)
	sb.WriteString(fmt.Sprintf(`%s <strong>ICC Profile:</strong> %s`, icon("adjustments"), html.EscapeString(icc.ProfileDescription)))
	if icc.ColorSpace != "" {
		sb.WriteString(fmt.Sprintf(` <span class="mono">%s</span>`, html.EscapeString(icc.ColorSpace)))
	}
	if icc.DeviceClass != "" {
		sb.WriteString(fmt.Sprintf(` (%s)`, html.EscapeString(icc.DeviceClass)))
	}
	sb.WriteString(fmt.Sprintf(` - %s`, humanSize(int64(icc.ProfileSize))))
	sb.WriteString(`</div>`)
}

// writeMediaXMP renders parsed XMP (Dublin-Core/Exif/tiff/photoshop) fields
// as a key/value list, collapsible alongside the raw packet for full review.
func writeMediaXMP(sb htmlWriter, extra *media.MediaMetadata) {
	if len(extra.XMP) == 0 {
		return
	}
	sb.WriteString(`<details class="media-xmp">`)
	sb.WriteString(fmt.Sprintf(`<summary>%s XMP Metadata (%d fields)</summary>`, icon("tag"), len(extra.XMP)))
	sb.WriteString(`<ul class="recovered-list">`)
	keys := make([]string, 0, len(extra.XMP))
	for k := range extra.XMP {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteString(fmt.Sprintf(`<li>%s<strong>%s:</strong> <span class="mono">%s</span></li>`,
			icon("info-circle"), html.EscapeString(k), html.EscapeString(extra.XMP[k])))
	}
	sb.WriteString(`</ul>`)
	if extra.XMPRaw != "" {
		sb.WriteString(`<details class="media-xmp-raw"><summary>Raw XMP packet</summary>`)
		sb.WriteString(fmt.Sprintf(`<pre class="mono">%s</pre>`, html.EscapeString(extra.XMPRaw)))
		sb.WriteString(`</details>`)
	}
	sb.WriteString(`</details>`)
}

// writeMediaAllTags renders the complete generic EXIF tag dump (every tag
// the file carries across IFD0/ExifSubIFD/GPS, recognized or not) in a
// collapsible table - the forensic "show me everything" view that a curated
// field list can never fully replace (MakerNote, InteropIFD, etc.).
func writeMediaAllTags(sb htmlWriter, extra *media.MediaMetadata) {
	if len(extra.AllTags) == 0 {
		return
	}
	sb.WriteString(`<details class="media-alltags">`)
	sb.WriteString(fmt.Sprintf(`<summary>%s All EXIF Tags (%d)</summary>`, icon("list-details"), len(extra.AllTags)))
	sb.WriteString(`<table class="mc-hardening"><thead><tr><th>IFD</th><th>Tag</th><th>Name</th><th>Type</th><th>Value</th></tr></thead><tbody>`)
	for _, tg := range extra.AllTags {
		name := tg.Name
		if name == "" {
			name = `<span class="text-muted">unknown</span>`
		} else {
			name = html.EscapeString(name)
		}
		sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td class="mono">%s</td><td>%s</td><td class="mono">%s</td><td class="mono">%s</td></tr>`,
			html.EscapeString(tg.IFD.String()), html.EscapeString(tg.Tag.String()), name, html.EscapeString(tg.Type.String()), html.EscapeString(tg.Value)))
	}
	sb.WriteString(`</tbody></table></details>`)
}

// writeMediaPNGChunks renders the full ordered PNG chunk table - offset,
// type, size, CRC validity - "очень полезно для форензики": a hand-crafted
// or steganography-laden PNG often shows up here as unexpected chunk types,
// suspicious sizes, or a chunk with an invalid CRC.
func writeMediaPNGChunks(sb htmlWriter, extra *media.MediaMetadata) {
	if len(extra.PNGChunks) == 0 {
		return
	}
	sb.WriteString(`<details class="media-pngchunks">`)
	sb.WriteString(fmt.Sprintf(`<summary>%s PNG Chunk Table (%d chunks)</summary>`, icon("box"), len(extra.PNGChunks)))
	sb.WriteString(`<table class="mc-hardening"><thead><tr><th>Offset</th><th>Type</th><th>Size</th><th>CRC</th></tr></thead><tbody>`)
	for _, c := range extra.PNGChunks {
		crcIcon := icon("check-circle-feedback")
		crcClass := "text-low"
		if !c.CRCValid {
			crcIcon = icon("x-circle-feedback")
			crcClass = "text-critical"
		}
		sb.WriteString(fmt.Sprintf(`<tr><td class="mono">0x%x</td><td class="mono">%s</td><td>%s</td><td><span class="%s">%s</span></td></tr>`,
			c.Offset, html.EscapeString(c.Type), humanSize(int64(c.Size)), crcClass, crcIcon))
	}
	sb.WriteString(`</tbody></table></details>`)
}
