package media

import "regexp"

type MediaType string

const (
	TypeUnknown MediaType = "unknown"
	TypeJPEG    MediaType = "jpeg"
	TypePNG     MediaType = "png"
	TypeGIF     MediaType = "gif"
	TypeMP4     MediaType = "mp4"
	TypeMP3     MediaType = "mp3"
	TypeWAV     MediaType = "wav"
	TypeOGG     MediaType = "ogg"
	TypeWEBP    MediaType = "webp"
	TypePDF     MediaType = "pdf"
	TypeDEX     MediaType = "dex"
	TypeZIP     MediaType = "zip"
	TypeAPK     MediaType = "apk"
	TypeICO     MediaType = "ico"
	TypeSVG     MediaType = "svg"
	// Still-image formats that sniffFormat/detector previously missed.
	// TIFF is also the container for most vendor RAWs (DNG/CR2/NEF/ARW/..),
	// which are refined to TypeDNG/TypeRAW by identifyTIFFVariant.
	TypeTIFF MediaType = "tiff"
	TypeBMP  MediaType = "bmp"
	TypeHEIC MediaType = "heic" // HEIF/HEIC stills
	TypeAVIF MediaType = "avif"
	TypeDNG  MediaType = "dng"
	TypeRAW  MediaType = "raw" // generic vendor RAW (CR2/NEF/ARW/RW2/ORF/RAF/..)
	TypePSD  MediaType = "psd"
	TypeJXL  MediaType = "jxl"
)

type SignalType string

const (
	SignalMagic       SignalType = "magic_signature"
	SignalHighEntropy SignalType = "high_entropy"
	SignalPayload     SignalType = "suspicious_payload"
	SignalZIPEOCD     SignalType = "zip_eocd_valid"
	SignalAPKStruct   SignalType = "apk_structure_valid"
	SignalPrivacyLeak SignalType = "privacy_leak"
)

// SignalMetadata provides JSON-safe, typed metadata without interface{} panics
type SignalMetadata struct {
	EntropyScore float64 `json:"entropy_score,omitempty"`
	ZScore       float64 `json:"z_score,omitempty"`
	Evidence     string  `json:"evidence,omitempty"`
	Field        string  `json:"field,omitempty"`
	Priority     int     `json:"priority,omitempty"`
}

type Signal struct {
	Type       SignalType     `json:"type"`
	Value      string         `json:"value"`
	Offset     int            `json:"offset"`
	Length     int            `json:"length"`
	Confidence float64        `json:"confidence"`
	Severity   float64        `json:"severity"`
	Metadata   SignalMetadata `json:"metadata"`
}

func Clamp(v float64) float64 {
	if v < 0.0 {
		return 0.0
	}
	if v > 1.0 {
		return 1.0
	}
	return v
}

type GlobalStats struct {
	MeanEntropy float64 `json:"mean_entropy"`
	Variance    float64 `json:"variance"`
	Peaks       int     `json:"peaks"`
	MaxEntropy  float64 `json:"max_entropy"`
}

type Region struct {
	StartOffset     int      `json:"start_offset"`
	EndOffset       int      `json:"end_offset"`
	Signals         []Signal `json:"signals"`
	DominantSignals []string `json:"dominant_signals"`
	MaxEntropy      float64  `json:"max_entropy"`
	FusedConfidence float64  `json:"fused_confidence"`
	FusedSeverity   float64  `json:"fused_severity"`
	// Benign marks regions fully explained by the file's own format
	// (its own magic signature and/or normal compression entropy).
	Benign bool `json:"benign,omitempty"`
	// Reason explains in plain language why the region is suspicious,
	// or why it is not (when Benign). Set by Scorer.AnnotateRegions.
	Reason string `json:"reason,omitempty"`
}

type PayloadSignature struct {
	Name       string
	Regexp     *regexp.Regexp
	MinLength  int
	Confidence float64
	Severity   float64
}

// Safely compile regexes, panic here is acceptable as it's static init time
var PrecompiledPayloads = []PayloadSignature{
	{
		Name:       "SQLi",
		Regexp:     regexp.MustCompile(`(?i)(UNION\s+SELECT|DROP\s+TABLE|WAITFOR\s+DELAY)`), // Removed SELECT * FROM
		MinLength:  10,
		Confidence: 0.9,
		Severity:   0.8,
	},
	{
		Name:       "XSS",
		Regexp:     regexp.MustCompile(`(?i)(<script[^>]*>|javascript:|onerror\s*=)`),
		MinLength:  10,
		Confidence: 0.9,
		Severity:   0.7,
	},
	{
		Name:       "Command_Inject",
		Regexp:     regexp.MustCompile(`(?i)(;\s*bash\s+-i|\|\s*nc\s+-e|/bin/sh)`),
		MinLength:  7,
		Confidence: 0.95,
		Severity:   0.9,
	},
}

type PrivacySignature struct {
	Field  string
	Regexp *regexp.Regexp
}

var PrecompiledPrivacy = []PrivacySignature{
	{"GPS", regexp.MustCompile(`(?i)(Lat|Lon).*?(\d{1,3}°\s*\d{1,2}'\s*\d{1,2}\.?\d*")`)},
}

type MagicSignature struct {
	Type       MediaType
	Magic      []byte
	Confidence float64
	Priority   int
}

var PrecompiledMagic = []MagicSignature{
	{TypeJPEG, []byte{0xFF, 0xD8, 0xFF}, 1.0, 50},
	{TypePNG, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 1.0, 50},
	{TypeGIF, []byte("GIF87a"), 0.9, 50},
	// MP4 ftyp is NOT here — it must appear at offset 4 per ISO 14496-12,
	// so it's checked with a dedicated offset-4 guard in detector.go to
	// avoid false positives from "ftyp" appearing mid-buffer.
	{TypeMP3, []byte{0x49, 0x44, 0x33}, 0.9, 50},
	{TypeOGG, []byte("OggS"), 1.0, 50},
	{TypePDF, []byte("%PDF-"), 1.0, 50},
	{TypeZIP, []byte("PK\x03\x04"), 1.0, 40},
}
