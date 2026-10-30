package report

// ═══════════════════════════════════════════════════════════════════════════════
// ARTIFACTS VIEW — opt-in section data for HTML / JSON renderers.
// All fields are populated only when EnableArtifacts is true.
// Schema bump → 2.1.
// ═══════════════════════════════════════════════════════════════════════════════

// ArtifactsView is the root structure for the optional Artifacts panel.
type ArtifactsView struct {
	Summary ArtifactsSummary `json:"summary"`
	Items   []ArtifactItem   `json:"items"`
	// AllowExport mirrors the runtime flag so the HTML renderer can
	// decide whether to draw the Export buttons without re-reading
	// CLI options.
	AllowExport bool `json:"allow_export"`
	// NoImageBlur disables blur overlay on possible-sensitive images.
	NoImageBlur bool `json:"no_image_blur"`
}

// ArtifactsSummary aggregates counts for the summary bar.
type ArtifactsSummary struct {
	Total   int            `json:"total"`
	Flagged int            `json:"flagged"`
	ByType  map[string]int `json:"by_type"`
	// ScanNotes records skipped paths and walk errors so coverage gaps
	// stay visible instead of silent. Omitted when empty. R2/R12.
	ScanNotes []string `json:"scan_notes,omitempty"`
}

// ArtifactItem describes a single extracted artifact.
type ArtifactItem struct {
	ID      string  `json:"id"`
	Path    string  `json:"path"`
	Type    string  `json:"type"` // image | model3d | native | font | audio | video | archive | other
	Mime    string  `json:"mime"`
	Size    int64   `json:"size"`
	SHA256  string  `json:"sha256"`
	Entropy float64 `json:"entropy"`

	// Either embed or external — never both.
	EmbeddedDataURI string `json:"embedded_data_uri,omitempty"`
	ExternalPath    string `json:"external_path,omitempty"`

	Image    *ImageArtifact    `json:"image,omitempty"`
	Native   *NativeArtifact   `json:"native,omitempty"`
	ThreeDee *ThreeDeeArtifact `json:"three_d,omitempty"`
	Code     *CodeArtifact     `json:"code,omitempty"`
	Archive  *ArchiveArtifact  `json:"archive,omitempty"`
	Forensic ForensicReport    `json:"forensic"`

	Warnings []string `json:"warnings,omitempty"`
}

// ArchiveArtifact holds the zip/archive-specific list of files.
type ArchiveArtifact struct {
	Files []ArchiveFile `json:"files,omitempty"`
}

// ArchiveFile describes a single file inside an archive.
type ArchiveFile struct {
	Path           string `json:"path"`
	Size           int64  `json:"size"`
	CompressedSize int64  `json:"compressed_size"`
	Modified       string `json:"modified,omitempty"`
}

// ImageArtifact is the image-specific payload.
type ImageArtifact struct {
	Width          int               `json:"width"`
	Height         int               `json:"height"`
	EXIF           map[string]string `json:"exif,omitempty"`
	SensitiveScore float64           `json:"sensitive_score"`
	SensitiveLabel string            `json:"sensitive_label,omitempty"`
}

// NativeArtifact mirrors the .so deep-view structure.
type NativeArtifact struct {
	Arch              string       `json:"arch"`
	Stripped          bool         `json:"stripped"`
	JNIBindings       []JNIBinding `json:"jni_bindings,omitempty"`
	CrackPoints       []string     `json:"crack_points,omitempty"`
	SuspiciousStrings []string     `json:"suspicious_strings,omitempty"`
	AntiSignals       []string     `json:"anti_signals,omitempty"`
	RecoveredStrings  []string     `json:"recovered_strings,omitempty"`
	ScanReportRef     string       `json:"scan_report_ref,omitempty"`
	Score             uint32       `json:"score"`
	Verdict           string       `json:"verdict,omitempty"`
}

// JNIBinding maps a native symbol to its Smali entry-point.
type JNIBinding struct {
	Symbol      string `json:"symbol"`
	SmaliTarget string `json:"smali_target,omitempty"`
}

// ThreeDeeArtifact holds 3D-model metadata.
type ThreeDeeArtifact struct {
	Format    string     `json:"format"` // obj | gltf | glb | fbx | dae | stl | ply | 3ds
	Vertices  int        `json:"vertices,omitempty"`
	Faces     int        `json:"faces,omitempty"`
	BBoxMin   [3]float64 `json:"bbox_min,omitempty"`
	BBoxMax   [3]float64 `json:"bbox_max,omitempty"`
	Triangles int        `json:"triangles,omitempty"`
}

// CodeArtifact holds the deep-inspection payload for JS / HTML / proto /
// JSON / WASM / shell / lua / python and other text-based payloads
// extracted from the APK. The embedded text is stored at the artifact
// level (EmbeddedDataURI) — this struct only carries metadata and the
// list of static-analysis findings the renderer surfaces in the viewer.
type CodeArtifact struct {
	Language     string        `json:"language"`                // js | ts | html | css | proto | json | wasm | lua | python | shell | sql | yaml | toml | ini | text | bundle
	Lines        int           `json:"lines"`                   // line count, 0 for binary (wasm)
	Bytes        int64         `json:"bytes"`                   // logical text size after BOM strip (binary uses raw size)
	Truncated    bool          `json:"truncated,omitempty"`     // true when the embedded preview was capped
	IsMinified   bool          `json:"is_minified,omitempty"`   // single huge line / very low ws ratio
	IsObfuscated bool          `json:"is_obfuscated,omitempty"` // packers / mangled identifiers / hex literal soup
	Score        int           `json:"score"`                   // 0..100, weighted finding severity
	Verdict      string        `json:"verdict"`                 // ok | suspicious | potentially unsafe | possible embedded payload
	Findings     []CodeFinding `json:"findings,omitempty"`
	// Schema info — populated only for proto: proto package, services, RPCs.
	Schema *CodeSchema `json:"schema,omitempty"`
}

// CodeFinding describes a single static-analysis hit inside a code
// artifact. Severity is one of: low | medium | high | critical.
type CodeFinding struct {
	ID       string `json:"id"`             // stable rule id
	Title    string `json:"title"`          // human-readable summary
	Severity string `json:"severity"`       // low|medium|high|critical
	Category string `json:"category"`       // xss | eval | secret | network | proto-bomb | crypto | …
	Line     int    `json:"line,omitempty"` // 1-based
	Column   int    `json:"column,omitempty"`
	Snippet  string `json:"snippet,omitempty"` // up to ~200 chars around the hit
	Rule     string `json:"rule,omitempty"`    // raw pattern / hint
	Detail   string `json:"detail,omitempty"`  // why this matters
}

// CodeSchema captures the high-level shape of a .proto file (or other
// schema-style payloads). All fields are optional.
type CodeSchema struct {
	Package  string            `json:"package,omitempty"`
	Imports  []string          `json:"imports,omitempty"`
	Messages []string          `json:"messages,omitempty"`
	Enums    []string          `json:"enums,omitempty"`
	Services []SchemaServ      `json:"services,omitempty"`
	Options  map[string]string `json:"options,omitempty"`
}

// SchemaServ describes a service block from a .proto schema.
type SchemaServ struct {
	Name string   `json:"name"`
	RPCs []string `json:"rpcs,omitempty"`
}

// ForensicReport summarises detector signals for a single artifact.
//
// Verdict values are restricted to the whitelist and never include "virus":
//
//	ok | suspicious | potentially unsafe | unusual structure | possible embedded payload
type ForensicReport struct {
	MimeMismatch     bool     `json:"mime_mismatch"`
	Truncated        bool     `json:"truncated,omitempty"`
	TrailingData     int      `json:"trailing_data"`
	PolyglotSignals  []string `json:"polyglot_signals,omitempty"`
	SuspiciousChunks []string `json:"suspicious_chunks,omitempty"`
	BadCRC           []string `json:"bad_crc,omitempty"`
	Reasons          []string `json:"reasons,omitempty"`
	Verdict          string   `json:"verdict"`
}
