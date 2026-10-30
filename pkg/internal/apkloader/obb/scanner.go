package obb

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ScanResult aggregates everything found inside an OBB / data / cache archive.
type ScanResult struct {
	Path           string            `json:"path"`
	Size           int64             `json:"size"`
	Format         string            `json:"format"`        // "obb", "zip", "data"
	Engine         string            `json:"engine"`        // "unity", "unreal", "godot", "cocos", "unknown"
	EngineVersion  string            `json:"engineVersion"` // e.g. "Unity 2021.3.15f1"
	AssetBundles   []AssetBundleInfo `json:"assetBundles,omitempty"`
	Resources      []ResourceInfo    `json:"resources,omitempty"`
	HiddenPayloads []PayloadFinding  `json:"hiddenPayloads,omitempty"`
	SuspiciousURLs []string          `json:"suspiciousUrls,omitempty"`
	TrackerHints   []string          `json:"trackerHints,omitempty"`
	Warnings       []string          `json:"warnings,omitempty"`
}

// AssetBundleInfo describes a Unity/Unreal asset bundle.
type AssetBundleInfo struct {
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	Engine      string `json:"engine"`
	Version     string `json:"version,omitempty"`     // parsed from header
	Compression string `json:"compression,omitempty"` // lz4, lzma, none
	Encrypted   bool   `json:"encrypted,omitempty"`
}

// ResourceInfo is a generic file entry (texture, audio, model, etc).
type ResourceInfo struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Type       string `json:"type"`       // "texture", "audio", "model", "shader", "script", "unknown"
	FormatHint string `json:"formatHint"` // e.g. "dds", "ogg", "fbx", "lua"
}

// PayloadFinding flags a hidden binary inside an archive.
type PayloadFinding struct {
	Path        string `json:"path"`
	Type        string `json:"type"` // "dex", "so", "elf", "pe", "apk"
	Size        int64  `json:"size"`
	Severity    string `json:"severity"` // "medium" | "high"
	Description string `json:"description"`
}

// Scan opens an OBB, data, or cache archive and performs deep analysis.
func Scan(path string) (*ScanResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	r := &ScanResult{
		Path:   path,
		Size:   info.Size(),
		Format: detectFormat(path),
	}

	z, err := zip.OpenReader(path)
	if err != nil {
		// Not a ZIP — try as raw directory or data dump
		return scanRaw(path, r)
	}
	defer z.Close()

	// Phase 1: inventory + engine fingerprint
	for _, f := range z.File {
		switch {
		case isUnityAssetBundle(f.Name):
			ab := parseUnityAssetBundle(f)
			r.AssetBundles = append(r.AssetBundles, ab)
			if r.Engine == "" || r.Engine == "unknown" {
				r.Engine = "unity"
				if ab.Version != "" {
					r.EngineVersion = ab.Version
				}
			}
		case isUnrealPak(f.Name):
			if r.Engine == "" || r.Engine == "unknown" {
				r.Engine = "unreal"
			}
			ab, entries := parseUnrealPak(f)
			r.AssetBundles = append(r.AssetBundles, ab)
			for _, e := range entries {
				r.Resources = append(r.Resources, ResourceInfo{
					Path:       e.Name,
					Size:       int64(e.UncompressedSize),
					Type:       classifyPakResource(e.Name),
					FormatHint: filepath.Ext(strings.ToLower(e.Name)),
				})
			}
		case isGodotPCK(f.Name):
			if r.Engine == "" || r.Engine == "unknown" {
				r.Engine = "godot"
			}
		}

		// Resource inventory
		if res := classifyResource(f.Name, f.UncompressedSize64); res.Type != "" {
			r.Resources = append(r.Resources, res)
		}

		// Hidden payload detection
		if payload := detectHiddenPayload(f); payload != nil {
			r.HiddenPayloads = append(r.HiddenPayloads, *payload)
		}
	}

	// Phase 2: strings / URL extraction from selected large files
	for _, f := range z.File {
		if f.UncompressedSize64 > 10<<20 { // skip > 10 MB for speed
			continue
		}
		if shouldScanForStrings(f.Name) {
			subr, _ := f.Open()
			if subr != nil {
				extractStrings(subr, r)
				subr.Close()
			}
		}
	}

	if r.Engine == "" {
		r.Engine = "unknown"
	}

	return r, nil
}

// ─────────────────────────────────────────────────────────────────
// DETECTION HELPERS
// ─────────────────────────────────────────────────────────────────

func detectFormat(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".obb":
		return "obb"
	case ".zip", ".data", ".cache":
		return ext[1:]
	default:
		return "archive"
	}
}

func isUnityAssetBundle(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".assets") ||
		strings.HasSuffix(lower, ".unity3d") ||
		strings.HasSuffix(lower, ".bundle") ||
		strings.HasSuffix(lower, ".assetbundle") ||
		strings.HasSuffix(lower, ".ab")
}

func isUnrealPak(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".pak") ||
		strings.HasSuffix(lower, ".utoc") ||
		strings.HasSuffix(lower, ".ucas")
}

func isGodotPCK(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".pck") || strings.HasSuffix(lower, ".zip")
}

func classifyResource(name string, size uint64) ResourceInfo {
	lower := strings.ToLower(name)
	res := ResourceInfo{Path: name, Size: int64(size)}

	switch {
	case strings.HasSuffix(lower, ".png"), strings.HasSuffix(lower, ".jpg"),
		strings.HasSuffix(lower, ".jpeg"), strings.HasSuffix(lower, ".dds"),
		strings.HasSuffix(lower, ".tga"), strings.HasSuffix(lower, ".ktx"):
		res.Type = "texture"
		res.FormatHint = filepath.Ext(lower)[1:]
	case strings.HasSuffix(lower, ".ogg"), strings.HasSuffix(lower, ".mp3"),
		strings.HasSuffix(lower, ".wav"), strings.HasSuffix(lower, ".aac"):
		res.Type = "audio"
		res.FormatHint = filepath.Ext(lower)[1:]
	case strings.HasSuffix(lower, ".fbx"), strings.HasSuffix(lower, ".obj"),
		strings.HasSuffix(lower, ".gltf"), strings.HasSuffix(lower, ".glb"):
		res.Type = "model"
		res.FormatHint = filepath.Ext(lower)[1:]
	case strings.HasSuffix(lower, ".shader"), strings.HasSuffix(lower, ".cginc"):
		res.Type = "shader"
	case strings.HasSuffix(lower, ".lua"), strings.HasSuffix(lower, ".js"),
		strings.HasSuffix(lower, ".ts"):
		res.Type = "script"
		res.FormatHint = filepath.Ext(lower)[1:]
	default:
		if size > 1<<20 { // > 1 MB unknown = likely resource
			res.Type = "unknown"
		} else {
			return ResourceInfo{} // skip small unknown
		}
	}
	return res
}

func detectHiddenPayload(f *zip.File) *PayloadFinding {
	lower := strings.ToLower(f.Name)

	// DEX in unexpected place
	if strings.HasSuffix(lower, ".dex") && !strings.Contains(lower, "classes") {
		return &PayloadFinding{
			Path:        f.Name,
			Type:        "dex",
			Size:        int64(f.UncompressedSize64),
			Severity:    "high",
			Description: "hidden DEX file inside OBB/data",
		}
	}

	// SO in non-lib/ path
	if strings.HasSuffix(lower, ".so") && !strings.Contains(lower, "/lib/") && !strings.Contains(lower, "lib/") {
		return &PayloadFinding{
			Path:        f.Name,
			Type:        "so",
			Size:        int64(f.UncompressedSize64),
			Severity:    "medium",
			Description: "native library outside lib/ directory",
		}
	}

	// ELF / PE headers inside raw data
	if strings.HasSuffix(lower, ".dat") || strings.HasSuffix(lower, ".raw") || strings.HasSuffix(lower, ".bin") {
		if f.UncompressedSize64 > 4096 {
			rc, err := f.Open()
			if err == nil {
				defer rc.Close()
				buf := make([]byte, 4)
				n, _ := io.ReadFull(rc, buf)
				if n == 4 {
					magic := binary.BigEndian.Uint32(buf)
					if magic == 0x7F454C46 { // ELF
						return &PayloadFinding{
							Path:        f.Name,
							Type:        "elf",
							Size:        int64(f.UncompressedSize64),
							Severity:    "high",
							Description: "ELF binary disguised as .dat/.raw/.bin",
						}
					}
					if buf[0] == 'M' && buf[1] == 'Z' { // PE
						return &PayloadFinding{
							Path:        f.Name,
							Type:        "pe",
							Size:        int64(f.UncompressedSize64),
							Severity:    "high",
							Description: "PE/Windows binary disguised as data file",
						}
					}
				}
			}
		}
	}

	return nil
}

func shouldScanForStrings(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".json") ||
		strings.HasSuffix(lower, ".xml") ||
		strings.HasSuffix(lower, ".txt") ||
		strings.HasSuffix(lower, ".lua") ||
		strings.HasSuffix(lower, ".js") ||
		strings.HasSuffix(lower, ".asset") ||
		strings.HasSuffix(lower, ".dat") ||
		strings.HasSuffix(lower, ".config") ||
		strings.HasSuffix(lower, ".ini")
}

// ─────────────────────────────────────────────────────────────────
// UNITY ASSET BUNDLE PARSER
// ─────────────────────────────────────────────────────────────────

func parseUnityAssetBundle(f *zip.File) AssetBundleInfo {
	ab := AssetBundleInfo{
		Path:   f.Name,
		Size:   int64(f.UncompressedSize64),
		Engine: "unity",
	}

	rc, err := f.Open()
	if err != nil {
		return ab
	}
	defer rc.Close()

	// Read first 128 bytes for header detection
	header := make([]byte, 128)
	n, _ := io.ReadFull(rc, header)
	if n < 16 {
		return ab
	}

	// UnityFS format (newer bundles)
	if bytes.HasPrefix(header[:8], []byte("UnityFS")) {
		ab.Compression = "lz4"
		// version string follows UnityFS\x00
		if idx := bytes.IndexByte(header[8:], 0); idx > 0 && idx < 32 {
			ver := string(header[8 : 8+idx])
			ab.Version = ver
		}
		return ab
	}

	// Legacy Unity raw format
	if bytes.HasPrefix(header[:6], []byte("Unity")) {
		ab.Compression = "none"
		return ab
	}

	// Some bundles start with compressed data (check for gzip/lzma magic)
	if len(header) > 2 && header[0] == 0x1F && header[1] == 0x8B {
		ab.Compression = "gzip"
	} else if len(header) > 4 && binary.LittleEndian.Uint32(header[:4]) == 0x5D000080 {
		ab.Compression = "lzma"
	}

	return ab
}

// ─────────────────────────────────────────────────────────────────
// UNREAL ENGINE .pak PARSER
// ─────────────────────────────────────────────────────────────────

const pakMagic = 0x5A6F12E1

type pakInfo struct {
	Version     uint32
	IndexOffset uint64
	IndexSize   uint64
	IndexHash   [20]byte
	Encrypted   bool
}

type pakEntry struct {
	Name              string
	Offset            uint64
	Size              uint64
	UncompressedSize  uint64
	CompressionMethod uint32
	Hash              [20]byte
	BlockCount        int
}

func parseUnrealPak(f *zip.File) (AssetBundleInfo, []pakEntry) {
	ab := AssetBundleInfo{
		Path:   f.Name,
		Size:   int64(f.UncompressedSize64),
		Engine: "unreal",
	}

	rc, err := f.Open()
	if err != nil {
		return ab, nil
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil || len(data) < 64 {
		return ab, nil
	}

	info, err := readPakInfo(data)
	if err != nil {
		return ab, nil
	}

	ab.Version = fmt.Sprintf("Pak v%d", info.Version)
	ab.Compression = "pak"
	if info.Encrypted {
		ab.Encrypted = true
	}

	entries, err := readPakTOC(data, info)
	if err != nil {
		return ab, nil
	}
	return ab, entries
}

func readPakInfo(data []byte) (*pakInfo, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("too small for pak")
	}
	// Search for magic from the end backwards (FPakInfo lives at EOF)
	for i := len(data) - 4; i >= 0; i-- {
		if binary.LittleEndian.Uint32(data[i:i+4]) == pakMagic {
			if i+8 > len(data) {
				continue
			}
			version := binary.LittleEndian.Uint32(data[i+4 : i+8])
			hdrSize := pakHeaderSize(version)
			if i+hdrSize > len(data) {
				continue
			}
			info := &pakInfo{Version: version}
			off := i + 8
			info.IndexOffset = binary.LittleEndian.Uint64(data[off : off+8])
			off += 8
			info.IndexSize = binary.LittleEndian.Uint64(data[off : off+8])
			off += 8
			copy(info.IndexHash[:], data[off:off+20])
			off += 20
			if off < len(data) {
				info.Encrypted = data[off] != 0
			}
			if info.IndexOffset+info.IndexSize <= uint64(len(data)) {
				return info, nil
			}
		}
	}
	return nil, fmt.Errorf("pak magic not found")
}

func pakHeaderSize(version uint32) int {
	base := 45 // magic+version+offset+size+hash+encrypted
	if version >= 4 {
		// compression methods array (32 × 32 bytes) + guid + padding
		return base + 1024 + 16
	}
	return base
}

func readPakTOC(data []byte, info *pakInfo) ([]pakEntry, error) {
	if info.IndexOffset+info.IndexSize > uint64(len(data)) {
		return nil, fmt.Errorf("index out of bounds")
	}
	buf := data[info.IndexOffset : info.IndexOffset+info.IndexSize]
	r := bytes.NewReader(buf)

	// Mount point (FString: int32 length)
	mpLen, err := readPakStringLength(r)
	if err != nil {
		return nil, err
	}
	if mpLen != 0 {
		skip := mpLen
		if skip < 0 {
			skip = -skip * 2
		}
		r.Seek(int64(skip), io.SeekCurrent)
	}

	var count uint32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return nil, err
	}

	entries := make([]pakEntry, 0, count)
	for i := uint32(0); i < count; i++ {
		nameLen, err := readPakStringLength(r)
		if err != nil {
			break
		}
		var name string
		if nameLen > 0 {
			b := make([]byte, nameLen)
			if _, err := io.ReadFull(r, b); err != nil {
				break
			}
			name = string(b)
		} else if nameLen < 0 {
			b := make([]byte, -nameLen*2)
			if _, err := io.ReadFull(r, b); err != nil {
				break
			}
			runes := make([]rune, 0, -nameLen)
			for j := 0; j < len(b); j += 2 {
				if j+1 < len(b) {
					ru := rune(binary.LittleEndian.Uint16(b[j : j+2]))
					if ru == 0 {
						break
					}
					runes = append(runes, ru)
				}
			}
			name = string(runes)
		}

		var entry pakEntry
		entry.Name = name
		binary.Read(r, binary.LittleEndian, &entry.Offset)
		binary.Read(r, binary.LittleEndian, &entry.Size)
		binary.Read(r, binary.LittleEndian, &entry.UncompressedSize)
		binary.Read(r, binary.LittleEndian, &entry.CompressionMethod)
		io.ReadFull(r, entry.Hash[:])

		if info.Version >= 3 && entry.CompressionMethod != 0 {
			var blockCount uint32
			binary.Read(r, binary.LittleEndian, &blockCount)
			entry.BlockCount = int(blockCount)
			r.Seek(int64(blockCount)*16, io.SeekCurrent)
		}
		if info.Version >= 2 {
			var flags uint32
			binary.Read(r, binary.LittleEndian, &flags)
			_ = flags
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func readPakStringLength(r io.Reader) (int, error) {
	var length int32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return 0, err
	}
	return int(length), nil
}

func classifyPakResource(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".uasset"), strings.HasSuffix(lower, ".umap"):
		return "unreal-asset"
	case strings.HasSuffix(lower, ".uexp"):
		return "unreal-export"
	case strings.HasSuffix(lower, ".ubulk"):
		return "unreal-bulk"
	case strings.HasSuffix(lower, ".png"), strings.HasSuffix(lower, ".jpg"),
		strings.HasSuffix(lower, ".dds"), strings.HasSuffix(lower, ".tga"):
		return "texture"
	case strings.HasSuffix(lower, ".ogg"), strings.HasSuffix(lower, ".wav"),
		strings.HasSuffix(lower, ".mp3"):
		return "audio"
	case strings.HasSuffix(lower, ".fbx"), strings.HasSuffix(lower, ".obj"):
		return "model"
	case strings.HasSuffix(lower, ".ini"), strings.HasSuffix(lower, ".json"),
		strings.HasSuffix(lower, ".xml"):
		return "config"
	default:
		return "unknown"
	}
}

// ─────────────────────────────────────────────────────────────────
// STRINGS / URL EXTRACTION
// ─────────────────────────────────────────────────────────────────

func extractStrings(r io.ReadCloser, result *ScanResult) {
	// Read up to 4 MB for string scanning
	const maxScan = 4 << 20
	buf := make([]byte, maxScan)
	n, _ := io.ReadFull(r, buf)
	data := buf[:n]

	// Find printable strings of length >= 8
	var current strings.Builder
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c >= 0x20 && c < 0x7F {
			current.WriteByte(c)
		} else {
			if current.Len() >= 8 {
				s := current.String()
				analyzeString(s, result)
			}
			current.Reset()
		}
	}
	if current.Len() >= 8 {
		analyzeString(current.String(), result)
	}
}

func analyzeString(s string, result *ScanResult) {
	lower := strings.ToLower(s)

	// URL / endpoint detection
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		result.SuspiciousURLs = append(result.SuspiciousURLs, s)
	}

	// Tracker / ad SDK hints
	trackerPatterns := []string{
		"googleads", "admob", "facebook.com/audience", "appsflyer",
		"adjust.com", "tapjoy", "chartboost", "ironsource",
		"unityads", "vungle", "applovin", "adcolony",
		"firebase", "crashlytics", "analytics",
		"telemetry", "tracking", "beacon",
	}
	for _, pat := range trackerPatterns {
		if strings.Contains(lower, pat) {
			result.TrackerHints = append(result.TrackerHints, fmt.Sprintf("%s: %s", pat, s))
		}
	}
}

// ─────────────────────────────────────────────────────────────────
// RAW (NON-ZIP) SCANNER
// ─────────────────────────────────────────────────────────────────

func scanRaw(path string, r *ScanResult) (*ScanResult, error) {
	// Try to detect engine from file structure (e.g. .obb renamed from data)
	data, err := os.ReadFile(path)
	if err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("cannot read raw file: %v", err))
		return r, nil
	}

	if len(data) > 7 && bytes.HasPrefix(data, []byte("UnityFS")) {
		r.Engine = "unity"
		r.Format = "unity-assetbundle"
		r.AssetBundles = append(r.AssetBundles, AssetBundleInfo{
			Path:        path,
			Size:        int64(len(data)),
			Engine:      "unity",
			Compression: "lz4",
		})
		return r, nil
	}

	// Check for Godot PCK
	if len(data) > 4 {
		magic := binary.LittleEndian.Uint32(data[:4])
		if magic == 0x43504447 || magic == 0x47445043 { // "GDPC" / "CPDG"
			r.Engine = "godot"
			r.Format = "godot-pck"
			return r, nil
		}
	}

	r.Warnings = append(r.Warnings, "unrecognized raw data format")
	return r, nil
}
