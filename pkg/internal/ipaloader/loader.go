package ipaloader

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Extraction / plist limits (anti-DoS). Tune via the exported vars if a large
// but legitimate bundle trips a guard.
// ═══════════════════════════════════════════════════════════════════════════════

var (
	// MaxPlistSize caps how much of an Info.plist we read into memory.
	MaxPlistSize int64 = 16 << 20 // 16 MiB
	// MaxUncompressedPerFile caps a single decompressed zip entry.
	MaxUncompressedPerFile int64 = 512 << 20 // 512 MiB
	// MaxTotalUncompressed caps the total bytes written during one extraction.
	MaxTotalUncompressed int64 = 2 << 30 // 2 GiB
	// MaxCompressionRatio flags decompression bombs (only applied above 1 MiB).
	MaxCompressionRatio uint64 = 200
)

// IPAMeta holds parsed metadata from Info.plist.
type IPAMeta struct {
	BundleID    string            `json:"bundle_id"`
	Version     string            `json:"version"`
	MinOS       string            `json:"min_os"`
	Permissions map[string]string `json:"permissions,omitempty"`
}

// privacyKeys is the canonical set of iOS privacy usage-description keys we
// surface for the permission audit: the classic set plus the modern ones
// App Store review actually rejects for (tracking/ATT, health, local
// network, calendars, photo-add, ...). Array-valued keys (NSBonjourServices)
// are intentionally absent — asString only reads strings.
var privacyKeys = []string{
	"NSCameraUsageDescription",
	"NSMicrophoneUsageDescription",
	"NSLocationWhenInUseUsageDescription",
	"NSLocationAlwaysAndWhenInUseUsageDescription",
	"NSLocationAlwaysUsageDescription", // legacy
	"NSLocationUsageDescription",       // legacy
	"NSPhotoLibraryUsageDescription",
	"NSPhotoLibraryAddUsageDescription",
	"NSContactsUsageDescription",
	"NSBluetoothAlwaysUsageDescription",
	"NSBluetoothPeripheralUsageDescription", // legacy
	"NSFaceIDUsageDescription",
	"NSUserTrackingUsageDescription", // ATT — App Tracking Transparency
	"NSLocalNetworkUsageDescription",
	"NSHealthShareUsageDescription",
	"NSHealthUpdateUsageDescription",
	"NSCalendarsUsageDescription",
	"NSRemindersUsageDescription",
	"NSMotionUsageDescription",
	"NSSpeechRecognitionUsageDescription",
	"NSAppleMusicUsageDescription",
	"NSSiriUsageDescription",
	"NSVideoSubscriberAccountUsageDescription",
	"NFCReaderUsageDescription",
}

// DetectIPA checks whether the target path is a valid iOS IPA archive.
func DetectIPA(path string) bool {
	r, err := zip.OpenReader(path)
	if err != nil {
		return false
	}
	defer r.Close()

	for _, f := range r.File {
		if strings.HasPrefix(f.Name, "Payload/") && strings.Contains(f.Name, ".app/") {
			return true
		}
	}
	return false
}

// ExtractIPA extracts Info.plist and candidate Mach-O binaries from the IPA into
// destDir. It is hardened against zip-slip, symlink escapes and decompression
// bombs, and honours ctx cancellation between entries.
func ExtractIPA(ctx context.Context, ipaPath, destDir string) error {
	if err := ctx.Err(); err != nil { return err }
	r, err := zip.OpenReader(ipaPath)
	if err != nil {
		return err
	}
	defer r.Close()

	cleanDest := filepath.Clean(destDir) + string(os.PathSeparator)
	var total int64

	for _, f := range r.File {
		if err := ctx.Err(); err != nil {
			return err
		}

		fpath := filepath.Join(destDir, filepath.FromSlash(f.Name))
		if !strings.HasPrefix(filepath.Clean(fpath)+string(os.PathSeparator), cleanDest) {
			slog.Debug("ipa: skipping zip-slip entry", "name", f.Name)
			continue
		}

		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(fpath, 0o755)
			continue
		}

		// Never materialise symlinks: a crafted link can redirect later writes
		// outside destDir or point analysis at arbitrary host files.
		if f.Mode()&os.ModeSymlink != 0 {
			slog.Debug("ipa: skipping symlink entry", "name", f.Name)
			continue
		}

		if !shouldExtract(f.Name) {
			continue
		}

		// Decompression-bomb guards, evaluated before we allocate anything.
		uncompressed := f.UncompressedSize64
		if int64(uncompressed) > MaxUncompressedPerFile {
			slog.Warn("ipa: entry exceeds per-file limit, skipping", "name", f.Name, "size", uncompressed)
			continue
		}
		if uncompressed > 1<<20 && f.CompressedSize64 > 0 && uncompressed/f.CompressedSize64 > MaxCompressionRatio {
			slog.Warn("ipa: entry compression ratio too high, skipping", "name", f.Name, "ratio", uncompressed/f.CompressedSize64)
			continue
		}
		if total+int64(uncompressed) > MaxTotalUncompressed {
			return fmt.Errorf("extraction aborted: total uncompressed size would exceed %d bytes", MaxTotalUncompressed)
		}

		if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}
		// LimitReader is the real ceiling; the header size is only advisory and
		// can be forged, so we cap the actual copy independently.
		data, err := io.ReadAll(contextReader{ctx: ctx, reader: io.LimitReader(rc, MaxUncompressedPerFile+1)})
		rc.Close()
		if err != nil {
			return err
		}
		if int64(len(data)) > MaxUncompressedPerFile {
			slog.Warn("ipa: entry exceeded per-file limit during read, skipping", "name", f.Name)
			continue
		}

		if err := ctx.Err(); err != nil { return err }
		if err := os.WriteFile(fpath, data, 0o644); err != nil {
			return err
		}
		total += int64(len(data))
	}

	return ctx.Err()
}

type contextReader struct {
	ctx context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil { return 0, err }
	return r.reader.Read(p)
}

// shouldExtract keeps the extraction surface small: only Info.plist and likely
// Mach-O carriers (extensionless executables, dylibs, framework binaries).
func shouldExtract(name string) bool {
	lower := strings.ToLower(name)
	base := filepath.Base(lower)
	if strings.HasSuffix(lower, "info.plist") {
		return true
	}
	if strings.HasSuffix(lower, ".dylib") {
		return true
	}
	// Files inside a .framework: only the (extensionless) binary or a dylib.
	if strings.Contains(lower, ".framework/") {
		return !strings.Contains(base, ".") || strings.HasSuffix(base, ".dylib")
	}
	return !strings.Contains(base, ".")
}

// ParseInfoPlist parses Info.plist, supporting XML and binary (bplist00) formats.
func ParseInfoPlist(path string) (*IPAMeta, error) {
	data, err := readFileCapped(path, MaxPlistSize)
	if err != nil {
		return nil, err
	}

	meta := &IPAMeta{Permissions: make(map[string]string)}

	// Route on the document start, not on a substring match anywhere: a
	// binary plist can legitimately CONTAIN "<?xml"/"<plist" inside a stored
	// string, and the old Contains-first order fed such files to the XML
	// parser (silent empty result). Binary always starts at offset 0, so a
	// bplist prefix is authoritative; the Contains fallback only preserves
	// exotic XML with leading comments.
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	trimmed = bytes.TrimPrefix(trimmed, []byte("\xef\xbb\xbf")) // UTF-8 BOM
	switch {
	case bytes.HasPrefix(trimmed, []byte("bplist")):
		parseBinaryPlist(data, meta)
		return meta, nil
	case bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<plist")):
		parseXMLPlist(data, meta)
		return meta, nil
	case bytes.Contains(data, []byte("<?xml")) || bytes.Contains(data, []byte("<plist")):
		parseXMLPlist(data, meta)
		return meta, nil
	default:
		return nil, fmt.Errorf("unknown plist format")
	}
}

func readFileCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// ─────────────────────────────────────────────────────────────────────────────
// XML plist parsing (real streaming decoder, not regex).
// ─────────────────────────────────────────────────────────────────────────────

func parseXMLPlist(data []byte, meta *IPAMeta) {
	root := decodeXMLPlistRoot(data)
	if root == nil {
		return
	}

	meta.BundleID = asString(root, "CFBundleIdentifier")
	meta.Version = asString(root, "CFBundleShortVersionString")
	if meta.Version == "" {
		meta.Version = asString(root, "CFBundleVersion")
	}
	meta.MinOS = asString(root, "MinimumOSVersion")

	for _, k := range privacyKeys {
		if v := asString(root, k); v != "" {
			meta.Permissions[k] = v
		}
	}
}

func asString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// decodeXMLPlistRoot returns the top-level <dict> as a map. Only string values
// are retained; nested dicts/arrays are decoded structurally so key/value
// pairing stays correct even with nested containers.
func decodeXMLPlistRoot(data []byte) map[string]interface{} {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	d.Entity = xml.HTMLEntity

	first, ok := nextStart(d)
	if !ok {
		return nil
	}
	if first.Name.Local == "dict" {
		return decodeDict(d, 0)
	}
	// first is <plist> (or similar wrapper): decode its first child value.
	vs, ok := nextStart(d)
	if !ok {
		return nil
	}
	if v, ok := decodeValue(d, vs, 0).(map[string]interface{}); ok {
		return v
	}
	return nil
}

func nextStart(d *xml.Decoder) (xml.StartElement, bool) {
	for {
		tok, err := d.Token()
		if err != nil {
			return xml.StartElement{}, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t, true
		case xml.EndElement:
			return xml.StartElement{}, false
		}
	}
}

// maxXMLPlistDepth caps <dict> nesting. The bplist parser already guards
// recursion (depth > 32); without a cap here a hostile Info.plist with
// 100k nested dicts exhausts the goroutine stack via decodeDict's recursion.
const maxXMLPlistDepth = 64

// decodeDict assumes the opening <dict> was already consumed.
func decodeDict(d *xml.Decoder, depth int) map[string]interface{} {
	m := make(map[string]interface{})
	for {
		tok, err := d.Token()
		if err != nil {
			return m
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local != "key" {
				_ = d.Skip()
				continue
			}
			key := strings.TrimSpace(textUntilEnd(d))
			vs, ok := nextStart(d)
			if !ok {
				return m
			}
			m[key] = decodeValue(d, vs, depth)
		case xml.EndElement:
			if t.Name.Local == "dict" {
				return m
			}
		}
	}
}

// decodeValue decodes the element whose StartElement was already consumed.
func decodeValue(d *xml.Decoder, start xml.StartElement, depth int) interface{} {
	switch start.Name.Local {
	case "dict":
		if depth+1 > maxXMLPlistDepth {
			_ = d.Skip()
			return nil
		}
		return decodeDict(d, depth+1)
	case "string", "integer", "real", "data", "date":
		return textUntilEnd(d)
	case "true":
		_ = d.Skip()
		return true
	case "false":
		_ = d.Skip()
		return false
	default: // array and anything unexpected
		_ = d.Skip()
		return nil
	}
}

// textUntilEnd concatenates character data until the current element closes.
func textUntilEnd(d *xml.Decoder) string {
	var sb strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			return sb.String()
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			return sb.String()
		}
	}
}

// extractXMLKeyString is retained as a lightweight single-key helper and
// fallback. The primary path is decodeXMLPlistRoot.
func extractXMLKeyString(plist, key string) string {
	root := decodeXMLPlistRoot([]byte(plist))
	if root == nil {
		return ""
	}
	return asString(root, key)
}

// ─────────────────────────────────────────────────────────────────────────────
// Binary plist parsing: structural bplist00 decode with a heuristic fallback.
// ─────────────────────────────────────────────────────────────────────────────

func parseBinaryPlist(data []byte, meta *IPAMeta) {
	if kv, ok := decodeBPlist(data); ok && len(kv) > 0 {
		if v := kv["CFBundleIdentifier"]; v != "" {
			meta.BundleID = v
		}
		if v := kv["CFBundleShortVersionString"]; v != "" {
			meta.Version = v
		} else if v := kv["CFBundleVersion"]; v != "" {
			meta.Version = v
		}
		if v := kv["MinimumOSVersion"]; v != "" {
			meta.MinOS = v
		}
		for _, k := range privacyKeys {
			if v := kv[k]; v != "" {
				meta.Permissions[k] = v
			}
		}
		if meta.BundleID != "" || meta.MinOS != "" || len(meta.Permissions) > 0 {
			return
		}
	}
	// Structural parse failed or yielded nothing usable (e.g. truncated or
	// synthetic payloads) — fall back to the tolerant scanner.
	parseBinaryPlistHeuristic(data, meta)
}

// decodeBPlist parses a well-formed bplist00 and returns the top-level dict's
// string→string entries. ok is false on any structural problem.
func decodeBPlist(data []byte) (kv map[string]string, ok bool) {
	defer func() {
		if recover() != nil {
			kv, ok = nil, false
		}
	}()

	if len(data) < 40 || !bytes.HasPrefix(data, []byte("bplist00")) {
		return nil, false
	}
	trailer := data[len(data)-32:]
	offsetSize := int(trailer[6])
	objRefSize := int(trailer[7])
	numObjects := binary.BigEndian.Uint64(trailer[8:16])
	topObject := binary.BigEndian.Uint64(trailer[16:24])
	tableOffset := binary.BigEndian.Uint64(trailer[24:32])

	if offsetSize < 1 || offsetSize > 8 || objRefSize < 1 || objRefSize > 8 {
		return nil, false
	}
	if numObjects == 0 || numObjects > 5_000_000 || topObject >= numObjects {
		return nil, false
	}
	tableEnd := tableOffset + numObjects*uint64(offsetSize)
	if tableOffset > uint64(len(data)) || tableEnd > uint64(len(data)-32) {
		return nil, false
	}

	offsets := make([]uint64, numObjects)
	for i := uint64(0); i < numObjects; i++ {
		p := tableOffset + i*uint64(offsetSize)
		offsets[i] = readUintBE(data[p : p+uint64(offsetSize)])
	}

	p := &bplistParser{data: data, offsets: offsets, objRefSize: objRefSize, numObjects: numObjects}
	root := p.object(topObject, 0)
	m, isMap := root.(map[string]interface{})
	if !isMap {
		return nil, false
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out, true
}

type bplistParser struct {
	data       []byte
	offsets    []uint64
	objRefSize int
	numObjects uint64
}

func (p *bplistParser) object(idx uint64, depth int) interface{} {
	if depth > 32 || idx >= p.numObjects {
		return nil
	}
	pos := p.offsets[idx]
	if pos >= uint64(len(p.data)) {
		return nil
	}
	marker := p.data[pos]
	high := marker >> 4
	low := marker & 0x0f

	switch high {
	case 0x5: // ASCII string
		n, start := p.sizedCount(low, pos+1)
		if start+n > uint64(len(p.data)) {
			return nil
		}
		return string(p.data[start : start+n])
	case 0x6: // UTF-16BE string
		n, start := p.sizedCount(low, pos+1)
		byteLen := n * 2
		if start+byteLen > uint64(len(p.data)) {
			return nil
		}
		u := make([]uint16, n)
		for i := uint64(0); i < n; i++ {
			u[i] = binary.BigEndian.Uint16(p.data[start+i*2:])
		}
		return string(utf16.Decode(u))
	case 0x7: // UTF-8 string (rare)
		n, start := p.sizedCount(low, pos+1)
		if start+n > uint64(len(p.data)) {
			return nil
		}
		return string(p.data[start : start+n])
	case 0xd: // dict
		n, start := p.sizedCount(low, pos+1)
		keyRefs := start
		valRefs := start + n*uint64(p.objRefSize)
		if valRefs+n*uint64(p.objRefSize) > uint64(len(p.data)) {
			return nil
		}
		m := make(map[string]interface{}, n)
		for i := uint64(0); i < n; i++ {
			kIdx := readUintBE(p.data[keyRefs+i*uint64(p.objRefSize):][:p.objRefSize])
			vIdx := readUintBE(p.data[valRefs+i*uint64(p.objRefSize):][:p.objRefSize])
			key, ok := p.object(kIdx, depth+1).(string)
			if !ok {
				continue
			}
			m[key] = p.object(vIdx, depth+1)
		}
		return m
	default:
		return nil
	}
}

// sizedCount decodes the element count for strings/collections. A low nibble of
// 0xF means the next object is an int giving the real count.
func (p *bplistParser) sizedCount(low byte, pos uint64) (count, next uint64) {
	if low != 0x0f {
		return uint64(low), pos
	}
	if pos >= uint64(len(p.data)) {
		return 0, pos
	}
	intMarker := p.data[pos]
	if intMarker>>4 != 0x1 {
		return 0, pos + 1
	}
	nbytes := uint64(1) << (intMarker & 0x0f)
	start := pos + 1
	if start+nbytes > uint64(len(p.data)) {
		return 0, start
	}
	return readUintBE(p.data[start : start+nbytes]), start + nbytes
}

func readUintBE(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// parseBinaryPlistHeuristic is the tolerant fallback for malformed/synthetic
// bplist payloads: it locates known keys and grabs the next printable run.
func parseBinaryPlistHeuristic(data []byte, meta *IPAMeta) {
	dataStr := string(data)
	keysToFind := append([]string{
		"CFBundleIdentifier",
		"CFBundleShortVersionString",
		"CFBundleVersion",
		"MinimumOSVersion",
	}, privacyKeys...)

	for _, k := range keysToFind {
		idx := strings.Index(dataStr, k)
		if idx == -1 {
			continue
		}
		val := extractNextBinaryString(data, idx+len(k))
		if val == "" || val == k {
			continue
		}
		switch k {
		case "CFBundleIdentifier":
			meta.BundleID = val
		case "CFBundleShortVersionString", "CFBundleVersion":
			if meta.Version == "" {
				meta.Version = val
			}
		case "MinimumOSVersion":
			meta.MinOS = val
		default:
			meta.Permissions[k] = val
		}
	}
}

func extractNextBinaryString(data []byte, start int) string {
	if start >= len(data) {
		return ""
	}
	curr := start
	for curr < len(data) {
		if data[curr] >= 32 && data[curr] <= 126 {
			end := curr
			for end < len(data) && data[end] >= 32 && data[end] <= 126 {
				end++
			}
			if end-curr > 1 {
				return string(data[curr:end])
			}
			curr = end
		} else {
			curr++
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────────
// Permission audit (deterministic ordering + placeholder detection).
// ─────────────────────────────────────────────────────────────────────────────

var placeholderDescriptions = map[string]bool{
	"test": true, "asdf": true, "none": true, "na": true, "n/a": true,
	"xxx": true, "todo": true, "tbd": true, "placeholder": true,
}

// AuditPermissions audits Info.plist permissions for weak/abusable usage
// descriptions. Findings are emitted in a stable, sorted order.
func AuditPermissions(meta *IPAMeta, plistRelPath string) []types.ArtifactFinding {
	keys := make([]string, 0, len(meta.Permissions))
	for k := range meta.Permissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var findings []types.ArtifactFinding
	for _, k := range keys {
		desc := strings.TrimSpace(meta.Permissions[k])
		if len(desc) < 5 || placeholderDescriptions[strings.ToLower(desc)] {
			findings = append(findings, types.ArtifactFinding{
				Path:     plistRelPath,
				Severity: types.SeverityHigh,
				Reason:   fmt.Sprintf("Insecure Permission Description: %s has an empty or trivial explanation (%q). App Store review will reject this.", k, desc),
				Payload:  fmt.Sprintf("%s = %s", k, desc),
				Stages:   []string{"ipa", "permissions", "policy"},
			})
			continue
		}
		findings = append(findings, types.ArtifactFinding{
			Path:     plistRelPath,
			Severity: types.SeverityInfo,
			Reason:   fmt.Sprintf("Permission requested: %s with description: %q", k, desc),
			Payload:  fmt.Sprintf("%s = %s", k, desc),
			Stages:   []string{"ipa", "permissions"},
		})
	}
	return findings
}
