package pipeline

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/internal/apkloader/axml"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/logger"
)

// Offline second-stage container recovery.
//
// Packers ship the next stage as an opaque encrypted blob in assets and
// decrypt it at runtime; static rules see nothing. This pass tries a fixed
// set of offline transforms (no code execution, no artifacts written to
// disk) over high-entropy asset blobs, using the app's own byte-array
// constants — collected by the StringFog evaluator — as candidate keys:
//
//  1. raw zlib inflate;
//  2. single-byte XOR, then inflate;
//  3. header-key scheme (observed in the wild): magic[0:4] marker,
//     key = data[4:8], body = data[8:] XOR key[i%4], optionally XORed again
//     with a candidate key K (body[i] ^= K[i%len(K)]), then inflate.
//
// A transform succeeds when the output starts with a ZIP local header
// ("PK\x03\x04") or a DEX header ("dex\n"). For ZIP payloads the embedded
// AndroidManifest.xml is decoded in memory to name the recovered package and
// its permission profile.

const (
	payloadRecoveryMinSize   = 64 << 10 // 64 KiB
	payloadRecoveryMaxSize   = 512 << 20
	payloadRecoveryMaxFiles  = 64
	payloadRecoveryMaxFound  = 8
	payloadInflateCheckLimit = 1 << 16
	payloadInflateFullLimit  = 512 << 20
)

var payloadKnownMagicPrefixes = [][]byte{
	[]byte("PK\x03\x04"), []byte("dex\n"), []byte("dey\n"),
	[]byte("\x89PNG"), {0xff, 0xd8, 0xff}, {0x1f, 0x8b}, {0x42, 0x4d},
	{0x00, 0x00, 0x00, 0x18}, {0x00, 0x00, 0x00, 0x20}, // ftyp/mp4 boxes
}

func hasKnownMagic(head []byte) bool {
	for _, m := range payloadKnownMagicPrefixes {
		if len(head) >= len(m) && bytes.Equal(head[:len(m)], m) {
			return true
		}
	}
	return false
}

// isLowEntropyHead skips plain text and structured (non-encrypted) content:
// encrypted or compressed data measures close to 8 bits/byte, while text and
// structured binary sit well below. ASCII text alone is also rejected.
func isLowEntropyHead(data []byte) bool {
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	if len(head) == 0 {
		return true
	}
	// Plain-ASCII text: never a container.
	ascii := 0
	for _, b := range head {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b != 0x7f) {
			ascii++
		}
	}
	if ascii*100 >= len(head)*98 {
		return true
	}
	// Shannon entropy in bits/byte over byte values.
	var counts [256]int
	for _, b := range head {
		counts[b]++
	}
	n := float64(len(head))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy < payloadMinHeadEntropy
}

// payloadMinHeadEntropy: encrypted/compressed payloads measure > 7.0; text
// ~4.5-5.5; structured binary (already filtered by magic) below that too.
const payloadMinHeadEntropy = 6.0

// recoverEncryptedPayloads scans extracted assets and unclassified root
// files for encrypted second-stage containers.
func (p *Pipeline) recoverEncryptedPayloads() {
	if p.result == nil {
		return
	}
	root := p.result.TargetDir
	if root == "" {
		return
	}
	keys := p.fogKeys.snapshot()

	found := 0
	inspected := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || found >= payloadRecoveryMaxFound || inspected >= payloadRecoveryMaxFiles {
			return filepath.SkipAll
		}
		if d.IsDir() {
			name := d.Name()
			// Skip the code trees: their content is analyzed elsewhere.
			if strings.HasPrefix(name, "smali") || name == "original" ||
				name == "unknown" || name == "build" || strings.EqualFold(name, "META-INF") {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() < payloadRecoveryMinSize || info.Size() > payloadRecoveryMaxSize {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		// Only asset-like locations: the assets tree and unclassified root files.
		if !strings.HasPrefix(rel, "assets/") && strings.Contains(rel, "/") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		inspected++
		if len(data) < 64 || hasKnownMagic(data) || isLowEntropyHead(data) {
			return nil
		}
		for _, payload := range p.tryRecoverContainer(data, keys) {
			found++
			p.recordRecoveredPayload(rel, data, payload)
			if found >= payloadRecoveryMaxFound {
				break
			}
		}
		return nil
	})
	if found > 0 {
		logger.Warn("offline payload recovery: encrypted second-stage containers identified",
			"count", found, "inspected", inspected)
	}
}

// tryRecoverContainer applies the offline transforms and returns recovered
// payloads (deduplicated).
func (p *Pipeline) tryRecoverContainer(data []byte, keys [][]byte) [][]byte {
	var out [][]byte
	seen := make(map[uint64]struct{}, 4)

	try := func(buf []byte) {
		payload, ok := inflatePrefix(buf)
		if !ok {
			return
		}
		h := fnv64Head(payload)
		if _, dup := seen[h]; dup {
			return
		}
		seen[h] = struct{}{}
		out = append(out, payload)
	}

	// 1. Raw zlib.
	try(data)

	// 2. Single-byte XOR, then inflate. The two-byte zlib-header probe keeps
	// the full-buffer XOR for the ~1/255 candidates that can be a zlib stream.
	x1 := make([]byte, len(data))
	for b := 1; b < 256; b++ {
		if !looksLikeZlib(data[0]^byte(b), data[1]^byte(b)) {
			continue
		}
		for i := range x1 {
			x1[i] = data[i] ^ byte(b)
		}
		try(x1)
	}

	// 3. Header-key scheme: data[0:4] marker, data[4:8] key, body XOR key[i%4].
	if len(data) >= 12 {
		key4 := data[4:8]
		body := make([]byte, len(data)-8)
		for i := range body {
			body[i] = data[i+8] ^ key4[i%4]
		}
		try(body)
		// 3b. Additional XOR layer with the app's own byte-array constants.
		// Again: probe the first two bytes against the zlib header before
		// paying for a whole-buffer XOR.
		layered := make([]byte, len(body))
		for _, k := range keys {
			if len(k) == 0 {
				continue
			}
			if !looksLikeZlib(body[0]^k[0], body[1]^k[1%len(k)]) {
				continue
			}
			for i := range body {
				layered[i] = body[i] ^ k[i%len(k)]
			}
			try(layered)
		}
	}
	return out
}

// looksLikeZlib checks the 2-byte zlib header (CMF=8, FCHECK divisor) —
// a cheap gate that ~1/500 random byte pairs pass.
func looksLikeZlib(b0, b1 byte) bool {
	return b0&0x0f == 8 && (uint16(b0)<<8|uint16(b1))%31 == 0
}

// inflatePrefix validates a zlib stream on the first bytes without committing
// to a full decompression; returns the fully inflated payload when the
// recovered magic matches an APK/DEX container.
func inflatePrefix(buf []byte) ([]byte, bool) {
	if len(buf) < 8 {
		return nil, false
	}
	zr, err := zlib.NewReader(bytes.NewReader(buf))
	if err != nil {
		return nil, false
	}
	defer zr.Close()

	head := make([]byte, payloadInflateCheckLimit)
	n, err := io.ReadFull(zr, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, false
	}
	head = head[:n]
	if !bytes.HasPrefix(head, []byte("PK\x03\x04")) && !bytes.HasPrefix(head, []byte("dex\n")) {
		return nil, false
	}

	// Confirmed container: inflate fully (bounded).
	var full bytes.Buffer
	full.Write(head)
	buf2 := make([]byte, 64<<10)
	for full.Len() < payloadInflateFullLimit {
		n, err := zr.Read(buf2)
		if n > 0 {
			full.Write(buf2[:n])
		}
		if err != nil {
			break
		}
	}
	return full.Bytes(), true
}

// recordRecoveredPayload emits the artifact finding with an in-memory
// summary of the recovered container. The payload itself is never written
// to disk.
func (p *Pipeline) recordRecoveredPayload(rel string, blob, payload []byte) {
	sum := sha256.Sum256(payload)
	detail := "sha256=" + hex.EncodeToString(sum[:])
	switch {
	case bytes.HasPrefix(payload, []byte("PK\x03\x04")):
		detail += describeRecoveredZip(payload)
	case bytes.HasPrefix(payload, []byte("dex\n")):
		detail += " (DEX image, " + itoa(len(payload)) + " bytes)"
	}

	severity := types.SeverityHigh
	p.result.ArtifactFindings = append(p.result.ArtifactFindings, types.ArtifactFinding{
		Path:     rel,
		Severity: severity,
		Reason: "Encrypted second-stage container recovered offline: " + detail +
			". The blob decrypts to an executable image under static transforms; the payload is described in-memory only and was not written to disk.",
	})
	p.result.Stats.TotalMatches++
}

// describeRecoveredZip names the embedded package and its permission profile.
func describeRecoveredZip(payload []byte) string {
	summary := " (ZIP container"
	entries := parseCentralDirectoryFromPayload(payload)
	if len(entries) > 0 {
		// Counted from the central directory: a byte-scan for PK\x03\x04
		// false-positives inside compressed data.
		summary += ", " + itoa(len(entries)) + " entries"
	}
	summary += describeInnerManifestWith(entries, payload)
	return summary + ")"
}

// describeInnerManifest decodes the embedded AndroidManifest.xml (binary
// AXML) in memory and returns the package name plus the permission profile.
func describeInnerManifest(payload []byte) string {
	return describeInnerManifestWith(parseCentralDirectoryFromPayload(payload), payload)
}

func describeInnerManifestWith(entries []recoveredZipEntry, payload []byte) string {
	for _, e := range entries {
		if !strings.EqualFold(e.name, "AndroidManifest.xml") {
			continue
		}
		start := int(e.localOffset)
		if start+30 > len(payload) {
			return ""
		}
		nameLen := int(binary.LittleEndian.Uint16(payload[start+26 : start+28]))
		extraLen := int(binary.LittleEndian.Uint16(payload[start+28 : start+30]))
		dataStart := start + 30 + nameLen + extraLen
		// Slice by the size that matches the stored encoding: the central
		// directory records the COMPRESSED size at i+20 and the uncompressed
		// one at i+24 — slicing deflated data by the uncompressed size runs
		// past the stream into the next entry.
		size := int(e.size)
		if e.compressed {
			size = int(e.compSize)
		}
		end := dataStart + size
		if dataStart > len(payload) || end > len(payload) {
			return ""
		}
		raw := payload[dataStart:end]
		if e.compressed {
			// ZIP entries use raw DEFLATE (no zlib wrapper).
			fr := flate.NewReader(bytes.NewReader(raw))
			inflated, err := io.ReadAll(io.LimitReader(fr, payloadInflateFullLimit))
			fr.Close()
			if err != nil && len(inflated) == 0 {
				return ""
			}
			raw = inflated
		}
		manifest, err := axml.Decode(raw)
		if err != nil || manifest == nil {
			return ""
		}
		permSummary := ""
		if n := len(manifest.Permissions); n > 0 {
			dangerous := make([]string, 0, 6)
			for _, perm := range manifest.Permissions {
				p := strings.TrimPrefix(perm, "android.permission.")
				switch p {
				case "SEND_SMS", "READ_SMS", "WRITE_SMS", "READ_CALL_LOG", "WRITE_CALL_LOG",
					"CALL_PHONE", "READ_PHONE_STATE", "MANAGE_ACCOUNTS", "AUTHENTICATE_ACCOUNTS",
					"SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES",
					"RECEIVE_BOOT_COMPLETED", "FOREGROUND_SERVICE_MEDIA_PROJECTION":
					dangerous = append(dangerous, p)
				}
			}
			permSummary = ", permissions=" + itoa(n)
			if len(dangerous) > 0 {
				permSummary += " (" + strings.Join(dedupStringsSmall(dangerous), ",") + ")"
			}
		}
		return ", package=" + manifest.Package + permSummary
	}
	return ""
}

type recoveredZipEntry struct {
	name        string
	localOffset uint32
	size        uint32 // uncompressed
	compSize    uint32 // compressed (deflated entries)
	compressed  bool
}

// parseCentralDirectoryFromPayload locates the EOCD and parses the central
// directory entries.
func parseCentralDirectoryFromPayload(payload []byte) []recoveredZipEntry {
	off := findCentralDirectory(payload)
	if off < 0 {
		return nil
	}
	return parseCentralDirectory(payload, off)
}

func findCentralDirectory(payload []byte) int {
	// Scan backwards for the EOCD signature "PK\x05\x06"; the comment is
	// allowed to be absent. Bound the scan to the last megabyte.
	const tailLimit = 1 << 20
	floor := len(payload) - tailLimit
	if floor < 0 {
		floor = 0
	}
	for i := len(payload) - 22; i >= floor; i-- {
		if payload[i] == 'P' && payload[i+1] == 'K' && payload[i+2] == 5 && payload[i+3] == 6 {
			size := int(binary.LittleEndian.Uint32(payload[i+12 : i+16]))
			offset := int(binary.LittleEndian.Uint32(payload[i+16 : i+20]))
			if size > 0 && offset+size <= len(payload) {
				return offset
			}
		}
	}
	return -1
}

func parseCentralDirectory(payload []byte, cdOffset int) []recoveredZipEntry {
	var out []recoveredZipEntry
	i := cdOffset
	for i+46 <= len(payload) {
		if !(payload[i] == 'P' && payload[i+1] == 'K' && payload[i+2] == 1 && payload[i+3] == 2) {
			break
		}
		method := binary.LittleEndian.Uint16(payload[i+10 : i+12])
		compSize := binary.LittleEndian.Uint32(payload[i+20 : i+24]) // compressed
		size := binary.LittleEndian.Uint32(payload[i+24 : i+28])     // uncompressed
		nameLen := int(binary.LittleEndian.Uint16(payload[i+28 : i+30]))
		extraLen := int(binary.LittleEndian.Uint16(payload[i+30 : i+32]))
		commentLen := int(binary.LittleEndian.Uint16(payload[i+32 : i+34]))
		localOffset := binary.LittleEndian.Uint32(payload[i+42 : i+46])
		if i+46+nameLen > len(payload) {
			break
		}
		out = append(out, recoveredZipEntry{
			name:        string(payload[i+46 : i+46+nameLen]),
			localOffset: localOffset,
			size:        size,
			compSize:    compSize,
			compressed:  method != 0,
		})
		i += 46 + nameLen + extraLen + commentLen
	}
	return out
}

func dedupStringsSmall(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// fnv64Head hashes a prefix for dedup without hashing full payloads twice.
func fnv64Head(data []byte) uint64 {
	n := len(data)
	if n > 4096 {
		n = 4096
	}
	return fnv64(data[:n]) ^ uint64(len(data))<<32
}
