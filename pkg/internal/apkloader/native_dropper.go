package apkloader

// native_dropper.go — static countermeasures against resource droppers.
//
// An encrypted payload is opaque by definition: no static scanner can read
// it without the key. What static analysis CAN do is surround it:
//
//	import-set hash	identical builders produce identical import sets —
//			clusters samples to one actor/toolchain without any IOC
//	payload sections	a multi-MB high-entropy non-code section (.rsrc)
//			is the encrypted body; name its size and entropy
//	overlay		data past the last section (outside Authenticode) is a
//			classic secondary hiding spot
//	dropper combo	FindResource+LockResource → CreateFile/WriteFile is the
//			resource-to-file extraction shape; with a payload section
//			above it escalates from MEDIUM to HIGH
//	vbinder residue	the XOR-encrypted config/payloads of the VBinder-style
//			staged-dropper family are opaque, but the builder leaves its
//			runtime API names, the Run-key path and cmd.exe delay tricks
//			in the clear — that residue alone identifies the family
//
// None of this decrypts anything. It tells the analyst exactly where the
// body is buried and which builder buried it.

import (
	"bytes"
	"crypto/md5"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/peinspect"
)

// importSetHash is a stable MD5 over the normalized, SORTED import set
// ("dll.func", lowercased). Unlike VirusTotal imphash it is order-insensitive
// on purpose: reordered tables from the same builder still cluster. Do NOT
// present it as a VT imphash — present it as a same-builder correlator.
func importSetHash(imports []string) string {
	norm := make([]string, 0, len(imports))
	for _, imp := range imports {
		n := normalizeImport(imp)
		if n != "" {
			norm = append(norm, n)
		}
	}
	if len(norm) == 0 {
		return ""
	}
	sort.Strings(norm)
	sum := md5.Sum([]byte(strings.Join(norm, ",")))
	return fmt.Sprintf("%x", sum)
}

// normalizeImport unifies the two shapes seen in this package: "func:DLL"
// from the fallback table walker and "DLL.func" from debug/pe.
func normalizeImport(imp string) string {
	imp = strings.TrimSpace(imp)
	if imp == "" {
		return ""
	}
	if i := strings.IndexByte(imp, ':'); i >= 0 {
		fn, dll := imp[:i], imp[i+1:]
		if fn == "" || dll == "" {
			return ""
		}
		return strings.ToLower(dll + "." + fn)
	}
	return strings.ToLower(imp)
}

// payloadSectionAnomaly reports whether a non-executable section looks like
// an embedded encrypted body. Thresholds are deliberately coarse: a 34 MB
// all-0x00 bitmap also trips entropy... no — zeroes have ~0 entropy. Only
// dense, random-looking blobs qualify.
func payloadSectionAnomaly(name string, rawSize uint64, entropy float64) (bool, string) {
	const minBytes = 4 << 20 // 4 MiB: installer payloads also get big, see combo rule
	if rawSize < minBytes || entropy < 7.5 {
		return false, ""
	}
	return true, fmt.Sprintf("embedded encrypted payload in %s (%.1f MB, entropy %.2f/8.0)", name, float64(rawSize)/(1<<20), entropy)
}

// overlaySize returns trailing bytes past the last section's raw data.
func overlaySize(fileLen uint64, sections [][2]uint64) uint64 {
	var end uint64
	for _, s := range sections {
		if off, size := s[0], s[1]; off+size > end {
			end = off + size
		}
	}
	if end >= fileLen {
		return 0
	}
	return fileLen - end
}

// DropperSignalsForPE is the self-contained entry point used by the
// extractor: it parses the image itself so dropper detection works no
// matter which scanner (Rust or pure-Go) produced the main report.
func DropperSignalsForPE(data []byte) []NativeFinding {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer f.Close()
	var imps []string
	if list, err := f.ImportedSymbols(); err == nil {
		imps = list
	} else if list := parsePEImports(data); len(list) > 0 {
		imps = list
	}
	var out []NativeFinding
	emit := func(id, cat, sev, title, desc string) {
		out = append(out, mkFinding(id, cat, sev, title, desc))
	}
	if h := importSetHash(imps); h != "" {
		emit("import-set-hash", "attribution", "low",
			"Import-set hash "+h,
			"identical builders produce identical import sets — cluster samples by this value")
		if fam, bad := badBuilderHash[h]; bad {
			emit("known-builder", "attribution", "high",
				"Known malicious builder: "+fam,
				"import set exactly matches a confirmed-malicious toolchain — no behavior analysis needed")
		}
	}
	funcs := map[string]bool{}
	for _, imp := range imps {
		n := imp
		if i := strings.IndexByte(n, ':'); i >= 0 {
			n = n[:i]
		} else if i := strings.LastIndexByte(n, '.'); i >= 0 {
			n = n[i+1:]
		}
		if n = strings.TrimSpace(n); n != "" {
			funcs[strings.ToLower(n)] = true
		}
	}
	const execBit = 0x20000000 // IMAGE_SCN_MEM_EXECUTE
	payloadAnomaly := false
	spans := make([][2]uint64, 0, len(f.Sections))
	var textRaw, rsrcRaw uint64
	haveSections := len(f.Sections) > 0
	var rsrcSec *pe.Section
	cert := ""
	if meta, err := peinspect.Inspect(data); err == nil {
		cert = meta.Signature.Status
	}
	for _, s := range f.Sections {
		spans = append(spans, [2]uint64{uint64(s.Offset), uint64(s.Size)})
		switch peSectionName(s) {
		case ".text":
			textRaw = uint64(s.Size)
		case ".rsrc":
			rsrcRaw = uint64(s.Size)
			rsrcSec = s
		}
		if s.Characteristics&execBit != 0 {
			continue
		}
		sd, err := s.Data()
		if err != nil || uint64(len(sd)) < 4<<20 {
			continue
		}
		if ok, desc := payloadSectionAnomaly(peSectionName(s), uint64(len(sd)), shannonEntropy(sd)); ok {
			payloadAnomaly = true
			emit("embedded-payload", "packing", "high", "Embedded encrypted payload", desc)
		}
	}
	if ov := overlaySize(uint64(len(data)), spans); ov > 1<<20 && cert != "present" {
		emit("large-overlay", "packing", "medium", "Large overlay data",
			fmt.Sprintf("%.1f MB past the last section with no Authenticode signature — secondary hiding spot", float64(ov)/(1<<20)))
	}
	if fired, sev, detail := dropperComboSeverity(funcs, payloadAnomaly); fired {
		emit("dropper-combo", "malware", sev, "Resource-to-file dropper pattern",
			detail+" — extracts embedded resources to disk and executes them")
	}
	if rsrcSec != nil {
		if raw, err := rsrcSec.Data(); err == nil {
			for _, f := range rsrcVaultSignals(raw, rsrcSec.VirtualAddress) {
				out = append(out, f)
			}
		}
	}
	for _, f := range vbinderSignals(data, textRaw, rsrcRaw, haveSections) {
		out = append(out, f)
	}
	return out
}

// peSectionName renders a debug/pe section name without NUL padding.
func peSectionName(s *pe.Section) string {
	return strings.TrimRight(s.Name, "\x00")
}

// Returns (fired, severity, detail). Alone it is MEDIUM (self-extractors
// exist); with a payload anomaly alongside it becomes HIGH.
func dropperComboSeverity(funcs map[string]bool, hasPayloadAnomaly bool) (bool, string, string) {
	has := func(names ...string) bool {
		for _, n := range names {
			if funcs[strings.ToLower(n)] {
				return true
			}
		}
		return false
	}
	extract := has("FindResourceA", "FindResourceW", "FindResourceExA", "FindResourceExW") &&
		has("LoadResource", "LockResource") &&
		has("SizeofResource")
	write := has("CreateFileA", "CreateFileW", "WriteFile")
	if !extract || !write {
		return false, "", ""
	}
	staging := ""
	if has("GetTempPathA", "GetTempPathW", "GetWindowsDirectoryA", "GetSystemDirectoryA") {
		staging = "; stages through temp/system directories"
	}
	sev := "medium"
	if hasPayloadAnomaly {
		sev = "high"
	}
	return true, sev, fmt.Sprintf("resource-to-file extraction shape (FindResource/LockResource → CreateFile/WriteFile%s)", staging)
}

// vbinderDynAPIs is the plaintext residue of the VBinder-style staged-dropper
// builder (YouTube "crack" stubs: midnight, delta builds and kin). The config
// and payload blobs are XOR-encrypted, but the stub resolves its second-stage
// APIs at runtime via LoadLibraryA/GetProcAddress, so every name sits in the
// clear in .data — alongside the Run-key path and cmd.exe delay tricks.
var vbinderDynAPIs = []string{
	"RtlDecompressBuffer",
	"SHGetSpecialFolderPathA",
	"PathAddBackslashA",
	"PathFindFileNameA",
	"RegCreateKeyExA",
	"RegSetValueExA",
	"RegCloseKey",
	"ShellExecuteA",
	"ntdll.dll",
	"shlwapi.dll",
	"advapi32.dll",
}

const (
	vbinderRunKey  = `Software\Microsoft\Windows\CurrentVersion\Run`
	vbinderDelayEx = "ping -n 3 127.0.0.1"
)

// vbinderSignals matches that residue plus the stub silhouette (a few KB of
// code next to megabytes of .rsrc). Returns nil when nothing matches so the
// battery stays silent on ordinary binaries: the Run-key path and the ping
// delay each appear in legitimate software, so neither fires on its own.
func vbinderSignals(data []byte, textRaw, rsrcRaw uint64, haveSections bool) []NativeFinding {
	var hits []string
	for _, m := range vbinderDynAPIs {
		if bytes.Contains(data, []byte(m)) {
			hits = append(hits, m)
		}
	}
	runKey := bytes.Contains(data, []byte(vbinderRunKey))
	delay := bytes.Contains(data, []byte(vbinderDelayEx))
	stub := haveSections && textRaw > 0 && textRaw < 32<<10 && rsrcRaw >= 1<<20

	has := func(name string) bool {
		for _, h := range hits {
			if h == name {
				return true
			}
		}
		return false
	}
	detail := fmt.Sprintf("runtime-API residue: %s", strings.Join(hits, ", "))
	if runKey {
		detail += "; Run-key persistence path in the clear"
	}
	if delay {
		detail += "; sandbox-delay execution trick (ping-loop)"
	}
	if stub {
		detail += fmt.Sprintf("; stub silhouette (.text %.1f KB, .rsrc %.1f MB)",
			float64(textRaw)/1024, float64(rsrcRaw)/(1<<20))
	}
	switch {
	case stub && has("RtlDecompressBuffer") && len(hits) >= 5 && (runKey || delay):
		return []NativeFinding{mkFinding("vbinder-residue", "malware", "high",
			"VBinder-style staged dropper",
			detail+" — XOR-encrypted RCDATA stages dropped to disk, decompressed via RtlDecompressBuffer, executed/persisted")}
	case len(hits) >= 4 && (runKey || delay || stub):
		return []NativeFinding{mkFinding("vbinder-residue", "malware", "medium",
			"Suspicious staged-dropper residue", detail)}
	case len(hits) >= 2:
		return []NativeFinding{mkFinding("dynapi-cluster", "import", "low",
			"Dynamic API name cluster", detail)}
	default:
		return nil
	}
}

// badBuilderHash maps confirmed-malicious import-set hashes (as produced by
// importSetHash) to a family label. An exact 44-import match is far beyond
// coincidence — it turns attribution clustering into a verdict.
var badBuilderHash = map[string]string{
	// VBinder-style YouTube-"crack" stub: identical on the midnight
	// (J1maNMxOED4DhT82Ir3ZVHbRS40fZ) and delta (delta-crack) builds.
	"35b35c971266b8c601286be105c03606": "VBinder-style YouTube-crack stub (midnight/delta builds)",
}

// rsrcBlob is one numeric-ID resource payload: type ID, name ID and bytes.
type rsrcBlob struct {
	rtype uint32
	name  uint32
	data  []byte
}

// parseRsrcBlobs walks the resource tree inside .rsrc section bytes (raw at
// section RVA rva) down to type → name → language → data. Subdirectory jumps
// are section-relative in well-formed images; some builders emit them as
// absolute RVAs instead, so both are tried (with sanity checks) and the mode
// that validates is kept. Every read is bounds-checked: garbage in, nil out,
// never a panic. Named entries are skipped — the staged-dropper builders use
// numeric RCDATA IDs.
func parseRsrcBlobs(raw []byte, rva uint32) []rsrcBlob {
	type dirEnt struct {
		id  uint32
		sub bool
		off uint32
	}
	readDir := func(at int) ([]dirEnt, bool) {
		if at < 0 || at+16 > len(raw) {
			return nil, false
		}
		named := binary.LittleEndian.Uint16(raw[at+12:])
		ids := binary.LittleEndian.Uint16(raw[at+14:])
		if int(named)+int(ids) > 4096 {
			return nil, false
		}
		ents := make([]dirEnt, 0, int(named)+int(ids))
		for i := 0; i < int(named)+int(ids); i++ {
			o := at + 16 + 8*i
			if o+8 > len(raw) {
				return nil, false
			}
			nm := binary.LittleEndian.Uint32(raw[o:])
			da := binary.LittleEndian.Uint32(raw[o+4:])
			if nm&0x80000000 != 0 {
				continue // named entry: skip
			}
			ents = append(ents, dirEnt{id: nm, sub: da&0x80000000 != 0, off: da & 0x7fffffff})
		}
		return ents, true
	}
	// resolve tries a subdirectory jump in both encodings.
	resolve := func(off uint32) (int, bool) {
		if int(off) < len(raw) {
			if _, ok := readDir(int(off)); ok {
				return int(off), true
			}
		}
		if rel := int64(off) - int64(rva); rel >= 0 && rel < int64(len(raw)) {
			if _, ok := readDir(int(rel)); ok {
				return int(rel), true
			}
		}
		return 0, false
	}
	root, ok := readDir(0)
	if !ok {
		return nil
	}
	var out []rsrcBlob
	for _, te := range root {
		if !te.sub {
			continue
		}
		ta, ok := resolve(te.off)
		if !ok {
			continue
		}
		names, ok := readDir(ta)
		if !ok {
			continue
		}
		for _, ne := range names {
			if !ne.sub {
				continue
			}
			la, ok := resolve(ne.off)
			if !ok {
				continue
			}
			langs, ok := readDir(la)
			if !ok {
				continue
			}
			for _, le := range langs {
				if le.sub {
					continue
				}
				o := int(le.off)
				if o < 0 || o+16 > len(raw) {
					continue
				}
				dataRVA := binary.LittleEndian.Uint32(raw[o:])
				size := binary.LittleEndian.Uint32(raw[o+4:])
				start := int64(dataRVA) - int64(rva)
				if start < 0 || start+int64(size) > int64(len(raw)) || size == 0 {
					continue
				}
				out = append(out, rsrcBlob{rtype: te.id, name: ne.id, data: raw[start : start+int64(size)]})
			}
		}
	}
	return out
}

// rsrcVaultSignals hunts multi-stage RCDATA vaults: two or more megabyte-plus
// blobs of type 10 (RT_RCDATA) plus a small snarled config blob. When the
// config answers to the builder's own XOR-16 self-key scheme the finding is
// HIGH and names the decrypted drop filenames as IOCs; an unconfirmed vault
// stays MEDIUM.
func rsrcVaultSignals(raw []byte, rva uint32) []NativeFinding {
	const rtRCDATA = 10
	var big []rsrcBlob
	var cfg *rsrcBlob
	for _, b := range parseRsrcBlobs(raw, rva) {
		if b.rtype != rtRCDATA {
			continue
		}
		switch {
		case len(b.data) >= 1<<20:
			big = append(big, b)
		// Config gate is deliberately loose (entropy >= 5.0): a measured
		// real VBinder config sits at 5.8, since XOR-ing structured
		// plaintext with a 16-byte repeating key barely randomizes it.
		// tryVBinderConfig below is the strict discriminator.
		case len(b.data) >= 64 && len(b.data) <= 1024 && shannonEntropy(b.data) >= 5.0:
			if c := b; cfg == nil {
				cfg = &c
			}
		}
	}
	if len(big) < 2 {
		return nil
	}
	stages := make([]string, 0, len(big))
	for i, b := range big {
		stages = append(stages, fmt.Sprintf("stage %d: RCDATA/%d, %.1f MB", i+1, b.name, float64(len(b.data))/(1<<20)))
	}
	if cfg != nil {
		if names, key, ok := tryVBinderConfig(cfg.data); ok {
			for i := range big {
				if fm, sz, pok := probeVBinderStage(big[i].data, key); pok {
					stages[i] += fmt.Sprintf(" (%s, %.1f MB)", fm, float64(sz)/(1<<20))
				}
			}
			return []NativeFinding{mkFinding("rcdata-vault", "malware", "high",
				"Decrypted dropper config in RCDATA vault",
				fmt.Sprintf("%d encrypted stages [%s]; config RCDATA/%d decrypts with its own first 16 bytes as XOR-16 key and orders drops of %s",
					len(big), strings.Join(stages, "; "), cfg.name, strings.Join(names, ", ")))}
		}
	}
	return []NativeFinding{mkFinding("rcdata-vault", "packing", "medium",
		"Multi-stage RCDATA vault",
		fmt.Sprintf("%d megabyte-plus RCDATA blobs [%s] with no readable config — staged encrypted payloads",
			len(big), strings.Join(stages, "; ")))}
}

// tryVBinderConfig applies the builder's own config scheme: the first 16
// bytes are the repeating XOR-16 key for the rest. Success is strict — the
// plaintext must carry a drop filename — so random small blobs never qualify.
func tryVBinderConfig(b []byte) (names []string, key []byte, ok bool) {
	if len(b) < 32 || bytes.HasPrefix(b, []byte("MZ")) || bytes.HasPrefix(b, []byte("BM")) {
		return nil, nil, false
	}
	key = b[:16]
	dec := make([]byte, len(b)-16)
	for i, c := range b[16:] {
		dec[i] = c ^ key[i%16]
	}
	if !bytes.Contains(bytes.ToLower(dec), []byte(".exe")) || printableRatio(dec) < 0.6 {
		return nil, nil, false
	}
	seen := map[string]bool{}
	for _, m := range exeNameRe.FindAll(dec, 8) {
		n := string(m)
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil, nil, false
	}
	return names, key, true
}

var exeNameRe = regexp.MustCompile(`(?i)[\w][\w.\- ]{1,64}\.exe`)

// probeVBinderStage reads a stage blob's 8-byte header ([format u32][size
// u32]) through the config key. Format 2 is XPRESS compressed (ntdll
// RtlDecompressBuffer); 0 is written raw.
func probeVBinderStage(blob, key []byte) (format string, size uint32, ok bool) {
	if len(blob) < 8 || len(key) == 0 {
		return "", 0, false
	}
	var h [8]byte
	for i := 0; i < 8; i++ {
		h[i] = blob[i] ^ key[i%len(key)]
	}
	fm := binary.LittleEndian.Uint32(h[0:4])
	sz := binary.LittleEndian.Uint32(h[4:8])
	if fm > 4 || sz == 0 || uint64(sz) > uint64(len(blob)) {
		return "", 0, false
	}
	switch fm {
	case 0:
		format = "raw"
	case 2:
		format = "XPRESS"
	default:
		format = fmt.Sprintf("format-%d", fm)
	}
	return format, sz, true
}

// printableRatio is the fraction of printable-ASCII-or-common-whitespace
// bytes. Encrypted blobs sit near 0.3; decoded configs near 0.9.
func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	n := 0
	for _, c := range b {
		if (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t' || c == 0 {
			n++
		}
	}
	return float64(n) / float64(len(b))
}
