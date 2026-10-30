package experimental

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// MACH-O / iOS MODULE
// ═══════════════════════════════════════════════════════════════════════════════
//
// A focused Mach-O loader that does NOT depend on debug/macho — we want to
// keep the experimental package self-contained and resilient to the exotic
// flavors that show up in iOS apps (fat binaries, dyld_shared_cache stubs,
// encrypted __TEXT, ARM64e pointer authentication, ...).
//
// Goals:
//   * Identify Mach-O artifacts (.dylib, executables inside .app, frameworks).
//   * Parse load commands enough to surface SDK target, codesign status,
//     encryption, and entitlements presence.
//   * Highlight common iOS hardening / weakness markers
//     (PIE off, stack canaries off, jailbreak-detect strings, FairPlay flag).

// MachOModule implements Module.
type MachOModule struct{}

// NewMachOModule constructs the module.
func NewMachOModule() *MachOModule { return &MachOModule{} }

func (m *MachOModule) ID() string          { return "macho" }
func (m *MachOModule) Name() string        { return "Mach-O / iOS Support" }
func (m *MachOModule) Description() string { return "iOS / macOS Mach-O loader and hardening triage" }
func (m *MachOModule) Aliases() []string   { return []string{"ios", "ipa", "darwin", "1"} }
func (m *MachOModule) Tier() string        { return "experimental" }

// Mach-O magic numbers.
const (
	machoMagic32       uint32 = 0xFEEDFACE
	machoMagic32Cigam  uint32 = 0xCEFAEDFE
	machoMagic64       uint32 = 0xFEEDFACF
	machoMagic64Cigam  uint32 = 0xCFFAEDFE
	machoFatMagic      uint32 = 0xCAFEBABE
	machoFatMagicCigam uint32 = 0xBEBAFECA
)

// Load command identifiers we care about.
const (
	lcSegment         uint32 = 0x1
	lcSegment64       uint32 = 0x19
	lcLoadDylib       uint32 = 0xC
	lcCodeSignature   uint32 = 0x1D
	lcEncryptionInfo  uint32 = 0x21
	lcEncrypt64       uint32 = 0x2C
	lcVersionMinIOS   uint32 = 0x25
	lcVersionMinMacOS uint32 = 0x24
	lcBuildVersion    uint32 = 0x32
	lcMain            uint32 = 0x80000028
)

// MachOFlag bits we surface.
const (
	flagPIE         uint32 = 0x00200000
	flagNoHeapExec  uint32 = 0x01000000
	flagWeakDefines uint32 = 0x00800000
	flagBindsToWeak uint32 = 0x00400000
)

// machoHeader is the in-memory parsed view of the Mach-O header.
type machoHeader struct {
	Magic     uint32
	CPU       uint32
	CPUSub    uint32
	FileType  uint32
	NCmds     uint32
	SizeCmds  uint32
	Flags     uint32
	Is64      bool
	BigEndian bool
}

// machoBriefing is the per-binary triage payload.
type machoBriefing struct {
	Path            string
	Header          machoHeader
	IsFat           bool
	Slices          int
	HasEncryption   bool
	Encrypted       bool
	HasCodeSign     bool
	CodeSignOff     uint32
	CodeSignSize    uint32
	Entitlements    []string
	RawEntitlements string
	HasMain         bool
	PIE             bool
	NoHeapExec      bool
	MinIOS          string
	MinMacOS        string
	BuildPlatform   string
	BuildSDK        string
	Dylibs          []string
	JailbreakHints  []string
	WeakHardening   []string
}

// Run implements Module.Run.
func (m *MachOModule) Run(ctx context.Context, in Input) (*ModuleResult, error) {
	res := &ModuleResult{
		ModuleID:   m.ID(),
		ModuleName: m.Name(),
		Tier:       m.Tier(),
	}

	if in.TargetDir == "" {
		res.Skipped = true
		res.SkipReason = "no target directory"
		return res, nil
	}

	candidates, err := collectMachOCandidates(ctx, in.TargetDir)
	if err != nil {
		return res, err
	}
	res.Bump("candidates", len(candidates))

	if len(candidates) == 0 {
		res.Notes = append(res.Notes,
			"No Mach-O candidates found. Module is intended for .ipa / iOS / macOS bundles.")
		return res, nil
	}

	for _, path := range candidates {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		brief, err := analyzeMachO(path)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			continue
		}
		res.Bump("parsed", 1)
		summarizeBriefing(res, brief, in.TargetDir)
	}

	return res, nil
}

// collectMachOCandidates walks the target directory looking for Mach-O files.
func collectMachOCandidates(ctx context.Context, root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // tolerate transient FS errors
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			// Common iOS bundle dirs are good places to scan.
			return nil
		}
		if shouldInspectAsMachO(path, d) {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// shouldInspectAsMachO returns true when a file should be sniffed for Mach-O.
func shouldInspectAsMachO(path string, d fs.DirEntry) bool {
	name := strings.ToLower(d.Name())
	switch {
	case strings.HasSuffix(name, ".dylib"),
		strings.HasSuffix(name, ".framework"),
		strings.HasSuffix(name, ".bundle"),
		strings.Contains(path, ".app/"),
		strings.Contains(path, ".framework/"),
		strings.Contains(path, "Frameworks/"),
		strings.Contains(path, "PlugIns/"):
		// fall through to magic check
	default:
		// Skip obvious non-binary by extension.
		if strings.HasSuffix(name, ".png") ||
			strings.HasSuffix(name, ".jpg") ||
			strings.HasSuffix(name, ".plist") ||
			strings.HasSuffix(name, ".strings") ||
			strings.HasSuffix(name, ".txt") ||
			strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, ".xml") ||
			strings.HasSuffix(name, ".html") ||
			strings.HasSuffix(name, ".css") ||
			strings.HasSuffix(name, ".js") {
			return false
		}
	}

	// Sniff magic bytes — cheaper than full open in walk if we already filtered.
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	be := binary.BigEndian.Uint32(magic[:])
	le := binary.LittleEndian.Uint32(magic[:])
	switch be {
	case machoMagic32, machoMagic32Cigam, machoMagic64, machoMagic64Cigam,
		machoFatMagic, machoFatMagicCigam:
		return true
	}
	switch le {
	case machoMagic32, machoMagic32Cigam, machoMagic64, machoMagic64Cigam,
		machoFatMagic, machoFatMagicCigam:
		return true
	}
	return false
}

// analyzeMachO parses a Mach-O file into a briefing.
func analyzeMachO(path string) (*machoBriefing, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 8 {
		return nil, errors.New("file too small to be Mach-O")
	}

	brief := &machoBriefing{Path: path}

	magicBE := binary.BigEndian.Uint32(data[:4])
	if magicBE == machoFatMagic || magicBE == machoFatMagicCigam {
		brief.IsFat = true
		// Walk the fat header to count slices and parse the first one.
		offset, count, err := parseFatHeader(data)
		if err != nil {
			return brief, err
		}
		brief.Slices = count
		if offset > 0 && offset < len(data) {
			data = data[offset:]
		} else {
			return brief, errors.New("fat slice offset out of range")
		}
	}

	if len(data) < 28 {
		return brief, errors.New("truncated Mach-O header")
	}

	hdr, hdrSize, err := parseMachOHeader(data)
	if err != nil {
		return brief, err
	}
	brief.Header = hdr
	brief.PIE = hdr.Flags&flagPIE != 0
	brief.NoHeapExec = hdr.Flags&flagNoHeapExec != 0

	// Parse load commands.
	if err := parseLoadCommands(data[hdrSize:], hdr, brief); err != nil {
		return brief, err
	}
	if brief.HasCodeSign && brief.CodeSignOff > 0 && brief.CodeSignSize > 0 {
		keys, rawPlist := parseMachOEntitlements(data, brief.CodeSignOff, brief.CodeSignSize)
		brief.Entitlements = keys
		brief.RawEntitlements = rawPlist
	}
	scanForJailbreakHints(data, brief)
	return brief, nil
}

func parseFatHeader(data []byte) (firstOffset, count int, err error) {
	if len(data) < 8 {
		return 0, 0, errors.New("fat header too short")
	}
	// Fat headers are big-endian regardless of magic.
	nfat := binary.BigEndian.Uint32(data[4:8])
	if nfat == 0 || nfat > 16 {
		return 0, 0, fmt.Errorf("implausible fat slice count: %d", nfat)
	}
	const fatArchSize = 20
	if len(data) < 8+int(nfat)*fatArchSize {
		return 0, 0, errors.New("fat arch table truncated")
	}
	off := binary.BigEndian.Uint32(data[8+8 : 8+12])
	return int(off), int(nfat), nil
}

func parseMachOHeader(data []byte) (machoHeader, int, error) {
	var hdr machoHeader
	magic := binary.LittleEndian.Uint32(data[:4])
	switch magic {
	case machoMagic32:
		hdr.Is64 = false
	case machoMagic64:
		hdr.Is64 = true
	case machoMagic32Cigam:
		hdr.Is64 = false
		hdr.BigEndian = true
	case machoMagic64Cigam:
		hdr.Is64 = true
		hdr.BigEndian = true
	default:
		// Try BE
		bemagic := binary.BigEndian.Uint32(data[:4])
		switch bemagic {
		case machoMagic32, machoMagic32Cigam:
			hdr.BigEndian = true
		case machoMagic64, machoMagic64Cigam:
			hdr.BigEndian = true
			hdr.Is64 = true
		default:
			return hdr, 0, fmt.Errorf("not a Mach-O file (magic=0x%08x)", magic)
		}
	}

	rd := newReader(data, hdr.BigEndian)
	hdr.Magic = rd.u32(0)
	hdr.CPU = rd.u32(4)
	hdr.CPUSub = rd.u32(8)
	hdr.FileType = rd.u32(12)
	hdr.NCmds = rd.u32(16)
	hdr.SizeCmds = rd.u32(20)
	hdr.Flags = rd.u32(24)

	hdrSize := 28
	if hdr.Is64 {
		hdrSize = 32
	}
	return hdr, hdrSize, nil
}

func parseLoadCommands(data []byte, hdr machoHeader, brief *machoBriefing) error {
	rd := newReader(data, hdr.BigEndian)
	off := 0
	for i := uint32(0); i < hdr.NCmds; i++ {
		if off+8 > len(data) {
			return errors.New("load commands truncated")
		}
		cmd := rd.u32(off)
		size := rd.u32(off + 4)
		if size < 8 || off+int(size) > len(data) {
			return fmt.Errorf("invalid load command size %d at offset %d", size, off)
		}
		body := data[off : off+int(size)]
		switch cmd {
		case lcLoadDylib:
			if name := readDylibName(body, hdr.BigEndian); name != "" {
				brief.Dylibs = append(brief.Dylibs, name)
			}
		case lcCodeSignature:
			brief.HasCodeSign = true
			if len(body) >= 16 {
				brief.CodeSignOff = rd.u32At(body, 8)
				brief.CodeSignSize = rd.u32At(body, 12)
			}
		case lcEncryptionInfo, lcEncrypt64:
			brief.HasEncryption = true
			// CryptID is at offset 16 (after cmd, size, cryptoff, cryptsize).
			if len(body) >= 20 {
				cryptID := rd.u32At(body, 16)
				brief.Encrypted = cryptID != 0
			}
		case lcVersionMinIOS:
			if len(body) >= 12 {
				brief.MinIOS = decodeMachOVersion(rd.u32At(body, 8))
			}
		case lcVersionMinMacOS:
			if len(body) >= 12 {
				brief.MinMacOS = decodeMachOVersion(rd.u32At(body, 8))
			}
		case lcBuildVersion:
			if len(body) >= 24 {
				platform := rd.u32At(body, 8)
				brief.BuildPlatform = decodeBuildPlatform(platform)
				brief.BuildSDK = decodeMachOVersion(rd.u32At(body, 16))
			}
		case lcMain:
			brief.HasMain = true
		}
		off += int(size)
	}
	return nil
}

// readDylibName extracts the dylib name string from an LC_LOAD_DYLIB body.
func readDylibName(body []byte, be bool) string {
	if len(body) < 24 {
		return ""
	}
	rd := newReader(nil, be)
	nameOff := rd.u32At(body, 8)
	if int(nameOff) >= len(body) {
		return ""
	}
	raw := body[nameOff:]
	// NUL terminate.
	end := 0
	for end < len(raw) && raw[end] != 0 {
		end++
	}
	return string(raw[:end])
}

func decodeMachOVersion(v uint32) string {
	major := (v >> 16) & 0xFFFF
	minor := (v >> 8) & 0xFF
	patch := v & 0xFF
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

func decodeBuildPlatform(p uint32) string {
	switch p {
	case 1:
		return "macOS"
	case 2:
		return "iOS"
	case 3:
		return "tvOS"
	case 4:
		return "watchOS"
	case 6:
		return "macCatalyst"
	case 7:
		return "iOSSimulator"
	default:
		return fmt.Sprintf("platform-%d", p)
	}
}

// scanForJailbreakHints searches the binary for common JB-detect strings.
func scanForJailbreakHints(data []byte, brief *machoBriefing) {
	hints := []string{
		"/Applications/Cydia.app",
		"/Library/MobileSubstrate/MobileSubstrate.dylib",
		"/bin/bash",
		"/usr/sbin/sshd",
		"/etc/apt",
		"/private/var/lib/apt/",
		"cydia://",
		"checkra1n",
		"unc0ver",
		"taurine",
	}
	seen := make(map[string]bool)
	for _, h := range hints {
		if bytesContains(data, h) {
			if !seen[h] {
				brief.JailbreakHints = append(brief.JailbreakHints, h)
				seen[h] = true
			}
		}
	}
}

func bytesContains(haystack []byte, needle string) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	return strings.Contains(string(haystack), needle)
}

// summarizeBriefing turns a briefing into one or more findings.
func summarizeBriefing(res *ModuleResult, b *machoBriefing, root string) {
	rel, _ := filepath.Rel(root, b.Path)
	if rel == "" {
		rel = b.Path
	}

	// Headline finding for every parsed binary.
	headline := Finding{
		ID:         "macho-overview",
		Title:      "Mach-O binary parsed",
		Severity:   SevInfo,
		Confidence: 1.0,
		File:       rel,
		Description: fmt.Sprintf("CPU=0x%x, NCmds=%d, fat=%v, codesign=%v, encrypted=%v, PIE=%v",
			b.Header.CPU, b.Header.NCmds, b.IsFat, b.HasCodeSign, b.Encrypted, b.PIE),
		Tags:  []string{"macho", "ios", "overview"},
		Extra: map[string]string{},
	}
	if b.MinIOS != "" {
		headline.Extra["min_ios"] = b.MinIOS
	}
	if b.BuildPlatform != "" {
		headline.Extra["build_platform"] = b.BuildPlatform
	}
	if b.BuildSDK != "" {
		headline.Extra["build_sdk"] = b.BuildSDK
	}
	if len(b.Dylibs) > 0 {
		headline.Extra["dylibs"] = fmt.Sprintf("%d", len(b.Dylibs))
	}
	res.AddFinding(headline)

	// Hardening checks.
	if !b.PIE && b.Header.FileType == 2 /* MH_EXECUTE */ {
		res.AddFinding(Finding{
			ID:          "macho-no-pie",
			Title:       "Executable is not PIE",
			Severity:    SevHigh,
			Confidence:  0.95,
			File:        rel,
			Description: "Mach-O executable was linked without MH_PIE — defeats ASLR for the main image.",
			Tags:        []string{"macho", "hardening", "aslr"},
		})
	}
	if b.HasEncryption && !b.Encrypted {
		res.AddFinding(Finding{
			ID:          "macho-decrypted-text",
			Title:       "FairPlay encryption metadata present but cryptid=0",
			Severity:    SevMedium,
			Confidence:  0.85,
			File:        rel,
			Description: "Mach-O carries LC_ENCRYPTION_INFO but the slice is decrypted — likely cracked / repackaged binary.",
			Tags:        []string{"macho", "ios", "fairplay", "piracy"},
		})
	}
	if !b.HasCodeSign {
		res.AddFinding(Finding{
			ID:          "macho-no-codesign",
			Title:       "Mach-O has no code signature",
			Severity:    SevMedium,
			Confidence:  0.8,
			File:        rel,
			Description: "LC_CODE_SIGNATURE missing — file is unsigned or stripped.",
			Tags:        []string{"macho", "codesign"},
		})
	}
	if len(b.JailbreakHints) > 0 {
		res.AddFinding(Finding{
			ID:          "macho-jailbreak-detect",
			Title:       "Jailbreak detection markers present",
			Severity:    SevLow,
			Confidence:  0.7,
			File:        rel,
			Description: "Binary references typical jailbreak indicators — check whether they are part of an anti-tamper routine.",
			Evidence:    b.JailbreakHints,
			Tags:        []string{"macho", "ios", "jailbreak", "anti-tamper"},
		})
	}
	if len(b.Entitlements) > 0 {
		res.AddFinding(Finding{
			ID:          "macho-entitlements-overview",
			Title:       "Mach-O entitlements extracted",
			Severity:    SevInfo,
			Confidence:  1.0,
			File:        rel,
			Description: fmt.Sprintf("Extracted %d entitlements from the code signature.", len(b.Entitlements)),
			Evidence:    b.Entitlements,
			Tags:        []string{"macho", "codesign", "entitlements"},
		})
	}
	if hasTrueValue(b.RawEntitlements, "get-task-allow") {
		res.AddFinding(Finding{
			ID:          "macho-entitlements-debuggable",
			Title:       "Application has get-task-allow enabled",
			Severity:    SevHigh,
			Confidence:  1.0,
			File:        rel,
			Description: "The get-task-allow entitlement is set to true. This permits debuggers to attach, violating secure release constraints.",
			Tags:        []string{"macho", "hardening", "entitlements", "debuggable"},
		})
	}
	if strings.Contains(b.RawEntitlements, "com.apple.private.tcc.allow") {
		res.AddFinding(Finding{
			ID:          "macho-entitlements-tcc-bypass",
			Title:       "TCC bypass entitlement present",
			Severity:    SevHigh,
			Confidence:  0.9,
			File:        rel,
			Description: "The application contains a private com.apple.private.tcc.allow entitlement which may bypass privacy prompts.",
			Tags:        []string{"macho", "entitlements", "tcc"},
		})
	}
	res.Bump("findings", 1+
		boolToInt(!b.PIE && b.Header.FileType == 2)+
		boolToInt(b.HasEncryption && !b.Encrypted)+
		boolToInt(!b.HasCodeSign)+
		boolToInt(len(b.JailbreakHints) > 0)+
		boolToInt(len(b.Entitlements) > 0)+
		boolToInt(hasTrueValue(b.RawEntitlements, "get-task-allow"))+
		boolToInt(strings.Contains(b.RawEntitlements, "com.apple.private.tcc.allow")))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ─── tiny endian-aware reader ──────────────────────────────────────────────

type machoReader struct {
	data []byte
	be   bool
}

func newReader(data []byte, be bool) machoReader { return machoReader{data: data, be: be} }

func (r machoReader) u32(off int) uint32 { return r.u32At(r.data, off) }

func (r machoReader) u32At(buf []byte, off int) uint32 {
	if off+4 > len(buf) {
		return 0
	}
	if r.be {
		return binary.BigEndian.Uint32(buf[off : off+4])
	}
	return binary.LittleEndian.Uint32(buf[off : off+4])
}

// parseMachOEntitlements extracts XML plist entitlements from Code Signature block.
func parseMachOEntitlements(data []byte, off, size uint32) ([]string, string) {
	if off == 0 || size == 0 || off+size > uint32(len(data)) {
		return nil, ""
	}
	sigData := data[off : off+size]
	if len(sigData) < 12 {
		return nil, ""
	}
	// SuperBlob header: magic(4), length(4), count(4)
	magic := binary.BigEndian.Uint32(sigData[0:4])
	if magic != 0xfade0cc0 {
		return nil, ""
	}
	count := binary.BigEndian.Uint32(sigData[8:12])
	if count > 100 { // sanity check
		return nil, ""
	}
	for i := uint32(0); i < count; i++ {
		blobOff := 12 + i*8
		if blobOff+8 > uint32(len(sigData)) {
			break
		}
		blobType := binary.BigEndian.Uint32(sigData[blobOff : blobOff+4])
		blobOffset := binary.BigEndian.Uint32(sigData[blobOff+4 : blobOff+8])
		if blobType == 5 { // CS_SLOT_ENTITLEMENTS = 5
			if blobOffset+8 > uint32(len(sigData)) {
				break
			}
			entBlob := sigData[blobOffset:]
			entMagic := binary.BigEndian.Uint32(entBlob[0:4])
			if entMagic != 0xfade7171 {
				break
			}
			entLen := binary.BigEndian.Uint32(entBlob[4:8])
			if entLen < 8 || entLen > uint32(len(entBlob)) {
				break
			}
			xmlBytes := entBlob[8:entLen]
			xmlStr := string(xmlBytes)
			keys := parseEntitlementsPlist(xmlStr)
			return keys, xmlStr
		}
	}
	return nil, ""
}

var keyRegex = regexp.MustCompile(`<key>([^<]+)</key>`)

// parseEntitlementsPlist extracts key strings from the XML plist.
func parseEntitlementsPlist(plist string) []string {
	matches := keyRegex.FindAllStringSubmatch(plist, -1)
	var keys []string
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 {
			k := strings.TrimSpace(m[1])
			if k != "" && !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// hasTrueValue returns true if a key exists in the XML plist and its value is <true/>.
func hasTrueValue(plist, key string) bool {
	idx := strings.Index(plist, "<key>"+key+"</key>")
	if idx == -1 {
		return false
	}
	sub := plist[idx:]
	nextKey := strings.Index(sub[len("<key>"+key+"</key>"):], "<key>")
	nextTrue := strings.Index(sub, "<true/>")
	if nextTrue != -1 {
		if nextKey == -1 || nextTrue < nextKey+len("<key>"+key+"</key>") {
			return true
		}
	}
	return false
}
