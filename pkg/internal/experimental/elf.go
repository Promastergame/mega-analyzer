package experimental

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ELF / LINUX HARDENING TRIAGE MODULE
// ═══════════════════════════════════════════════════════════════════════════════
//
// A focused, dependency-free ELF loader that parses 32-bit and 64-bit ELF binaries
// (.so shared libraries and executables) to audit their compilation and hardening posture:
//
//   * PIE (Position Independent Executable): Checks if e_type is ET_DYN vs ET_EXEC.
//   * DEP/NX (Executable Stack): Parses PT_GNU_STACK and alerts if flags allow execution.
//   * RELRO (Read-Only Relocations): Parses PT_GNU_RELRO and PT_DYNAMIC to check for Full, Partial, or No RELRO.
//   * Stack Canary (SSP): Sniffs binary symbols for `__stack_chk_fail` or `__stack_chk_guard`.
//   * Fortify Source: Checks for usage of hardened `_chk` functions.
//   * Insecure RPATH/RUNPATH: Parses DT_RPATH/DT_RUNPATH and flags entries pointing to '.' or '/tmp'.

// ELFModule implements Module.
type ELFModule struct{}

// NewELFModule constructs the module.
func NewELFModule() *ELFModule { return &ELFModule{} }

func (m *ELFModule) ID() string   { return "elf" }
func (m *ELFModule) Name() string { return "ELF / Linux Hardening Triage" }
func (m *ELFModule) Description() string {
	return "Triage security and compilation hardening for ELF / .so binaries"
}
func (m *ELFModule) Aliases() []string { return []string{"so", "linux", "5"} }
func (m *ELFModule) Tier() string      { return "experimental" }

// ELF magic bytes.
var elfMagic = []byte{0x7F, 'E', 'L', 'F'}

// ELF dynamic tags.
const (
	dtNull    uint64 = 0
	dtNeeded  uint64 = 1
	dtStrTab  uint64 = 5
	dtRpath   uint64 = 15
	dtBindNow uint64 = 24
	dtFlags   uint64 = 30
	dtRunpath uint64 = 29
	dtFlags1  uint64 = 0x6ffffffb
)

// Program header types.
const (
	ptDynamic  uint32 = 2
	ptGnuStack uint32 = 0x6474e551
	ptGnuRelro uint32 = 0x6474e552
)

// ELF header fields.
type elfHeader struct {
	Class     byte // 1 = 32-bit, 2 = 64-bit
	Data      byte // 1 = Little Endian, 2 = Big Endian
	Type      uint16
	Machine   uint16
	PhOff     uint64
	PhNum     uint16
	PhEntSize uint16
}

type progHeader struct {
	Type   uint32
	Flags  uint32
	Offset uint64
	Vaddr  uint64
	Memsz  uint64
	Filesz uint64
}

type elfBriefing struct {
	Path            string
	Header          elfHeader
	PIE             bool
	HasNX           bool
	NXEnabled       bool
	HasRelro        bool
	FullRelro       bool
	StackCanary     bool
	FortifyCount    int
	Rpaths          []string
	Runpaths        []string
	InsecureRpath   bool
	InsecureRunpath bool
}

// Run implements Module.Run.
func (m *ELFModule) Run(ctx context.Context, in Input) (*ModuleResult, error) {
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

	candidates, err := collectELFCandidates(ctx, in.TargetDir)
	if err != nil {
		return res, err
	}
	res.Bump("candidates", len(candidates))

	if len(candidates) == 0 {
		res.Notes = append(res.Notes, "No ELF / .so candidates found.")
		return res, nil
	}

	for _, path := range candidates {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		brief, err := analyzeELF(path)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			continue
		}
		res.Bump("parsed", 1)
		summarizeELFBriefing(res, brief, in.TargetDir)
	}

	return res, nil
}

func collectELFCandidates(ctx context.Context, root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if shouldInspectAsELF(path, d) {
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

func shouldInspectAsELF(path string, d fs.DirEntry) bool {
	name := strings.ToLower(d.Name())
	// Quick extension filter
	switch {
	case strings.HasSuffix(name, ".so"),
		strings.HasSuffix(name, ".bin"),
		strings.HasSuffix(name, ".elf"),
		!strings.Contains(name, "."): // Executables
		// Proceed to magic byte check
	default:
		return false
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return bytes.Equal(magic[:], elfMagic)
}

func analyzeELF(path string) (*elfBriefing, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 52 {
		return nil, errors.New("file too small to be ELF")
	}

	brief := &elfBriefing{Path: path}

	// Parse ELF Header
	hdr, err := parseELFHeader(data)
	if err != nil {
		return nil, err
	}
	brief.Header = hdr

	// Shared library (.so) or PIE binary has type ET_DYN (3).
	// Static or non-PIE executable has type ET_EXEC (2).
	brief.PIE = hdr.Type == 3

	// Read Program Headers
	phs, err := parseProgHeaders(data, hdr)
	if err != nil {
		return brief, fmt.Errorf("parse program headers: %v", err)
	}

	// Process stack and RELRO
	var dynOffset, dynSize uint64
	for _, ph := range phs {
		switch ph.Type {
		case ptGnuStack:
			brief.HasNX = true
			// Flag PF_X (1) indicates executable stack
			brief.NXEnabled = (ph.Flags & 1) == 0
		case ptGnuRelro:
			brief.HasRelro = true
		case ptDynamic:
			dynOffset = ph.Offset
			dynSize = ph.Filesz
		}
	}

	// Dynamic Section details
	if dynOffset > 0 && dynSize > 0 {
		parseDynamicSection(data, dynOffset, dynSize, phs, brief)
	}

	// Fast and resilient scanner for stack canaries and fortify checks
	checkSSPAndFortify(data, brief)

	return brief, nil
}

func parseELFHeader(data []byte) (elfHeader, error) {
	var hdr elfHeader
	if !bytes.Equal(data[:4], elfMagic) {
		return hdr, errors.New("not an ELF file")
	}
	hdr.Class = data[4]
	hdr.Data = data[5]

	if hdr.Class != 1 && hdr.Class != 2 {
		return hdr, fmt.Errorf("invalid ELF class: %d", hdr.Class)
	}
	if hdr.Data != 1 && hdr.Data != 2 {
		return hdr, fmt.Errorf("invalid ELF endianness: %d", hdr.Data)
	}

	be := hdr.Data == 2
	rd := newELFReader(data, be)

	hdr.Type = rd.u16(16)
	hdr.Machine = rd.u16(18)

	if hdr.Class == 1 { // 32-bit
		hdr.PhOff = uint64(rd.u32(28))
		hdr.PhEntSize = rd.u16(42)
		hdr.PhNum = rd.u16(44)
	} else { // 64-bit
		if len(data) < 64 {
			return hdr, errors.New("truncated 64-bit ELF header")
		}
		hdr.PhOff = rd.u64(32)
		hdr.PhEntSize = rd.u16(54)
		hdr.PhNum = rd.u16(56)
	}

	return hdr, nil
}

func parseProgHeaders(data []byte, hdr elfHeader) ([]progHeader, error) {
	if hdr.PhNum == 0 {
		return nil, nil
	}
	if hdr.PhOff >= uint64(len(data)) {
		return nil, errors.New("program header offset out of bounds")
	}

	be := hdr.Data == 2
	rd := newELFReader(data, be)
	phs := make([]progHeader, 0, hdr.PhNum)
	offset := int(hdr.PhOff)

	for i := 0; i < int(hdr.PhNum); i++ {
		if offset+int(hdr.PhEntSize) > len(data) {
			return nil, errors.New("program header table truncated")
		}
		curr := data[offset : offset+int(hdr.PhEntSize)]
		var ph progHeader
		if hdr.Class == 1 { // 32-bit
			ph.Type = rd.u32At(curr, 0)
			ph.Offset = uint64(rd.u32At(curr, 4))
			ph.Vaddr = uint64(rd.u32At(curr, 8))
			ph.Filesz = uint64(rd.u32At(curr, 16))
			ph.Memsz = uint64(rd.u32At(curr, 20))
			ph.Flags = rd.u32At(curr, 24)
		} else { // 64-bit
			ph.Type = rd.u32At(curr, 0)
			ph.Flags = rd.u32At(curr, 4)
			ph.Offset = rd.u64At(curr, 8)
			ph.Vaddr = rd.u64At(curr, 16)
			ph.Filesz = rd.u64At(curr, 32)
			ph.Memsz = rd.u64At(curr, 40)
		}
		phs = append(phs, ph)
		offset += int(hdr.PhEntSize)
	}

	return phs, nil
}

func parseDynamicSection(data []byte, offset, size uint64, phs []progHeader, brief *elfBriefing) {
	if offset+size > uint64(len(data)) {
		return
	}
	be := brief.Header.Data == 2
	rd := newELFReader(data, be)

	entrySize := 8 // 32-bit: tag(4) + val(4)
	if brief.Header.Class == 2 {
		entrySize = 16 // 64-bit: tag(8) + val(8)
	}

	var strTabVaddr uint64
	type rawDyn struct {
		tag uint64
		val uint64
	}
	var entries []rawDyn

	curr := offset
	limit := offset + size
	for curr+uint64(entrySize) <= limit {
		var tag, val uint64
		if brief.Header.Class == 1 {
			tag = uint64(rd.u32(int(curr)))
			val = uint64(rd.u32(int(curr + 4)))
		} else {
			tag = rd.u64(int(curr))
			val = rd.u64(int(curr + 8))
		}
		if tag == dtNull {
			break
		}
		entries = append(entries, rawDyn{tag: tag, val: val})
		if tag == dtStrTab {
			strTabVaddr = val
		}
		curr += uint64(entrySize)
	}

	// Resolve RELRO details
	bindNow := false
	for _, entry := range entries {
		switch entry.tag {
		case dtBindNow:
			bindNow = true
		case dtFlags:
			// DF_BIND_NOW = 0x08
			if (entry.val & 0x08) != 0 {
				bindNow = true
			}
		case dtFlags1:
			// DF_1_NOW = 0x01
			if (entry.val & 0x01) != 0 {
				bindNow = true
			}
		}
	}
	brief.FullRelro = brief.HasRelro && bindNow

	// Resolve strings (RPATH / RUNPATH)
	if strTabVaddr > 0 {
		strTabOff := vaddrToOffset(strTabVaddr, phs)
		if strTabOff > 0 && strTabOff < len(data) {
			for _, entry := range entries {
				if entry.tag == dtRpath || entry.tag == dtRunpath {
					strOff := strTabOff + int(entry.val)
					if strOff < len(data) {
						end := strOff
						for end < len(data) && data[end] != 0 {
							end++
						}
						valStr := string(data[strOff:end])
						if entry.tag == dtRpath {
							brief.Rpaths = append(brief.Rpaths, valStr)
							if isInsecurePath(valStr) {
								brief.InsecureRpath = true
							}
						} else {
							brief.Runpaths = append(brief.Runpaths, valStr)
							if isInsecurePath(valStr) {
								brief.InsecureRunpath = true
							}
						}
					}
				}
			}
		}
	}
}

func isInsecurePath(p string) bool {
	for _, token := range strings.Split(p, ":") {
		token = strings.TrimSpace(token)
		if token == "." || token == "" || strings.HasPrefix(token, "/tmp") || strings.HasPrefix(token, "/data/local/tmp") {
			return true
		}
	}
	return false
}

func vaddrToOffset(vaddr uint64, phs []progHeader) int {
	for _, ph := range phs {
		if vaddr >= ph.Vaddr && vaddr < ph.Vaddr+ph.Memsz {
			return int(vaddr - ph.Vaddr + ph.Offset)
		}
	}
	return -1
}

func checkSSPAndFortify(data []byte, brief *elfBriefing) {
	// Look for stack canary trigger symbol
	if bytes.Contains(data, []byte("__stack_chk_fail")) || bytes.Contains(data, []byte("__stack_chk_guard")) {
		brief.StackCanary = true
	}

	// Estimate fortify count by sniffing `_chk` occurrences in symbols
	// Standard hardened functions: `__memcpy_chk`, `__strcpy_chk`, `__sprintf_chk`, `__read_chk`
	tokens := [][]byte{
		[]byte("_chk"),
		[]byte("__memcpy_chk"),
		[]byte("__strcpy_chk"),
		[]byte("__sprintf_chk"),
	}
	for _, t := range tokens {
		if bytes.Contains(data, t) {
			brief.FortifyCount++
		}
	}
}

func summarizeELFBriefing(res *ModuleResult, b *elfBriefing, root string) {
	rel, _ := filepath.Rel(root, b.Path)
	if rel == "" {
		rel = b.Path
	}

	// Headline overview
	headline := Finding{
		ID:         "elf-overview",
		Title:      "ELF binary triaged",
		Severity:   SevInfo,
		Confidence: 1.0,
		File:       rel,
		Description: fmt.Sprintf("Class=%d-bit, Endian=%s, PIE=%v, NX=%v, RELRO=%s, Canary=%v, FortifyCount=%d",
			b.Header.Class*32, endianStr(b.Header.Data), b.PIE, b.NXEnabled, relroStr(b.HasRelro, b.FullRelro), b.StackCanary, b.FortifyCount),
		Tags:  []string{"elf", "linux", "native", "overview"},
		Extra: map[string]string{},
	}
	res.AddFinding(headline)

	// PIE hardening check
	if !b.PIE {
		res.AddFinding(Finding{
			ID:          "elf-no-pie",
			Title:       "ELF executable lacks PIE",
			Severity:    SevHigh,
			Confidence:  1.0,
			File:        rel,
			Description: "ELF binary was linked as a static executable (ET_EXEC) instead of Position Independent Executable (PIE). ASLR is disabled for this binary.",
			Tags:        []string{"elf", "hardening", "aslr", "pie"},
		})
	}

	// NX hardening check
	if b.HasNX && !b.NXEnabled {
		res.AddFinding(Finding{
			ID:          "elf-executable-stack",
			Title:       "ELF has executable stack (NX disabled)",
			Severity:    SevHigh,
			Confidence:  0.95,
			File:        rel,
			Description: "The PT_GNU_STACK segment is marked as executable. Defeats Data Execution Prevention (DEP/NX) and makes shellcode execution on the stack trivial.",
			Tags:        []string{"elf", "hardening", "nx", "dep"},
		})
	}

	// RELRO hardening check
	if !b.HasRelro {
		res.AddFinding(Finding{
			ID:          "elf-no-relro",
			Title:       "ELF lacks RELRO protection",
			Severity:    SevHigh,
			Confidence:  0.9,
			File:        rel,
			Description: "No PT_GNU_RELRO program header is present. Relocations remain writable, leaving the GOT (Global Offset Table) vulnerable to hijack.",
			Tags:        []string{"elf", "hardening", "relro", "got"},
		})
	} else if !b.FullRelro {
		res.AddFinding(Finding{
			ID:          "elf-partial-relro",
			Title:       "ELF has Partial RELRO only",
			Severity:    SevMedium,
			Confidence:  0.85,
			File:        rel,
			Description: "PT_GNU_RELRO is present, but BIND_NOW is disabled (Partial RELRO). The GOT remains writable after lazy binding resolution, permitting GOT overwrite attacks.",
			Tags:        []string{"elf", "hardening", "relro", "partial"},
		})
	}

	// Stack Canary SSP check
	if !b.StackCanary {
		res.AddFinding(Finding{
			ID:          "elf-no-canary",
			Title:       "ELF has no Stack Canary protection",
			Severity:    SevMedium,
			Confidence:  0.8,
			File:        rel,
			Description: "Binary does not refer to stack protection symbols (__stack_chk_fail). Vulnerable to stack buffer overflow attacks.",
			Tags:        []string{"elf", "hardening", "ssp", "canary"},
		})
	}

	// Insecure paths checks
	if b.InsecureRpath {
		res.AddFinding(Finding{
			ID:          "elf-insecure-rpath",
			Title:       "Insecure DT_RPATH configured",
			Severity:    SevHigh,
			Confidence:  0.9,
			File:        rel,
			Description: "The DT_RPATH contains insecure search paths (e.g. '.', '/tmp' or empty values). Leads to local library injection.",
			Evidence:    b.Rpaths,
			Tags:        []string{"elf", "security", "rpath", "hijack"},
		})
	}
	if b.InsecureRunpath {
		res.AddFinding(Finding{
			ID:          "elf-insecure-runpath",
			Title:       "Insecure DT_RUNPATH configured",
			Severity:    SevHigh,
			Confidence:  0.9,
			File:        rel,
			Description: "The DT_RUNPATH contains insecure search paths (e.g. '.', '/tmp' or empty values). Leads to local library injection.",
			Evidence:    b.Runpaths,
			Tags:        []string{"elf", "security", "runpath", "hijack"},
		})
	}

	res.Bump("findings", 1+
		boolToInt(!b.PIE)+
		boolToInt(b.HasNX && !b.NXEnabled)+
		boolToInt(!b.HasRelro || !b.FullRelro)+
		boolToInt(!b.StackCanary)+
		boolToInt(b.InsecureRpath || b.InsecureRunpath))
}

func endianStr(data byte) string {
	if data == 2 {
		return "Big"
	}
	return "Little"
}

func relroStr(has, full bool) string {
	if !has {
		return "None"
	}
	if full {
		return "Full"
	}
	return "Partial"
}

// ─── tiny endian-aware reader ──────────────────────────────────────────────

type elfReader struct {
	data []byte
	be   bool
}

func newELFReader(data []byte, be bool) elfReader { return elfReader{data: data, be: be} }

func (r elfReader) u16(off int) uint16 {
	if off+2 > len(r.data) {
		return 0
	}
	if r.be {
		return binary.BigEndian.Uint16(r.data[off : off+2])
	}
	return binary.LittleEndian.Uint16(r.data[off : off+2])
}

func (r elfReader) u32(off int) uint32 { return r.u32At(r.data, off) }

func (r elfReader) u32At(buf []byte, off int) uint32 {
	if off+4 > len(buf) {
		return 0
	}
	if r.be {
		return binary.BigEndian.Uint32(buf[off : off+4])
	}
	return binary.LittleEndian.Uint32(buf[off : off+4])
}

func (r elfReader) u64(off int) uint64 { return r.u64At(r.data, off) }

func (r elfReader) u64At(buf []byte, off int) uint64 {
	if off+8 > len(buf) {
		return 0
	}
	if r.be {
		return binary.BigEndian.Uint64(buf[off : off+8])
	}
	return binary.LittleEndian.Uint64(buf[off : off+8])
}
