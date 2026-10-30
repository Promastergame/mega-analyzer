package experimental

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"mega-analyzer/pkg/internal/peinspect"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PE / WINDOWS HARDENING TRIAGE MODULE
// ═══════════════════════════════════════════════════════════════════════════════
//
// A focused, dependency-free PE loader that parses 32-bit and 64-bit Windows binaries
// (.exe, .dll, .sys, .ocx) to audit their compilation and hardening posture:
//
//   * ASLR (Address Space Layout Randomization): Checks for dynamic base and high entropy.
//   * DEP/NX (Data Execution Prevention): Checks DllCharacteristics compatibility flag.
//   * AppContainer: Checks for AppContainer execution posture.
//   * Control Flow Guard (CFG): Checks CFG compliance.
//   * Code Signature: Audits if a digital signature is embedded in the Security Directory.
//   * SafeSEH: For 32-bit PE files, audits if structured exception handling is locked down.
//   * Stack Cookie (GS): Sniffs compiler stack cookie metadata and references.

// PEModule implements Module.
type PEModule struct{}

// NewPEModule constructs the module.
func NewPEModule() *PEModule { return &PEModule{} }

func (m *PEModule) ID() string   { return "pe" }
func (m *PEModule) Name() string { return "PE / Windows Hardening Triage" }
func (m *PEModule) Description() string {
	return "Triage security and compilation hardening for PE / Windows binaries"
}
func (m *PEModule) Aliases() []string { return []string{"exe", "dll", "windows", "6"} }
func (m *PEModule) Tier() string      { return "experimental" }

var peMagic = []byte{'P', 'E', 0, 0}
var dosMagic = []byte{'M', 'Z'}

type peBriefing struct {
	Path                 string
	Is64Bit              bool
	ASLR                 bool
	ASLRFlagOnly         bool // DYNAMICBASE set, but no relocations to apply it through
	HighEntropyASLR      bool
	DEP                  bool
	AppContainer         bool
	CFG                  bool
	CFGFlagOnly          bool // GUARD_CF set, but no load config to arm it
	HasEmbeddedSignature bool
	Signature            peinspect.Signature
	Architecture         string
	StackCookieKnown     bool
	SEHApplicable        bool
	SafeSEH              bool
	NoSEH                bool
	HasStackCookie       bool
	LoadConfigPresent    bool
}

// Run implements Module.Run.
func (m *PEModule) Run(ctx context.Context, in Input) (*ModuleResult, error) {
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

	candidates, err := collectPECandidates(ctx, in.TargetDir)
	if err != nil {
		return res, err
	}
	res.Bump("candidates", len(candidates))

	if len(candidates) == 0 {
		res.Notes = append(res.Notes, "No PE / Windows candidates found.")
		return res, nil
	}

	for _, path := range candidates {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		brief, err := analyzePE(path)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			continue
		}
		res.Bump("parsed", 1)
		summarizePEBriefing(res, brief, in.TargetDir)
	}

	return res, nil
}

func collectPECandidates(ctx context.Context, root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if shouldInspectAsPE(path, d) {
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

func shouldInspectAsPE(path string, d fs.DirEntry) bool {
	if !d.Type().IsRegular() {
		return false
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	// DOS header magic
	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	if !bytes.Equal(magic[:], dosMagic) {
		return false
	}

	// Seek to e_lfanew
	if _, err := f.Seek(0x3C, io.SeekStart); err != nil {
		return false
	}
	var elfanew uint32
	if err := binary.Read(f, binary.LittleEndian, &elfanew); err != nil {
		return false
	}

	// Read PE Signature
	if _, err := f.Seek(int64(elfanew), io.SeekStart); err != nil {
		return false
	}
	var peSig [4]byte
	if _, err := io.ReadFull(f, peSig[:]); err != nil {
		return false
	}

	return bytes.Equal(peSig[:], peMagic)
}

func analyzePE(path string) (*peBriefing, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	meta, err := peinspect.Inspect(data)
	if err != nil {
		return nil, err
	}
	chars := meta.DllCharacteristics
	// A mitigation flag is a request, not a fact. DYNAMICBASE only relocates
	// through a base-relocation table, so RELOCS_STRIPPED or an empty
	// directory means no ASLR; GUARD_CF arms itself via the load config, so
	// without that directory CFG is inert.
	aslrFlag := chars&0x40 != 0
	highEntropyFlag := chars&0x20 != 0
	cfgFlag := chars&0x4000 != 0
	aslr := aslrFlag &&
		meta.FileCharacteristics&0x0001 == 0 &&
		meta.HasRelocations && meta.RelocValid
	cfg := cfgFlag && meta.CFValid
	b := &peBriefing{
		Path: path, Is64Bit: meta.Is64Bit, Architecture: meta.Architecture,
		ASLR: aslr, ASLRFlagOnly: aslrFlag && !aslr,
		HighEntropyASLR: highEntropyFlag && aslr,
		DEP:             chars&0x100 != 0, NoSEH: chars&0x400 != 0,
		AppContainer: chars&0x1000 != 0, CFG: cfg, CFGFlagOnly: cfgFlag && !cfg,
		HasEmbeddedSignature: meta.Signature.Status == "present", Signature: meta.Signature,
		LoadConfigPresent: meta.LoadConfigPresent,
		StackCookieKnown:  meta.StackCookie != nil, SEHApplicable: meta.SafeSEH != nil,
	}
	if meta.StackCookie != nil {
		b.HasStackCookie = *meta.StackCookie
	}
	if meta.SafeSEH != nil {
		b.SafeSEH = *meta.SafeSEH
	}
	return b, nil
}

func summarizePEBriefing(res *ModuleResult, b *peBriefing, root string) {
	before := len(res.Findings)
	rel, _ := filepath.Rel(root, b.Path)
	if rel == "" {
		rel = b.Path
	}

	archStr := "32-bit"
	if b.Is64Bit {
		archStr = "64-bit"
	}

	// Dynamic base representation
	aslrStr := "None"
	if b.ASLR {
		if b.HighEntropyASLR {
			aslrStr = "HighEntropy"
		} else {
			aslrStr = "Standard"
		}
	}

	// Exception handling status
	sehStr := "Vulnerable"
	if !b.SEHApplicable {
		sehStr = "N/A"
	} else if b.NoSEH {
		sehStr = "NoSEH"
	} else if b.SafeSEH {
		sehStr = "SafeSEH"
	}

	if b.Architecture != "" {
		archStr = b.Architecture + " (" + archStr + ")"
	}
	cookieStr := "unknown"
	if b.StackCookieKnown {
		cookieStr = fmt.Sprint(b.HasStackCookie)
	}
	// Headline overview
	headline := Finding{
		ID:         "pe-overview",
		Title:      "PE binary triaged",
		Severity:   SevInfo,
		Confidence: 1.0,
		File:       rel,
		Description: fmt.Sprintf("Arch=%s, ASLR=%s, DEP=%v, CFG=%v, SafeSEH=%s, Cookie=%s, EmbeddedSignature=%s, SignatureIntegrity=%s, SignatureTrust=%s, AppContainer=%v",
			archStr, aslrStr, b.DEP, b.CFG, sehStr, cookieStr, b.Signature.Status, b.Signature.Integrity, b.Signature.Trust, b.AppContainer),
		Tags:  []string{"pe", "windows", "native", "overview"},
		Extra: map[string]string{"signature_status": b.Signature.Status, "signature_integrity": b.Signature.Integrity, "signature_trust": b.Signature.Trust},
	}
	res.AddFinding(headline)

	// ASLR check
	if !b.ASLR {
		desc := "PE binary lacks the dynamic base characteristic. Image relocation is not requested by this flag; effective ASLR also depends on relocations and operating-system policy."
		if b.ASLRFlagOnly {
			desc = "PE sets the dynamic base characteristic, but relocations are stripped or absent, so the loader has nothing to relocate through and the image is not ASLR-randomized."
		}
		res.AddFinding(Finding{
			ID:          "pe-no-aslr",
			Title:       "PE lacks ASLR protection",
			Severity:    SevHigh,
			Confidence:  1.0,
			File:        rel,
			Description: desc,
			Tags:        []string{"pe", "hardening", "aslr"},
		})
	} else if b.Is64Bit && !b.HighEntropyASLR {
		res.AddFinding(Finding{
			ID:          "pe-no-high-entropy-aslr",
			Title:       "PE lacks High Entropy ASLR",
			Severity:    SevLow,
			Confidence:  1.0,
			File:        rel,
			Description: "PE is 64-bit but does not specify high entropy dynamic base characteristic. Relocation space is restricted, reducing ASLR efficacy.",
			Tags:        []string{"pe", "hardening", "aslr", "high-entropy"},
		})
	}

	// DEP/NX check
	if !b.DEP {
		res.AddFinding(Finding{
			ID:          "pe-no-dep",
			Title:       "PE lacks DEP/NX protection",
			Severity:    SevHigh,
			Confidence:  1.0,
			File:        rel,
			Description: "PE binary lacks the NX compatibility flag. Memory pages containing data (stack/heap) might be executable, allowing standard shellcode execution.",
			Tags:        []string{"pe", "hardening", "dep", "nx"},
		})
	}

	// Control Flow Guard check
	if !b.CFG {
		desc := "Binary was not compiled with Control Flow Guard (CFG). Indirection branch calls remain unvalidated, rendering it susceptible to control-flow hijacking."
		if b.CFGFlagOnly {
			desc = "PE sets the GUARD_CF characteristic, but no load config directory is present, so CFG is not armed and indirect calls remain unvalidated."
		}
		res.AddFinding(Finding{
			ID:          "pe-no-cfg",
			Title:       "Control Flow Guard is disabled",
			Severity:    SevMedium,
			Confidence:  1.0,
			File:        rel,
			Description: desc,
			Tags:        []string{"pe", "hardening", "cfg"},
		})
	}

	// SafeSEH check
	if b.SEHApplicable && !b.SafeSEH {
		res.AddFinding(Finding{
			ID:          "pe-no-safeseh",
			Title:       "PE lacks SafeSEH protection",
			Severity:    SevHigh,
			Confidence:  0.95,
			File:        rel,
			Description: "32-bit PE does not have SafeSEH enabled nor disables SEH entirely. Attackers can hijack structured exception handlers to gain execution flow control.",
			Tags:        []string{"pe", "hardening", "safeseh", "seh"},
		})
	}

	// Stack Cookie check
	if !b.StackCookieKnown {
		res.AddFinding(Finding{
			ID: "pe-stack-cookie-unknown", Title: "Stack Cookie status is unknown",
			Severity: SevInfo, Confidence: 1.0, File: rel,
			Description: "No validated SecurityCookie metadata was found. This does not establish that stack protection is disabled.",
			Tags:        []string{"pe", "hardening", "cookie"},
		})
	} else if !b.HasStackCookie {
		res.AddFinding(Finding{
			ID:          "pe-no-stack-cookie",
			Title:       "PE lacks Stack Cookie (GS) protection",
			Severity:    SevMedium,
			Confidence:  0.8,
			File:        rel,
			Description: "Binary lacks GS stack buffer security cookie protection or does not register it in the Load Config Directory. Vulnerable to stack-based buffer overflows.",
			Tags:        []string{"pe", "hardening", "ssp", "cookie"},
		})
	}

	// Certificate presence is independent of signature integrity or trust.
	if b.Signature.Status == "invalid" {
		res.AddFinding(Finding{
			ID: "pe-invalid-certificate", Title: "Invalid embedded certificate table",
			Severity: SevMedium, Confidence: 1.0, File: rel,
			Description: "The Security Directory does not contain a structurally valid aligned WIN_CERTIFICATE/CMS SignedData table.",
			Tags:        []string{"pe", "security", "signature"},
		})
	} else if !b.HasEmbeddedSignature {
		res.AddFinding(Finding{
			ID: "pe-unsigned", Title: "No embedded Authenticode signature",
			Severity: SevMedium, Confidence: 1.0, File: rel,
			Description: "No embedded Authenticode certificate was found. Catalog signatures, cryptographic integrity and publisher trust have not been checked.",
			Tags:        []string{"pe", "security", "signature"},
		})
	} else {
		res.AddFinding(Finding{
			ID: "pe-signed-unverified", Title: "Embedded Authenticode present, integrity/trust unverified",
			Severity: SevInfo, Confidence: 1.0, File: rel,
			Description: fmt.Sprintf("Embedded Authenticode structure valid (certs=%d, signers=%d, kind=%s). Integrity=%s, trust=%s: offline parser does not verify them; confirm via WinVerifyTrust on Windows.",
				b.Signature.Certs, b.Signature.Signers, b.Signature.Kind, b.Signature.Integrity, b.Signature.Trust),
			Tags: []string{"pe", "security", "signature"},
		})
	}

	res.Bump("findings", len(res.Findings)-before)
}
