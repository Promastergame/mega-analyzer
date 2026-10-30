package ipaloader

import (
	"bytes"
	"context"
	"debug/macho"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/crackpoint"
	"mega-analyzer/pkg/internal/types"
	llmkeys "mega-analyzer/pkg/ml/llm_but_this_ml_lol"
)

// ═══════════════════════════════════════════════════════════════════════════════
// iOS CRACK POINTS + OFFLINE SECRET CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════════════
//
// Crack-point detection runs over Mach-O binaries' imported symbols, linked
// frameworks, entitlement keys and string constants. Both thin and fat/universal
// binaries are parsed (every architecture slice is inspected). FairPlay-encrypted
// __TEXT hides symbols/strings — a coverage note is emitted when detected.
//
// Binaries are scanned concurrently and the whole scan honours ctx cancellation.

var entitlementKeyRe = regexp.MustCompile(`<key>([A-Za-z0-9_.\-]+)</key>`)

// Scan bounds (anti-DoS + predictable memory).
var (
	// MaxBinaries caps how many Mach-O carriers are scanned per app.
	MaxBinaries = 256
	// MaxBinarySize caps how much of a single binary is read into memory.
	MaxBinarySize int64 = 256 << 20 // 256 MiB
	// MaxStringsPerBinary caps extracted printable strings per binary.
	MaxStringsPerBinary = 500_000
	// ScanConcurrency is the worker count; <=0 means runtime.NumCPU().
	ScanConcurrency = 0
)

// entitlementAllow lists dotless entitlement keys we still treat as real
// entitlements (most entitlements contain a dot and are matched generically).
var entitlementAllow = map[string]bool{
	"get-task-allow":         true,
	"application-identifier": true,
	"keychain-access-groups": true,
	"aps-environment":        true,
}

// SecretVerdict is the classifier's decision for one candidate string.
type SecretVerdict struct {
	IsSecret   bool
	Family     string
	Confidence float64
	Reason     string
}

// FamilyCount is one credential family bucket in an insights summary.
type FamilyCount struct {
	Family string
	Count  int
}

// SecretInsights is the aggregate summary over many candidate credentials.
type SecretInsights struct {
	Secrets      int
	ClusterCount int
	AnomalyCount int
	Families     []FamilyCount
}

// SecretClassifier decouples crack-point scanning from the concrete offline
// classifier, so it can be swapped or mocked in tests.
type SecretClassifier interface {
	Classify(value string) SecretVerdict
	Summarize(values []string) SecretInsights
}

// llmClassifier is the default classifier backed by the offline insights
// engine. Classify is guarded by a mutex because its memoization cache is not
// guaranteed to be concurrency-safe under the parallel scan.
type llmClassifier struct{ mu sync.Mutex }

func (c *llmClassifier) Classify(v string) SecretVerdict {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := llmkeys.ClassifyCached(v)
	return SecretVerdict{IsSecret: r.IsSecret, Family: r.Family, Confidence: r.Confidence, Reason: r.Reason}
}

func (c *llmClassifier) Summarize(vals []string) SecretInsights {
	ins := llmkeys.Summarize(vals)
	out := SecretInsights{Secrets: ins.Secrets, ClusterCount: ins.ClusterCount, AnomalyCount: len(ins.Anomalies)}
	for _, fc := range ins.ByFamily {
		out.Families = append(out.Families, FamilyCount{Family: fc.Family, Count: fc.Count})
	}
	return out
}

func defaultClassifier() SecretClassifier { return &llmClassifier{} }

// CrackPointsForIPA scans every Mach-O binary under the extracted IPA directory
// for iOS license / IAP / jailbreak gates and embedded secrets.
func CrackPointsForIPA(ctx context.Context, appDir, bundleID string) ([]types.CrackPoint, []types.ArtifactFinding) {
	return CrackPointsForIPAWithClassifier(ctx, appDir, bundleID, defaultClassifier())
}

// CrackPointsForIPAWithClassifier is CrackPointsForIPA with an injectable secret
// classifier.
func CrackPointsForIPAWithClassifier(ctx context.Context, appDir, bundleID string, classifier SecretClassifier) ([]types.CrackPoint, []types.ArtifactFinding) {
	bins, truncated := findMachOBinaries(ctx, appDir)
	if len(bins) == 0 {
		return nil, nil
	}
	container := bundleID
	if container == "" {
		container = "ios-app"
	}
	if classifier == nil {
		classifier = defaultClassifier()
	}

	workers := ScanConcurrency
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > len(bins) {
		workers = len(bins)
	}

	results := make([]binResult, len(bins))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, path := range bins {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, path string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = scanBinary(ctx, path, appDir, container, classifier)
		}(i, path)
	}
	wg.Wait()

	var points []types.CrackPoint
	var findings []types.ArtifactFinding
	var secretValues []string
	for _, r := range results {
		points = append(points, r.points...)
		findings = append(findings, r.findings...)
		secretValues = append(secretValues, r.secrets...)
	}

	if truncated {
		findings = append(findings, types.ArtifactFinding{
			Path:     container,
			Severity: types.SeverityInfo,
			Reason:   fmt.Sprintf("Binary scan truncated at %d Mach-O files: some binaries were not analyzed for crack points.", MaxBinaries),
			Stages:   []string{"ipa", "coverage"},
		})
	}

	// Aggregate embedded-credential insights (statistics only, never raw values).
	if f, ok := secretInsightFinding(secretValues, container, classifier); ok {
		findings = append(findings, f)
	}
	// Drop references to raw secret material as soon as it is no longer needed.
	for i := range secretValues {
		secretValues[i] = ""
	}

	sortCrackPoints(points)
	sortFindings(findings)
	return points, findings
}

type binResult struct {
	points   []types.CrackPoint
	findings []types.ArtifactFinding
	secrets  []string
}

// scanBinary performs the full per-binary analysis: read (capped), extract
// strings once, derive symbol refs (thin+fat), run the finder and classify
// embedded secrets.
func scanBinary(ctx context.Context, path, root, container string, classifier SecretClassifier) binResult {
	var r binResult
	if ctx.Err() != nil {
		return r
	}
	data, truncated, err := readCapped(path, MaxBinarySize)
	if err != nil {
		slog.Debug("ios: cannot read binary", "path", path, "err", err)
		return r
	}
	rel := relIPAPath(root, path)

	// Single extraction pass shared by the symbol path (minLen 5) and the
	// secret path (minLen 12, filtered from the same slice).
	strs := extractPrintableStringsLimited(data, 5, MaxStringsPerBinary)

	refs, encrypted := machoSymbolRefs(data, container, strs)
	finder := crackpoint.NewFinder() // per-binary: avoids shared mutable state
	res := finder.FindCrackPointsInSymbols(refs, container, crackpoint.PlatformIOS)
	for _, cp := range res.CrackPoints {
		r.points = append(r.points, types.CrackPoint{
			Location:   types.SourceLocation{File: rel, Method: cp.MethodName},
			ClassName:  cp.ClassName,
			Method:     cp.MethodName,
			Category:   cp.Category,
			Confidence: cp.Confidence,
			Impact:     cp.Impact,
			Suggestion: cp.SuggestedAction,
			PatchRisk:  cp.PatchRisk,
		})
	}

	secFindings, secVals := machoSecrets(strs, rel, classifier)
	r.findings = append(r.findings, secFindings...)
	r.secrets = secVals

	if encrypted {
		r.findings = append(r.findings, types.ArtifactFinding{
			Path:     rel,
			Severity: types.SeverityInfo,
			Reason:   "Binary is FairPlay-encrypted (cryptid != 0): symbol/string coverage for crack-point detection is limited until decrypted.",
			Stages:   []string{"ipa", "fairplay", "coverage"},
		})
	}
	if truncated {
		r.findings = append(r.findings, types.ArtifactFinding{
			Path:     rel,
			Severity: types.SeverityInfo,
			Reason:   fmt.Sprintf("Binary larger than %d bytes: only the leading bytes were analyzed.", MaxBinarySize),
			Stages:   []string{"ipa", "coverage"},
		})
	}
	return r
}

func readCapped(path string, max int64) (data []byte, truncated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	if fi, statErr := f.Stat(); statErr == nil && fi.Size() > max {
		truncated = true
	}
	data, err = io.ReadAll(io.LimitReader(f, max))
	return data, truncated, err
}

// findMachOBinaries walks the extracted IPA and returns paths whose first bytes
// are a Mach-O magic. truncated is true when MaxBinaries was hit.
func findMachOBinaries(ctx context.Context, appDir string) (out []string, truncated bool) {
	_ = filepath.Walk(appDir, func(path string, fi os.FileInfo, err error) error {
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil || fi.IsDir() || fi.Size() < 4 {
			return nil
		}
		// 0xCAFEBABE is both a Mach-O fat magic and a Java class magic;
		// a stray .class file must not be mistaken for a fat binary.
		if strings.HasSuffix(strings.ToLower(path), ".class") {
			return nil
		}
		if len(out) >= MaxBinaries {
			truncated = true
			return filepath.SkipAll
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		var hdr [4]byte
		n, _ := f.Read(hdr[:])
		f.Close()
		if n == 4 && isMachOMagicBytes(hdr[:]) {
			out = append(out, path)
		}
		return nil
	})
	return out, truncated
}

func isMachOMagicBytes(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	m := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	switch m {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, // thin (BE/LE, 32/64)
		0xCAFEBABE, 0xBEBAFECA, // fat 32
		0xCAFEBABF, 0xBFBAFECA: // fat 64
		return true
	}
	return false
}

// machoSymbolRefs collects imported symbols, linked frameworks, entitlement keys
// and printable strings as crack-point symbols across every architecture slice
// (thin or fat). Returns whether any slice is FairPlay-encrypted. strs is the
// already-extracted printable-string set, so no second scan is performed.
func machoSymbolRefs(data []byte, container string, strs []string) ([]crackpoint.SymbolRef, bool) {
	var refs []crackpoint.SymbolRef
	add := func(name string, kind crackpoint.SymbolKind) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		refs = append(refs, crackpoint.SymbolRef{Name: name, Kind: kind, Class: container, Raw: name})
	}

	encrypted := false
	handle := func(f *macho.File) {
		if imps, err := f.ImportedSymbols(); err == nil {
			for _, s := range imps {
				add(s, crackpoint.SymbolImport)
			}
		}
		if libs, err := f.ImportedLibraries(); err == nil {
			for _, l := range libs {
				add(l, crackpoint.SymbolDylib)
			}
		}
		if machoFileEncrypted(f) {
			encrypted = true
		}
	}

	if fat, err := macho.NewFatFile(bytes.NewReader(data)); err == nil {
		for _, arch := range fat.Arches {
			if arch.File != nil {
				handle(arch.File)
			}
		}
		fat.Close()
	} else if f, err := macho.NewFile(bytes.NewReader(data)); err == nil {
		handle(f)
		f.Close()
	}

	for _, s := range strs {
		if len(s) > 200 {
			continue
		}
		add(s, crackpoint.SymbolString)
	}
	for _, k := range entitlementKeys(data) {
		add(k, crackpoint.SymbolEntitlement)
	}
	return refs, encrypted
}

// machoFileEncrypted reports whether any LC_ENCRYPTION_INFO[_64] load command
// has a non-zero cryptid (FairPlay DRM still applied).
func machoFileEncrypted(f *macho.File) bool {
	const (
		lcEncryptionInfo   = 0x21
		lcEncryptionInfo64 = 0x2C
	)
	for _, l := range f.Loads {
		lb, ok := l.(macho.LoadBytes)
		if !ok {
			continue
		}
		raw := lb.Raw()
		if len(raw) < 20 {
			continue
		}
		cmd := f.ByteOrder.Uint32(raw[0:4])
		if cmd == lcEncryptionInfo || cmd == lcEncryptionInfo64 {
			if f.ByteOrder.Uint32(raw[16:20]) != 0 {
				return true
			}
		}
	}
	return false
}

// entitlementKeys extracts entitlement <key> names from any embedded
// entitlements plist. It filters to keys that look like real entitlements
// (contain a dot, or are in the dotless allow-list) to avoid matching arbitrary
// Info.plist / resource keys.
func entitlementKeys(data []byte) []string {
	// Prefer the __TEXT,__entitlements section over a whole-binary scan:
	// embedded non-entitlement plists (preferences, resources) also contain
	// dotted <key>s that the filter below cannot tell apart. Falls back to
	// the whole data when it does not parse as Mach-O.
	if blob := entitlementsSection(data); blob != nil {
		data = blob
	}
	matches := entitlementKeyRe.FindAllSubmatch(data, -1)
	seen := make(map[string]bool)
	var out []string
	for _, m := range matches {
		k := string(m[1])
		if seen[k] {
			continue
		}
		if !strings.Contains(k, ".") && !entitlementAllow[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
		if len(out) >= 256 {
			break
		}
	}
	return out
}

// entitlementsSection returns the __TEXT,__entitlements section bytes when
// data parses as Mach-O (thin or fat, every slice inspected), nil otherwise.
// For fat slices the section offset is slice-relative, so the arch's file
// offset is added back before slicing the original data.
func entitlementsSection(data []byte) []byte {
	sections := func(f *macho.File, base int64) []byte {
		for _, s := range f.Sections {
			if s.Seg != "__TEXT" || s.Name != "__entitlements" || s.Size == 0 {
				continue
			}
			start := base + int64(s.Offset)
			if start < 0 || start+int64(s.Size) > int64(len(data)) {
				continue
			}
			return data[start : start+int64(s.Size)]
		}
		return nil
	}
	if fat, err := macho.NewFatFile(bytes.NewReader(data)); err == nil {
		for _, arch := range fat.Arches {
			if arch.File == nil {
				continue
			}
			if blob := sections(arch.File, int64(arch.Offset)); blob != nil {
				fat.Close()
				return blob
			}
		}
		fat.Close()
		return nil
	}
	if f, err := macho.NewFile(bytes.NewReader(data)); err == nil {
		blob := sections(f, 0)
		f.Close()
		return blob
	}
	return nil
}

// machoSecrets runs the offline credential classifier over the already-extracted
// strings. Returns artifact findings plus the raw surfaced values (used only to
// build the aggregate insights summary; never reported verbatim).
func machoSecrets(strs []string, rel string, classifier SecretClassifier) ([]types.ArtifactFinding, []string) {
	var out []types.ArtifactFinding
	var surfaced []string
	seen := make(map[string]bool)
	for _, s := range strs {
		v := strings.TrimSpace(s)
		if len(v) < 12 || len(v) > 512 || seen[v] {
			continue
		}
		verdict := classifier.Classify(v)
		if !verdict.IsSecret || (verdict.Family == "" && verdict.Confidence < 0.8) {
			continue
		}
		seen[v] = true
		surfaced = append(surfaced, v)
		reason := "Embedded credential detected by offline classifier"
		if verdict.Family != "" {
			reason += " (" + verdict.Family + " family)"
		}
		reason += ". " + verdict.Reason
		out = append(out, types.ArtifactFinding{
			Path:     rel,
			Severity: secretSeverityIOS(verdict.Confidence),
			Reason:   reason,
			Payload:  maskIOSSecret(v),
			Stages:   []string{"ios", "secret", "llmkeys"},
		})
	}
	return out, surfaced
}

// secretInsightFinding condenses embedded-credential values into one aggregate
// summary. Emits nothing for fewer than two credentials. Only statistics are
// reported — never a raw or masked value.
func secretInsightFinding(values []string, container string, classifier SecretClassifier) (types.ArtifactFinding, bool) {
	if len(values) < 2 {
		return types.ArtifactFinding{}, false
	}
	ins := classifier.Summarize(values)
	if ins.Secrets < 2 {
		return types.ArtifactFinding{}, false
	}
	var fams []string
	for _, fc := range ins.Families {
		fams = append(fams, fmt.Sprintf("%s×%d", fc.Family, fc.Count))
	}
	famPart := "no recognized family"
	if len(fams) > 0 {
		famPart = strings.Join(fams, ", ")
	}
	reason := fmt.Sprintf(
		"Embedded-secret summary for %s: %d candidate credential(s) in %d structural cluster(s); families: %s",
		container, ins.Secrets, ins.ClusterCount, famPart)
	if ins.AnomalyCount > 0 {
		reason += fmt.Sprintf("; %d anomalous unknown-format token(s) flagged for review", ins.AnomalyCount)
	}
	return types.ArtifactFinding{
		Path:     container,
		Severity: types.SeverityInfo,
		Reason:   reason,
		Stages:   []string{"ipa", "secret", "llmkeys", "insights"},
	}, true
}

func secretSeverityIOS(confidence float64) types.Severity {
	switch {
	case confidence >= 0.9:
		return types.SeverityHigh
	case confidence >= 0.7:
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}

// maskIOSSecret reveals minimal context: the first 2 and last 1 characters for
// longer values, nothing for short ones.
func maskIOSSecret(s string) string {
	n := len(s)
	if n <= 6 {
		return strings.Repeat("*", n)
	}
	return s[:2] + strings.Repeat("*", n-3) + s[n-1:]
}

func relIPAPath(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

// extractPrintableStrings returns runs of printable ASCII of at least minLen.
func extractPrintableStrings(data []byte, minLen int) []string {
	return extractPrintableStringsLimited(data, minLen, 0)
}

// extractPrintableStringsLimited is extractPrintableStrings with an optional cap
// on the number of returned strings (max <= 0 means unlimited).
func extractPrintableStringsLimited(data []byte, minLen, max int) []string {
	var out []string
	start := -1
	emit := func(s string) bool {
		out = append(out, s)
		return max > 0 && len(out) >= max
	}
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b >= 0x20 && b <= 0x7e {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if i-start >= minLen {
				if emit(string(data[start:i])) {
					return out
				}
			}
			start = -1
		}
	}
	if start >= 0 && len(data)-start >= minLen {
		emit(string(data[start:]))
	}
	return out
}

func sortCrackPoints(p []types.CrackPoint) {
	sort.SliceStable(p, func(i, j int) bool {
		if p[i].Location.File != p[j].Location.File {
			return p[i].Location.File < p[j].Location.File
		}
		if p[i].Category != p[j].Category {
			return p[i].Category < p[j].Category
		}
		return p[i].Method < p[j].Method
	})
}

func sortFindings(f []types.ArtifactFinding) {
	// Triage order: most severe first (Severity is an ordered uint8), then
	// path/reason/payload for determinism. The previous string-compare order
	// (critical, high, info, low, medium) was alphabetical accident, and it
	// paid a Sprintf per comparison.
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Severity != f[j].Severity {
			return f[i].Severity > f[j].Severity
		}
		if f[i].Path != f[j].Path {
			return f[i].Path < f[j].Path
		}
		if f[i].Reason != f[j].Reason {
			return f[i].Reason < f[j].Reason
		}
		return f[i].Payload < f[j].Payload
	})
}
