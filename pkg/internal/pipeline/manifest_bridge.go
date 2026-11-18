// pkg/internal/pipeline/manifest_bridge.go
//
// Manifest vulnerability detector — unified on the binary-AXML
// manifestaudit module (roadmap task #3).
//
// This file replaces the retired byte-scanner (VulnManifestDetector text
// scans: indexManifestTag / manifestAttrValue / detectExportedComponents).
// All detection semantics now come from one structured parse:
//
//	content -> axml.Manifest -> manifestaudit.Audit -> pipeline findings
//
// Mapping (old byte-scanner check -> new source):
//
//	usesCleartextTraffic="true"      -> ApplicationPolicy.Cleartext (declared && effective)
//	allowBackup="true"               -> ApplicationPolicy.AllowBackup (declared && effective)
//	privileged/sensitive permissions -> axml.Manifest.Permissions (uses-permission list)
//	exported components (explicit)   -> Report.ExportedComponents (ExportedDeclared=true, no permission gate)
//	exported components (implicit)   -> Report.ExportedComponents (no exported attr + intent-filter)
//	Android-12 missing exported      -> same implicit branch gated on effective targetSdk >= 31
//	StrandHogg (taskAffinity="")     -> per-component XML attributes + manifestaudit APK-TASK-001
//	hostless custom-scheme deep link -> Report.ExportedComponents[].DeepLinks (custom scheme, empty host)
//
// Launcher exemption is preserved: an activity carrying both
// android.intent.action.MAIN and android.intent.category.LAUNCHER must be
// reachable for the app to start and is never flagged.
//
// Where manifestaudit is more precise than the old text scans its semantics
// win:
//   - effective exported rules come from the real Android default-export
//     model (including provider default-export on targetSdk < 17, which the
//     byte scanner missed entirely),
//   - cleartext honours a networkSecurityConfig override instead of blindly
//     trusting the attribute,
//   - attribute matching is namespace- and case-exact instead of lowercased
//     substring search.
//
// One narrow supplementary XML walk (encoding/xml, fully structured — NOT a
// byte scan) collects the only two facts the axml component model does not
// carry: android:readPermission / android:writePermission on providers
// (permission-gate exemption parity) and the declared-empty
// android:taskAffinity + android:allowTaskReparenting pair (the classic
// StrandHogg shape from CVE-2020-0096, which needs attribute *presence* and
// cannot be recovered from the decoded model). The same walk also records
// element offsets so findings keep accurate line numbers.
package pipeline

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"mega-analyzer/pkg/internal/finding"
	"strings"

	"mega-analyzer/pkg/internal/apkloader/axml"
	"mega-analyzer/pkg/internal/manifestaudit"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// MANIFEST VULNERABILITY DETECTOR (binary-AXML bridge)
// ═══════════════════════════════════════════════════════════════════════════════

type VulnManifestDetector struct{}

func NewVulnManifestDetector() *VulnManifestDetector { return &VulnManifestDetector{} }

func (d *VulnManifestDetector) Name() string { return "vuln_manifest" }

func (d *VulnManifestDetector) SupportsFile(fileType types.FileType, path string) bool {
	return fileType == types.FileTypeXML && strings.HasSuffix(strings.ToLower(path), "androidmanifest.xml")
}

func (d *VulnManifestDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType != types.FileTypeXML {
		return
	}
	p := strings.ToLower(analysis.Path)
	if !strings.HasSuffix(p, "androidmanifest.xml") {
		return
	}

	manifest, err := bridgeDecodeManifest(ctx.Content)
	if err != nil || manifest == nil {
		// Unparseable manifest: the retired byte scanner would have produced
		// best-effort substring hits here, but a manifest that is not even
		// well-formed XML carries no trustworthy attribute semantics. The
		// decode-tree path always hands us rendered text, so this only fires
		// on genuinely broken input.
		return
	}

	report := manifestaudit.Audit(analysis.Path, manifest)
	supp := bridgeCollectSupplements(ctx.Content)

	d.bridgeApplicationFlags(report, supp, ctx, analysis)
	d.bridgePermissionFlags(manifest, supp, ctx, analysis)
	d.bridgeExportedComponents(report, supp, ctx, analysis)
	d.bridgeStrandHogg(report, supp, ctx, analysis)
	d.bridgeHostlessDeepLinks(report, supp, ctx, analysis)
	d.bridgeUnverifiedAppLinks(report, supp, ctx, analysis)
}

// bridgeDecodeManifest parses the manifest content through the same axml
// entry points manifestaudit.LoadManifest uses, so APK-path (binary AXML)
// and extracted-directory-path (plaintext) scans share one model.
func bridgeDecodeManifest(content []byte) (*axml.Manifest, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("empty manifest")
	}
	if axml.IsBinaryXML(content) {
		return axml.Decode(content)
	}
	return axml.DecodePlainXML(content)
}

// ── Supplementary structured walk ─────────────────────────────────────────────
//
// Collects element offsets (for line anchoring) plus the two attribute facts
// the axml component model drops. Best-effort: any parse problem simply
// leaves the supplements empty and findings fall back to line 1.

type manifestBridgeComponent struct {
	kind                 string // "activity" | "service" | "receiver" | "provider"
	name                 string
	offset               int
	hasReadPermission    bool
	hasWritePermission   bool
	taskAffinityDeclared bool
	taskAffinityEmpty    bool
	allowTaskReparenting bool
}

type manifestBridgeData struct {
	scheme string
	offset int
}

type manifestBridgeSupplements struct {
	applicationOffset int
	hasApplication    bool
	components        []manifestBridgeComponent
	data              []manifestBridgeData
}

func isBridgeComponentTag(tag string) bool {
	switch tag {
	case "activity", "service", "receiver", "provider":
		return true
	}
	return false
}

// bridgeAttr returns the value of the attribute with the given local name
// (namespace prefix stripped) and whether it is present at all.
func bridgeAttr(attrs []xml.Attr, local string) (string, bool) {
	for _, a := range attrs {
		if a.Name.Local == local {
			return a.Value, true
		}
	}
	return "", false
}

func bridgeCollectSupplements(content []byte) *manifestBridgeSupplements {
	s := &manifestBridgeSupplements{applicationOffset: -1}
	dec := xml.NewDecoder(bytes.NewReader(content))
	var openComponents []int // stack of indices into s.components
	for {
		off := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch el := tok.(type) {
		case xml.StartElement:
			tag := el.Name.Local
			switch {
			case tag == "application":
				if !s.hasApplication {
					s.hasApplication = true
					s.applicationOffset = int(off)
				}
			case isBridgeComponentTag(tag):
				comp := manifestBridgeComponent{kind: tag, offset: int(off)}
				comp.name, _ = bridgeAttr(el.Attr, "name")
				_, comp.hasReadPermission = bridgeAttr(el.Attr, "readPermission")
				_, comp.hasWritePermission = bridgeAttr(el.Attr, "writePermission")
				if aff, ok := bridgeAttr(el.Attr, "taskAffinity"); ok {
					comp.taskAffinityDeclared = true
					comp.taskAffinityEmpty = strings.TrimSpace(aff) == ""
				}
				if rp, ok := bridgeAttr(el.Attr, "allowTaskReparenting"); ok {
					comp.allowTaskReparenting = strings.EqualFold(rp, "true")
				}
				s.components = append(s.components, comp)
				openComponents = append(openComponents, len(s.components)-1)
			case tag == "data":
				if scheme, ok := bridgeAttr(el.Attr, "scheme"); ok && scheme != "" {
					s.data = append(s.data, manifestBridgeData{scheme: scheme, offset: int(off)})
				}
			}
		case xml.EndElement:
			if isBridgeComponentTag(el.Name.Local) && len(openComponents) > 0 {
				idx := openComponents[len(openComponents)-1]
				if s.components[idx].kind == el.Name.Local {
					openComponents = openComponents[:len(openComponents)-1]
				}
			}
		}
	}
	return s
}

func (s *manifestBridgeSupplements) componentByName(name string) *manifestBridgeComponent {
	for i := range s.components {
		if s.components[i].name == name {
			return &s.components[i]
		}
	}
	return nil
}

// bridgeLine converts a byte offset recorded by the supplement walk into a
// 1-based line number, falling back to 1 when no offset is available.
func bridgeLine(ctx *FileDetectContext, offset int) int {
	if offset < 0 {
		return 1
	}
	line := lineAt(ctx.LineOffsets, offset)
	if line <= 0 {
		return 1
	}
	return line
}

func (s *manifestBridgeSupplements) componentLine(ctx *FileDetectContext, name string) int {
	if comp := s.componentByName(name); comp != nil {
		return bridgeLine(ctx, comp.offset)
	}
	return 1
}

func (s *manifestBridgeSupplements) applicationLine(ctx *FileDetectContext) int {
	if s.hasApplication {
		return bridgeLine(ctx, s.applicationOffset)
	}
	return 1
}

// dataLine locates the first <data android:scheme="…"> element for anchoring
// deep-link findings; falls back to the owning component's line.
func (s *manifestBridgeSupplements) dataLine(ctx *FileDetectContext, scheme, componentName string) int {
	for _, d := range s.data {
		if strings.EqualFold(d.scheme, scheme) {
			return bridgeLine(ctx, d.offset)
		}
	}
	return s.componentLine(ctx, componentName)
}

// ── Application-level flags ───────────────────────────────────────────────────

func (d *VulnManifestDetector) bridgeApplicationFlags(report *manifestaudit.Report, supp *manifestBridgeSupplements, ctx *FileDetectContext, analysis *types.FileAnalysis) {
	line := supp.applicationLine(ctx)
	policy := report.ApplicationPolicy

	// Cleartext: the byte scanner matched the literal attribute; the bridge
	// requires the attribute to be declared true AND still effective (a
	// networkSecurityConfig reference defers the decision to that policy
	// file, so the finding is withheld instead of asserted).
	if policy.Cleartext.Declared && policy.Cleartext.Known && policy.Cleartext.Value {
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryCleartextTraffic, analysis.Path,
			line,
			"android:usesCleartextTraffic=\"true\" — allows unencrypted HTTP on Android 9+",
			`usesCleartextTraffic="true"`,
			true,
		))
	}

	// Backup: only an explicit allowBackup="true" declaration is flagged —
	// the platform default (absent attribute) stays out of the pipeline
	// channel, matching the retired scanner's semantics.
	if policy.AllowBackup.Declared && policy.AllowBackup.Value {
		m := newMatch(
			types.CategoryInsecureBackup, analysis.Path,
			line,
			"android:allowBackup=\"true\" — application backup is enabled; extraction depends on Android version and backup rules",
			`allowBackup="true"`,
			false,
		)
		m.Severity = types.SeverityInfo
		m.Metadata = map[string]string{"finding_kind": "inventory", "rule_id": "manifest.backup_enabled", "title": "Application backup enabled"}
		m.Explanation = &finding.Explanation{Status: "observation", Summary: "The manifest enables application backup.",
			Limitations: []string{"This declaration does not prove extraction of private data. Device Android version, target SDK, backup exclusions, dataExtractionRules and user authorization determine actual exposure."},
			NextChecks:  []string{"Inspect the effective backup rules and sensitive data stored in included locations."}}
		analysis.Matches = append(analysis.Matches, m)
	}
}

// ── Privileged / sensitive declared permissions ──────────────────────────────

var bridgePrivilegedPermissions = []string{
	"android.permission.dump",
	"android.permission.read_logs",
	"android.permission.write_secure_settings",
	"android.permission.mount_unmount_filesystems",
	"android.permission.install_packages",
}

var bridgeSensitivePermissions = []string{
	"android.permission.get_accounts",
	"android.permission.read_contacts",
	"android.permission.read_phone_state",
	"android.permission.access_fine_location",
}

func (d *VulnManifestDetector) bridgePermissionFlags(manifest *axml.Manifest, supp *manifestBridgeSupplements, ctx *FileDetectContext, analysis *types.FileAnalysis) {
	declared := make(map[string]struct{}, len(manifest.Permissions)+len(manifest.OptionalPerms))
	for _, perm := range manifest.Permissions {
		declared[strings.ToLower(perm)] = struct{}{}
	}
	for _, perm := range manifest.OptionalPerms {
		declared[strings.ToLower(perm)] = struct{}{}
	}
	if len(declared) == 0 {
		return
	}
	line := supp.applicationLine(ctx)

	for _, pp := range bridgePrivilegedPermissions {
		if _, ok := declared[pp]; !ok {
			continue
		}
		m := newMatch(
			types.CategoryPrivilegedPermission, analysis.Path,
			line,
			fmt.Sprintf("Declares privileged/signature permission %q — not grantable to ordinary apps; unusual for a store build", pp),
			pp,
			false,
		)
		m.Severity = types.SeverityLow
		analysis.Matches = append(analysis.Matches, m)
	}
	for _, sp := range bridgeSensitivePermissions {
		if _, ok := declared[sp]; !ok {
			continue
		}
		m := newMatch(
			types.CategoryPrivilegedPermission, analysis.Path,
			line,
			fmt.Sprintf("Requests sensitive/privacy permission %q", sp),
			sp,
			false,
		)
		m.Severity = types.SeverityLow
		analysis.Matches = append(analysis.Matches, m)
	}
}

// ── Exported components ───────────────────────────────────────────────────────

// bridgeIsLauncherExempt reproduces the launcher-activity exemption: the
// MAIN/LAUNCHER entry point must be reachable for the app to start.
func bridgeIsLauncherExempt(ec manifestaudit.ExportedComponent) bool {
	hasMain := false
	hasLauncher := false
	for _, a := range ec.IntentActions {
		if a == "android.intent.action.MAIN" {
			hasMain = true
			break
		}
	}
	for _, c := range ec.IntentCategories {
		if c == "android.intent.category.LAUNCHER" {
			hasLauncher = true
			break
		}
	}
	return hasMain && hasLauncher
}

func (d *VulnManifestDetector) bridgeExportedComponents(report *manifestaudit.Report, supp *manifestBridgeSupplements, ctx *FileDetectContext, analysis *types.FileAnalysis) {
	effectiveTarget := report.ApplicationPolicy.TargetSDK

	for _, ec := range report.ExportedComponents {
		if !ec.ExportedEffective {
			continue
		}
		if bridgeIsLauncherExempt(ec) {
			continue
		}
		// Permission gate: android:permission from the structured model,
		// plus provider readPermission/writePermission recovered by the
		// supplement walk (the axml component model does not carry them).
		comp := supp.componentByName(ec.Name)
		if ec.Permission != "" || (comp != nil && (comp.hasReadPermission || comp.hasWritePermission)) {
			continue
		}

		tagName := string(ec.Kind)
		line := supp.componentLine(ctx, ec.Name)

		switch {
		case ec.ExportedDeclared != nil && *ec.ExportedDeclared:
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategoryExportedComponent, analysis.Path,
				line,
				fmt.Sprintf("<%s> %s exported=\"true\" without android:permission — reachable and invocable by any app (CWE-926)", tagName, ec.Name),
				fmt.Sprintf("exported %s without permission", tagName),
				ec.Kind == manifestaudit.KindProvider,
			))

		case ec.ExportedDeclared == nil && ec.HasIntentFilter:
			if effectiveTarget >= 31 {
				m := newMatch(
					types.CategoryExportedComponent, analysis.Path,
					line,
					fmt.Sprintf("<%s> %s declares an intent-filter without android:exported — targetSdkVersion >= 31 rejects such manifests at install time; the export must be declared explicitly", tagName, ec.Name),
					fmt.Sprintf("missing android:exported on %s (targetSdk %d)", tagName, effectiveTarget),
					false,
				)
				m.Severity = types.SeverityMedium
				m.Confidence = "high"
				analysis.Matches = append(analysis.Matches, m)
			} else {
				analysis.Matches = append(analysis.Matches, newMatch(
					types.CategoryExportedComponent, analysis.Path,
					line,
					fmt.Sprintf("<%s> %s has an intent-filter without android:exported — implicitly EXPORTED on targetSdk < 31: any app can invoke it (CWE-926)", tagName, ec.Name),
					fmt.Sprintf("implicitly exported %s (intent-filter, no exported attribute)", tagName),
					ec.Kind == manifestaudit.KindProvider,
				))
			}

		case ec.Kind == manifestaudit.KindProvider && ec.ExportedDeclared == nil && !ec.HasIntentFilter:
			// Provider default-export on targetSdk < 17: invisible to the
			// retired byte scanner (which required an intent-filter for
			// implicit exports) but correct Android semantics — manifestaudit
			// is more precise here, so its answer wins.
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategoryExportedComponent, analysis.Path,
				line,
				fmt.Sprintf("<provider> %s omits android:exported on targetSdkVersion < 17 — implicitly EXPORTED by platform default: any app can query it (CWE-926)", ec.Name),
				"implicitly exported provider (platform default, targetSdk < 17)",
				true,
			))
		}
	}
}

// ── StrandHogg / task hijacking ───────────────────────────────────────────────

func (d *VulnManifestDetector) bridgeStrandHogg(report *manifestaudit.Report, supp *manifestBridgeSupplements, ctx *FileDetectContext, analysis *types.FileAnalysis) {
	emitted := make(map[string]bool, 2)

	// Classic StrandHogg shape (CVE-2020-0096): an activity declares an
	// EMPTY taskAffinity together with allowTaskReparenting="true". The axml
	// component model cannot distinguish a declared-empty affinity from an
	// absent one, and allowTaskReparenting is not modeled at all, so this
	// specific pair is recovered from the structured XML walk.
	for i := range supp.components {
		comp := &supp.components[i]
		if !comp.taskAffinityDeclared || !comp.taskAffinityEmpty || !comp.allowTaskReparenting {
			continue
		}
		label := comp.name
		if label == "" {
			label = "<" + comp.kind + ">"
		}
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryStrandHogg, analysis.Path,
			bridgeLine(ctx, comp.offset),
			"StrandHogg: taskAffinity=\"\" + allowTaskReparenting=\"true\" — activity can be hijacked",
			`taskAffinity="" + allowTaskReparenting="true"`,
			true,
		))
		emitted[comp.name] = true
	}

	// Broader task-hijack configurations detected by manifestaudit on the
	// binary attributes (custom non-package taskAffinity, singleTask/
	// singleInstance on legacy targets).
	for _, issue := range report.Issues {
		if issue.ID != "APK-TASK-001" || emitted[issue.Component] {
			continue
		}
		m := newMatch(
			types.CategoryStrandHogg, analysis.Path,
			supp.componentLine(ctx, issue.Component),
			issue.Description,
			"task-hijack configuration ("+issue.Reference+")",
			issue.Severity == manifestaudit.SevMedium ||
				issue.Severity == manifestaudit.SevHigh ||
				issue.Severity == manifestaudit.SevCritical,
		)
		switch issue.Severity {
		case manifestaudit.SevCritical, manifestaudit.SevHigh:
			m.Severity = types.SeverityHigh
		case manifestaudit.SevMedium:
			m.Severity = types.SeverityMedium
		default:
			m.Severity = types.SeverityLow
		}
		analysis.Matches = append(analysis.Matches, m)
	}
}

// ── Hostless custom-scheme deep links ────────────────────────────────────────
//
// Custom-scheme deep links without android:host are hijackable: any app can
// register the same scheme and intercept the URI. http/https app links are
// exempt — without a host they are merely broad, and verified app links gate
// them on domain ownership (audit B8).

// Standard Android intent schemes are designed for sharing and are not app-specific deep links.
func isCommonIntentScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "", "http", "https", "content", "file", "mailto", "tel", "sms", "smsto", "mms", "mmsto", "geo":
		return true
	}
	return false
}

func (d *VulnManifestDetector) bridgeHostlessDeepLinks(report *manifestaudit.Report, supp *manifestBridgeSupplements, ctx *FileDetectContext, analysis *types.FileAnalysis) {
	seen := make(map[string]bool, 4)
	for _, ec := range report.ExportedComponents {
		for _, dl := range ec.DeepLinks {
			if isCommonIntentScheme(dl.Scheme) {
				continue
			}
			if dl.Host != "" {
				continue
			}
			key := ec.Name + "\x00" + dl.Scheme
			if seen[key] {
				continue
			}
			seen[key] = true
			m := newMatch(
				types.CategoryDeepLinkVuln, analysis.Path,
				supp.dataLine(ctx, dl.Scheme, ec.Name),
				fmt.Sprintf("Deep link scheme %q declared without android:host — any app can register the same scheme and intercept these URIs (CWE-939)", dl.Scheme),
				`<data android:scheme="`+dl.Scheme+`"> without android:host`,
				false,
			)
			m.Confidence = "high"
			analysis.Matches = append(analysis.Matches, m)
		}
	}
}

// ── Unverified http(s) App Links (manifestaudit APK-DEEPLINK-001) ────────────
//
// manifestaudit flags browsable VIEW activities whose http(s) deep links are
// not protected by App Link verification (android:autoVerify="true" +
// assetlinks.json). This check exists ONLY in the binary-AXML audit — the
// retired byte scanner exempted http/https entirely. Wiring it into the
// pipeline keeps one manifest code path for every report channel.

func (d *VulnManifestDetector) bridgeUnverifiedAppLinks(report *manifestaudit.Report, supp *manifestBridgeSupplements, ctx *FileDetectContext, analysis *types.FileAnalysis) {
	for _, issue := range report.Issues {
		if issue.ID != "APK-DEEPLINK-001" {
			continue
		}
		m := newMatch(
			types.CategoryDeepLinkVuln, analysis.Path,
			supp.componentLine(ctx, issue.Component),
			issue.Description,
			"unverified http(s) deep link (no android:autoVerify / assetlinks.json)",
			false,
		)
		m.Confidence = "high"
		m.Severity = types.SeverityMedium
		analysis.Matches = append(analysis.Matches, m)
	}
}
