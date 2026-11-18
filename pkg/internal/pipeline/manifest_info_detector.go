// pkg/internal/pipeline/manifest_info_detector.go
package pipeline

import (
	"bytes"
	"regexp"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// dangerousPermissions — permissions classified as "dangerous" by Android (runtime permissions).
var dangerousPermissions = map[string]struct{}{
	"android.permission.READ_CALENDAR":                   {},
	"android.permission.WRITE_CALENDAR":                  {},
	"android.permission.CAMERA":                          {},
	"android.permission.READ_CONTACTS":                   {},
	"android.permission.WRITE_CONTACTS":                  {},
	"android.permission.GET_ACCOUNTS":                    {},
	"android.permission.ACCESS_FINE_LOCATION":            {},
	"android.permission.ACCESS_COARSE_LOCATION":          {},
	"android.permission.ACCESS_BACKGROUND_LOCATION":      {},
	"android.permission.RECORD_AUDIO":                    {},
	"android.permission.READ_PHONE_STATE":                {},
	"android.permission.READ_PHONE_NUMBERS":              {},
	"android.permission.CALL_PHONE":                      {},
	"android.permission.ANSWER_PHONE_CALLS":              {},
	"android.permission.ADD_VOICEMAIL":                   {},
	"android.permission.USE_SIP":                         {},
	"android.permission.BODY_SENSORS":                    {},
	"android.permission.BODY_SENSORS_BACKGROUND":         {},
	"android.permission.SEND_SMS":                        {},
	"android.permission.RECEIVE_SMS":                     {},
	"android.permission.READ_SMS":                        {},
	"android.permission.RECEIVE_WAP_PUSH":                {},
	"android.permission.RECEIVE_MMS":                     {},
	"android.permission.READ_EXTERNAL_STORAGE":           {},
	"android.permission.WRITE_EXTERNAL_STORAGE":          {},
	"android.permission.MANAGE_EXTERNAL_STORAGE":         {},
	"android.permission.READ_MEDIA_IMAGES":               {},
	"android.permission.READ_MEDIA_VIDEO":                {},
	"android.permission.READ_MEDIA_AUDIO":                {},
	"android.permission.ACTIVITY_RECOGNITION":            {},
	"android.permission.READ_CALL_LOG":                   {},
	"android.permission.WRITE_CALL_LOG":                  {},
	"android.permission.PROCESS_OUTGOING_CALLS":          {},
	"android.permission.NEARBY_WIFI_DEVICES":             {},
	"android.permission.POST_NOTIFICATIONS":              {},
	"android.permission.READ_MEDIA_VISUAL_USER_SELECTED": {},
}

// highRiskPermissions — permissions that pose elevated security/privacy risk.
var highRiskPermissions = map[string]struct{}{
	"android.permission.SYSTEM_ALERT_WINDOW":                 {},
	"android.permission.WRITE_SETTINGS":                      {},
	"android.permission.REQUEST_INSTALL_PACKAGES":            {},
	"android.permission.REQUEST_DELETE_PACKAGES":             {},
	"android.permission.BIND_ACCESSIBILITY_SERVICE":          {},
	"android.permission.BIND_DEVICE_ADMIN":                   {},
	"android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":  {},
	"android.permission.PACKAGE_USAGE_STATS":                 {},
	"android.permission.READ_LOGS":                           {},
	"android.permission.CHANGE_NETWORK_STATE":                {},
	"android.permission.RECEIVE_BOOT_COMPLETED":              {},
	"android.permission.FOREGROUND_SERVICE":                  {},
	"android.permission.FOREGROUND_SERVICE_CAMERA":           {},
	"android.permission.FOREGROUND_SERVICE_MICROPHONE":       {},
	"android.permission.FOREGROUND_SERVICE_LOCATION":         {},
	"android.permission.FOREGROUND_SERVICE_DATA_SYNC":        {},
	"android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION": {},
	"android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE": {},
	"android.permission.FOREGROUND_SERVICE_SPECIAL_USE":      {},
	"android.permission.QUERY_ALL_PACKAGES":                  {},
	"android.permission.SCHEDULE_EXACT_ALARM":                {},
	"android.permission.USE_EXACT_ALARM":                     {},
}

// ManifestInfoDetector extracts comprehensive app metadata, security attributes,
// permissions (with risk classification), and exported components from AndroidManifest.xml.
type ManifestInfoDetector struct {
	// Core metadata
	manifestPkgRe  *regexp.Regexp
	appLabelRe     *regexp.Regexp
	versionCodeRe  *regexp.Regexp
	versionNameRe  *regexp.Regexp
	sharedUserIdRe *regexp.Regexp

	// SDK versions
	minSdkRe    *regexp.Regexp
	targetSdkRe *regexp.Regexp

	// Application-level security attributes
	debuggableRe       *regexp.Regexp
	allowBackupRe      *regexp.Regexp
	cleartextTrafficRe *regexp.Regexp
	networkSecConfigRe *regexp.Regexp

	// Permissions
	permRe *regexp.Regexp

	// Exported components
	componentRe  *regexp.Regexp
	exportedAttr *regexp.Regexp
	nameAttr     *regexp.Regexp

	maxPerms      int
	maxComponents int
}

func NewManifestInfoDetector() *ManifestInfoDetector {
	return &ManifestInfoDetector{
		// Core metadata from <manifest ...>
		manifestPkgRe:  regexp.MustCompile(`(?is)<manifest[^>]*\bpackage\s*=\s*"([^"]+)"`),
		versionCodeRe:  regexp.MustCompile(`(?is)<manifest[^>]*\bandroid:versionCode\s*=\s*"([^"]+)"`),
		versionNameRe:  regexp.MustCompile(`(?is)<manifest[^>]*\bandroid:versionName\s*=\s*"([^"]+)"`),
		sharedUserIdRe: regexp.MustCompile(`(?is)<manifest[^>]*\bandroid:sharedUserId\s*=\s*"([^"]+)"`),

		// Application tag attributes
		appLabelRe:         regexp.MustCompile(`(?is)<application[^>]*\bandroid:label\s*=\s*"([^"]+)"`),
		debuggableRe:       regexp.MustCompile(`(?is)<application[^>]*\bandroid:debuggable\s*=\s*"(true)"`),
		allowBackupRe:      regexp.MustCompile(`(?is)<application[^>]*\bandroid:allowBackup\s*=\s*"(true)"`),
		cleartextTrafficRe: regexp.MustCompile(`(?is)<application[^>]*\bandroid:usesCleartextTraffic\s*=\s*"(true)"`),
		networkSecConfigRe: regexp.MustCompile(`(?is)<application[^>]*\bandroid:networkSecurityConfig\s*=\s*"([^"]+)"`),

		// SDK versions
		minSdkRe:    regexp.MustCompile(`(?is)<uses-sdk[^>]*\bandroid:minSdkVersion\s*=\s*"([^"]+)"`),
		targetSdkRe: regexp.MustCompile(`(?is)<uses-sdk[^>]*\bandroid:targetSdkVersion\s*=\s*"([^"]+)"`),

		// Permissions: both uses-permission and uses-permission-sdk-23
		permRe: regexp.MustCompile(`(?is)<uses-permission(?:-sdk-23)?\s[^>]*\bandroid:name\s*=\s*"([^"]+)"`),

		// Component detection for exported analysis
		componentRe:  regexp.MustCompile(`(?is)<(activity|service|receiver|provider)(\s[^>]*)/?>`),
		exportedAttr: regexp.MustCompile(`(?i)\bandroid:exported\s*=\s*"true"`),
		nameAttr:     regexp.MustCompile(`(?i)\bandroid:name\s*=\s*"([^"]+)"`),

		maxPerms:      100,
		maxComponents: 200,
	}
}

func (d *ManifestInfoDetector) Name() string { return "manifest_info" }

func (d *ManifestInfoDetector) SupportsFile(fileType types.FileType, path string) bool {
	return fileType == types.FileTypeXML && d.isAndroidManifest(path)
}

func (d *ManifestInfoDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType != types.FileTypeXML {
		return
	}
	if !d.isAndroidManifest(ctx.Path) {
		return
	}

	d.extractManifestMeta(ctx, analysis)
	d.extractAppAttributes(ctx, analysis)
	d.extractSdkVersions(ctx, analysis)
	d.extractPermissions(ctx, analysis)
	d.extractExportedComponents(ctx, analysis)
}

// isAndroidManifest checks if the file path ends with AndroidManifest.xml
// preceded by a path separator (or is exactly the filename).
func (d *ManifestInfoDetector) isAndroidManifest(path string) bool {
	return isAndroidManifestPath(path)
}

// isAndroidManifestPath is the package-level form of the check above so the
// pipeline can recognise the manifest before any detector runs.
func isAndroidManifestPath(path string) bool {
	lower := strings.ToLower(path)
	const target = "androidmanifest.xml"
	if !strings.HasSuffix(lower, target) {
		return false
	}
	// Ensure it's a full filename, not e.g. "xandroidmanifest.xml"
	if len(lower) == len(target) {
		return true
	}
	preceding := lower[len(lower)-len(target)-1]
	return preceding == '/' || preceding == '\\'
}

// extractManifestMeta extracts package name, versionCode, versionName, sharedUserId from <manifest>.
func (d *ManifestInfoDetector) extractManifestMeta(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	type metaEntry struct {
		re   *regexp.Regexp
		desc string
	}
	entries := []metaEntry{
		{d.manifestPkgRe, "Manifest package name"},
		{d.versionCodeRe, "Version code"},
		{d.versionNameRe, "Version name"},
		{d.sharedUserIdRe, "Shared user ID"},
	}
	for _, e := range entries {
		if m := e.re.FindSubmatchIndex(ctx.Content); len(m) >= 4 {
			val := string(ctx.Content[m[2]:m[3]])
			line := lineAt(ctx.LineOffsets, m[0])
			suspicious := e.desc == "Shared user ID"
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategoryManifestInfo,
				analysis.Path, line,
				e.desc, val, suspicious,
			))
		}
	}
}

// extractAppAttributes extracts security-sensitive attributes from <application>.
func (d *ManifestInfoDetector) extractAppAttributes(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	// Application label (informational)
	if m := d.appLabelRe.FindSubmatchIndex(ctx.Content); len(m) >= 4 {
		label := string(ctx.Content[m[2]:m[3]])
		line := lineAt(ctx.LineOffsets, m[0])
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryManifestInfo,
			analysis.Path, line,
			"Application label", label, false,
		))
	}

	// Debuggable (critical security issue)
	if m := d.debuggableRe.FindSubmatchIndex(ctx.Content); len(m) >= 4 {
		line := lineAt(ctx.LineOffsets, m[0])
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryManifestInfo,
			analysis.Path, line,
			"Application is debuggable", "true", true,
		))
	}

	// allowBackup (security concern)
	if m := d.allowBackupRe.FindSubmatchIndex(ctx.Content); len(m) >= 4 {
		line := lineAt(ctx.LineOffsets, m[0])
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryManifestInfo,
			analysis.Path, line,
			// A hardening note, not a crack indicator — never critical.
			"Application allows backup", "true", false,
		))
	}

	// Cleartext traffic
	if m := d.cleartextTrafficRe.FindSubmatchIndex(ctx.Content); len(m) >= 4 {
		line := lineAt(ctx.LineOffsets, m[0])
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryManifestInfo,
			analysis.Path, line,
			"Cleartext traffic allowed", "true", true,
		))
	}

	// Network security config (informational)
	if m := d.networkSecConfigRe.FindSubmatchIndex(ctx.Content); len(m) >= 4 {
		val := string(ctx.Content[m[2]:m[3]])
		line := lineAt(ctx.LineOffsets, m[0])
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryManifestInfo,
			analysis.Path, line,
			"Network security config", val, false,
		))
	}
}

// extractSdkVersions extracts minSdkVersion and targetSdkVersion.
func (d *ManifestInfoDetector) extractSdkVersions(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if m := d.minSdkRe.FindSubmatchIndex(ctx.Content); len(m) >= 4 {
		val := string(ctx.Content[m[2]:m[3]])
		line := lineAt(ctx.LineOffsets, m[0])
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryManifestInfo,
			analysis.Path, line,
			"Min SDK version", val, false,
		))
	}
	if m := d.targetSdkRe.FindSubmatchIndex(ctx.Content); len(m) >= 4 {
		val := string(ctx.Content[m[2]:m[3]])
		line := lineAt(ctx.LineOffsets, m[0])
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryManifestInfo,
			analysis.Path, line,
			"Target SDK version", val, false,
		))
	}
}

// extractPermissions extracts uses-permission and uses-permission-sdk-23 entries
// with deduplication and risk classification.
func (d *ManifestInfoDetector) extractPermissions(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	matches := d.permRe.FindAllSubmatchIndex(ctx.Content, d.maxPerms)
	if len(matches) == 0 {
		return
	}

	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		if len(m) < 4 {
			continue
		}
		perm := string(bytes.TrimSpace(ctx.Content[m[2]:m[3]]))
		if perm == "" {
			continue
		}
		if _, ok := seen[perm]; ok {
			continue
		}
		seen[perm] = struct{}{}

		line := lineAt(ctx.LineOffsets, m[0])

		// Classify risk level
		desc, _ := d.classifyPermission(perm)

		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryManifestPermission,
			analysis.Path, line,
			desc, perm, false,
		))
	}
}

// classifyPermission returns (description, isSuspicious) based on permission risk level.
func (d *ManifestInfoDetector) classifyPermission(perm string) (string, bool) {
	if _, ok := highRiskPermissions[perm]; ok {
		return "High-risk permission", true
	}
	if _, ok := dangerousPermissions[perm]; ok {
		return "Dangerous permission (runtime)", true
	}
	return "Declared permission", false
}

// extractExportedComponents finds activities, services, receivers, and providers
// with android:exported="true".
func (d *ManifestInfoDetector) extractExportedComponents(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	matches := d.componentRe.FindAllSubmatchIndex(ctx.Content, d.maxComponents)
	if len(matches) == 0 {
		return
	}

	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		// m[0]:m[1] = full match, m[2]:m[3] = component type, m[4]:m[5] = attributes (may be -1)
		if len(m) < 6 || m[4] < 0 || m[5] < 0 {
			continue
		}
		attrs := ctx.Content[m[4]:m[5]]

		// Check for android:exported="true"
		if !d.exportedAttr.Match(attrs) {
			continue
		}

		// Extract android:name
		nameMatch := d.nameAttr.FindSubmatch(attrs)
		if nameMatch == nil {
			continue
		}
		name := string(bytes.TrimSpace(nameMatch[1]))
		if name == "" {
			continue
		}

		compType := string(ctx.Content[m[2]:m[3]])
		key := compType + ":" + name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		line := lineAt(ctx.LineOffsets, m[0])
		desc := "Exported " + compType
		// Inventory entry, not a vulnerability — the launcher activity of
		// every app is exported by design. Never critical.
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryManifestInfo,
			analysis.Path, line,
			desc, name, false,
		))
	}
}
