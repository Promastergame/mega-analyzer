package manifestaudit

import (
	"sort"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/apkloader/axml"
)

// Audit runs the full set of static checks on a parsed manifest and
// returns a report. The target string is informational (used in JSON
// output) — pass the .apk / directory path here.
func Audit(target string, m *axml.Manifest) *Report {
	r := &Report{
		GeneratedAt: time.Now().UTC(),
		Target:      target,
	}
	if m == nil {
		r.Verdict = "no_manifest"
		return r
	}

	r.Package = m.Package
	r.MinSDK = m.MinSDK
	r.TargetSDK = m.TargetSDK
	r.VersionCode = m.VersionCode
	r.VersionName = m.VersionName
	r.SharedUserID = m.SharedUserID

	r.ApplicationPolicy = EffectiveApplicationPolicy(m, EffectiveTargetSDK(m))
	r.Debuggable = m.Application.Debuggable
	r.AllowBackup = r.ApplicationPolicy.AllowBackup.Value
	r.UsesCleartext = r.ApplicationPolicy.Cleartext.Known && r.ApplicationPolicy.Cleartext.Value
	r.HasNetworkSecCfg = strings.TrimSpace(m.Application.NetworkSecCfg) != ""
	r.ExtractNativeLibs = m.Application.ExtractNativeLibs

	r.Counts.Activities = len(m.Activities)
	r.Counts.Services = len(m.Services)
	r.Counts.Receivers = len(m.Receivers)
	r.Counts.Providers = len(m.Providers)

	checkApplicationFlags(r, m)
	checkSDKConfig(r, m)
	checkSharedUserID(r, m)

	exported := collectExported(r, m)
	r.ExportedComponents = exported
	for _, c := range exported {
		switch c.Kind {
		case KindActivity:
			r.Counts.ExportedActivities++
		case KindService:
			r.Counts.ExportedServices++
		case KindReceiver:
			r.Counts.ExportedReceivers++
		case KindProvider:
			r.Counts.ExportedProviders++
			r.WorldAccessProvider = append(r.WorldAccessProvider, c)
		}
	}

	finalizeIssues(r)
	r.Score, r.Verdict = scoreReport(r)
	return r
}

// effectiveExported applies Android's default-export rules.
//
// For activities / services / receivers:
//   - exported declared explicitly: use it.
//   - else: exported if there is at least one <intent-filter>.
//
// For providers:
//   - exported declared explicitly: use it.
//   - else (Android <17): true ; (Android >=17): false.
func effectiveExported(c axml.Component, kind ComponentKind, targetSDK uint32) bool {
	if c.Exported != nil {
		return *c.Exported
	}
	if kind == KindProvider {
		return targetSDK < 17
	}
	return len(c.IntentFilts) > 0
}

func collectExported(r *Report, m *axml.Manifest) []ExportedComponent {
	var out []ExportedComponent
	collect := func(items []axml.Component, kind ComponentKind) {
		for _, c := range items {
			targetSDK := EffectiveTargetSDK(m)
			eff := effectiveExported(c, kind, targetSDK)
			hasFilters := len(c.IntentFilts) > 0
			if kind != KindProvider && targetSDK >= 31 && c.Exported == nil && hasFilters {
				r.Issues = append(r.Issues, Issue{
					ID:            "component_missing_exported_android12",
					Title:         "Component with intent filter omits android:exported",
					Description:   "Apps targeting Android 12 or newer must explicitly declare android:exported for components with intent filters; the package cannot be installed reliably until this is fixed.",
					Severity:      SevMedium,
					Score:         8,
					Component:     c.Name,
					ComponentKind: kind,
					Reference:     "Android 12 behavior changes; CWE-16",
				})
			}
			if !eff && !hasFilters {
				continue
			}
			ec := ExportedComponent{
				Name:              c.Name,
				Kind:              kind,
				ExportedDeclared:  c.Exported,
				ExportedEffective: eff,
				HasIntentFilter:   hasFilters,
				Permission:        c.Permission,
				ReadPermission:    c.ReadPermission,
				WritePermission:   c.WritePermission,
				Authorities:       c.Authorities,
			}
			actSet := map[string]struct{}{}
			catSet := map[string]struct{}{}
			verified := c.AutoVerify != nil && *c.AutoVerify
			for _, f := range c.IntentFilts {
				schemeSeen := map[string]struct{}{}
				for _, a := range f.Actions {
					if a != "" {
						actSet[a] = struct{}{}
					}
				}
				for _, cat := range f.Categories {
					if cat != "" {
						catSet[cat] = struct{}{}
					}
				}
				for _, s := range f.DataScheme {
					if _, dup := schemeSeen[s]; dup {
						// Hosts are pooled per filter in the axml model, so a
						// repeated scheme would only duplicate the DeepLink.
						continue
					}
					schemeSeen[s] = struct{}{}
					dl := parseDeepLink(s, f)
					dl.Verified = verified
					ec.DeepLinks = append(ec.DeepLinks, dl)
				}
			}
			ec.IntentActions = sortedKeys(actSet)
			ec.IntentCategories = sortedKeys(catSet)

			ec.Severity, ec.Risk = classifyComponent(ec, c, kind, m)
			r.Issues = append(r.Issues, perComponentIssues(ec, c, kind, m)...)
			out = append(out, ec)
		}
	}
	collect(m.Activities, KindActivity)
	collect(m.Services, KindService)
	collect(m.Receivers, KindReceiver)
	collect(m.Providers, KindProvider)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// parseDeepLink materializes one scheme of an intent-filter into a DeepLink.
// Every <data android:host> entry of the filter is preserved in Hosts
// (deduplicated, declaration order); Host keeps the first one for
// backward-compatible consumers.
func parseDeepLink(scheme string, f axml.IntentFilter) DeepLink {
	dl := DeepLink{Scheme: scheme}
	seen := make(map[string]struct{}, len(f.DataHost))
	for _, h := range f.DataHost {
		if h == "" {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		dl.Hosts = append(dl.Hosts, h)
	}
	if len(dl.Hosts) > 0 {
		dl.Host = dl.Hosts[0]
	}
	return dl
}

// classifyComponent returns the worst-case severity and a short
// human-readable reason for the component.
func classifyComponent(ec ExportedComponent, c axml.Component, kind ComponentKind, m *axml.Manifest) (Severity, string) {
	if !ec.ExportedEffective {
		return SevInfo, "intent-filter present but not exported"
	}
	if ec.Permission == "" {
		switch kind {
		case KindProvider:
			if EffectiveTargetSDK(m) < 17 && c.Exported == nil {
				return SevHigh, "Provider exported by default on minSdk<17 without permission"
			}
			return SevHigh, "Exported provider without android:permission"
		case KindReceiver:
			return SevMedium, "Exported receiver without android:permission"
		case KindService:
			return SevMedium, "Exported service without android:permission"
		case KindActivity:
			if hasBrowsableViewFilter(ec) {
				return SevMedium, "Exported activity with browsable VIEW intent (deep link)"
			}
			if hasMainLauncher(ec) {
				return SevInfo, "MAIN/LAUNCHER activity (expected to be exported)"
			}
			return SevLow, "Exported activity without android:permission"
		}
	}
	return SevInfo, "exported with permission guard"
}

func hasBrowsableViewFilter(ec ExportedComponent) bool {
	hasView := false
	hasBrowsable := false
	for _, a := range ec.IntentActions {
		if a == "android.intent.action.VIEW" {
			hasView = true
			break
		}
	}
	for _, c := range ec.IntentCategories {
		if c == "android.intent.category.BROWSABLE" {
			hasBrowsable = true
			break
		}
	}
	return hasView && hasBrowsable
}

func hasMainLauncher(ec ExportedComponent) bool {
	hasMain := false
	hasLauncher := false
	for _, a := range ec.IntentActions {
		if a == "android.intent.action.MAIN" {
			hasMain = true
		}
	}
	for _, c := range ec.IntentCategories {
		if c == "android.intent.category.LAUNCHER" {
			hasLauncher = true
		}
	}
	return hasMain && hasLauncher
}

func perComponentIssues(ec ExportedComponent, c axml.Component, kind ComponentKind, m *axml.Manifest) []Issue {
	var out []Issue
	if !ec.ExportedEffective {
		return out
	}
	switch kind {
	case KindProvider:
		if ec.Permission == "" {
			sev := SevHigh
			score := 18
			if EffectiveTargetSDK(m) < 17 && c.Exported == nil {
				sev = SevCritical
				score = 25
			}
			out = append(out, Issue{
				ID:            "provider_exported_no_permission",
				Title:         "Exported provider without android:permission",
				Description:   "Content provider " + ec.Name + " is exported and reachable from any app on the device. Without android:permission attribute, any installed app may read or write data through it.",
				Severity:      sev,
				Score:         score,
				Component:     ec.Name,
				ComponentKind: kind,
				Reference:     "OWASP MASVS-PLATFORM-1; CWE-926",
			})
		}
		if c.Permission != "" && c.ReadPermission == "" && c.WritePermission == "" {
			out = append(out, Issue{
				ID: "provider_coarse_permission", Title: "Provider uses one permission for read and write",
				Description: "Provider " + ec.Name + " relies on android:permission for both operations. Split android:readPermission and android:writePermission when callers need different privileges.",
				Severity:    SevLow, Score: 3, Component: ec.Name, ComponentKind: kind,
				Reference: "CWE-732; MASVS-PLATFORM-1",
			})
		}
		if c.WritePermission == "" {
			out = append(out, Issue{
				ID: "provider_missing_write_permission", Title: "Exported provider has no explicit write permission",
				Description: "Provider " + ec.Name + " is exported without android:writePermission. Verify that write/update/delete operations are blocked or protected by a signature-level permission.",
				Severity:    SevHigh, Score: 14, Component: ec.Name, ComponentKind: kind,
				Reference: "CWE-926; MASVS-PLATFORM-1",
			})
		}
		if c.GrantUriPermissions != nil && *c.GrantUriPermissions {
			out = append(out, Issue{
				ID:            "provider_grant_uri_permissions",
				Title:         "Exported provider grants URI permissions",
				Description:   "Provider " + ec.Name + " is exported with android:grantUriPermissions=\"true\". Temporary URI grants bypass android:permission, so a path-traversal or over-broad <grant-uri-permission> path can leak private files to any app that receives a granted Uri. Scope grants with <path-permission>/FileProvider and keep the provider android:exported=\"false\" if internal.",
				Severity:      SevMedium,
				Score:         9,
				Component:     ec.Name,
				ComponentKind: kind,
				Reference:     "CWE-926; MASVS-STORAGE-2",
			})
		}
	case KindReceiver:
		if ec.Permission == "" && !isSystemReceiver(ec) {
			out = append(out, Issue{
				ID:            "receiver_exported_no_permission",
				Title:         "Exported broadcast receiver without permission",
				Description:   "Receiver " + ec.Name + " accepts broadcasts from any app. Use android:permission or android:exported=\"false\" if internal.",
				Severity:      SevMedium,
				Score:         10,
				Component:     ec.Name,
				ComponentKind: kind,
				Reference:     "OWASP MASVS-PLATFORM-1; CWE-925",
			})
		}
	case KindService:
		if ec.Permission == "" {
			out = append(out, Issue{
				ID:            "service_exported_no_permission",
				Title:         "Exported service without permission",
				Description:   "Service " + ec.Name + " can be bound or started by any app on the device.",
				Severity:      SevMedium,
				Score:         12,
				Component:     ec.Name,
				ComponentKind: kind,
				Reference:     "OWASP MASVS-PLATFORM-1; CWE-925",
			})
		}
	case KindActivity:
		if hasBrowsableViewFilter(ec) {
			// APK-DEEPLINK-001: http(s) deep links are risky unless they are
			// verified Android App Links. https + android:autoVerify="true"
			// hands URL-pattern ownership to the OS (assetlinks.json check),
			// so those filters are exempt. http can never be verified —
			// App Link verification requires https — hence it stays flagged
			// even when autoVerify is declared.
			hasHTTP := false
			hasUnverifiedHTTPS := false
			for _, dl := range ec.DeepLinks {
				switch dl.Scheme {
				case "http":
					hasHTTP = true
				case "https":
					if !dl.Verified {
						hasUnverifiedHTTPS = true
					}
				}
			}
			if hasHTTP || hasUnverifiedHTTPS {
				var reasons []string
				if hasUnverifiedHTTPS {
					reasons = append(reasons, "its https links are declared without android:autoVerify=\"true\", so no /.well-known/assetlinks.json ownership check runs")
				}
				if hasHTTP {
					reasons = append(reasons, "its http links can never pass App Link verification (verification requires https), regardless of autoVerify")
				}
				out = append(out, Issue{
					ID:            "APK-DEEPLINK-001",
					Title:         "HTTP(S) deep link without App Link verification",
					Description:   "Activity " + ec.Name + " accepts http(s) deep links that are not protected by App Link verification: " + strings.Join(reasons, "; ") + ". Any app can register the same URL pattern and intercept these links. Verified https App Links (android:autoVerify=\"true\" + assetlinks.json) are exempt from this finding.",
					Severity:      SevMedium,
					Score:         10,
					Component:     ec.Name,
					ComponentKind: kind,
					Reference:     "Android App Links; CWE-939",
				})
			}
		}
		if iss := taskHijackIssue(ec, c, m); iss != nil {
			out = append(out, *iss)
		}
	}
	if c.Process != "" && !strings.HasPrefix(c.Process, ":") {
		// Public process name suggests cross-app sharing.
		out = append(out, Issue{
			ID:            "component_public_process",
			Title:         "Component runs in a public (non-private) process",
			Description:   "Component " + ec.Name + " uses android:process=\"" + c.Process + "\" which is not a private \":\"-prefixed process.",
			Severity:      SevLow,
			Score:         3,
			Component:     ec.Name,
			ComponentKind: kind,
			Reference:     "Android process model",
		})
	}
	return out
}

// normalizeLaunchMode maps the numeric android:launchMode enum to its symbolic
// name so the task-hijacking check works whether the binary XML carried the int
// or the keyword form.
func normalizeLaunchMode(s string) string {
	switch s {
	case "0":
		return "standard"
	case "1":
		return "singleTop"
	case "2":
		return "singleTask"
	case "3":
		return "singleInstance"
	case "4":
		return "singleInstancePerTask"
	default:
		return s
	}
}

// taskHijackIssue flags activities configured in a way that enables task
// hijacking (StrandHogg): a custom android:taskAffinity, or a singleTask/
// singleInstance launch mode, on a reachable (exported / filtered) activity.
// A malicious app declaring a matching task affinity can reparent its own
// activities into the victim's task to phish the user or capture input.
//
// To keep false positives low, a custom taskAffinity is the primary signal
// (always flagged). A single* launch mode on its own is only flagged on legacy
// targets (targetSdk < 28, before Android's task-reparenting mitigations) and
// never for the MAIN/LAUNCHER activity, where single* is the normal pattern.
func taskHijackIssue(ec ExportedComponent, c axml.Component, m *axml.Manifest) *Issue {
	if !ec.ExportedEffective {
		return nil
	}
	lm := normalizeLaunchMode(c.LaunchMode)
	customAffinity := c.TaskAffinity != "" && c.TaskAffinity != m.Package
	singleMode := lm == "singleTask" || lm == "singleInstance"
	if !customAffinity && !singleMode {
		return nil
	}
	if !customAffinity {
		// single* alone: ignore on modern targets and on the launcher.
		if hasMainLauncher(ec) || m.TargetSDK == 0 || m.TargetSDK >= 28 {
			return nil
		}
	}

	var reasons []string
	if customAffinity {
		reasons = append(reasons, "custom android:taskAffinity=\""+c.TaskAffinity+"\"")
	}
	if singleMode {
		reasons = append(reasons, "android:launchMode=\""+lm+"\"")
	}

	sev := SevLow
	score := 5
	if customAffinity {
		sev = SevMedium
		score = 10
	}
	impact := ""
	if m.TargetSDK != 0 && m.TargetSDK < 28 {
		score += 4
		impact = " targetSdk<28 lacks Android's task-reparenting mitigations, making this directly exploitable."
	}

	return &Issue{
		ID:            "APK-TASK-001",
		Title:         "Activity exposed to task hijacking (StrandHogg)",
		Description:   "Activity " + ec.Name + " is exported and uses " + strings.Join(reasons, " + ") + ". A malicious app declaring a matching task affinity can insert its activities into this task to phish the user or capture input. Set android:taskAffinity=\"\" and avoid singleTask/singleInstance for exposed activities." + impact,
		Severity:      sev,
		Score:         score,
		Component:     ec.Name,
		ComponentKind: KindActivity,
		Reference:     "CVE-2020-0096 (StrandHogg 2.0); MASVS-PLATFORM-1; CWE-926",
	}
}

// isSystemReceiver heuristically checks if a receiver only listens to
// system-protected actions (BOOT_COMPLETED, etc) — those broadcasts
// can only be sent by the OS, so missing permission is fine there.
func isSystemReceiver(ec ExportedComponent) bool {
	if len(ec.IntentActions) == 0 {
		return false
	}
	for _, a := range ec.IntentActions {
		switch a {
		case "android.intent.action.BOOT_COMPLETED",
			"android.intent.action.MY_PACKAGE_REPLACED",
			"android.intent.action.PACKAGE_REPLACED",
			"android.intent.action.LOCKED_BOOT_COMPLETED",
			"android.intent.action.TIME_SET",
			"android.intent.action.TIMEZONE_CHANGED":
			continue
		default:
			return false
		}
	}
	return true
}

func checkApplicationFlags(r *Report, m *axml.Manifest) {
	if m.Application.Debuggable {
		r.Issues = append(r.Issues, Issue{
			ID:          "app_debuggable",
			Title:       "Application is debuggable",
			Description: "android:debuggable=\"true\" allows arbitrary code execution via run-as / adb. Must be false for release builds.",
			Severity:    SevHigh,
			Score:       20,
			Reference:   "OWASP MASVS-RESILIENCE-1; CWE-489",
		})
	}
	policy := r.ApplicationPolicy
	if policy.AllowBackup.Value && (policy.BackupRules == "" || strings.EqualFold(policy.BackupRules, "true")) {
		r.Issues = append(r.Issues, Issue{
			ID:          "app_allow_backup",
			Title:       "Application data backup is not scoped",
			Description: "Application backup is enabled by manifest or platform default without dataExtractionRules/fullBackupContent restrictions. Sensitive application data may be transferred through cloud or device-to-device backup.",
			Severity:    SevMedium,
			Score:       8,
			Reference:   "OWASP MASVS-STORAGE-2; CWE-200",
		})
	}
	if policy.Cleartext.Known && policy.Cleartext.Value {
		r.Issues = append(r.Issues, Issue{
			ID:          "app_cleartext_traffic",
			Title:       "Cleartext HTTP traffic permitted",
			Description: "android:usesCleartextTraffic=\"true\" allows unencrypted HTTP traffic.",
			Severity:    SevMedium,
			Score:       10,
			Reference:   "OWASP MASVS-NETWORK-1; CWE-319",
		})
	}
}

func checkSDKConfig(r *Report, m *axml.Manifest) {
	if m.MinSDK != 0 && m.MinSDK < 21 {
		r.Issues = append(r.Issues, Issue{
			ID:          "min_sdk_too_low",
			Title:       "minSdkVersion is below 21 (Android 5.0)",
			Description: "Old Android versions lack ASLR, modern TLS, scoped storage and many hardening features. minSdk<21 widens the attack surface considerably.",
			Severity:    SevMedium,
			Score:       8,
			Reference:   "MASVS-PLATFORM-1",
		})
	}
	if m.TargetSDK != 0 && m.TargetSDK < 28 {
		r.Issues = append(r.Issues, Issue{
			ID:          "target_sdk_outdated",
			Title:       "targetSdkVersion is outdated",
			Description: "targetSdkVersion below 28 disables several platform hardening (NSC defaults, file:// share clamp-down, etc).",
			Severity:    SevLow,
			Score:       4,
			Reference:   "MASVS-PLATFORM-2",
		})
	}
}

func checkSharedUserID(r *Report, m *axml.Manifest) {
	if m.SharedUserID == "" {
		return
	}
	sev := SevMedium
	score := 8
	if strings.HasPrefix(m.SharedUserID, "android.uid.system") {
		sev = SevCritical
		score = 25
	}
	r.Issues = append(r.Issues, Issue{
		ID:          "shared_user_id",
		Title:       "Uses android:sharedUserId",
		Description: "sharedUserId=\"" + m.SharedUserID + "\" makes this app share a Linux UID with any other app declaring the same id. Allows file-system cross-access. Deprecated since API 29.",
		Severity:    sev,
		Score:       score,
		Reference:   "CWE-732; deprecated since API 29",
	})
}

func finalizeIssues(r *Report) {
	// Stable severity-then-score order, then count per severity.
	sort.SliceStable(r.Issues, func(i, j int) bool {
		if r.Issues[i].Severity != r.Issues[j].Severity {
			return severityRank(r.Issues[i].Severity) > severityRank(r.Issues[j].Severity)
		}
		if r.Issues[i].Score != r.Issues[j].Score {
			return r.Issues[i].Score > r.Issues[j].Score
		}
		return r.Issues[i].ID < r.Issues[j].ID
	})
	for _, is := range r.Issues {
		switch is.Severity {
		case SevCritical:
			r.Counts.Critical++
		case SevHigh:
			r.Counts.High++
		case SevMedium:
			r.Counts.Medium++
		case SevLow:
			r.Counts.Low++
		default:
			r.Counts.Info++
		}
	}
}

func severityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

func scoreReport(r *Report) (int, string) {
	total := 0
	for _, is := range r.Issues {
		total += is.Score
	}
	if total > 100 {
		total = 100
	}
	switch {
	case total >= 60:
		return total, "dangerous"
	case total >= 30:
		return total, "weak"
	case total >= 10:
		return total, "ok"
	default:
		return total, "hardened"
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
