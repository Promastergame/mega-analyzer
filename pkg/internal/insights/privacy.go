package insights

import (
	"archive/zip"
	"bytes"
	"io"
	"mega-analyzer/pkg/internal/apkloader/axml"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type privacyPattern struct {
	Name     string
	Category string
	Needles  []string
}

var privacySources = []privacyPattern{
	{Name: "Android ID", Category: "device_id", Needles: []string{"android_id", "Settings$Secure;->getString"}},
	{Name: "Advertising ID", Category: "ad_id", Needles: []string{"AdvertisingIdClient", "getAdvertisingIdInfo"}},
	{Name: "IMEI / device ID", Category: "device_id", Needles: []string{"TelephonyManager;->getDeviceId", "TelephonyManager;->getImei", "getDeviceId()"}},
	{Name: "Subscriber ID", Category: "subscriber_id", Needles: []string{"getSubscriberId", "getSimSerialNumber"}},
	{Name: "Location", Category: "location", Needles: []string{"getLastKnownLocation", "requestLocationUpdates", "FusedLocationProviderClient"}},
	{Name: "Contacts", Category: "contacts", Needles: []string{"ContactsContract", "READ_CONTACTS"}},
	{Name: "SMS", Category: "sms", Needles: []string{"SmsManager", "READ_SMS", "RECEIVE_SMS"}},
	{Name: "Camera", Category: "camera", Needles: []string{"android/hardware/Camera", "androidx/camera", "CAMERA"}},
	{Name: "Microphone", Category: "microphone", Needles: []string{"MediaRecorder", "AudioRecord", "RECORD_AUDIO"}},
	{Name: "Clipboard", Category: "clipboard", Needles: []string{"ClipboardManager", "getPrimaryClip"}},
	{Name: "Installed apps", Category: "app_inventory", Needles: []string{"getInstalledPackages", "getInstalledApplications", "QUERY_ALL_PACKAGES"}},
}

var privacySinks = []privacyPattern{
	{Name: "OkHttp", Category: "network", Needles: []string{"okhttp3/OkHttpClient", "Lokhttp3/Request", "OkHttpClient"}},
	{Name: "HttpURLConnection", Category: "network", Needles: []string{"HttpURLConnection", "openConnection"}},
	{Name: "Retrofit", Category: "network", Needles: []string{"retrofit2/", "Retrofit;"}},
	{Name: "Volley", Category: "network", Needles: []string{"com/android/volley", "Volley"}},
	{Name: "WebView bridge", Category: "webview", Needles: []string{"addJavascriptInterface", "setJavaScriptEnabled"}},
	{Name: "JSON serialization", Category: "serialization", Needles: []string{"JSONObject;->put", "Gson", "Moshi"}},
	{Name: "SharedPreferences", Category: "local_storage", Needles: []string{"SharedPreferences$Editor;->put", "getSharedPreferences"}},
	{Name: "File write", Category: "local_storage", Needles: []string{"FileOutputStream", "->write("}},
}

var trackerPatterns = []privacyPattern{
	{Name: "Firebase Analytics", Category: "tracker", Needles: []string{"firebase/analytics", "FirebaseAnalytics", "google-services.json"}},
	{Name: "Crashlytics", Category: "tracker", Needles: []string{"crashlytics", "FirebaseCrashlytics"}},
	{Name: "Facebook SDK", Category: "tracker", Needles: []string{"com/facebook/", "FacebookSdk"}},
	{Name: "AppsFlyer", Category: "tracker", Needles: []string{"appsflyer", "AppsFlyerLib"}},
	{Name: "Adjust", Category: "tracker", Needles: []string{"adjust/sdk", "AdjustConfig"}},
	{Name: "Amplitude", Category: "tracker", Needles: []string{"amplitude", "AmplitudeClient"}},
	{Name: "Mixpanel", Category: "tracker", Needles: []string{"mixpanel", "MixpanelAPI"}},
	{Name: "Flurry", Category: "tracker", Needles: []string{"flurry", "FlurryAgent"}},
	{Name: "Unity Ads", Category: "tracker", Needles: []string{"unityads", "UnityAds"}},
	{Name: "AdMob", Category: "tracker", Needles: []string{"gms/ads", "AdView", "MobileAds"}},
}

func AnalyzePrivacy(target string) (*PrivacyReport, error) {
	files, err := LoadFiles(target, LoadOptions{MaxBytesPerFile: 8 << 20})
	if err != nil {
		return nil, err
	}
	report := &PrivacyReport{GeneratedAt: time.Now(), Target: target}
	seenPerm := map[string]struct{}{}
	seenEndpoint := map[string]struct{}{}
	seenTracker := map[string]struct{}{}

	// Load declared permissions from the manifest first. These are
	// the source of truth — anything the app actually requests at
	// install/runtime appears here. Smali-only matches downstream
	// are categorized as "code" Origin so reports don't conflate
	// SDK-internal permission strings with grants the app declares.
	declaredPerms := loadManifestPermissions(target)
	for _, p := range declaredPerms {
		if _, ok := seenPerm[p]; ok {
			continue
		}
		seenPerm[p] = struct{}{}
		report.Permissions = append(report.Permissions, PrivacySignal{
			Name:     p,
			Category: "permission",
			Path:     "AndroidManifest.xml",
			Origin:   "manifest",
		})
	}

	for _, f := range files {
		lower := bytes.ToLower(f.Data)
		// Skip the manifest in the regex pass — we already covered it.
		isManifest := strings.EqualFold(filepath.Base(f.Path), "AndroidManifest.xml")
		if !isManifest {
			for _, p := range extractPermissions(f.Data) {
				if _, ok := seenPerm[p]; !ok {
					seenPerm[p] = struct{}{}
					report.Permissions = append(report.Permissions, PrivacySignal{
						Name:     p,
						Category: "permission",
						Path:     f.Path,
						Origin:   "code",
					})
				}
			}
		}
		for _, u := range extractURLs(f.Data) {
			if _, ok := seenEndpoint[u]; !ok {
				seenEndpoint[u] = struct{}{}
				report.Endpoints = append(report.Endpoints, PrivacySignal{Name: u, Category: "endpoint", Path: f.Path})
			}
		}
		sources := matchPrivacyPatterns(f, lower, privacySources)
		sinks := matchPrivacyPatterns(f, lower, privacySinks)
		trackers := matchPrivacyPatterns(f, lower, trackerPatterns)
		report.Sources = append(report.Sources, sources...)
		report.Sinks = append(report.Sinks, sinks...)
		for _, t := range trackers {
			if _, ok := seenTracker[t.Name]; ok {
				continue
			}
			seenTracker[t.Name] = struct{}{}
			report.Trackers = append(report.Trackers, t)
		}
		if len(sources) > 0 && len(sinks) > 0 {
			endpoint := ""
			urls := extractURLs(f.Data)
			if len(urls) > 0 {
				endpoint = urls[0]
			}
			report.Flows = append(report.Flows, PrivacyFlow{Source: sources[0].Name, Sink: sinks[0].Name, Endpoint: endpoint, Path: f.Path, Reason: "same file contains sensitive source and outbound/storage sink"})
		}
	}
	sortPrivacy(report)
	report.Score, report.Risk = scorePrivacy(report)
	report.Findings = buildPrivacyFindings(report)
	return report, nil
}

func matchPrivacyPatterns(f ScannedFile, lower []byte, patterns []privacyPattern) []PrivacySignal {
	var out []PrivacySignal
	for _, p := range patterns {
		for _, needle := range p.Needles {
			idx := bytes.Index(lower, bytes.ToLower([]byte(needle)))
			if idx < 0 {
				continue
			}
			ln := lineNumber(f.Data, idx)
			out = append(out, PrivacySignal{Name: p.Name, Category: p.Category, Path: f.Path, Line: ln, Evidence: lineAt(f.Data, ln)})
			break
		}
	}
	return out
}

func sortPrivacy(report *PrivacyReport) {
	sort.Slice(report.Permissions, func(i, j int) bool { return report.Permissions[i].Name < report.Permissions[j].Name })
	sort.Slice(report.Sources, func(i, j int) bool { return signalLess(report.Sources[i], report.Sources[j]) })
	sort.Slice(report.Sinks, func(i, j int) bool { return signalLess(report.Sinks[i], report.Sinks[j]) })
	sort.Slice(report.Trackers, func(i, j int) bool { return report.Trackers[i].Name < report.Trackers[j].Name })
	sort.Slice(report.Endpoints, func(i, j int) bool { return report.Endpoints[i].Name < report.Endpoints[j].Name })
}

func signalLess(a, b PrivacySignal) bool {
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	return a.Name < b.Name
}

func scorePrivacy(report *PrivacyReport) (int, string) {
	score := 100
	score -= len(report.Flows) * 12
	score -= len(report.Sources) * 3
	score -= len(report.Trackers) * 4
	for _, p := range report.Permissions {
		if isSensitivePermission(p.Name) {
			score -= 5
		}
	}
	if score < 0 {
		score = 0
	}
	risk := "low"
	if score < 40 {
		risk = "high"
	} else if score < 70 {
		risk = "medium"
	}
	return score, risk
}

func buildPrivacyFindings(report *PrivacyReport) []Finding {
	var out []Finding
	if len(report.Flows) > 0 {
		out = append(out, Finding{Severity: "high", Category: "privacy", Title: "Sensitive data flow candidates", Detail: "flows: " + intString(len(report.Flows))})
	}
	if len(report.Trackers) >= 3 {
		out = append(out, Finding{Severity: "medium", Category: "privacy", Title: "Multiple tracker SDKs detected", Detail: "trackers: " + intString(len(report.Trackers))})
	}
	for _, p := range report.Permissions {
		if isSensitivePermission(p.Name) {
			out = append(out, Finding{Severity: "medium", Category: "privacy", Path: p.Path, Title: "Sensitive permission", Detail: p.Name})
		}
	}
	return out
}

func isSensitivePermission(p string) bool {
	p = strings.ToUpper(p)
	for _, token := range []string{"LOCATION", "CONTACTS", "SMS", "CAMERA", "RECORD_AUDIO", "READ_PHONE", "QUERY_ALL_PACKAGES", "BLUETOOTH_SCAN"} {
		if strings.Contains(p, token) {
			return true
		}
	}
	return false
}

// loadManifestPermissions reads AndroidManifest.xml from the target
// directory or APK and returns the declared <uses-permission> names.
//
// Three input cases must work, because the privacy analyzer can be
// pointed at any of them:
//
//   - extracted directory containing a plaintext manifest (typical
//     after the apkloader extractor decoded AXML for us)
//   - extracted directory containing a binary AXML manifest (older
//     extraction runs, or third-party extractors)
//   - raw APK file or zip — we walk the archive entries directly
//
// We never error out: missing/unparseable manifests just return nil
// so the caller falls back to its smali-only heuristic, the same way
// it behaved before this layer existed.
func loadManifestPermissions(target string) []string {
	info, err := os.Stat(target)
	if err != nil {
		return nil
	}

	var data []byte
	if info.IsDir() {
		data = readManifestFromDir(target)
	} else {
		// File — could be a plaintext xml, binary axml, or zip/apk.
		data = readManifestFromArchive(target)
	}
	if len(data) == 0 {
		return nil
	}

	if axml.IsBinaryXML(data) {
		m, err := axml.Decode(data)
		if err != nil {
			return nil
		}
		return append(append([]string{}, m.Permissions...), m.OptionalPerms...)
	}
	return parsePlaintextPermissions(data)
}

func readManifestFromDir(root string) []byte {
	candidate := filepath.Join(root, "AndroidManifest.xml")
	data, err := os.ReadFile(candidate)
	if err == nil {
		return data
	}
	// Some pipelines stash a binary copy as ".bin"; fall through to it
	// before giving up.
	if bin, err := os.ReadFile(candidate + ".bin"); err == nil {
		return bin
	}
	return nil
}

// parsePlaintextPermissions extracts <uses-permission android:name="..."/>
// values from textual XML. We avoid pulling in the encoding/xml
// package because the manifest is small and a regex is dramatically
// faster — we already use one for the smali fallback.
func parsePlaintextPermissions(data []byte) []string {
	const marker = "uses-permission"
	out := make([]string, 0, 16)
	seen := make(map[string]struct{}, 16)
	rest := string(data)
	for {
		idx := strings.Index(rest, marker)
		if idx < 0 {
			break
		}
		// Find android:name="..."
		end := strings.IndexByte(rest[idx:], '>')
		if end < 0 {
			break
		}
		segment := rest[idx : idx+end]
		nameIdx := strings.Index(segment, `android:name="`)
		if nameIdx < 0 {
			rest = rest[idx+end:]
			continue
		}
		nameStart := nameIdx + len(`android:name="`)
		nameEnd := strings.IndexByte(segment[nameStart:], '"')
		if nameEnd < 0 {
			rest = rest[idx+end:]
			continue
		}
		name := segment[nameStart : nameStart+nameEnd]
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			out = append(out, name)
		}
		rest = rest[idx+end:]
	}
	return out
}

// readManifestFromArchive opens an APK/zip and pulls out the
// AndroidManifest.xml entry without unpacking the rest. Used when
// AnalyzePrivacy is pointed at a raw .apk file.
func readManifestFromArchive(path string) []byte {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer zr.Close()
	for _, f := range zr.File {
		if !strings.EqualFold(f.Name, "AndroidManifest.xml") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		return data
	}
	return nil
}
