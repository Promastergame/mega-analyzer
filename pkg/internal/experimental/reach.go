package experimental

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/insights"
)

// ═══════════════════════════════════════════════════════════════════════════════
// REACHABILITY ANALYSIS MODULE
// ═══════════════════════════════════════════════════════════════════════════════
//
// Builds a lightweight call graph from Smali files and answers two questions:
//
//   1. Which sensitive sinks (crypto, JNI, network, dynamic loading, runtime
//      exec, native libs) are reachable from public entry points?
//   2. Which sinks are dead — declared but not reachable — and therefore are
//      strong candidates for noise filtering elsewhere in the pipeline?
//
// Reachability is computed as a forward BFS over a method-edge graph. Edges
// are the `invoke-*` instructions parsed lexically from smali source; nodes
// are method signatures `Lcom/foo;->bar(Ljava/lang/String;)V`.

// ReachModule implements Module.
type ReachModule struct{}

// NewReachModule constructs the module.
func NewReachModule() *ReachModule { return &ReachModule{} }

func (m *ReachModule) ID() string   { return "reach" }
func (m *ReachModule) Name() string { return "Reachability Analysis" }
func (m *ReachModule) Description() string {
	return "Trace which sensitive sinks are reachable from app entry points"
}
func (m *ReachModule) Aliases() []string { return []string{"reachability", "callgraph-ex", "3"} }
func (m *ReachModule) Tier() string      { return "experimental" }

const (
	reachMaxFiles   = 25000 // hard cap; anything larger truncates with a warning
	reachMaxLineLen = 8 * 1024
)

// sinkPattern represents a sensitive API.
type sinkPattern struct {
	ID       string
	Match    string // substring inside the invoke target
	Severity Severity
	Tags     []string
}

var defaultSinks = []sinkPattern{
	{ID: "crypto-cipher-init", Match: "Ljavax/crypto/Cipher;->init", Severity: SevMedium, Tags: []string{"crypto"}},
	{ID: "crypto-cipher-doFinal", Match: "Ljavax/crypto/Cipher;->doFinal", Severity: SevMedium, Tags: []string{"crypto"}},
	{ID: "ssl-trust-all", Match: "Ljavax/net/ssl/X509TrustManager;->checkServerTrusted", Severity: SevHigh, Tags: []string{"ssl", "tls", "mitm"}},
	{ID: "runtime-exec", Match: "Ljava/lang/Runtime;->exec", Severity: SevHigh, Tags: []string{"exec", "command"}},
	{ID: "process-builder", Match: "Ljava/lang/ProcessBuilder;->start", Severity: SevHigh, Tags: []string{"exec", "command"}},
	{ID: "load-library", Match: "Ljava/lang/System;->loadLibrary", Severity: SevMedium, Tags: []string{"native", "jni"}},
	{ID: "load-binary", Match: "Ljava/lang/Runtime;->load", Severity: SevHigh, Tags: []string{"native", "dynamic"}},
	{ID: "dex-classloader", Match: "Ldalvik/system/DexClassLoader;-><init>", Severity: SevHigh, Tags: []string{"dynamic", "dex"}},
	{ID: "path-classloader", Match: "Ldalvik/system/PathClassLoader;-><init>", Severity: SevMedium, Tags: []string{"dynamic", "dex"}},
	{ID: "in-memory-dex", Match: "Ldalvik/system/InMemoryDexClassLoader;-><init>", Severity: SevHigh, Tags: []string{"dynamic", "dex", "memory"}},
	{ID: "url-conn", Match: "Ljava/net/URL;->openConnection", Severity: SevLow, Tags: []string{"network"}},
	{ID: "okhttp-call", Match: "Lokhttp3/Call;->execute", Severity: SevLow, Tags: []string{"network", "okhttp"}},
	{ID: "webview-loadurl", Match: "Landroid/webkit/WebView;->loadUrl", Severity: SevMedium, Tags: []string{"webview"}},
	{ID: "webview-jsenable", Match: "Landroid/webkit/WebSettings;->setJavaScriptEnabled", Severity: SevMedium, Tags: []string{"webview", "js"}},
	{ID: "smb-content-resolver", Match: "Landroid/content/ContentResolver;->openInputStream", Severity: SevLow, Tags: []string{"io"}},
	{ID: "shared-prefs", Match: "Landroid/content/SharedPreferences;->edit", Severity: SevInfo, Tags: []string{"storage"}},
	{ID: "telephony-imei", Match: "Landroid/telephony/TelephonyManager;->getDeviceId", Severity: SevHigh, Tags: []string{"pii"}},
	{ID: "location-getlast", Match: "Landroid/location/LocationManager;->getLastKnownLocation", Severity: SevMedium, Tags: []string{"pii", "location"}},
	{ID: "clipboard-read", Match: "Landroid/content/ClipboardManager;->getPrimaryClip", Severity: SevMedium, Tags: []string{"pii", "clipboard"}},
	{ID: "smsmgr-send", Match: "Landroid/telephony/SmsManager;->sendTextMessage", Severity: SevHigh, Tags: []string{"sms"}},
}

var (
	smaliMethodRe = regexp.MustCompile(`^\.method\s+(?:public|private|protected|static|final|synthetic|abstract|bridge|varargs|native|synchronized|declared-synchronized|constructor|\s)+\s*([\w$<>]+\([^)]*\)[\w/$\[;]+)`)
	// invoke-virtual {p1, v0}, Lcom/foo/Bar;->baz(Ljava/lang/String;)V
	invokeRe = regexp.MustCompile(`invoke-(?:virtual|direct|super|static|interface|polymorphic|custom)(?:/range)?\s*\{[^}]*\}\s*,\s*([^\s]+)`)
)

type methodNode struct {
	Owner    string // class name e.g. Lcom/foo/Bar;
	Sig      string // baz(Ljava/lang/String;)V
	File     string
	Edges    map[string]struct{} // outgoing invoke targets (qualified)
	IsPublic bool
	IsExport bool
	IsEntry  bool
	Hits     []sinkHit
}

type sinkHit struct {
	SinkID   string
	Severity Severity
	Tags     []string
	Target   string
}

// Run implements Module.Run.
func (m *ReachModule) Run(ctx context.Context, in Input) (*ModuleResult, error) {
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

	smaliFiles, err := collectSmaliFiles(ctx, in.TargetDir)
	if err != nil {
		return res, err
	}
	res.Bump("smali_files", len(smaliFiles))
	if len(smaliFiles) == 0 {
		res.Notes = append(res.Notes, "No Smali files found — reachability analysis is APK-focused.")
		return res, nil
	}
	if len(smaliFiles) > reachMaxFiles {
		res.Notes = append(res.Notes, fmt.Sprintf("Truncated to %d Smali files (had %d).", reachMaxFiles, len(smaliFiles)))
		smaliFiles = smaliFiles[:reachMaxFiles]
	}

	graph := make(map[string]*methodNode)
	exportedActivities := loadExportedComponents(in.TargetDir)

	for _, path := range smaliFiles {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if err := parseSmaliFile(path, graph, exportedActivities); err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %v", filepath.Base(path), err))
		}
	}
	res.Bump("methods", len(graph))

	// Inject JNI Cross-Boundary links
	jniReport, err := insights.AnalyzeJNI(in.TargetDir)
	if err == nil && jniReport != nil {
		res.Bump("jni_bindings", len(jniReport.Bindings))
		for _, binding := range jniReport.Bindings {
			prefix := binding.JavaClass + "->" + binding.JavaMethod + "("
			for sig, node := range graph {
				if strings.HasPrefix(sig, prefix) {
					// Found the Smali method declaring this JNI export!
					node.Hits = append(node.Hits, sinkHit{
						SinkID:   "jni-native-call",
						Severity: SevInfo,
						Tags:     []string{"jni", "native"},
						Target:   binding.Library + "!" + binding.NativeSymbol,
					})

					// Sniff for sensitive native operations or symbols
					lowerSym := strings.ToLower(binding.NativeSymbol)
					isSensitive := false
					for _, tok := range []string{"root", "debug", "frida", "xposed", "emulator", "license", "premium", "integrity", "signature", "decrypt", "token"} {
						if strings.Contains(lowerSym, tok) {
							isSensitive = true
							break
						}
					}
					if isSensitive {
						node.Hits = append(node.Hits, sinkHit{
							SinkID:   "jni-sensitive-native",
							Severity: SevHigh,
							Tags:     []string{"jni", "native", "security"},
							Target:   binding.Library + "!" + binding.NativeSymbol,
						})
					}
				}
			}
		}
	}

	entries := selectEntryPoints(graph)
	res.Bump("entry_points", len(entries))

	// BFS forward from each entry point and collect reachable sinks.
	reachable := bfsForward(graph, entries)
	res.Bump("reachable_methods", len(reachable))

	// Aggregate hits.
	type aggKey struct {
		SinkID string
		Sev    Severity
	}
	type aggVal struct {
		HitCount   int
		ReachCount int
		Examples   []string
		Reachable  bool
		Tags       []string
		EntryHints map[string]struct{}
	}
	agg := make(map[aggKey]*aggVal)

	for sig, node := range graph {
		for _, hit := range node.Hits {
			k := aggKey{SinkID: hit.SinkID, Sev: hit.Severity}
			v := agg[k]
			if v == nil {
				v = &aggVal{Tags: hit.Tags, EntryHints: make(map[string]struct{})}
				agg[k] = v
			}
			v.HitCount++
			if _, ok := reachable[sig]; ok {
				v.ReachCount++
				v.Reachable = true
				if len(v.Examples) < 5 {
					v.Examples = append(v.Examples, fmt.Sprintf("%s (%s)", sig, filepath.Base(node.File)))
				}
			}
		}
	}

	// Emit findings: reachable sinks (high signal) and pure-dead sinks (noise).
	for k, v := range agg {
		if v.Reachable {
			conf := 0.6 + 0.4*minFloat(float64(v.ReachCount)/8.0, 1.0)
			res.AddFinding(Finding{
				ID:          fmt.Sprintf("reach-%s", k.SinkID),
				Title:       fmt.Sprintf("Sink %s reachable from entry points", k.SinkID),
				Severity:    k.Sev,
				Confidence:  conf,
				Description: fmt.Sprintf("Reachable hits: %d / total hits: %d. Strongly indicates the sink is exercised at runtime.", v.ReachCount, v.HitCount),
				Evidence:    v.Examples,
				Tags:        append([]string{"reach"}, v.Tags...),
				Extra: map[string]string{
					"reach_count": fmt.Sprintf("%d", v.ReachCount),
					"hit_count":   fmt.Sprintf("%d", v.HitCount),
				},
			})
			res.Bump("reachable_sinks", 1)
			continue
		}
		if v.HitCount > 0 {
			res.AddFinding(Finding{
				ID:          fmt.Sprintf("reach-dead-%s", k.SinkID),
				Title:       fmt.Sprintf("Sink %s is unreachable from any entry point", k.SinkID),
				Severity:    SevInfo,
				Confidence:  0.6,
				Description: fmt.Sprintf("Hits: %d. Dead code candidate — useful for noise filtering.", v.HitCount),
				Tags:        append([]string{"reach", "dead-code"}, v.Tags...),
				Extra:       map[string]string{"hit_count": fmt.Sprintf("%d", v.HitCount)},
			})
			res.Bump("dead_sinks", 1)
		}
	}

	return res, nil
}

func collectSmaliFiles(ctx context.Context, root string) ([]string, error) {
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
		if strings.HasSuffix(strings.ToLower(d.Name()), ".smali") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

func parseSmaliFile(path string, graph map[string]*methodNode, exportedClasses map[string]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	owner := classFromSmaliPath(path)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), reachMaxLineLen)

	var (
		currentSig    string
		currentMethod *methodNode
	)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, ".class") {
			if cls := extractClassName(line); cls != "" {
				owner = cls
			}
			continue
		}
		if strings.HasPrefix(line, ".method") {
			matches := smaliMethodRe.FindStringSubmatch(line)
			if len(matches) > 1 {
				currentSig = qualifySig(owner, matches[1])
				currentMethod = ensureNode(graph, currentSig, owner, path)
				if strings.Contains(line, " public ") || strings.HasPrefix(line, ".method public ") {
					currentMethod.IsPublic = true
				}
				if isLikelyEntry(currentSig) {
					currentMethod.IsEntry = true
				}
				if _, ok := exportedClasses[owner]; ok {
					currentMethod.IsExport = true
					currentMethod.IsEntry = true
				}
			}
			continue
		}
		if strings.HasPrefix(line, ".end method") {
			currentSig = ""
			currentMethod = nil
			continue
		}

		if currentMethod == nil {
			continue
		}

		if !strings.Contains(line, "invoke-") {
			continue
		}
		matches := invokeRe.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		target := matches[1]
		// Track edges.
		currentMethod.Edges[target] = struct{}{}

		// Sink check.
		for _, s := range defaultSinks {
			if strings.Contains(target, s.Match) {
				currentMethod.Hits = append(currentMethod.Hits, sinkHit{
					SinkID:   s.ID,
					Severity: s.Severity,
					Tags:     s.Tags,
					Target:   target,
				})
			}
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return err
	}
	return nil
}

func extractClassName(line string) string {
	// .class public Lcom/foo/Bar;
	idx := strings.Index(line, "L")
	if idx < 0 {
		return ""
	}
	// find trailing ; — keep as the canonical owner with semicolon.
	end := strings.IndexByte(line[idx:], ';')
	if end < 0 {
		return ""
	}
	return line[idx : idx+end+1]
}

func classFromSmaliPath(path string) string {
	// pkg/internal/.../smali_classes/com/foo/Bar.smali -> Lcom/foo/Bar;
	p := filepath.ToSlash(path)
	low := strings.ToLower(p)
	idx := strings.LastIndex(low, "/smali")
	if idx < 0 {
		return ""
	}
	rest := p[idx:]
	// drop /smali[_classesN]/
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 3 {
		return ""
	}
	cls := parts[2]
	cls = strings.TrimSuffix(cls, ".smali")
	cls = strings.ReplaceAll(cls, "/", "/")
	return "L" + cls + ";"
}

func qualifySig(owner, methodSig string) string {
	if owner == "" {
		return methodSig
	}
	return owner + "->" + methodSig
}

func ensureNode(graph map[string]*methodNode, sig, owner, path string) *methodNode {
	node := graph[sig]
	if node == nil {
		node = &methodNode{
			Owner: owner,
			Sig:   sig,
			File:  path,
			Edges: make(map[string]struct{}),
		}
		graph[sig] = node
	}
	return node
}

// isLikelyEntry returns true for Android lifecycle / framework callbacks that
// are commonly invoked by the system rather than by user code.
func isLikelyEntry(sig string) bool {
	patterns := []string{
		"->onCreate(", "->onStart(", "->onResume(", "->onPause(", "->onStop(",
		"->onDestroy(", "->onReceive(", "->onHandleIntent(", "->onBind(",
		"->onStartCommand(", "->onClick(", "->onLongClick(", "->onCheckedChanged(",
		"->main([Ljava/lang/String;)V",
		"->run()V",
		"->onActivityResult(",
		"->doInBackground([Ljava/lang/Object;)Ljava/lang/Object;",
		"->call()Ljava/lang/Object;",
	}
	for _, p := range patterns {
		if strings.Contains(sig, p) {
			return true
		}
	}
	return false
}

// loadExportedComponents reads AndroidManifest.xml (if present, even decompiled
// AndroidManifest.txt) and returns the set of classes marked exported=true or
// without an explicit exported attribute but carrying an intent-filter.
func loadExportedComponents(root string) map[string]struct{} {
	out := make(map[string]struct{})
	candidates := []string{
		filepath.Join(root, "AndroidManifest.xml"),
		filepath.Join(root, "original", "AndroidManifest.xml"),
		filepath.Join(root, "AndroidManifest.txt"),
	}
	for _, p := range candidates {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		// Lightweight scan: look for android:name="com.foo.Bar" near an
		// android:exported="true" or intent-filter block. We do not parse XML
		// strictly — we only need a hint for entry-point selection.
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			continue
		}
		scanExportedNames(string(data), out)
	}
	return out
}

var (
	nameAttrRe   = regexp.MustCompile(`android:name="([^"]+)"`)
	exportedAttr = regexp.MustCompile(`android:exported="true"`)
)

func scanExportedNames(text string, out map[string]struct{}) {
	// Split by tag close; for each tag carrying exported=true OR <intent-filter
	// inside, capture the nearest android:name.
	tags := strings.Split(text, ">")
	for i, tag := range tags {
		hasIntent := strings.Contains(tag, "<intent-filter")
		hasExported := exportedAttr.MatchString(tag)
		if !hasIntent && !hasExported {
			// Look-ahead: maybe intent-filter is in the next tag.
			if i+1 < len(tags) && strings.Contains(tags[i+1], "<intent-filter") {
				hasIntent = true
			}
			if !hasExported && !hasIntent {
				continue
			}
		}
		m := nameAttrRe.FindStringSubmatch(tag)
		if len(m) < 2 {
			continue
		}
		cls := dotToSmaliClass(m[1])
		if cls != "" {
			out[cls] = struct{}{}
		}
	}
}

func dotToSmaliClass(name string) string {
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, ".") {
		// relative — we cannot resolve without the package prefix here.
		return ""
	}
	return "L" + strings.ReplaceAll(name, ".", "/") + ";"
}

// selectEntryPoints picks methods that act as graph entry points.
func selectEntryPoints(graph map[string]*methodNode) []string {
	var entries []string
	for sig, node := range graph {
		if node.IsEntry || node.IsExport {
			entries = append(entries, sig)
		}
	}
	if len(entries) == 0 {
		// Fallback: treat every public method as a possible entry.
		for sig, node := range graph {
			if node.IsPublic {
				entries = append(entries, sig)
			}
		}
	}
	sort.Strings(entries)
	return entries
}

func bfsForward(graph map[string]*methodNode, entries []string) map[string]struct{} {
	seen := make(map[string]struct{}, len(graph))
	queue := make([]string, 0, len(entries))
	for _, e := range entries {
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		queue = append(queue, e)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		node := graph[cur]
		if node == nil {
			continue
		}
		for tgt := range node.Edges {
			if _, ok := seen[tgt]; ok {
				continue
			}
			seen[tgt] = struct{}{}
			queue = append(queue, tgt)
		}
	}
	return seen
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
