package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"mega-analyzer/pkg/debugger"
	"mega-analyzer/pkg/internal/netflow"
)

// ═══════════════════════════════════════════════════════════════════════════════
// MEGA ANALYZER TUI — single-screen settings cockpit
//
// One screen. Arrow keys navigate. No new "windows" per action — every
// keypress just re-renders the dashboard in place. Inline prompt appears
// at the bottom only when an actual text/number value is being entered.
// ═══════════════════════════════════════════════════════════════════════════════

type tuiState struct {
	opts    *CLIOptions
	theme   Theme
	out     *Output
	term    *rawTerm
	started time.Time

	cursor  int    // selected menu row (main menu)
	flash   string // transient warning/error shown in status bar
	vpStart int    // viewport start for main menu

	activity []activityEntry

	// keyboard pump runs in a goroutine so the main loop can also
	// re-render on a periodic tick (e.g. for live uptime).
	keyCh chan keyEvent
	errCh chan error

	// Router / screens
	screen string // "home" | "settings" | "help" | "results"
	quit   bool

	// Screens
	home *homeScreen

	// OpenCode-style overlays
	palette   *paletteState
	toasts    toastQueue
	dialog    *dialogState
	help      *helpScreen
	results   *resultsScreen
	intercept *interceptScreen
	// Logo animation state
	logoAnim     bool
	logoFrameIdx int
}

type activityEntry struct {
	at   time.Time
	kind string // "ok", "warn", "info"
	text string
}

// menuRow describes a single navigable line.
//
// kind:
//
//	"text"   — Enter opens inline prompt
//	"int"    — Enter opens inline prompt (integer)
//	"bool"   — Enter / Space / ←→ toggles
//	"choice" — ←→ cycles, Enter cycles
//	"action" — Enter triggers run()
//	"sep"    — visual separator (not selectable)
type menuRow struct {
	label   string
	hint    string
	kind    string
	choices []string
	value   func() string // current display value
	intMin  int
	intMax  int

	getStr  func() string
	setStr  func(string)
	getBool func() bool
	setBool func(bool)
	getInt  func() int
	setInt  func(int)
	getIdx  func() int
	setIdx  func(int)

	run func() error // for action rows; returns errStartAnalysis / errQuit / nil
}

var (
	errStartAnalysis = errors.New("tui:start")
	errQuit          = errors.New("tui:quit")
)

func (a *App) runTUIWizard(parsed *CLIOptions) (*CLIOptions, bool, error) {
	opts := defaultCLIOptions()
	opts.Target = parsed.Target
	opts.NoColor = parsed.NoColor
	// Preserve a few opt-in modes the user passed on the command line so the
	// TUI doesn't silently drop them when the wizard opens.
	opts.MachineCode = parsed.MachineCode
	opts.EnableArtifacts = parsed.EnableArtifacts
	opts.OBBScan = parsed.OBBScan
	opts.CacheScan = parsed.CacheScan
	opts.MLCacheScript = parsed.MLCacheScript
	opts.EnableMobSFAll = parsed.EnableMobSFAll
	opts.EnableSASTRules = parsed.EnableSASTRules
	opts.EnableTrackers = parsed.EnableTrackers
	opts.EnableNSCAudit = parsed.EnableNSCAudit
	opts.EnableManifestAudit = parsed.EnableManifestAudit
	opts.EnableAPKID = parsed.EnableAPKID
	opts.EnableMediumAll = parsed.EnableMediumAll
	opts.EnablePlayStore = parsed.EnablePlayStore
	opts.EnableSBOM = parsed.EnableSBOM
	opts.EnablePermMap = parsed.EnablePermMap
	opts.EnableCertAudit = parsed.EnableCertAudit
	opts.EnableMalwareDomains = parsed.EnableMalwareDomains
	opts.EnableNIAP = parsed.EnableNIAP

	theme := DetectTheme(opts.NoColor)
	out := NewOutput(theme, false)
	out.SetTUI(true)

	term, err := newRawTerm()
	if err != nil {
		// Caller treats errTUIUnsupported as "fall back to -notui".
		return opts, false, err
	}

	t := &tuiState{
		opts:    opts,
		theme:   theme,
		out:     out,
		term:    term,
		started: time.Now(),
		keyCh:   make(chan keyEvent, 8),
		errCh:   make(chan error, 1),
		screen:  "home",
	}
	t.palette = newPalette(t)
	t.dialog = newDialog(t)
	t.help = newHelpScreen(t)
	t.results = newResultsScreen(t)
	t.intercept = newInterceptScreen(t)
	t.home = newHomeScreen(t)
	// Keep a reference so Run() can populate the Results screen with real
	// data and briefly reopen the TUI to show it once analysis completes.
	a.tui = t
	t.log("ok", "session started")
	t.log("info", "configuration loaded")
	t.log("ok", "modules ready")
	t.log("info", "ready for target selection")

	defer term.Close()
	term.EnterAltScreen()
	term.HideCursor()

	// Keyboard pump
	go func() {
		for {
			ev, err := term.ReadKey()
			if err != nil {
				t.errCh <- err
				return
			}
			t.keyCh <- ev
		}
	}()

	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		t.render()

		var ev keyEvent
		select {
		case ev = <-t.keyCh:
		case <-tick.C:
			// just re-render so live values (uptime) stay current
			continue
		case rerr := <-t.errCh:
			return opts, false, rerr
		}

		err := t.handleKey(ev)
		switch {
		case t.quit:
			term.ShowCursor()
			fmt.Fprintln(out.writer)
			return opts, false, nil
		case errors.Is(err, errStartAnalysis):
			term.ShowCursor()
			fmt.Fprintln(out.writer)
			return opts, true, nil
		case errors.Is(err, errQuit):
			term.ShowCursor()
			fmt.Fprintln(out.writer)
			return opts, false, nil
		case err != nil:
			term.ShowCursor()
			return opts, false, err
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MENU MODEL
// ═══════════════════════════════════════════════════════════════════════════════

func (t *tuiState) allRows() []menuRow {
	rows := []menuRow{
		{
			label:  "target",
			hint:   "APK / DEX / decompiled directory",
			kind:   "text",
			value:  func() string { return emptyAs(t.opts.Target, "<not selected>") },
			getStr: func() string { return t.opts.Target },
			setStr: func(s string) { t.opts.Target = s },
		},
		{
			label:  "output",
			hint:   "where reports and artifacts go",
			kind:   "text",
			value:  func() string { return t.opts.Output },
			getStr: func() string { return t.opts.Output },
			setStr: func(s string) { t.opts.Output = s },
		},
		{
			label:   "profile",
			hint:    "analysis depth preset",
			kind:    "choice",
			choices: []string{"quick", "balanced", "deep", "paranoid"},
			value:   func() string { return string(t.opts.Profile) },
			getIdx: func() int {
				profiles := []AnalysisProfile{ProfileQuick, ProfileBalanced, ProfileDeep, ProfileParanoid}
				for i, p := range profiles {
					if p == t.opts.Profile {
						return i
					}
				}
				return 1
			},
			setIdx: func(i int) {
				profiles := []AnalysisProfile{ProfileQuick, ProfileBalanced, ProfileDeep, ProfileParanoid}
				if i >= 0 && i < len(profiles) {
					t.opts.Profile = profiles[i]
				}
			},
		},
		{
			label:  "workers",
			hint:   "parallel analysis threads",
			kind:   "int",
			intMin: 1, intMax: 64,
			value:  func() string { return strconv.Itoa(t.opts.Workers) },
			getInt: func() int { return t.opts.Workers },
			setInt: func(v int) { t.opts.Workers = v },
		},
		{
			label:  "timeout",
			hint:   "seconds, 0 = unlimited",
			kind:   "int",
			intMin: 0, intMax: 86400,
			value:  func() string { return strconv.Itoa(t.opts.Timeout) + "s" },
			getInt: func() int { return t.opts.Timeout },
			setInt: func(v int) { t.opts.Timeout = v },
		},
		{
			label:  "max-files",
			hint:   "0 = unlimited",
			kind:   "int",
			intMin: 0, intMax: 100000000,
			value:  func() string { return strconv.Itoa(t.opts.MaxFiles) },
			getInt: func() int { return t.opts.MaxFiles },
			setInt: func(v int) { t.opts.MaxFiles = v },
		},
		{
			label:   "report",
			hint:    "report preset",
			kind:    "choice",
			choices: []string{"default", "short", "full", "all"},
			value:   func() string { return emptyAs(t.opts.Report, "default") },
			getIdx: func() int {
				v := emptyAs(t.opts.Report, "default")
				for i, c := range []string{"default", "short", "full", "all"} {
					if c == v {
						return i
					}
				}
				return 0
			},
			setIdx: func(i int) {
				choices := []string{"default", "short", "full", "all"}
				if i >= 0 && i < len(choices) {
					t.opts.Report = choices[i]
				}
			},
		},
		{label: "analysis", kind: "sep"},
		{
			label:   "callgraph",
			hint:    "build inter-procedural call graph",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableCallGraph) },
			getBool: func() bool { return t.opts.EnableCallGraph },
			setBool: func(v bool) { t.opts.EnableCallGraph = v },
		},
		{
			label:   "correlations",
			hint:    "cross-module correlation engine",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableCorrelations) },
			getBool: func() bool { return t.opts.EnableCorrelations },
			setBool: func(v bool) { t.opts.EnableCorrelations = v },
		},
		{
			label:   "deep scan",
			hint:    "extra deep analysis passes",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableDeepScan) },
			getBool: func() bool { return t.opts.EnableDeepScan },
			setBool: func(v bool) { t.opts.EnableDeepScan = v },
		},
		{
			label:   "artifacts",
			hint:    "extract images / 3D / .so + forensic viewer",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableArtifacts) },
			getBool: func() bool { return t.opts.EnableArtifacts },
			setBool: func(v bool) {
				t.opts.EnableArtifacts = v
				if v {
					t.log("ok", "artifacts panel enabled")
				} else {
					t.log("info", "artifacts panel disabled")
				}
			},
		},
		{
			label:   "machine code",
			hint:    "treat target as raw PE / ELF / .so binary",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.MachineCode) },
			getBool: func() bool { return t.opts.MachineCode },
			setBool: func(v bool) {
				t.opts.MachineCode = v
				if v {
					t.log("ok", "machine-code mode armed (Rust scan-native)")
				}
			},
		},
		{
			label:   "obb scan",
			hint:    "deep-scan OBB expansion / data / cache files",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.OBBScan) },
			getBool: func() bool { return t.opts.OBBScan },
			setBool: func(v bool) {
				t.opts.OBBScan = v
				if v {
					t.log("ok", "OBB scanner armed (Unity/UE/Godot fingerprint + payload detection)")
				}
			},
		},
		{
			label:   "cache scan",
			hint:    "scan app cache for unencrypted saves, keys, weak crypto",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.CacheScan) },
			getBool: func() bool { return t.opts.CacheScan },
			setBool: func(v bool) {
				t.opts.CacheScan = v
				if v {
					t.log("ok", "Cache security scanner armed (save analysis + key detection)")
				}
			},
		},
		{
			label:   "ml cache script",
			hint:    "predictive exploitation analysis on cache (ML-Apli-Cache)",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.MLCacheScript) },
			getBool: func() bool { return t.opts.MLCacheScript },
			setBool: func(v bool) {
				t.opts.MLCacheScript = v
				if v {
					t.log("ok", "ML-Apli-Cache script armed (predictive attack chain + remediation)")
				}
			},
		},
		{label: "output", kind: "sep"},
		{
			label:   "dex only",
			hint:    "skip native code, scan DEX only",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.DEXOnly) },
			getBool: func() bool { return t.opts.DEXOnly },
			setBool: func(v bool) { t.opts.DEXOnly = v },
		},
		{
			label:   "html report",
			hint:    "generate REPORT.html",
			kind:    "bool",
			value:   func() string { return onOff(!t.opts.NoHTML) },
			getBool: func() bool { return !t.opts.NoHTML },
			setBool: func(v bool) { t.opts.NoHTML = !v },
		},
		{
			label:   "json report",
			hint:    "generate analysis.json",
			kind:    "bool",
			value:   func() string { return onOff(!t.opts.NoJSON) },
			getBool: func() bool { return !t.opts.NoJSON },
			setBool: func(v bool) { t.opts.NoJSON = !v },
		},
		{
			label:   "clean output",
			hint:    "wipe output directory before run",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.CleanOutput) },
			getBool: func() bool { return t.opts.CleanOutput },
			setBool: func(v bool) {
				if !v {
					// Turning it off is never destructive — no confirm needed.
					t.opts.CleanOutput = false
					return
				}
				t.dialog.show("Enable clean output?",
					"This deletes the output directory before the scan starts. Continue?",
					func() {
						t.opts.CleanOutput = true
						t.log("warn", "clean output armed — output dir will be wiped before run")
					})
			},
		},
		{
			label:   "ml patcher",
			hint:    "predict and generate patches",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.MLPatch) },
			getBool: func() bool { return t.opts.MLPatch },
			setBool: func(v bool) {
				t.opts.MLPatch = v
			},
		},
		{label: "toolkit", kind: "sep"},
		{
			label:   "make-server",
			hint:    "generate Elixir/OTP private server from target",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.MakeServer) },
			getBool: func() bool { return t.opts.MakeServer },
			setBool: func(v bool) { t.opts.MakeServer = v },
		},
		{
			label:   "jni bridge",
			hint:    "Java ↔ Native JNI boundary analyzer",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableJNI) },
			getBool: func() bool { return t.opts.EnableJNI },
			setBool: func(v bool) { t.opts.EnableJNI = v },
		},
		{
			label:   "privacy",
			hint:    "mobile privacy analyzer (trackers, sinks)",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnablePrivacy) },
			getBool: func() bool { return t.opts.EnablePrivacy },
			setBool: func(v bool) { t.opts.EnablePrivacy = v },
		},
		{
			label:   "graph explorer",
			hint:    "interactive HTML graph",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableGraphExplorer) },
			getBool: func() bool { return t.opts.EnableGraphExplorer },
			setBool: func(v bool) { t.opts.EnableGraphExplorer = v },
		},
		{
			label:   "firmware / IoT",
			hint:    "firmware analyzer for .bin/rootfs/archives",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.Firmware) },
			getBool: func() bool { return t.opts.Firmware },
			setBool: func(v bool) { t.opts.Firmware = v },
		},
		{label: "MobSF-derived analyzers", kind: "sep"},
		{
			label:   "mobsf all",
			hint:    "enable all 5 MobSF-style analyzers at once",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableMobSFAll) },
			getBool: func() bool { return t.opts.EnableMobSFAll },
			setBool: func(v bool) {
				t.opts.EnableMobSFAll = v
				t.opts.EnableSASTRules = v
				t.opts.EnableTrackers = v
				t.opts.EnableNSCAudit = v
				t.opts.EnableManifestAudit = v
				t.opts.EnableAPKID = v
			},
		},
		{
			label:   "sast rules",
			hint:    "MobSF regex SAST rule scanner (OWASP / MASVS / CWE)",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableSASTRules) },
			getBool: func() bool { return t.opts.EnableSASTRules },
			setBool: func(v bool) { t.opts.EnableSASTRules = v },
		},
		{
			label:   "trackers (Exodus)",
			hint:    "ad / analytics SDK fingerprinting",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableTrackers) },
			getBool: func() bool { return t.opts.EnableTrackers },
			setBool: func(v bool) { t.opts.EnableTrackers = v },
		},
		{
			label:   "nsc audit",
			hint:    "audit network_security_config.xml",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableNSCAudit) },
			getBool: func() bool { return t.opts.EnableNSCAudit },
			setBool: func(v bool) { t.opts.EnableNSCAudit = v },
		},
		{
			label:   "manifest audit",
			hint:    "exported components / debuggable / deep-link analysis",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableManifestAudit) },
			getBool: func() bool { return t.opts.EnableManifestAudit },
			setBool: func(v bool) { t.opts.EnableManifestAudit = v },
		},
		{
			label:   "apkid",
			hint:    "compiler / packer / obfuscator fingerprinting",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableAPKID) },
			getBool: func() bool { return t.opts.EnableAPKID },
			setBool: func(v bool) { t.opts.EnableAPKID = v },
		},
		{label: "medium-priority analyzers", kind: "sep"},
		{
			label:   "medium all",
			hint:    "enable all 7 medium-priority analyzers at once",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableMediumAll) },
			getBool: func() bool { return t.opts.EnableMediumAll },
			setBool: func(v bool) {
				t.opts.EnableMediumAll = v
				t.opts.EnablePlayStore = v
				t.opts.EnableSBOM = v
				t.opts.EnablePermMap = v
				t.opts.EnableCertAudit = v
			t.opts.EnableMalwareDomains = v
			t.opts.EnableNIAP = v
		},
	},
		{
			label:   "playstore",
			hint:    "Play Store metadata lookup",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnablePlayStore) },
			getBool: func() bool { return t.opts.EnablePlayStore },
			setBool: func(v bool) { t.opts.EnablePlayStore = v },
		},
		{
			label:   "sbom",
			hint:    "extract SBOM from .version files",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableSBOM) },
			getBool: func() bool { return t.opts.EnableSBOM },
			setBool: func(v bool) { t.opts.EnableSBOM = v },
		},
		{
			label:   "permmap",
			hint:    "permission-to-code mapping",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnablePermMap) },
			getBool: func() bool { return t.opts.EnablePermMap },
			setBool: func(v bool) { t.opts.EnablePermMap = v },
		},
		{
			label:   "cert audit",
			hint:    "deep certificate analysis",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableCertAudit) },
			getBool: func() bool { return t.opts.EnableCertAudit },
			setBool: func(v bool) { t.opts.EnableCertAudit = v },
		},
		{
			label:   "malware domains",
			hint:    "check URLs against malware blacklist",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableMalwareDomains) },
			getBool: func() bool { return t.opts.EnableMalwareDomains },
			setBool: func(v bool) { t.opts.EnableMalwareDomains = v },
		},
		{
			label:   "niap",
			hint:    "NIAP compliance rule scanner",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.EnableNIAP) },
			getBool: func() bool { return t.opts.EnableNIAP },
			setBool: func(v bool) { t.opts.EnableNIAP = v },
		},
		{label: "actions", kind: "sep"},
		{
			label: "─ start analysis",
			kind:  "action",
			value: func() string { return "" },
			run: func() error {
				if t.opts.Target == "" {
					t.flash = "target is required before starting"
					return nil
				}
				if _, err := os.Stat(t.opts.Target); err != nil {
					t.flash = "target not found: " + t.opts.Target
					return nil
				}
				t.log("ok", "starting analysis")
				return errStartAnalysis
			},
		},
		{
			label: "─ debug binary (machine-code)",
			kind:  "action",
			value: func() string { return "" },
			run: func() error {
				if t.opts.Target == "" {
					t.flash = "target is required for debugger"
					return nil
				}
				return t.runDebugger()
			},
		},
		{
			label: "─ make-server (generate now)",
			kind:  "action",
			value: func() string { return "" },
			run: func() error {
				if t.opts.Target == "" {
					t.flash = "target is required for make-server"
					return nil
				}
				if _, err := os.Stat(t.opts.Target); err != nil {
					t.flash = "target not found: " + t.opts.Target
					return nil
				}
				t.opts.MakeServer = true
				t.log("ok", "starting make-server pipeline")
				return errStartAnalysis
			},
		},
		{
			label: "─ firmware analysis (run now)",
			kind:  "action",
			value: func() string { return "" },
			run: func() error {
				if t.opts.Target == "" {
					t.flash = "target is required for firmware analysis"
					return nil
				}
				if _, err := os.Stat(t.opts.Target); err != nil {
					t.flash = "target not found: " + t.opts.Target
					return nil
				}
				t.opts.Firmware = true
				t.log("ok", "starting firmware/IoT analysis")
				return errStartAnalysis
			},
		},
		{
			label: "─ version diff (run now)",
			kind:  "action",
			value: func() string { return "" },
			run: func() error {
				old, ok := t.inlinePrompt("diff-old (old APK/dir)", t.opts.DiffOld, false)
				if !ok {
					return nil
				}
				old = strings.TrimSpace(strings.Trim(old, "\"'"))
				if old == "" {
					t.flash = "diff-old path is required"
					return nil
				}
				if runtime.GOOS == "windows" && len(old) > 2 && old[0] == '/' && old[2] == ':' {
					old = old[1:]
				}
				if abs, err := filepath.Abs(old); err == nil {
					old = abs
				}
				if _, err := os.Stat(old); err != nil {
					t.flash = "diff-old not found: " + old
					return nil
				}

				newPath, ok := t.inlinePrompt("diff-new (new APK/dir)", t.opts.DiffNew, false)
				if !ok {
					return nil
				}
				newPath = strings.TrimSpace(strings.Trim(newPath, "\"'"))
				if newPath == "" {
					t.flash = "diff-new path is required"
					return nil
				}
				if runtime.GOOS == "windows" && len(newPath) > 2 && newPath[0] == '/' && newPath[2] == ':' {
					newPath = newPath[1:]
				}
				if abs, err := filepath.Abs(newPath); err == nil {
					newPath = abs
				}
				if _, err := os.Stat(newPath); err != nil {
					t.flash = "diff-new not found: " + newPath
					return nil
				}

				t.opts.DiffOld = old
				t.opts.DiffNew = newPath
				t.opts.VersionDiff = true
				t.log("ok", "starting version diff: "+filepath.Base(old)+" → "+filepath.Base(newPath))
				return errStartAnalysis
			},
		},
		{label: "intercept", kind: "sep"},
		{
			label:  "net-filter",
			hint:   "display filter: proto / ip / port / len / dir / sni / payload",
			kind:   "text",
			value:  func() string { return emptyAs(t.opts.NetFilter, "<none>") },
			getStr: func() string { return t.opts.NetFilter },
			setStr: func(v string) {
				v = strings.TrimSpace(v)
				// Compile on entry: a bad expression should be a visible mistake
				// here, not a proxy that starts and drops every packet.
				if v != "" {
					if _, err := netflow.Compile(v); err != nil {
						t.flash = "invalid net-filter: " + err.Error()
						return
					}
				}
				t.opts.NetFilter = v
			},
		},
		{
			label:   "net-flows",
			hint:    "reassemble packets into classified bidirectional flows",
			kind:    "bool",
			value:   func() string { return onOff(t.opts.NetFlows) },
			getBool: func() bool { return t.opts.NetFlows },
			setBool: func(v bool) { t.opts.NetFlows = v },
		},
		{
			label: "─ live intercept (MITM)",
			kind:  "action",
			value: func() string { return "" },
			run: func() error {
				upstream, ok := t.inlinePrompt("upstream server (host:port)", t.opts.InterceptUpstream, false)
				if !ok {
					return nil
				}
				upstream = strings.TrimSpace(upstream)
				if upstream == "" {
					t.flash = "upstream server address is required"
					return nil
				}
				t.opts.InterceptUpstream = upstream
				t.screen = "intercept"
				if err := t.intercept.startProxy(upstream); err != nil {
					t.flash = "MITM proxy failed to start: " + err.Error()
					t.screen = "main"
					return nil
				}
				t.log("ok", "opening live MITM dashboard")
				return nil
			},
		},
		{
			label: "─ quit",
			kind:  "action",
			value: func() string { return "" },
			run: func() error {
				t.confirmQuit()
				return nil
			},
		},
	}
	return rows
}

func (t *tuiState) handleKey(ev keyEvent) error {
	// Overlay priority: palette > dialog > screen-specific handlers
	if t.palette.handleKey(ev) {
		return nil
	}
	if t.dialog.handleKey(ev) {
		return nil
	}

	// Global shortcuts
	if ev.kind == keyF1 {
		// F1 is documented in the help screen as a shortcut for help
		// (tui_help.go), so it needs to actually do something.
		if t.screen != "help" {
			t.leaveScreen()
			t.screen = "help"
		} else {
			t.screen = "settings"
		}
		return nil
	}
	if ev.kind == keyChar {
		switch ev.r {
		case '?':
			if t.screen != "help" {
				t.leaveScreen()
				t.screen = "help"
			} else {
				t.screen = "settings"
			}
			return nil
		case 'g', 'G':
			if t.screen != "results" {
				t.leaveScreen()
				t.screen = "results"
			} else {
				t.screen = "settings"
			}
			return nil
		}
	}

	// Screen router
	switch t.screen {
	case "home":
		if t.home.handleKey(ev) {
			if t.home.start {
				t.home.start = false
				return t.home.activate()
			}
			return nil
		}
		return nil
	case "help", "results":
		return t.handleNavScreen(ev)
	case "intercept":
		t.intercept.handleKey(ev)
		return nil
	}

	// Settings screen
	return t.handleSettingsKey(ev)
}

// leaveScreen runs any cleanup needed when navigating away from a screen
// via a global shortcut ('?', 'g'/'G', F1), so the transition doesn't skip
// the same teardown the screen's own handler would have done. In
// particular, leaving the intercept screen this way must still stop the
// MITM proxy listener, otherwise it keeps listening in the background.
func (t *tuiState) leaveScreen() {
	if t.screen == "intercept" && t.intercept != nil {
		t.intercept.stopProxy()
	}
}

// confirmQuit shows a Y/N confirmation dialog before actually quitting the
// TUI, so a stray Esc/Q/Ctrl+C press doesn't instantly kill the session.
func (t *tuiState) confirmQuit() {
	t.dialog.show("Quit Mega Analyzer?", "Any unsaved settings will be lost.", func() {
		t.log("info", "session quit")
		t.quit = true
	})
}

func (t *tuiState) handleNavScreen(ev keyEvent) error {
	switch ev.kind {
	case keyEsc, keyEnter:
		t.screen = "home"
		return nil
	case keyChar:
		switch ev.r {
		case 'q', 'Q', 'й', 'Й':
			t.confirmQuit()
			return nil
		case ' ':
			t.screen = "home"
			return nil
		case '/':
			t.palette.toggle()
			return nil
		case 0x0b: // Ctrl+K
			t.palette.toggle()
			return nil
		case 'g', 'G':
			if t.screen == "results" {
				t.screen = "home"
			} else {
				t.screen = "results"
			}
			return nil
		case '?':
			if t.screen == "help" {
				t.screen = "home"
			} else {
				t.screen = "help"
			}
			return nil
		}
	}
	return nil
}

func (t *tuiState) handleSettingsKey(ev keyEvent) error {
	rows := t.allRows()

	if t.cursor >= len(rows) {
		t.cursor = len(rows) - 1
	}
	if t.cursor < 0 {
		t.cursor = 0
	}
	if len(rows) > 0 && rows[t.cursor].kind == "sep" {
		t.move(+1, rows)
	}

	switch ev.kind {
	case keyUp:
		t.move(-1, rows)
	case keyDown:
		t.move(+1, rows)
	case keyPgUp:
		t.move(-5, rows)
	case keyPgDn:
		t.move(+5, rows)
	case keyHome:
		t.cursor = 0
	case keyEnd:
		t.cursor = len(rows) - 1
	case keyLeft:
		t.cycle(rows[t.cursor], -1)
	case keyRight:
		t.cycle(rows[t.cursor], +1)
	case keyEnter:
		return t.activate(rows[t.cursor])
	case keyEsc:
		t.screen = "home"
		return nil
	case keyTab:
		t.palette.toggle()
		return nil
	case keyChar:
		switch ev.r {
		case 'q', 'Q', 'й', 'Й':
			t.screen = "home"
			return nil
		case ' ':
			return t.activate(rows[t.cursor])
		case '/':
			t.palette.toggle()
			return nil
		case 0x0b: // Ctrl+K
			t.palette.toggle()
			return nil
		case 'h', 'H':
			t.screen = "home"
			return nil
		}
	}
	return nil
}

func (t *tuiState) move(delta int, rows []menuRow) {
	n := len(rows)
	if n == 0 {
		return
	}
	t.cursor = (t.cursor + delta + n) % n
	// Skip separator rows
	for tries := 0; tries < n; tries++ {
		if rows[t.cursor].kind != "sep" {
			return
		}
		if delta >= 0 {
			t.cursor = (t.cursor + 1) % n
		} else {
			t.cursor = (t.cursor - 1 + n) % n
		}
	}
}

func (t *tuiState) cycle(row menuRow, dir int) {
	t.flash = ""
	switch row.kind {
	case "bool":
		if row.getBool != nil && row.setBool != nil {
			row.setBool(!row.getBool())
		}
	case "choice":
		if row.getIdx != nil && row.setIdx != nil {
			n := len(row.choices)
			if n > 0 {
				row.setIdx((row.getIdx() + dir + n) % n)
			}
		}
	case "int":
		if row.getInt != nil && row.setInt != nil {
			step := 1
			if row.intMax > 1000 {
				step = 100
			} else if row.intMax > 100 {
				step = 10
			}
			v := row.getInt() + dir*step
			if v < row.intMin {
				v = row.intMin
			}
			if v > row.intMax {
				v = row.intMax
			}
			row.setInt(v)
		}
	}
}

func (t *tuiState) activate(row menuRow) error {
	t.flash = ""
	switch row.kind {
	case "bool":
		if row.getBool != nil && row.setBool != nil {
			row.setBool(!row.getBool())
		}
	case "choice":
		t.cycle(row, +1)
	case "text":
		if row.getStr != nil && row.setStr != nil {
			val, ok := t.inlinePrompt(row.label, row.getStr(), false)
			if !ok {
				return nil
			}
			// Trim quotes and surrounding spaces
			val = strings.TrimSpace(strings.Trim(val, "\"'"))
			if row.label == "target" && val != "" {
				// Handle Windows paths starting with a slash (common when pasting from some shells)
				if runtime.GOOS == "windows" && len(val) > 2 && val[0] == '/' && val[2] == ':' {
					val = val[1:]
				}
				if abs, err := filepath.Abs(val); err == nil {
					val = abs
				}
				// Set value FIRST so the user can see what we resolved it to, even if Stat fails
				row.setStr(val)
				if _, err := os.Stat(val); err != nil {
					t.flash = "target not found: " + val
					t.log("warn", "target not found: "+val)
					return nil
				}
				t.log("ok", "target updated")
			} else {
				row.setStr(val)
			}
		}
	case "int":
		if row.getInt != nil && row.setInt != nil {
			val, ok := t.inlinePrompt(row.label, strconv.Itoa(row.getInt()), true)
			if !ok {
				return nil
			}
			n, err := strconv.Atoi(strings.TrimSpace(val))
			if err != nil {
				t.flash = "not a number: " + val
				return nil
			}
			if n < row.intMin || n > row.intMax {
				t.flash = fmt.Sprintf("%s must be %d..%d", row.label, row.intMin, row.intMax)
				return nil
			}
			row.setInt(n)
		}
	case "action":
		if row.run != nil {
			return row.run()
		}
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// RENDER
// ═══════════════════════════════════════════════════════════════════════════════

func (t *tuiState) render() {
	// Build the whole frame in a buffer first, then flush to the terminal in
	// one syscall. Without this, every Fprintln becomes a separate write on
	// Windows console and the user sees flicker between rows.
	var buf bytes.Buffer
	realWriter := t.out.writer
	t.out.writer = &buf
	defer func() { t.out.writer = realWriter }()

	t.renderBody()

	t.flushFrame(realWriter, buf.Bytes())
}

// flushFrame writes the prepared frame to the real terminal in a single
// Write call. To eliminate flicker AND leftovers from previous frames
// (when the new frame is shorter, narrower, or the window has just been
// resized) the function:
//  1. Disables auto-wrap so over-wide lines are clipped instead of
//     bleeding into the next row.
//  2. Clips each frame line to the terminal width.
//  3. Caps the total line count to the terminal height so writing the
//     last line never triggers a scroll.
//  4. Erases each line before writing into it and clears the area below
//     the frame at the end.
func (t *tuiState) flushFrame(w io.Writer, frame []byte) {
	cols := termCols()
	rowsTerm := termRows()

	out := make([]byte, 0, len(frame)+256)
	// Hide cursor, disable auto-wrap, move home.
	out = append(out, "\x1b[?25l\x1b[?7l\x1b[H"...)

	lines := bytes.Split(frame, []byte{'\n'})
	// bytes.Split leaves a trailing empty element if the buffer ends with \n.
	// Drop it so we don't emit an extra blank row.
	if n := len(lines); n > 0 && len(lines[n-1]) == 0 {
		lines = lines[:n-1]
	}
	if rowsTerm > 0 && len(lines) > rowsTerm {
		lines = lines[:rowsTerm]
	}

	for i, line := range lines {
		if cols > 0 {
			line = clipVisible(line, cols)
		}
		// Instead of erasing the line (\x1b[2K) which causes flicker on
		// Windows, pad the line with spaces to the full terminal width.
		// This overwrites any leftover characters from the previous frame
		// without the visible blank-then-redraw flash.
		out = append(out, line...)
		if cols > 0 {
			vis := visibleLenBytes(line)
			if pad := cols - vis; pad > 0 {
				out = append(out, bytes.Repeat([]byte{' '}, pad)...)
			}
		}
		if i < len(lines)-1 {
			out = append(out, "\r\n"...)
		}
	}
	// Re-enable auto-wrap and clear any leftover lines below.
	out = append(out, "\x1b[J\x1b[?7h"...)
	_, _ = w.Write(out)
}

// clipVisible truncates a line so that its visible width (ignoring ANSI
// escape sequences) is at most max columns. Operates on runes, not bytes,
// so multi-byte UTF-8 characters (box drawing, logo art, cyrillic) are
// counted correctly. The reset sequence is appended so colour state
// doesn't bleed into the next line.
func clipVisible(line []byte, max int) []byte {
	if max <= 0 {
		return nil
	}
	s := string(line)
	visible := 0
	inEscape := false
	cutBytes := -1
	for i, r := range s {
		if inEscape {
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		if r == 0x1b {
			inEscape = true
			continue
		}
		if visible >= max {
			cutBytes = i
			break
		}
		visible++
	}
	if cutBytes < 0 {
		return line
	}
	out := make([]byte, 0, cutBytes+8)
	out = append(out, line[:cutBytes]...)
	out = append(out, "\x1b[0m"...)
	return out
}

// visibleLenBytes returns the visible column width of a byte slice,
// ignoring ANSI escape sequences and counting wide runes as 2 columns.
// This is the []byte counterpart of visibleLen(string).
func visibleLenBytes(b []byte) int {
	// Fast path for ASCII bytes without escape sequences
	hasSpecial := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c >= 0x80 || c == 0x1b {
			hasSpecial = true
			break
		}
	}
	if !hasSpecial {
		return len(b)
	}

	count := 0
	inEscape := false
	prevNarrowSymbol := false
	for _, c := range string(b) {
		if inEscape {
			if c == 'm' {
				inEscape = false
			}
			continue
		}
		if c == 0x1b {
			inEscape = true
			continue
		}
		if c >= 0xfe00 && c <= 0xfe0f {
			// Same emoji-presentation rule as visibleLen: U+FE0F widens a
			// 1-column text symbol to 2 columns.
			if c == 0xfe0f && prevNarrowSymbol {
				count++
				prevNarrowSymbol = false
			}
			continue
		}
		if isWideRune(c) {
			count += 2
			prevNarrowSymbol = false
		} else {
			count++
			prevNarrowSymbol = vs16WidensRune(c)
		}
	}
	return count
}

// renderBody writes the dashboard into t.out.writer (which is a buffer
// during render()). It contains the previous render() body verbatim.
func (t *tuiState) renderBody() {
	width := t.out.uiWidth()
	edge := t.out.uiEdge()
	cols := termCols()
	rowsTerm := termRows()
	if cols <= 0 {
		cols = width
	}

	// If the window is too small for any layout, show a friendly hint
	// instead of broken artwork.
	if cols < 50 || rowsTerm > 0 && rowsTerm < 14 {
		t.renderTooSmall(cols, rowsTerm)
		return
	}

	windowed := rowsTerm < 46
	paletteOpen := t.palette.open
	dialogOpen := t.dialog.open

	if windowed && paletteOpen {
		// Windowed + palette: render palette only, hide base screen
		lines := t.palette.render(width, edge, true)
		for _, ln := range lines {
			fmt.Fprintln(t.out.writer, strings.Repeat(" ", edge)+ln)
		}
		for i := len(lines); i < rowsTerm; i++ {
			fmt.Fprintln(t.out.writer)
		}
	} else if windowed && dialogOpen {
		// Windowed + dialog: render dialog only
		lines := t.dialog.render(width)
		for _, ln := range lines {
			fmt.Fprintln(t.out.writer, strings.Repeat(" ", edge)+ln)
		}
		for i := len(lines); i < rowsTerm; i++ {
			fmt.Fprintln(t.out.writer)
		}
	} else {
		// Route to active screen
		switch t.screen {
		case "home":
			t.renderHomeScreen(width, edge)
		case "help":
			t.renderHelpScreen(width, edge)
		case "results":
			t.renderResultsScreen(width, edge)
		case "intercept":
			t.renderInterceptScreen(width, edge)
		default:
			// Settings (classic table)
			rows := t.allRows()
			if t.cursor >= len(rows) {
				t.cursor = len(rows) - 1
			}
			wide := cols >= 110 && rowsTerm >= 30
			if wide {
				t.renderWide(width, edge, rows)
			} else {
				t.renderCompact(width, edge, rows, rowsTerm)
			}
		}

		// Tall mode overlays float on top (no blank-fill needed)
		if paletteOpen {
			for _, ln := range t.palette.render(width, edge, false) {
				fmt.Fprintln(t.out.writer, strings.Repeat(" ", edge)+ln)
			}
		}
		if dialogOpen {
			for _, ln := range t.dialog.render(width) {
				fmt.Fprintln(t.out.writer, strings.Repeat(" ", edge)+ln)
			}
		}
	}

	// Toasts float in top-right corner
	for _, ln := range t.renderToasts(cols) {
		// right-align: pad to cols - visibleLen(ln)
		pad := cols - visibleLen(ln)
		if pad < 0 {
			pad = 0
		}
		fmt.Fprintln(t.out.writer, strings.Repeat(" ", pad)+ln)
	}
}

func (t *tuiState) renderHomeScreen(width, edge int) {
	for _, ln := range t.home.render(width, edge) {
		fmt.Fprintln(t.out.writer, ln)
	}
}

func (t *tuiState) renderHelpScreen(width, edge int) {
	t.renderCompactHeader(width, edge)
	for _, ln := range t.help.render(width) {
		fmt.Fprintln(t.out.writer, strings.Repeat(" ", edge)+ln)
	}
}

func (t *tuiState) renderResultsScreen(width, edge int) {
	t.renderCompactHeader(width, edge)
	for _, ln := range t.results.render(width) {
		fmt.Fprintln(t.out.writer, strings.Repeat(" ", edge)+ln)
	}
}

func (t *tuiState) renderInterceptScreen(width, edge int) {
	rowsTerm := termRows()
	for _, ln := range t.intercept.render(width, rowsTerm) {
		fmt.Fprintln(t.out.writer, strings.Repeat(" ", edge)+ln)
	}
}

// renderTooSmall draws a minimal hint when the terminal is unusable.
func (t *tuiState) renderTooSmall(cols, rowsTerm int) {
	th := t.theme
	if cols <= 0 {
		cols = 40
	}
	pad := func(s string) string {
		if visibleLen(s) >= cols {
			return s
		}
		return s + strings.Repeat(" ", cols-visibleLen(s))
	}
	fmt.Fprintln(t.out.writer, pad(th.Bold+th.Primary+"mega analyzer"+th.Reset))
	fmt.Fprintln(t.out.writer, pad(th.Muted+"window is too small"+th.Reset))
	fmt.Fprintln(t.out.writer, pad(th.Muted+fmt.Sprintf("size: %d×%d, need ≥ 50×14", cols, rowsTerm)+th.Reset))
	fmt.Fprintln(t.out.writer, pad(th.Muted+"resize the window or press Q to quit"+th.Reset))
}

// renderWide draws the full two-column dashboard.
func (t *tuiState) renderWide(width, edge int, rows []menuRow) {
	t.renderHeader(width, edge)

	leftW := (width * 3) / 5
	if leftW < 50 {
		leftW = 50
	}
	rightW := width - 2 - leftW

	t.drawRow(edge, []rowPanel{
		{t.menuPanel(leftW, rows), leftW},
		{t.sidebarPanel(rightW), rightW},
	})

	fmt.Fprintln(t.out.writer)
	t.renderStatusBar(width, edge, rows)
}

// renderCompact draws a single-column layout for narrow / short windows.
// The menu becomes a viewport that scrolls with the cursor and a small
// inline status replaces the sidebar.
func (t *tuiState) renderCompact(width, edge int, rows []menuRow, rowsTerm int) {
	t.renderCompactHeader(width, edge)

	showActivity := rowsTerm >= 26

	// Reserve rows for all fixed UI sections so the menu viewport
	// doesn't overflow the terminal and cut off action rows.
	//   header (renderCompactHeader):         3 lines
	//   menu box overhead (top+2×empty+bot):  4 lines
	//   status bar:                           1 line
	//   "more above/below" indicators:        2 lines (worst case)
	reserved := 3 + 4 + 1 + 2 // = 10 (base overhead)
	if showActivity {
		//   spacer after menu:                    1 line
		//   activity panel (box overhead + sys):  7 lines  (5 min + 2 activity)
		//   spacer after activity:                1 line
		reserved += 9
	}

	avail := rowsTerm - reserved
	if rowsTerm <= 0 {
		avail = 10
	}
	if avail < 3 {
		avail = 3
	}
	if avail > len(rows) {
		avail = len(rows)
	}

	t.drawAt(t.compactMenuPanel(width, rows, avail), edge)

	if showActivity {
		fmt.Fprintln(t.out.writer)
		t.drawAt(t.compactActivityPanel(width), edge)
		fmt.Fprintln(t.out.writer)
	} else {
		fmt.Fprintln(t.out.writer)
	}

	t.renderStatusBar(width, edge, rows)
}

// renderCompactHeader draws a minimal one-line header for narrow windows.
func (t *tuiState) renderCompactHeader(width, edge int) {
	th := t.theme
	pad := strings.Repeat(" ", edge)

	left := fmt.Sprintf("%s%smega analyzer%s  %s//  interactive cockpit%s",
		th.Bold, th.Primary, th.Reset, th.Muted, th.Reset)
	right := fmt.Sprintf("%sv%s%s", th.Accent+th.Bold, Version, th.Reset)
	gap := width - visibleLen(left) - visibleLen(right)
	if gap < 1 {
		gap = 1
	}
	fmt.Fprintf(t.out.writer, "%s%s%s%s\n", pad, th.Edge, strings.Repeat("─", width), th.Reset)
	fmt.Fprintf(t.out.writer, "%s%s%s%s\n", pad, left, strings.Repeat(" ", gap), right)
	fmt.Fprintf(t.out.writer, "%s%s%s%s\n", pad, th.Edge, strings.Repeat("─", width), th.Reset)
}

// ─── header ───────────────────────────────────────────────────────────────────

var logoHuge = []string{
	"███╗   ███╗███████╗ ██████╗  █████╗     █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ ",
	"████╗ ████║██╔════╝██╔════╝ ██╔══██╗   ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗",
	"██╔████╔██║█████╗  ██║  ███╗███████║   ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝",
	"██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║   ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗",
	"██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║   ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║",
	"╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝",
}

var logoMedium = []string{
	"╔╦╗╔═╗╔═╗╔═╗  ╔═╗╔╗╔╔═╗╦ ╦ ╦╔═╗╔═╗╦═╗",
	"║║║║╣ ║ ╦╠═╣  ╠═╣║║║╠═╣║ ╚╦╝╔═╝║╣ ╠╦╝",
	"╩ ╩╚═╝╚═╝╩ ╩  ╩ ╩╝╚╝╩ ╩╩═╝╩ ╚══╝╚═╝╩╚═",
}

var logoTiny = []string{
	"M E G A   A N A L Y Z E R",
}

func (t *tuiState) renderHeader(width, edge int) {
	th := t.theme
	pad := strings.Repeat(" ", edge)

	rowsTerm := termRows()
	var logo []string

	// Smart adaptive logo selection to guarantee a beautiful logo is always visible,
	// adjusting dynamically to terminal height and width to prevent wrapping or distortion.
	if rowsTerm > 0 && rowsTerm < 20 {
		// Extremely tight vertically: use 1-line logoTiny
		logo = logoTiny
	} else if rowsTerm > 0 && rowsTerm < 32 {
		// Moderately tight vertically: use 3-line logoMedium if it fits horizontally, else logoTiny
		if visibleLen(logoMedium[0]) <= width {
			logo = logoMedium
		} else {
			logo = logoTiny
		}
	} else {
		// Full vertical space: use logoHuge if it fits, else logoMedium, else logoTiny
		if visibleLen(logoHuge[0]) <= width {
			logo = logoHuge
		} else if visibleLen(logoMedium[0]) <= width {
			logo = logoMedium
		} else {
			logo = logoTiny
		}
	}

	fmt.Fprintf(t.out.writer, "%s%s%s%s\n", pad, th.Edge, strings.Repeat("─", width), th.Reset)
	for _, line := range logo {
		fmt.Fprintln(t.out.writer, pad+centerText(th.Primary+th.Bold+line+th.Reset, width))
	}
	left := fmt.Sprintf("%s›%s %smega analyzer  //  interactive cockpit%s",
		th.Primary, th.Reset, th.Muted, th.Reset)
	right := fmt.Sprintf("%sv%s%s", th.Accent+th.Bold, Version, th.Reset)
	gap := width - visibleLen(left) - visibleLen(right) - 2
	if gap < 1 {
		gap = 1
	}
	fmt.Fprintf(t.out.writer, "%s %s%s%s \n", pad, left, strings.Repeat(" ", gap), right)
	fmt.Fprintf(t.out.writer, "%s%s%s%s\n", pad, th.Edge, strings.Repeat("─", width), th.Reset)
	fmt.Fprintln(t.out.writer)
}

// ─── menu panel ───────────────────────────────────────────────────────────────

func (t *tuiState) menuPanel(width int, rows []menuRow) []string {
	th := t.theme
	lines := []string{}

	labelW := 14
	valueW := width - labelW - 12
	if valueW < 18 {
		valueW = 18
	}

	// Viewport: limit visible rows in wide mode too, so the panel doesn't
	// overflow on smaller terminals. Show at most 22 rows with scroll indicators.
	rowsTerm := termRows()
	maxVisible := len(rows)
	if rowsTerm > 0 {
		maxVisible = rowsTerm - 14 // reserve for header, sidebar, status
		if maxVisible < 10 {
			maxVisible = 10
		}
	}
	if maxVisible > len(rows) {
		maxVisible = len(rows)
	}

	start := 0
	if len(rows) > maxVisible {
		// Stabilize viewport: only move if cursor is outside current view.
		start = t.vpStart
		if t.cursor < start {
			start = t.cursor
		} else if t.cursor >= start+maxVisible {
			start = t.cursor - maxVisible + 1
		}
		// Clamp
		if start < 0 {
			start = 0
		}
		if start+maxVisible > len(rows) {
			start = len(rows) - maxVisible
		}
		if start < 0 {
			start = 0
		}
		t.vpStart = start
	}
	end := start + maxVisible
	if end > len(rows) {
		end = len(rows)
	}

	if start > 0 {
		lines = append(lines, fmt.Sprintf("  %s▲ %d more above%s", th.Muted, start, th.Reset))
	}

	for i := start; i < end; i++ {
		row := rows[i]
		selected := i == t.cursor
		marker := "  "
		labelColor := th.Reset
		valueColor := th.Reset

		switch row.kind {
		case "sep":
			sepLine := fmt.Sprintf("  %s── %s ──%s", th.Edge, row.label, th.Reset)
			lines = append(lines, sepLine)
			continue
		case "action":
			labelColor = th.Accent + th.Bold
			marker = "  "
			if selected {
				marker = th.Accent + "▶ " + th.Reset
				labelColor = th.Bold + th.Success
			}
			lines = append(lines, fmt.Sprintf("%s%s%s%s",
				marker, labelColor, row.label, th.Reset))
			continue
		}

		if selected {
			marker = th.Primary + "▶ " + th.Reset
			labelColor = th.Bold + th.Primary
		}

		val := row.value()
		switch row.kind {
		case "bool":
			if row.getBool != nil && row.getBool() {
				valueColor = th.Success
			} else {
				valueColor = th.Muted
			}
		case "choice":
			valueColor = th.Secondary
		case "int":
			valueColor = th.Info
		case "text":
			if val == "<not selected>" || val == "" {
				valueColor = th.Muted
			} else {
				valueColor = th.Warning
			}
		}

		hint := ""
		if selected && row.hint != "" {
			hint = "  " + th.Muted + row.hint + th.Reset
		}

		// Indicator showing how to change the value
		ind := "    "
		if selected {
			switch row.kind {
			case "bool":
				ind = th.Muted + "[←→]" + th.Reset
			case "choice":
				ind = th.Muted + "[←→]" + th.Reset
			case "int", "text":
				ind = th.Muted + "[↵ ]" + th.Reset
			}
		}

		valDisp := truncate(val, valueW)
		lines = append(lines, fmt.Sprintf("%s%s%-*s%s  %s%s%s  %s%s",
			marker,
			labelColor, labelW, row.label, th.Reset,
			valueColor, padRight(valDisp, valueW), th.Reset,
			ind, hint))
	}

	if end < len(rows) {
		lines = append(lines, fmt.Sprintf("  %s▼ %d more below%s", th.Muted, len(rows)-end, th.Reset))
	}

	style := t.panelStyle(th.Primary, "▣")
	return t.out.renderBoxLines(style, "SETTINGS", lines, width)
}

// compactMenuPanel renders the menu inside a single panel with viewport
// scrolling so the selected row is always visible. Used for narrow windows.
// `viewport` is the maximum number of menu rows to display at once.
func (t *tuiState) compactMenuPanel(width int, rows []menuRow, viewport int) []string {
	th := t.theme
	if viewport <= 0 {
		viewport = 6
	}
	if viewport > len(rows) {
		viewport = len(rows)
	}

	// Slide the viewport so the cursor is always inside it.
	start := t.cursor - viewport/2
	if start < 0 {
		start = 0
	}
	if start+viewport > len(rows) {
		start = len(rows) - viewport
	}
	if start < 0 {
		start = 0
	}
	end := start + viewport
	if end > len(rows) {
		end = len(rows)
	}

	labelW := 14
	valueW := width - labelW - 14
	if valueW < 12 {
		valueW = 12
	}

	lines := make([]string, 0, viewport+2)

	// Top "more above" indicator.
	if start > 0 {
		lines = append(lines, fmt.Sprintf("  %s▲ %d more above%s", th.Muted, start, th.Reset))
	} else {
		lines = append(lines, "")
	}

	for i := start; i < end; i++ {
		row := rows[i]
		selected := i == t.cursor
		marker := "  "
		labelColor := th.Reset
		valueColor := th.Reset

		if row.kind == "sep" {
			sepLine := fmt.Sprintf("  %s── %s ──%s", th.Edge, row.label, th.Reset)
			lines = append(lines, sepLine)
			continue
		}

		if row.kind == "action" {
			labelColor = th.Accent + th.Bold
			if selected {
				marker = th.Accent + "▶ " + th.Reset
				labelColor = th.Bold + th.Success
			}
			lines = append(lines, fmt.Sprintf("%s%s%s%s", marker, labelColor, row.label, th.Reset))
			continue
		}

		if selected {
			marker = th.Primary + "▶ " + th.Reset
			labelColor = th.Bold + th.Primary
		}

		val := row.value()
		switch row.kind {
		case "bool":
			if row.getBool != nil && row.getBool() {
				valueColor = th.Success
			} else {
				valueColor = th.Muted
			}
		case "choice":
			valueColor = th.Secondary
		case "int":
			valueColor = th.Info
		case "text":
			if val == "<not selected>" || val == "" {
				valueColor = th.Muted
			} else {
				valueColor = th.Warning
			}
		}

		ind := "    "
		if selected {
			switch row.kind {
			case "bool", "choice":
				ind = th.Muted + "[←→]" + th.Reset
			case "int", "text":
				ind = th.Muted + "[↵ ]" + th.Reset
			}
		}

		valDisp := truncate(val, valueW)
		lines = append(lines, fmt.Sprintf("%s%s%-*s%s  %s%s%s  %s",
			marker,
			labelColor, labelW, row.label, th.Reset,
			valueColor, padRight(valDisp, valueW), th.Reset,
			ind))
	}

	// Bottom "more below" indicator.
	if end < len(rows) {
		lines = append(lines, fmt.Sprintf("  %s▼ %d more below%s", th.Muted, len(rows)-end, th.Reset))
	} else {
		lines = append(lines, "")
	}

	style := t.panelStyle(th.Primary, "▣")
	return t.out.renderBoxLines(style, "SETTINGS", lines, width)
}

// compactActivityPanel renders a tiny info strip combining a short status
// line with the most recent activity entry. Replaces the wide-mode sidebar
// when the window is narrow.
func (t *tuiState) compactActivityPanel(width int) []string {
	th := t.theme

	cpus := runtime.NumCPU()
	moduleCount := 0
	if t.opts.EnableCallGraph {
		moduleCount++
	}
	if t.opts.EnableCorrelations {
		moduleCount++
	}
	if t.opts.EnableDeepScan {
		moduleCount++
	}

	// One-line system summary.
	sys := fmt.Sprintf("%scpus%s %d  %sworkers%s %d  %smodules%s %d/3  %s%s/%s%s  %suptime%s %s",
		th.Muted, th.Reset, cpus,
		th.Muted, th.Reset, t.opts.Workers,
		th.Muted, th.Reset, moduleCount,
		th.Muted, runtime.GOOS, runtime.GOARCH, th.Reset,
		th.Muted, th.Reset, formatDuration(time.Since(t.started)))

	// Last 1–2 activity entries.
	maxN := 2
	start := 0
	if len(t.activity) > maxN {
		start = len(t.activity) - maxN
	}
	lines := []string{sys}
	for _, a := range t.activity[start:] {
		marker := th.Muted + "·" + th.Reset
		switch a.kind {
		case "ok":
			marker = th.Success + "+" + th.Reset
		case "warn":
			marker = th.Warning + "!" + th.Reset
		case "info":
			marker = th.Info + ">" + th.Reset
		}
		lines = append(lines, fmt.Sprintf("%s %s[%s]%s  %s",
			marker, th.Muted, a.at.Format("15:04:05"), th.Reset, a.text))
	}

	return t.out.renderBoxLines(t.panelStyle(th.Info, "▤"), "STATUS", lines, width)
}

// ─── sidebar (system + activity) ──────────────────────────────────────────────

func (t *tuiState) sidebarPanel(width int) []string {
	th := t.theme

	cpus := runtime.NumCPU()
	moduleCount := 0
	if t.opts.EnableCallGraph {
		moduleCount++
	}
	if t.opts.EnableCorrelations {
		moduleCount++
	}
	if t.opts.EnableDeepScan {
		moduleCount++
	}

	barW := width - 30
	if barW < 10 {
		barW = 10
	}
	if barW > 28 {
		barW = 28
	}

	sysLines := []string{
		fmt.Sprintf("%scpus       %s%s  %s%d%s", th.Muted, th.Reset,
			th.ProgressBar(t.opts.Workers, cpus, barW), th.Muted, cpus, th.Reset),
		fmt.Sprintf("%sworkers    %s%s  %s%d%s", th.Muted, th.Reset,
			th.ProgressBar(t.opts.Workers, cpus, barW), th.Muted, t.opts.Workers, th.Reset),
		fmt.Sprintf("%smodules    %s%s  %s%d/3%s", th.Muted, th.Reset,
			th.ProgressBar(moduleCount, 3, barW), th.Muted, moduleCount, th.Reset),
		"",
		fmt.Sprintf("%splatform   %s%s/%s", th.Muted, th.Reset, runtime.GOOS, runtime.GOARCH),
		fmt.Sprintf("%sengine     %s%s v%s", th.Muted, th.Reset, AppName, Version),
		fmt.Sprintf("%suptime     %s%s", th.Muted, th.Reset, formatDuration(time.Since(t.started))),
	}
	sysBox := t.out.renderBoxLines(t.panelStyle(th.Info, "▤"), "SYSTEM", sysLines, width)

	// Activity (last 6)
	maxN := 6
	start := 0
	if len(t.activity) > maxN {
		start = len(t.activity) - maxN
	}
	actLines := []string{}
	for _, a := range t.activity[start:] {
		marker := th.Muted + "·" + th.Reset
		switch a.kind {
		case "ok":
			marker = th.Success + "+" + th.Reset
		case "warn":
			marker = th.Warning + "!" + th.Reset
		case "info":
			marker = th.Info + ">" + th.Reset
		}
		actLines = append(actLines, fmt.Sprintf("%s %s[%s]%s  %s",
			marker, th.Muted, a.at.Format("15:04:05"), th.Reset, a.text))
	}
	actBox := t.out.renderBoxLines(t.panelStyle(th.Success, "▧"), "ACTIVITY", actLines, width)

	out := append([]string{}, sysBox...)
	out = append(out, "")
	out = append(out, actBox...)
	return out
}

// ─── status bar ───────────────────────────────────────────────────────────────

func (t *tuiState) renderStatusBar(width, edge int, rows []menuRow) {
	th := t.theme
	pad := strings.Repeat(" ", edge)

	keys := []struct{ k, v string }{
		{"↑↓", "navigate"},
		{"←→", "change"},
		{"↵ ", "edit"},
		{"H ", "home"},
	}
	left := []string{}
	for _, k := range keys {
		left = append(left, fmt.Sprintf("%s%s%s %s%s%s",
			th.Bold+th.Accent, k.k, th.Reset, th.Muted, k.v, th.Reset))
	}
	leftStr := strings.Join(left, "  ")

	state := "READY"
	stateColor := th.Success + th.Bold
	if t.opts.Target == "" {
		state = "AWAITING TARGET"
		stateColor = th.Warning + th.Bold
	}

	rightStr := ""
	if t.flash != "" {
		rightStr = fmt.Sprintf("%s! %s%s", th.Warning+th.Bold, t.flash, th.Reset)
	} else {
		// Show context-sensitive line for the selected row
		if t.cursor < len(rows) {
			r := rows[t.cursor]
			if r.hint != "" && r.kind != "action" {
				rightStr = fmt.Sprintf("%s%s  %s%s%s", th.Muted, r.label, th.Reset, th.Muted, th.Reset)
				_ = rightStr // avoid unused
				rightStr = fmt.Sprintf("%s%s%s", th.Muted, r.hint, th.Reset)
			}
		}
		if rightStr == "" {
			rightStr = fmt.Sprintf("%s%s%s", stateColor, state, th.Reset)
		} else {
			rightStr = rightStr + "   " + stateColor + state + th.Reset
		}
	}

	gap := width - visibleLen(leftStr) - visibleLen(rightStr)
	if gap < 1 {
		gap = 1
	}
	fmt.Fprintf(t.out.writer, "%s%s%s%s\n", pad, leftStr, strings.Repeat(" ", gap), rightStr)
}

// ═══════════════════════════════════════════════════════════════════════════════
// INLINE PROMPT
// ═══════════════════════════════════════════════════════════════════════════════

// inlinePrompt opens a single-line editor below the dashboard. Returns
// (value, ok). ok==false means the user cancelled with Esc.
func (t *tuiState) inlinePrompt(label, initial string, intOnly bool) (string, bool) {
	th := t.theme
	pad := strings.Repeat(" ", t.out.uiEdge())

	// Show cursor while typing.
	t.term.ShowCursor()
	defer t.term.HideCursor()

	buf := []rune(initial)
	render := func() {
		// Clear current line and redraw prompt
		fmt.Fprint(t.out.writer, "\r\x1b[K")
		fmt.Fprintf(t.out.writer, "%s%s>%s %s: %s%s%s",
			pad,
			th.Primary+th.Bold, th.Reset,
			label,
			th.Bold, string(buf), th.Reset)
	}
	render()

	for {
		ev, err := t.term.ReadKey()
		if err != nil {
			return "", false
		}
		switch ev.kind {
		case keyEnter:
			fmt.Fprintln(t.out.writer)
			return string(buf), true
		case keyEsc:
			fmt.Fprintln(t.out.writer)
			t.flash = "edit cancelled"
			return "", false
		case keyBackspace:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
		case keyChar:
			if intOnly {
				if !(ev.r >= '0' && ev.r <= '9') && ev.r != '-' {
					continue
				}
			}
			buf = append(buf, ev.r)
		}
		render()
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LAYOUT HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

type rowPanel struct {
	lines []string
	width int
}

func (t *tuiState) drawRow(edge int, panels []rowPanel) {
	maxH := 0
	for _, p := range panels {
		if len(p.lines) > maxH {
			maxH = len(p.lines)
		}
	}
	pad := strings.Repeat(" ", edge)
	gap := "  "
	for i := 0; i < maxH; i++ {
		fmt.Fprint(t.out.writer, pad)
		for pi, p := range panels {
			if pi > 0 {
				fmt.Fprint(t.out.writer, gap)
			}
			if i < len(p.lines) {
				fmt.Fprint(t.out.writer, p.lines[i])
			} else {
				fmt.Fprint(t.out.writer, strings.Repeat(" ", p.width))
			}
		}
		fmt.Fprintln(t.out.writer)
	}
}

func (t *tuiState) drawAt(lines []string, edge int) {
	pad := strings.Repeat(" ", edge)
	for _, ln := range lines {
		fmt.Fprintln(t.out.writer, pad+ln)
	}
}

func (t *tuiState) panelStyle(color, icon string) boxStyle {
	return boxStyle{
		topLeft: "╭", topRight: "╮", botLeft: "╰", botRight: "╯",
		horizontal: "─", vertical: "│",
		color:      color,
		titleColor: t.theme.Bold + color,
		icon:       icon,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

func (t *tuiState) log(kind, text string) {
	t.activity = append(t.activity, activityEntry{
		at:   time.Now(),
		kind: kind,
		text: text,
	})
	if len(t.activity) > 32 {
		t.activity = t.activity[len(t.activity)-32:]
	}
}

func emptyAs(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func truncate(s string, w int) string {
	if visibleLen(s) <= w {
		return s
	}
	if w <= 1 {
		return "…"
	}
	out := []rune{}
	count := 0
	for _, r := range s {
		if count >= w-1 {
			break
		}
		out = append(out, r)
		count++
	}
	return string(out) + "…"
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

// runDebugger switches to the interactive machine-code debugger REPL.
func (t *tuiState) runDebugger() error {
	// Restore terminal to normal mode so the debugger REPL can read stdin.
	if t.term != nil {
		t.term.Close()
	}
	fmt.Println()
	if err := debugger.RunREPL(t.opts.Target, ""); err != nil {
		fmt.Println("Debugger error:", err)
	}
	// Re-enter raw mode for TUI.
	term, err := newRawTerm()
	if err != nil {
		return err
	}
	term.HideCursor()
	term.EnterAltScreen()
	t.term = term
	return nil
}
