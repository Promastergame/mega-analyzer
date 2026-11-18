package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

var tuiSections = []string{
	"general", "analysis", "mobile", "compliance", "artifacts", "cache", "reports", "toolkit", "network",
}

var tuiSectionLabels = []string{
	"General", "Code analysis", "Mobile security", "Compliance", "Artifacts", "Data & cache", "Reports & triage", "Toolkit", "Network",
}

func tuiOptions(parsed *CLIOptions) *CLIOptions {
	// The parser has already applied defaults, environment and profile values.
	// Starting over here used to silently discard most command-line flags.
	copy := *parsed
	return &copy
}

func (t *tuiState) selectSection(name string) bool {
	for i, section := range tuiSections {
		if section == name {
			t.section, t.cursor, t.vpStart = i, 0, 0
			return true
		}
	}
	return false
}

func tuiBool(section, flag, label, hint string, value *bool) menuRow {
	return menuRow{section: section, flag: flag, label: label, hint: hint, kind: "bool",
		value: func() string { return onOff(*value) }, getBool: func() bool { return *value }, setBool: func(v bool) { *value = v }}
}

func tuiInt(section, flag, label, hint string, value *int, min, max int) menuRow {
	return menuRow{section: section, flag: flag, label: label, hint: hint, kind: "int", intMin: min, intMax: max,
		value: func() string { return strconv.Itoa(*value) }, getInt: func() int { return *value }, setInt: func(v int) { *value = v }}
}

func tuiText(section, flag, label, hint string, value *string) menuRow {
	return menuRow{section: section, flag: flag, label: label, hint: hint, kind: "text",
		value: func() string { return emptyAs(*value, "<default>") }, getStr: func() string { return *value }, setStr: func(v string) { *value = v }}
}

func (t *tuiState) allRows() []menuRow {
	rows := t.baseRows()
	section := "general"
	group := map[string]string{
		"analysis": "analysis", "output": "reports", "toolkit": "toolkit",
		"MobSF-derived analyzers": "mobile", "medium-priority analyzers": "compliance",
		"actions": "toolkit", "intercept": "network",
	}
	flags := map[string]string{
		"target": "target", "output": "output", "profile": "profile", "workers": "workers", "timeout": "timeout", "max-files": "max-files", "report": "report",
		"callgraph": "callgraph", "correlations": "correlations", "deep scan": "deep-scan", "artifacts": "artifacts", "machine code": "scan-native",
		"obb scan": "obb-scan", "cache scan": "cache-scan", "ml cache script": "ml-cache-script", "dex only": "dex-only", "html report": "no-html", "json report": "no-json",
		"clean output": "clean-output", "ml patcher": "ml-patch", "make-server": "make-server", "jni bridge": "jni-bridge", "privacy": "privacy", "graph explorer": "graph-explorer", "firmware / IoT": "firmware",
		"mobsf all": "mobsf-all", "sast rules": "sast-rules", "trackers (Exodus)": "trackers", "nsc audit": "nsc-audit", "manifest audit": "manifest-audit", "apkid": "apkid",
		"medium all": "medium-all", "playstore": "playstore", "sbom": "sbom", "permmap": "permmap", "cert audit": "cert-audit", "malware domains": "malware-domains", "niap": "niap",
		"net-filter": "net-filter", "net-flows": "net-flows",
	}
	result := make([]menuRow, 0, len(rows)+32)
	for _, row := range rows {
		if row.kind == "sep" {
			section = group[row.label]
			continue
		}
		row.section, row.flag = section, flags[row.label]
		if row.kind == "action" && row.run != nil {
			run := row.run
			row.run = func() error {
				t.opts.Target = cleanTUIPath(t.opts.Target)
				return run()
			}
		}
		switch row.label {
		case "target", "output", "profile", "workers", "timeout", "max-files":
			row.section = "general"
		case "artifacts":
			row.section = "artifacts"
		case "obb scan", "cache scan", "ml cache script":
			row.section = "cache"
		case "dex only", "ml patcher":
			row.section = "analysis"
		case "report", "html report", "json report", "clean output":
			row.section = "reports"
		}
		// Profile defaults must not override a user's explicit TUI edit.
		setBool := row.setBool
		switch row.flag {
		case "callgraph":
			row.setBool = func(v bool) { setBool(v); t.opts.CallGraphExplicit = true }
		case "correlations":
			row.setBool = func(v bool) { setBool(v); t.opts.CorrelationsExplicit = true }
		case "deep-scan":
			row.setBool = func(v bool) { setBool(v); t.opts.DeepScanExplicit = true }
		}
		if row.flag == "timeout" {
			set := row.setInt
			row.setInt = func(v int) { set(v); t.opts.TimeoutExplicit = true }
		}
		result = append(result, row)
	}
	o := t.opts
	extra := []menuRow{
		tuiBool("analysis", "scan-bytecode", "bytecode scan", "Scan APK, Smali or ASM bytecode", &o.Binzap),
		tuiBool("analysis", "scan-bytecode-deep", "bytecode data-flow", "Add offline taint and data-flow analysis", &o.BinzapActive),
		tuiBool("analysis", "enable-data-flow", "data-flow", "Follow values between methods", &o.EnableDataFlow),
		tuiInt("analysis", "data-flow-max-methods", "method limit", "Maximum methods visited by data-flow", &o.DataFlowMaxMethods, 1, 2000000),
		tuiInt("analysis", "data-flow-max-findings", "finding limit", "Maximum data-flow findings", &o.DataFlowMaxFindings, 1, 100000),
		tuiInt("analysis", "max-file-size", "code size (MB)", "0 uses the analysis profile's limit", &o.MaxFileSizeMB, 0, 4096),
		tuiInt("analysis", "max-resource-size", "resource size (MB)", "0 uses the analysis profile's limit", &o.MaxResourceSizeMB, 0, 4096),
		tuiBool("artifacts", "enable-media", "media forensics", "Inspect media for polyglots and hidden payloads", &o.EnableMedia),
		tuiBool("artifacts", "allow-export", "export buttons", "Allow downloads in the HTML artifact viewer", &o.AllowExport),
		tuiBool("artifacts", "no-image-blur", "unblur images", "Show potentially sensitive images without blur", &o.NoImageBlur),
		tuiInt("artifacts", "artifacts-max-mb", "file embed (MB)", "Maximum embedded size for each artifact", &o.ArtifactsMaxMB, 1, 4096),
		tuiInt("artifacts", "artifacts-budget", "embed budget (MB)", "Total size budget for embedded artifacts", &o.ArtifactsBudgetMB, 1, 32768),
		tuiBool("cache", "enable-content-cache", "content cache", "Reuse analysis of unchanged content", &o.EnableContentCache),
		tuiText("cache", "content-cache-dir", "cache directory", "Directory used by the content cache", &o.ContentCacheDir),
		tuiText("cache", "obb-data-dir", "OBB / data path", "Additional Android data or expansion directory", &o.OBBDataDir),
		tuiInt("cache", "obb-max-size", "OBB limit (MB)", "Skip expansion files above this limit", &o.OBBMaxSizeMB, 1, 32768),
		tuiBool("cache", "keep-temp", "keep temp files", "Keep decoded temporary files after analysis", &o.KeepTemp),
		tuiBool("reports", "sarif", "SARIF report", "Write analysis.sarif for code scanning tools", &o.SARIF),
		tuiBool("reports", "fp-strict", "strict triage", "Suppress findings without confirmed app or SDK risk", &o.FPStrict),
		tuiBool("reports", "fp-show-suppressed", "suppressed findings", "Keep suppressed-noise details in reports", &o.FPShowSuppressed),
		tuiInt("reports", "fp-suppressed-limit", "suppressed limit", "-1 profile default; 0 unlimited", &o.FPSuppressedLimit, -1, 100000),
		tuiBool("reports", "debug", "debug logging", "Include diagnostic details in the analysis log", &o.DebugVerbose),
		tuiText("reports", "known-set", "known-set bundle", "Compare against a known-good / known-bad bundle", &o.KnownSet),
	}
	for i := range extra {
		row := &extra[i]
		switch row.flag {
		case "max-file-size":
			set := row.setInt
			row.setInt = func(v int) { set(v); o.MaxFileSizeExplicit = true }
		case "max-resource-size":
			set := row.setInt
			row.setInt = func(v int) { set(v); o.MaxResourceSizeExplicit = true }
		case "enable-data-flow":
			setBool := row.setBool
			row.setBool = func(v bool) { setBool(v); o.DataFlowExplicit = true }
		case "scan-bytecode-deep":
			row.setBool = func(v bool) {
				o.BinzapActive = v
				if v {
					o.Binzap = true
				}
			}
		}
	}
	return append(result, extra...)
}

func (t *tuiState) sectionRows() []menuRow {
	if t.section < 0 || t.section >= len(tuiSections) {
		t.section = 0
	}
	var rows []menuRow
	for _, row := range t.allRows() {
		if row.section == tuiSections[t.section] {
			rows = append(rows, row)
		}
	}
	return rows
}

func (t *tuiState) readKey() (keyEvent, error) {
	if t.keyCh == nil {
		return t.term.ReadKey()
	}
	select {
	case ev := <-t.keyCh:
		return ev, nil
	case err := <-t.errCh:
		return keyEvent{}, err
	}
}

func (t *tuiState) startAnalysis() error {
	t.opts.Target = cleanTUIPath(t.opts.Target)
	if t.opts.Target == "" {
		t.flash = "Enter a target path first"
		return nil
	}
	if _, err := os.Stat(t.opts.Target); err != nil {
		t.flash = "Target not found: " + t.opts.Target
		return nil
	}
	// The primary Start command always runs analysis. Standalone tools have
	// their own explicit actions and must not hijack it via a settings toggle.
	t.opts.Firmware = false
	t.opts.MakeServer = false
	if t.home != nil {
		warn := t.home.checkCompatibility()
		if warn != "" && t.compatWarning != warn {
			t.compatWarning = warn
			t.flash = warn + " — press start again to proceed"
			return nil
		}
	}
	if err := t.opts.Validate(); err != nil {
		t.flash = err.Error()
		return nil
	}
	t.log("ok", "starting analysis")
	return errStartAnalysis
}

func (t *tuiState) renderSettings(width, edge, height int) {
	th := t.theme
	rows := t.sectionRows()
	if t.cursor < 0 || t.cursor >= len(rows) {
		t.cursor = 0
	}
	pad := strings.Repeat(" ", edge)
	fmt.Fprintln(t.out.writer, pad+th.Bold+th.Primary+"MEGA ANALYZER"+th.Reset+th.Muted+"  /  CONFIGURATION"+th.Reset)
	fmt.Fprintln(t.out.writer, pad+th.Edge+strings.Repeat("─", width)+th.Reset)
	wide := width >= 94 && (height <= 0 || height >= 26)
	listWidth := width
	if wide {
		listWidth = width - 26
	}
	avail := height - 12
	if !wide {
		avail -= 2
	}
	if height <= 0 {
		avail = 12
	}
	if avail < 1 {
		avail = 1
	}
	if avail > len(rows) {
		avail = len(rows)
	}
	start := t.vpStart
	if t.cursor < start {
		start = t.cursor
	}
	if t.cursor >= start+avail {
		start = t.cursor - avail + 1
	}
	if start < 0 {
		start = 0
	}
	if start+avail > len(rows) {
		start = len(rows) - avail
	}
	t.vpStart = start
	var nav []string
	for i, label := range tuiSectionLabels {
		marker, color := "  ", th.Muted
		if i == t.section {
			marker, color = "› ", th.Primary+th.Bold
		}
		nav = append(nav, fmt.Sprintf("%s%s%d %s%s", color, marker, i+1, truncateVisible(label, 14), th.Reset))
	}
	var list []string
	for i := start; i < start+avail; i++ {
		row := rows[i]
		marker, color := "  ", th.Text
		if i == t.cursor {
			marker, color = "› ", th.Bold+th.Primary
		}
		labelW := listWidth - 24
		if labelW > 28 {
			labelW = 28
		}
		valueW := listWidth - labelW - 10
		value := "↵ run"
		valueColor := th.Muted
		if row.value != nil && row.kind != "action" {
			value = row.value()
		}
		if row.kind == "bool" {
			value = "○ off"
			if row.getBool() {
				value, valueColor = "● on", th.Success
			}
		}
		if row.kind == "choice" {
			valueColor = th.Accent
		}
		list = append(list, color+marker+padRight(truncateVisible(row.label, labelW), labelW)+th.Reset+"  "+valueColor+truncateVisible(value, valueW)+th.Reset)
	}
	list = append(list, th.Muted+fmt.Sprintf("%d–%d / %d options", start+1, start+avail, len(rows))+th.Reset)
	listBox := t.out.renderBoxLines(t.panelStyle(th.Primary, ""), strings.ToUpper(tuiSectionLabels[t.section]), list, listWidth)
	if wide {
		navBox := t.out.renderBoxLines(t.panelStyle(th.Edge, ""), "SECTIONS", nav, 24)
		t.drawRow(edge, []rowPanel{{navBox, 24}, {listBox, listWidth}})
	} else {
		fmt.Fprintln(t.out.writer, pad+th.Primary+th.Bold+fmt.Sprintf("%d / 9  %s", t.section+1, tuiSectionLabels[t.section])+th.Reset)
		fmt.Fprintln(t.out.writer, pad+th.Muted+"Tab / Shift+Tab switch sections · 1–9 jump"+th.Reset)
		t.drawAt(listBox, edge)
	}
	if len(rows) > 0 {
		row := rows[t.cursor]
		flag := "Action"
		if row.flag != "" {
			flag = "--" + row.flag
		}
		if height > 0 && height <= 14 && t.flash != "" {
			fmt.Fprintln(t.out.writer, pad+th.Warning+truncateVisible(t.flash, width)+th.Reset)
		} else {
			fmt.Fprintln(t.out.writer, pad+th.Bold+th.Accent+flag+th.Reset+"  "+th.Muted+truncateVisible(row.hint, width-visibleLen(flag)-2)+th.Reset)
		}
	}
	state := fmt.Sprintf("%s profile · %d workers · %ds", t.opts.Profile, t.opts.Workers, t.opts.Timeout)
	if t.flash != "" {
		state = t.flash
	}
	if height <= 0 || height > 14 {
		fmt.Fprintln(t.out.writer, pad+th.Muted+truncateVisible(state, width)+th.Reset)
	}
	fmt.Fprintln(t.out.writer, pad+th.Edge+strings.Repeat("─", width)+th.Reset)
	fmt.Fprintln(t.out.writer, pad+th.Text+truncateVisible("Tab sections  ↑↓ select  ←→ change  Enter edit  Ctrl+K search  Ctrl+S start", width)+th.Reset)
	fmt.Fprintln(t.out.writer, pad+th.Muted+"Esc home  ·  F1 help  ·  1–9 jump to section"+th.Reset)
}
