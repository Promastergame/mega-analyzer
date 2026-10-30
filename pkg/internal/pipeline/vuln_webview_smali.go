// pkg/internal/pipeline/vuln_webview_smali.go
//
// AST-based WebView security detection (audit item P2-9 / B4).
//
// The legacy byte-pattern detector had two precision flaws:
//
//  1. Boolean setters were flagged by mere presence: a call site like
//     `setJavaScriptEnabled` invoked with `const/4 vX, 0x0` (explicitly
//     DISABLED) produced the same findings as an enabled one.
//  2. The remote-content signal `A || B && C` relied on operator
//     precedence: any bare `"http` string anywhere in the class was
//     enough to claim remote loading.
//
// This detector walks each method body with a small register tracker
// (int constants + const strings) and evaluates the real call sites:
//
//   - WebSettings.setJavaScriptEnabled / setAllowUniversalAccessFromFileURLs
//     / setAllowFileAccessFromFileURLs: boolean argument resolved per call
//     site — `0x0` → safe (no finding), non-zero → finding, unresolved →
//     medium-confidence finding.
//   - WebView.addJavascriptInterface + JS enabled (+ remote content) combo:
//     remote is proven by a const-string http(s):// URL or an unresolvable
//     loadUrl/postUrl argument — never by a stray string literal.

package pipeline

import (
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// webViewBoolSetter describes one WebSettings boolean security setter.
type webViewBoolSetter struct {
	category types.Category
	desc     string
	evidence string
	severity types.Severity
}

var webViewBoolSetters = map[string]webViewBoolSetter{
	"setJavaScriptEnabled": {
		// Not emitted standalone: feeds the JS-bridge combo below.
		category: types.CategoryWebViewRemoteJS,
	},
	"setAllowUniversalAccessFromFileURLs": {
		category: types.CategoryWebViewFileAccess,
		desc: "WebView setAllowUniversalAccessFromFileURLs(true) — a file:// page can read " +
			"arbitrary local files and any origin (CWE-200)",
		evidence: "setAllowUniversalAccessFromFileURLs(true)",
		severity: types.SeverityHigh,
	},
	"setAllowFileAccessFromFileURLs": {
		category: types.CategoryWebViewFileAccess,
		desc: "WebView setAllowFileAccessFromFileURLs(true) — a file:// page can read other " +
			"local files (CWE-200)",
		evidence: "setAllowFileAccessFromFileURLs(true)",
		severity: types.SeverityMedium,
	},
}

// webViewState holds signals from one method. Combining independent methods
// without object identity invents exploit chains and produces critical false
// positives, so cross-method escalation is deliberately not performed here.
type webViewState struct {
	ifaceLine    int    // first addJavascriptInterface call site
	ifaceMethod  string // method containing it
	jsEnabled    bool   // setJavaScriptEnabled(true) resolved
	jsUnknown    bool   // setter invoked with unresolved boolean
	remoteConst  bool   // const-string http(s):// URL passed to a loader
	remoteUnkown bool   // loader invoked with unresolvable URL register
}

func detectWebViewFromAST(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	class := ctx.Class
	if class == nil {
		return
	}
	for i := range class.Methods {
		state := webViewState{}
		detectWebViewInMethod(&class.Methods[i], class, analysis, &state)
		emitWebViewCombo(class, analysis, &state)
	}
}

func emitWebViewCombo(class *types.SmaliClass, analysis *types.FileAnalysis, state *webViewState) {
	// ── JS bridge combo: interface present AND JS actually enabled ──
	if state.ifaceLine == 0 || (!state.jsEnabled && !state.jsUnknown) {
		return
	}
	jsConfidence := "high"
	if !state.jsEnabled {
		jsConfidence = "medium"
	}
	m := newMatch(
		types.CategoryWebViewJSBridge, analysis.Path, state.ifaceLine,
		"WebView addJavascriptInterface + JavaScript enabled — native bridge exposed; on API < 17 "+
			"any loaded page gains reflection-based code execution (CVE-2012-6636)",
		"addJavascriptInterface + setJavaScriptEnabled",
		false,
	)
	m.Severity = types.SeverityMedium
	m.MethodName = state.ifaceMethod
	m.ClassName = class.Name
	m.Confidence = jsConfidence
	m.EvidenceType = "smali_ast_dataflow"
	analysis.Matches = append(analysis.Matches, m)

	// ── Escalate to remote-JS RCE when the bridge is exposed to remote content ──
	if state.remoteConst || state.remoteUnkown {
		confidence := "high"
		if !(state.jsEnabled && state.remoteConst) {
			confidence = "medium"
		}
		remote := newMatch(
			types.CategoryWebViewRemoteJS, analysis.Path, state.ifaceLine,
			"WebView RCE risk: addJavascriptInterface + setJavaScriptEnabled + remote URL — "+
				"JS bridge exposed to remote content",
			"addJavascriptInterface + JS enabled + remote loadUrl",
			true,
		)
		remote.MethodName = state.ifaceMethod
		remote.ClassName = class.Name
		remote.Confidence = confidence
		remote.EvidenceType = "smali_ast_dataflow"
		analysis.Matches = append(analysis.Matches, remote)
	}
}

func detectWebViewInMethod(m *types.SmaliMethod, class *types.SmaliClass, analysis *types.FileAnalysis, state *webViewState) {
	if len(m.Body) == 0 {
		return
	}
	ints := make(map[string]int64, 16) // boolean/int constant provenance
	strs := make(map[string]string, 8) // const-string provenance (URLs)

	for bodyIdx, raw := range m.Body {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, ".") || strings.HasPrefix(line, ":") {
			continue
		}
		lineNumber := m.LineStart + bodyIdx

		if strings.HasPrefix(line, "invoke-") {
			call, ok := parseCryptoInvoke(line)
			if !ok {
				continue
			}
			evalWebViewCallSite(call, ints, strs, m, class, analysis, state, lineNumber)
			continue
		}

		dest := parseDestRegister(line)
		if dest == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "const-string"):
			if reg, val, ok := parseConstStringLine(line); ok {
				strs[reg] = val
			} else {
				delete(strs, dest)
			}
			delete(ints, dest)
		case strings.HasPrefix(line, "const"):
			delete(strs, dest)
			if strings.HasPrefix(line, "const-wide") {
				delete(ints, dest)
			} else if v, ok := parseSmaliIntOperand(line); ok {
				ints[dest] = v
			} else {
				delete(ints, dest)
			}
		case strings.HasPrefix(line, "move"):
			// move* vX, vY — duplicate provenance of the source register.
			src := strings.Fields(strings.ReplaceAll(line, ",", ""))
			if len(src) >= 3 {
				if v, ok := ints[src[2]]; ok {
					ints[dest] = v
				} else {
					delete(ints, dest)
				}
				if s, ok := strs[src[2]]; ok {
					strs[dest] = s
				} else {
					delete(strs, dest)
				}
			}
		default:
			delete(ints, dest)
			delete(strs, dest)
		}
	}
}

// evalWebViewCallSite evaluates one WebView/WebSettings invocation.
func evalWebViewCallSite(
	call cryptoInvoke,
	ints map[string]int64,
	strs map[string]string,
	m *types.SmaliMethod,
	class *types.SmaliClass,
	analysis *types.FileAnalysis,
	state *webViewState,
	lineNumber int,
) {
	switch {
	// ── WebSettings boolean security setters ──
	case call.classDesc == "Landroid/webkit/WebSettings;":
		setter, ok := webViewBoolSetters[call.method]
		if !ok || len(call.registers) != 2 {
			return // {receiver, boolArg}
		}
		arg, resolved := ints[call.registers[1]]
		if call.method == "setJavaScriptEnabled" {
			switch {
			case resolved && arg == 0:
				// A later explicit disable must suppress an earlier enable in the
				// same method's linear flow.
				state.jsEnabled = false
				state.jsUnknown = false
			case resolved:
				state.jsEnabled = true
			default:
				state.jsUnknown = true
			}
			return
		}
		switch {
		case resolved && arg == 0:
			return // explicitly disabled: no finding
		case resolved:
			match := newMatch(setter.category, analysis.Path, lineNumber, setter.desc, setter.evidence, false)
			match.Severity = setter.severity
			match.MethodName = m.Name
			match.ClassName = class.Name
			match.Confidence = "high"
			match.EvidenceType = "smali_ast_dataflow"
			analysis.Matches = append(analysis.Matches, match)
		default:
			match := newMatch(setter.category, analysis.Path, lineNumber,
				setter.desc+" [boolean argument not resolvable]",
				setter.evidence+"(?)", false)
			match.Severity = types.SeverityMedium
			match.MethodName = m.Name
			match.ClassName = class.Name
			match.Confidence = "medium"
			match.EvidenceType = "smali_ast_dataflow"
			analysis.Matches = append(analysis.Matches, match)
		}

	// ── Native JS bridge registration ──
	case call.classDesc == "Landroid/webkit/WebView;" && call.method == "addJavascriptInterface":
		if state.ifaceLine == 0 {
			state.ifaceLine = lineNumber
			state.ifaceMethod = m.Name
		}

	// ── Content loaders: classify the URL argument ──
	case call.classDesc == "Landroid/webkit/WebView;" &&
		(call.method == "loadUrl" || call.method == "loadDataWithBaseURL" || call.method == "postUrl"):
		if len(call.registers) < 2 {
			return
		}
		if url, ok := strs[call.registers[1]]; ok {
			if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
				state.remoteConst = true
			}
			return // const file://, content://, data:, ... → local
		}
		// URL register not resolvable → possibly attacker/network supplied.
		state.remoteUnkown = true
	}
}
