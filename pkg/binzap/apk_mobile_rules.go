package binzap

import (
	"strings"

	"mega-analyzer/pkg/binzap/lex"
)

// This file adds the APK-* mobile code detectors requested for the Android
// analysis pack. Unlike a single-needle method reference match, these model
// real multi-call vulnerability patterns: a dangerous "sink" call must be
// present AND (when required) at least one corroborating "context" call must
// co-occur in the same smali file. Correlating calls this way keeps false
// positives low while still catching the genuine issue.
//
// IDs and topics follow the project vulnerability catalog:
//   APK-PENDING-001  Implicit / mutable PendingIntent      (CWE-927)
//   APK-INTENT-001   Intent redirection                    (CWE-940)
//   APK-WEBVIEW-001  WebView JavaScript bridge to content  (CWE-749)
//   APK-CPROV-001    ContentProvider / SQLite SQL injection (CWE-89)

// apkCorrelationRule fires when at least one of its sink method references is
// present in a file and, when context needles are configured, at least one of
// them also co-occurs in the same file. The finding is anchored at the sink.
type apkCorrelationRule struct {
	id, name    string
	severity    Severity
	confidence  Confidence
	cwe         string
	category    string
	remediation string
	message     string
	// sinks is the set of dangerous primary calls. At least one must appear.
	sinks []string
	// context is an optional set of corroborating calls. When non-empty, at
	// least one must also appear in the same file for the rule to fire.
	context []string
}

func (r *apkCorrelationRule) ID() string         { return r.id }
func (r *apkCorrelationRule) Name() string       { return r.name }
func (r *apkCorrelationRule) Severity() Severity { return r.severity }

func (r *apkCorrelationRule) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	sinkFound := false
	ctxFound := len(r.context) == 0
	var sinkEvidence string
	var sinkLine int

	for i := range tokens {
		t := tokens[i]
		if t.Type != lex.TokenMethodRef {
			continue
		}
		if !sinkFound {
			for _, s := range r.sinks {
				if strings.Contains(t.Value, s) {
					sinkFound = true
					sinkEvidence = t.Value
					sinkLine = t.Line
					break
				}
			}
		}
		if !ctxFound {
			for _, c := range r.context {
				if strings.Contains(t.Value, c) {
					ctxFound = true
					break
				}
			}
		}
		if sinkFound && ctxFound {
			break
		}
	}

	if !sinkFound || !ctxFound {
		return nil
	}
	return []Finding{Finding{
		RuleID:      r.id,
		RuleName:    r.name,
		Severity:    r.severity,
		Confidence:  r.confidence,
		Message:     r.message,
		File:        ctx.File,
		Line:        sinkLine,
		Evidence:    sinkEvidence,
		CWE:         r.cwe,
		Category:    r.category,
		Remediation: r.remediation,
	}.WithFingerprint()}
}

// apkMobileRules returns the APK-* correlation rules.
func apkMobileRules() []*apkCorrelationRule {
	return []*apkCorrelationRule{
		{
			id: "APK-PENDING-001", name: "Implicit or mutable PendingIntent", severity: SeverityHigh,
			confidence: ConfidenceMedium, cwe: "CWE-927", category: "ipc",
			remediation: "Create PendingIntents with FLAG_IMMUTABLE (required on API 31+) and back them with an explicit Intent (set the target package/component). Never hand a mutable PendingIntent wrapping an implicit Intent to another app.",
			message:     "PendingIntent created via a factory method; verify it is FLAG_IMMUTABLE and wraps an explicit Intent to prevent Intent hijacking/redirection",
			sinks: []string{
				"PendingIntent;->getActivity",
				"PendingIntent;->getActivities",
				"PendingIntent;->getBroadcast",
				"PendingIntent;->getService",
				"PendingIntent;->getForegroundService",
			},
		},
		{
			id: "APK-INTENT-001", name: "Intent redirection (unvalidated nested Intent)", severity: SeverityHigh,
			confidence: ConfidenceMedium, cwe: "CWE-940", category: "ipc",
			remediation: "Do not forward an Intent extracted from an incoming (untrusted) Intent. Validate the target component/action, or resolve and check it against an allowlist before start/bind/broadcast.",
			message:     "A nested Intent/Parcelable extracted from an incoming Intent is forwarded to a component launch; classic Intent-redirection primitive to reach unexported components",
			sinks: []string{
				"getParcelableExtra",
				"getParcelable(",
				"getParcelableArrayListExtra",
			},
			context: []string{
				";->startActivity",
				";->startActivityForResult",
				";->startService",
				";->bindService",
				";->sendBroadcast",
				";->startActivities",
			},
		},
		{
			id: "APK-WEBVIEW-001", name: "WebView JavaScript bridge exposed to loaded content", severity: SeverityHigh,
			confidence: ConfidenceHigh, cwe: "CWE-749", category: "webview",
			remediation: "Avoid addJavascriptInterface for untrusted/remote content. If required, restrict to https origins you control, annotate exposed methods with @JavascriptInterface (API 17+), and disable file/universal access.",
			message:     "WebView exposes a native @JavascriptInterface bridge and also loads content; remote or attacker-controlled pages can invoke bridged native methods (RCE surface)",
			sinks:       []string{"addJavascriptInterface"},
			context: []string{
				";->loadUrl",
				";->loadData",
				";->loadDataWithBaseURL",
				";->postUrl",
				"setJavaScriptEnabled",
			},
		},
		{
			id: "APK-CPROV-001", name: "ContentProvider / SQLite SQL injection", severity: SeverityHigh,
			confidence: ConfidenceMedium, cwe: "CWE-89", category: "injection",
			remediation: "Never build SQL by concatenating caller-supplied selection/args. Use parameterized selectionArgs (?) with SQLiteQueryBuilder/query(), and validate projection/sort columns against an allowlist. Export the provider only with a permission guard.",
			message:     "Raw SQLite query/exec is combined with dynamic string building; if reachable from a ContentProvider selection/URI this is SQL injection",
			sinks: []string{
				"SQLiteDatabase;->rawQuery",
				"SQLiteDatabase;->rawQueryWithFactory",
				"SQLiteDatabase;->execSQL",
				"SQLiteQueryBuilder;->appendWhere",
			},
			context: []string{
				"StringBuilder;->append",
				"StringBuilder;->toString",
				"String;->concat",
				"String;->format",
			},
		},
	}
}

// apkMobileRuleEntries wraps the APK-* rules as registry entries so they load
// with the rest of the mobile pack.
func apkMobileRuleEntries() []RuleEntry {
	rules := apkMobileRules()
	entries := make([]RuleEntry, 0, len(rules))
	for _, r := range rules {
		entries = append(entries, RuleEntry{
			Rule:    r,
			Enabled: true,
			Meta: RuleMetadata{
				ID: r.id, Name: r.name, Category: r.category, CWE: r.cwe,
				Severity: r.severity, Confidence: r.confidence,
				Remediation: r.remediation, Pack: "mobile",
			},
		})
	}
	return entries
}
