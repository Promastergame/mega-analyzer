package pipeline

import (
	"bytes"
	"fmt"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

func nativeStringIndex(content, lowerPattern []byte) int {
	if len(lowerPattern) == 0 {
		return -1
	}
	first := lowerPattern[0]
	upper := first
	if first >= 'a' && first <= 'z' {
		upper = first - ('a' - 'A')
	}
	for start := 0; start+len(lowerPattern) <= len(content); {
		i := bytes.IndexFunc(content[start:], func(r rune) bool { return r == rune(first) || r == rune(upper) })
		if i < 0 {
			return -1
		}
		i += start
		if i+len(lowerPattern) > len(content) {
			return -1
		}
		matched := true
		for j, want := range lowerPattern {
			got := content[i+j]
			if got >= 'A' && got <= 'Z' {
				got += 'a' - 'A'
			}
			if got != want {
				matched = false
				break
			}
		}
		// Brotli dictionaries contain "friday" and "exposed". These are
		// not references to Frida or Xposed. Check original ASCII offsets.
		if matched && (string(lowerPattern) == "frida" || string(lowerPattern) == "xposed") {
			end := i + len(lowerPattern)
			matched = (i == 0 || !nativeASCIIAlphaNumeric(content[i-1])) && (end == len(content) || !nativeASCIIAlphaNumeric(content[end]))
		}
		if matched {
			return i
		}
		start = i + 1
	}
	return -1
}

func nativeASCIIAlphaNumeric(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// A native string match locates bytes, not a loader call or a DEX payload.
// Retain it as inventory; linked behavior needs separate source evidence.
func nativeDexReference(file, matched string, offset int) types.Match {
	m := newMatch(types.CategorySuspiciousNativePayload, file, 0,
		"Native DEX loader reference", matched, false)
	m.EvidenceType = "native_string"
	m.ReasonForSeverity = fmt.Sprintf("The native file contains %q at byte offset 0x%x. This is a string reference, not a verified DEX loading operation.", matched, offset)
	m.Explanation = &finding.Explanation{
		Status: "observation", Summary: m.ReasonForSeverity,
		Conditions: []string{fmt.Sprintf("Matched bytes: %q; file offset: 0x%x.", matched, offset)},
		Limitations: []string{
			"No reachable JNI call, DEX input or source-to-loader path is established by this match.",
			"Packers, protectors and hot-update frameworks can contain the same references. The string alone identifies neither a framework nor malware.",
		},
		NextChecks: []string{
			"Find cross-references to these bytes in native code and trace them from JNI_OnLoad or registered native methods to the loader call.",
			"Identify the DEX bytes or path passed to the loader, their origin and any signature or integrity checks before loading.",
		},
	}
	m.Evidence = []finding.Evidence{finding.NewEvidence(m.EvidenceType,
		fmt.Sprintf("Native string at byte offset 0x%x", offset), matched, finding.Location{File: file})}
	return m
}

// Instrumentation strings can belong to protection, diagnostics or tooling.
// Keep the bytes and their offset without treating them as a malicious payload.
func nativeInstrumentationReference(file, matched string, offset int) types.Match {
	m := newMatch(types.CategorySuspiciousNativePayload, file, 0,
		"Native instrumentation string reference", matched, false)
	m.Score, m.Severity = 0, types.SeverityInfo
	if m.Metadata == nil {
		m.Metadata = make(map[string]string)
	}
	m.Metadata["finding_kind"] = "hardening"
	m.EvidenceType = "native_string"
	m.ReasonForSeverity = fmt.Sprintf("The native file contains %q at byte offset 0x%x. This locates an instrumentation-related string, not executed detection or malicious code.", matched, offset)
	m.Explanation = &finding.Explanation{Status: "observation", Summary: m.ReasonForSeverity,
		Limitations: []string{"Protection, diagnostics and instrumentation tools can use the same marker; the string alone establishes neither purpose nor execution."},
		NextChecks:  []string{"Inspect native cross-references and reachable callers of the marker before assigning behavior."}}
	m.Evidence = []finding.Evidence{finding.NewEvidence("native_string",
		fmt.Sprintf("Native string at byte offset 0x%x", offset), matched, finding.Location{File: file})}
	return m
}
