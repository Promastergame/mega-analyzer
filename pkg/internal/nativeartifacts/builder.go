package nativeartifacts

import (
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// NATIVE VIEW BUILDER
//
// Aggregates information already produced elsewhere (Rust scan report,
// Aetrium recovered strings, smali class list) into a single view ready
// for the report HTML / JSON renderers.
//
// We deliberately don't import apkloader to avoid pulling cgo into report
// downstreams. Instead the runner converts apkloader.NativeScanReport into
// the lightweight ScanInput defined here.
// ═══════════════════════════════════════════════════════════════════════════════

// ScanInput is a transport struct decoupled from apkloader.NativeScanReport.
type ScanInput struct {
	Arch              string
	Stripped          bool
	Score             uint32
	Verdict           string
	JNISymbols        []string
	SuspiciousStrings []string
	AntiSignals       []string
	RecoveredStrings  []string
	ScanReportRef     string
}

// View is the rendered native-artifact summary.
type View struct {
	Arch              string
	Stripped          bool
	Score             uint32
	Verdict           string
	JNIBindings       []Binding
	CrackPoints       []string
	SuspiciousStrings []string
	AntiSignals       []string
	RecoveredStrings  []string
	ScanReportRef     string
}

// Binding pairs a JNI symbol with its resolved Smali target.
type Binding struct {
	Symbol      string
	SmaliTarget string
}

// Build produces a View from the inputs. classes is the list of Smali
// class names available for resolution. crackPoints is filtered by the
// caller (only those for the current native lib).
func Build(in ScanInput, classes []string, crackPoints []string) View {
	v := View{
		Arch:              in.Arch,
		Stripped:          in.Stripped,
		Score:             in.Score,
		Verdict:           in.Verdict,
		SuspiciousStrings: dedupSorted(in.SuspiciousStrings),
		AntiSignals:       dedupSorted(in.AntiSignals),
		RecoveredStrings:  in.RecoveredStrings,
		ScanReportRef:     in.ScanReportRef,
		CrackPoints:       dedupSorted(crackPoints),
	}
	if len(in.JNISymbols) > 0 {
		bindings := make([]Binding, 0, len(in.JNISymbols))
		seen := make(map[string]struct{}, len(in.JNISymbols))
		for _, sym := range in.JNISymbols {
			if !strings.HasPrefix(sym, "Java_") {
				continue
			}
			if _, ok := seen[sym]; ok {
				continue
			}
			seen[sym] = struct{}{}
			ref, ok := ResolveJNI(sym, classes)
			b := Binding{Symbol: sym}
			if ok {
				b.SmaliTarget = ref
			}
			bindings = append(bindings, b)
		}
		sort.Slice(bindings, func(i, j int) bool {
			return bindings[i].Symbol < bindings[j].Symbol
		})
		v.JNIBindings = bindings
	}
	return v
}

func dedupSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
