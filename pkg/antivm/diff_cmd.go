package antivm

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// runSessionDiff implements `antivm session diff`. It compares two captured
// DeviceState JSON documents (the "before" and "after" snapshots a session
// persists) and, by default, scans the after-state for residual emulator/VM
// fingerprints. This turns the raw artifacts a session already writes into an
// actionable answer: which device attributes actually changed, and did any
// known VM "tells" survive the masking?
//
// The scan is a heuristic over the flattened JSON values, matching a curated
// table of well-known Android emulator / hypervisor indicators (QEMU goldfish/
// ranchu kernels, SDK images, Genymotion/VirtualBox/BlueStacks, QEMU/VBox MAC
// OUIs, default IMEI, the emulator phone number, etc.). It is intentionally
// dependency-free (stdlib only) so it works on any captured state JSON without
// needing the concrete DeviceState schema.
func runSessionDiff(args []string) int {
	fs := flag.NewFlagSet("session diff", flag.ContinueOnError)
	sessionDir := fs.String("session", "", "session dir containing before.json/after.json")
	beforePath := fs.String("before", "", "before-state JSON (overrides --session)")
	afterPath := fs.String("after", "", "after-state JSON (overrides --session)")
	format := fs.String("format", "text", "output format: json|text")
	scan := fs.Bool("scan", true, "scan the after-state for residual VM tells")
	failOnResidue := fs.Bool("fail-on-residue", false, "exit non-zero when residual VM tells remain")
	threshold := fs.Float64("residue-threshold", 0, "exposure score (0-100) above which --fail-on-residue trips")
	out := fs.String("out", "", "write output to this file instead of stdout")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	bPath, aPath, err := resolveDiffPaths(*sessionDir, *beforePath, *afterPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	switch *format {
	case "json", "text":
	default:
		fmt.Fprintf(os.Stderr, "error: unknown --format %q (want json|text)\n", *format)
		return 2
	}

	beforeVal, err := loadJSONFile(bPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load before: %v\n", err)
		return 1
	}
	afterVal, err := loadJSONFile(aPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load after: %v\n", err)
		return 1
	}

	beforeFlat := map[string]string{}
	flattenJSON("", beforeVal, beforeFlat)
	afterFlat := map[string]string{}
	flattenJSON("", afterVal, afterFlat)

	result := diffResult{
		Before:  bPath,
		After:   aPath,
		Diff:    diffStates(beforeFlat, afterFlat),
		Scanned: *scan,
	}
	if *scan {
		result.Residue = scanResidue(afterFlat)
		result.ExposureScore = residueScore(result.Residue)
	}
	result.Verdict = verdictFor(*scan, result.ExposureScore)

	rendered, rerr := renderDiff(result, *format)
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "render: %v\n", rerr)
		return 2
	}

	if *out != "" {
		if werr := os.WriteFile(*out, rendered, 0o644); werr != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", werr)
			return 1
		}
		fmt.Printf("wrote %s\n", *out)
	} else {
		fmt.Println(string(rendered))
	}

	// In CI, --fail-on-residue turns a leaky mask into a non-zero exit.
	if *scan && *failOnResidue && result.ExposureScore > *threshold {
		return 1
	}
	return 0
}

// resolveDiffPaths decides which two files to compare. Explicit --before/--after
// always win and are schema-agnostic; --session <dir> is a convenience that
// assumes the conventional before.json/after.json artifact names.
func resolveDiffPaths(sessionDir, before, after string) (string, string, error) {
	if before != "" && after != "" {
		return before, after, nil
	}
	if sessionDir != "" {
		b := filepath.Join(sessionDir, "before.json")
		a := filepath.Join(sessionDir, "after.json")
		if before != "" {
			b = before
		}
		if after != "" {
			a = after
		}
		return b, a, nil
	}
	return "", "", fmt.Errorf("error: provide --before and --after, or --session <dir>")
}

func loadJSONFile(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return v, nil
}

// flattenJSON collapses an arbitrary decoded JSON value into dotted-path keys so
// two documents can be compared and scanned without knowing their schema.
func flattenJSON(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			out[prefix] = "{}"
			return
		}
		for k, val := range t {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flattenJSON(key, val, out)
		}
	case []any:
		if len(t) == 0 {
			out[prefix] = "[]"
			return
		}
		for i, val := range t {
			flattenJSON(fmt.Sprintf("%s[%d]", prefix, i), val, out)
		}
	case nil:
		out[prefix] = "null"
	case bool:
		out[prefix] = strconv.FormatBool(t)
	case float64:
		out[prefix] = strconv.FormatFloat(t, 'g', -1, 64)
	case string:
		out[prefix] = t
	default:
		out[prefix] = fmt.Sprintf("%v", t)
	}
}

type diffEntry struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}

type changeEntry struct {
	Path   string `json:"path"`
	Before string `json:"before"`
	After  string `json:"after"`
}

type stateDiff struct {
	Added   []diffEntry   `json:"added"`
	Removed []diffEntry   `json:"removed"`
	Changed []changeEntry `json:"changed"`
}

func diffStates(before, after map[string]string) stateDiff {
	var d stateDiff
	for k, av := range after {
		if bv, ok := before[k]; !ok {
			d.Added = append(d.Added, diffEntry{Path: k, Value: av})
		} else if bv != av {
			d.Changed = append(d.Changed, changeEntry{Path: k, Before: bv, After: av})
		}
	}
	for k, bv := range before {
		if _, ok := after[k]; !ok {
			d.Removed = append(d.Removed, diffEntry{Path: k, Value: bv})
		}
	}
	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].Path < d.Added[j].Path })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].Path < d.Removed[j].Path })
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].Path < d.Changed[j].Path })
	return d
}

type vmIndicator struct {
	Substr   string
	Label    string
	Severity float64 // 0..1
}

// vmIndicators is a curated table of well-known Android emulator / hypervisor
// fingerprints. Substrings are lowercase; matching is case-insensitive.
var vmIndicators = []vmIndicator{
	{"/dev/qemu_pipe", "QEMU pipe device", 0.95},
	{"goldfish", "QEMU goldfish kernel", 0.90},
	{"ranchu", "QEMU ranchu kernel", 0.90},
	{"genymotion", "Genymotion", 0.90},
	{"virtualbox", "VirtualBox", 0.90},
	{"bluestacks", "BlueStacks", 0.90},
	{"qemud", "qemud daemon", 0.85},
	{"android sdk built for", "SDK build fingerprint", 0.85},
	{"sdk_gphone", "Android SDK phone image", 0.85},
	{"vmware", "VMware", 0.85},
	{"vbox", "VirtualBox/Genymotion artifact", 0.85},
	{"qemu", "QEMU artifact", 0.80},
	{"sdk_google", "Android SDK image", 0.80},
	{"52:54:00", "QEMU MAC OUI", 0.80},
	{"08:00:27", "VirtualBox MAC OUI", 0.80},
	{"ttygf", "goldfish serial console", 0.75},
	{"emulator", "emulator string", 0.70},
	{"000000000000000", "default/blank IMEI", 0.70},
	{"15555215", "emulator phone number", 0.70},
	{"test-keys", "test-keys build signature", 0.65},
	{"generic", "generic build product", 0.55},
	{"00:00:00:00:00:00", "null MAC address", 0.55},
}

type residueFinding struct {
	Path      string  `json:"path"`
	Value     string  `json:"value"`
	Indicator string  `json:"indicator"`
	Severity  float64 `json:"severity"`
}

// scanResidue reports at most one finding per flattened path (the
// highest-severity indicator matched), keeping the exposure score from being
// inflated by overlapping substrings such as "qemu" and "/dev/qemu_pipe".
func scanResidue(flat map[string]string) []residueFinding {
	var out []residueFinding
	for _, p := range sortedStringKeys(flat) {
		lv := strings.ToLower(flat[p])
		var best vmIndicator
		found := false
		for _, ind := range vmIndicators {
			if strings.Contains(lv, ind.Substr) {
				if !found || ind.Severity > best.Severity {
					best = ind
					found = true
				}
			}
		}
		if found {
			out = append(out, residueFinding{
				Path:      p,
				Value:     flat[p],
				Indicator: best.Label,
				Severity:  best.Severity,
			})
		}
	}
	return out
}

// residueScore combines per-finding severities via a probabilistic complement
// (1 - product of (1-sev)) and returns a 0..100 exposure score with one decimal.
func residueScore(f []residueFinding) float64 {
	prod := 1.0
	for _, x := range f {
		prod *= (1 - clamp01(x.Severity))
	}
	return math.Round((1-prod)*1000) / 10
}

func verdictFor(scanned bool, score float64) string {
	if !scanned {
		return "not scanned"
	}
	switch {
	case score == 0:
		return "CLEAN — no known VM tells in captured state"
	case score < 30:
		return "LOW — minor residual tells"
	case score < 70:
		return "MODERATE — several VM tells remain"
	default:
		return "HIGH — masking likely failed"
	}
}

type diffResult struct {
	Before        string           `json:"before"`
	After         string           `json:"after"`
	Diff          stateDiff        `json:"diff"`
	Scanned       bool             `json:"scanned"`
	Residue       []residueFinding `json:"residue,omitempty"`
	ExposureScore float64          `json:"exposure_score"`
	Verdict       string           `json:"verdict"`
}

func renderDiff(r diffResult, format string) ([]byte, error) {
	if format == "json" {
		return json.MarshalIndent(r, "", "  ")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "antivm — session diff\n")
	fmt.Fprintf(&b, "before: %s\n", r.Before)
	fmt.Fprintf(&b, "after:  %s\n\n", r.After)

	fmt.Fprintf(&b, "State changes: %d added, %d removed, %d changed\n",
		len(r.Diff.Added), len(r.Diff.Removed), len(r.Diff.Changed))
	for _, e := range r.Diff.Added {
		fmt.Fprintf(&b, "  + %s = %s\n", e.Path, e.Value)
	}
	for _, e := range r.Diff.Removed {
		fmt.Fprintf(&b, "  - %s = %s\n", e.Path, e.Value)
	}
	for _, e := range r.Diff.Changed {
		fmt.Fprintf(&b, "  ~ %s: %s => %s\n", e.Path, e.Before, e.After)
	}

	if !r.Scanned {
		fmt.Fprintf(&b, "\nVM residue scan: disabled (--scan=false)\n")
		return []byte(b.String()), nil
	}

	fmt.Fprintf(&b, "\nVM residue scan (after state): %s\n", r.Verdict)
	fmt.Fprintf(&b, "  exposure score: %.1f / 100\n", r.ExposureScore)
	if len(r.Residue) == 0 {
		fmt.Fprintf(&b, "  no residual VM indicators detected\n")
	} else {
		for _, f := range r.Residue {
			fmt.Fprintf(&b, "  [sev %.2f] %s = %s  (%s)\n", f.Severity, f.Path, f.Value, f.Indicator)
		}
	}
	return []byte(b.String()), nil
}

func sortedStringKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
