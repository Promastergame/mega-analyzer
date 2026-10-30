package pipeline

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The post-processing progress labels were, for a long time, a lie about where
// the time went. reportProgress fired once for "deobfuscation" and then seven
// further phases -- the rule engine, triage, piracy analysis, hotspot scoring,
// recommendations and the two deferred closing phases -- ran without reporting
// anything. Since runDeobfuscation only sums counters the scan workers already
// produced, the step it named finished in microseconds while the progress line
// stayed on it for however long the rest of the block took. Users reasonably
// read that as "deobfuscation is slow".
//
// These tests read the source rather than driving a Pipeline, because the
// property worth protecting is structural: every phase reports, and the
// denominator matches the number of reports. A behavioural test would need the
// full analysis state and would still not catch a newly added silent phase.

const postProcessSource = "pipeline.go"

var (
	reReportProgress = regexp.MustCompile(`reportProgress\("([^"]*)"\)`)
	reTotalSteps     = regexp.MustCompile(`const totalSteps = (\d+)`)
)

func postProcessProgressLabels(t *testing.T) []string {
	t.Helper()

	src, err := os.ReadFile(postProcessSource)
	if err != nil {
		t.Fatalf("reading %s: %v", postProcessSource, err)
	}

	matches := reReportProgress.FindAllStringSubmatch(string(src), -1)
	labels := make([]string, 0, len(matches))
	for _, m := range matches {
		labels = append(labels, m[1])
	}
	if len(labels) == 0 {
		t.Fatalf("no reportProgress calls found in %s", postProcessSource)
	}
	return labels
}

// TestPostProcessProgressTotalMatchesCallCount keeps the denominator honest.
// A phase added with a reportProgress call but no bump to totalSteps makes the
// bar overshoot; a bump without a call makes it stall short of 100%.
func TestPostProcessProgressTotalMatchesCallCount(t *testing.T) {
	labels := postProcessProgressLabels(t)

	src, err := os.ReadFile(postProcessSource)
	if err != nil {
		t.Fatalf("reading %s: %v", postProcessSource, err)
	}
	m := reTotalSteps.FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("could not find `const totalSteps` in " + postProcessSource)
	}
	total, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parsing totalSteps %q: %v", m[1], err)
	}

	if total != len(labels) {
		t.Errorf("totalSteps = %d but there are %d reportProgress calls %v; "+
			"the progress bar will not reach exactly 100%%", total, len(labels), labels)
	}
}

// TestPostProcessReportsEveryFormerlySilentPhase pins the specific phases that
// used to run under the "deobfuscation" label without reporting.
func TestPostProcessReportsEveryFormerlySilentPhase(t *testing.T) {
	labels := postProcessProgressLabels(t)

	seen := make(map[string]bool, len(labels))
	for _, l := range labels {
		seen[l] = true
	}

	formerlySilent := []string{
		"rule engine",
		"triage",
		"piracy analysis",
		"hotspot scoring",
		"recommendations",
		"typed findings",
		"evidence graph",
	}
	for _, phase := range formerlySilent {
		if !seen[phase] {
			t.Errorf("phase %q does not report progress; it will be attributed "+
				"to whichever step reported last", phase)
		}
	}
}

// TestPostProcessProgressLabelsAreUnique catches two phases sharing a label,
// which reintroduces the original defect in a subtler form: the bar advances
// but the text does not change, so the UI still looks stuck.
func TestPostProcessProgressLabelsAreUnique(t *testing.T) {
	labels := postProcessProgressLabels(t)

	first := make(map[string]int, len(labels))
	for i, l := range labels {
		if prev, dup := first[l]; dup {
			t.Errorf("progress label %q used at call %d and again at call %d", l, prev+1, i+1)
			continue
		}
		first[l] = i
	}
}
