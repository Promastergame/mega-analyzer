// Command eval runs the checked-in static-analysis regression corpus and
// reports per-rule precision, recall, and F1.
//
// Corpus schema (see testdata/eval/README.md for the full reference):
//
//	{
//	  "version": 2,
//	  "cases": [
//	    {
//	      "id":        unique case id,
//	      "files":     map of relative path -> file content,
//	      "expected":  categories that MUST fire,
//	      "forbidden": categories that MUST NOT fire,
//	      "locations": optional per-finding location assertions
//	                 ({category, file, line_min, line_max}),
//	      "known_gap": optional — marks the case as a documented detection
//	                 gap (expected-fail). Such cases are evaluated and
//	                 reported but excluded from precision/recall metrics.
//	    }
//	  ]
//	}
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"mega-analyzer/pkg/evalrunner"
)

type corpus struct {
	Version int        `json:"version"`
	Cases   []testCase `json:"cases"`
}

type testCase struct {
	ID        string              `json:"id"`
	Files     map[string]string   `json:"files"`
	Expected  []string            `json:"expected"`
	Forbidden []string            `json:"forbidden,omitempty"`
	Locations []locationAssertion `json:"locations,omitempty"`
	KnownGap  string              `json:"known_gap,omitempty"`
}

// locationAssertion pins a category finding to a file (and optionally a line
// range). All fields except Category are optional; a zero line_min/line_max
// means "any line".
type locationAssertion struct {
	Category string `json:"category"`
	File     string `json:"file"`
	LineMin  int    `json:"line_min,omitempty"`
	LineMax  int    `json:"line_max,omitempty"`
}

type counts struct {
	TruePositive  int     `json:"true_positive"`
	FalsePositive int     `json:"false_positive"`
	FalseNegative int     `json:"false_negative"`
	Precision     float64 `json:"precision"`
	Recall        float64 `json:"recall"`
	F1            float64 `json:"f1"`
}

// gapReport describes one known-gap case's evaluation outcome. Failures are
// the documented gaps; an empty failure list means the gap was closed and
// the known_gap marker should be removed.
type gapReport struct {
	ID              string   `json:"id"`
	Gap             string   `json:"known_gap"`
	MissingExpected []string `json:"missing_expected,omitempty"`
	Unexpected      []string `json:"unexpected,omitempty"`
	Resolved        bool     `json:"resolved,omitempty"`
}

type report struct {
	CorpusVersion int               `json:"corpus_version"`
	Cases         int               `json:"cases"`
	ScoredCases   int               `json:"scored_cases"`
	PerRule       map[string]counts `json:"per_rule"`
	Micro         counts            `json:"micro"`
	KnownGaps     []gapReport       `json:"known_gaps,omitempty"`
}

func main() {
	corpusPath := flag.String("corpus", filepath.FromSlash("testdata/eval/corpus.json"), "ground-truth corpus JSON")
	minimumPrecision := flag.Float64("min-precision", 0, "fail below this micro precision")
	minimumRecall := flag.Float64("min-recall", 0, "fail below this micro recall")
	ruleThresholds := flag.String("rule-thresholds", "", "JSON file of per-category precision/recall gates")
	flag.Parse()
	if err := run(*corpusPath, *minimumPrecision, *minimumRecall, *ruleThresholds); err != nil {
		fmt.Fprintln(os.Stderr, "eval:", err)
		os.Exit(1)
	}
}

func run(path string, minimumPrecision, minimumRecall float64, thresholdPaths ...string) error {
	if err := validateThreshold(ruleThreshold{minimumPrecision, minimumRecall}); err != nil {
		return err
	}
	gates, err := loadRuleThresholds(thresholdPaths)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var suite corpus
	if err := json.Unmarshal(data, &suite); err != nil {
		return fmt.Errorf("decode corpus: %w", err)
	}
	if suite.Version <= 0 || len(suite.Cases) == 0 {
		return errors.New("empty or unversioned corpus")
	}
	universe := make(map[string]bool)
	for _, item := range suite.Cases {
		for _, category := range item.Expected {
			universe[category] = true
		}
		for _, category := range item.Forbidden {
			universe[category] = true
		}
	}
	perRule := make(map[string]counts, len(universe))
	var gaps []gapReport
	scored := 0
	for _, item := range suite.Cases {
		actual, locations, err := analyzeCase(item)
		if err != nil {
			return fmt.Errorf("case %s: %w", item.ID, err)
		}
		actual = applyLocationAssertions(item, actual, locations)
		expected := stringSet(item.Expected)

		if item.KnownGap != "" {
			gaps = append(gaps, evaluateGap(item, expected, actual, universe))
			continue
		}
		scored++
		for category := range universe {
			metric := perRule[category]
			switch {
			case expected[category] && actual[category]:
				metric.TruePositive++
			case expected[category]:
				metric.FalseNegative++
				fmt.Fprintf(os.Stderr, "eval: case %s: missing %s\n", item.ID, category)
			case actual[category]:
				metric.FalsePositive++
				fmt.Fprintf(os.Stderr, "eval: case %s: unexpected %s\n", item.ID, category)
			}
			perRule[category] = metric
		}
	}

	micro := counts{}
	for category, metric := range perRule {
		metric = calculate(metric)
		perRule[category] = metric
		micro.TruePositive += metric.TruePositive
		micro.FalsePositive += metric.FalsePositive
		micro.FalseNegative += metric.FalseNegative
	}
	micro = calculate(micro)
	output := report{
		CorpusVersion: suite.Version,
		Cases:         len(suite.Cases),
		ScoredCases:   scored,
		PerRule:       perRule,
		Micro:         micro,
		KnownGaps:     gaps,
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	for _, gap := range gaps {
		if gap.Resolved {
			fmt.Fprintf(os.Stderr, "eval: known gap %q appears RESOLVED — consider removing the known_gap marker\n", gap.ID)
		}
	}
	if micro.Precision < minimumPrecision {
		return fmt.Errorf("precision %.3f below %.3f", micro.Precision, minimumPrecision)
	}
	if micro.Recall < minimumRecall {
		return fmt.Errorf("recall %.3f below %.3f", micro.Recall, minimumRecall)
	}
	return checkRuleThresholds(perRule, gates)
}

func analyzeCase(item testCase) (map[string]bool, []evalrunner.FindingLocation, error) {
	return evalrunner.AnalyzeDetailed(item.Files)
}

// applyLocationAssertions downgrades a detected category when it fired but
// not at the asserted file/line range: the case is scored as if the category
// were absent (turning a would-be TP into an FN). Assertions on categories
// that did not fire at all are no-ops here — the category is already scored
// as a false negative.
func applyLocationAssertions(item testCase, actual map[string]bool, locations []evalrunner.FindingLocation) map[string]bool {
	for _, assertion := range item.Locations {
		if !actual[assertion.Category] {
			continue
		}
		if locationSatisfied(assertion, locations) {
			continue
		}
		fmt.Fprintf(os.Stderr,
			"eval: case %s: location assertion failed for %s (file=%s line_min=%d line_max=%d) — scoring as not detected\n",
			item.ID, assertion.Category, assertion.File, assertion.LineMin, assertion.LineMax)
		downgraded := make(map[string]bool, len(actual))
		for category := range actual {
			if category != assertion.Category {
				downgraded[category] = true
			}
		}
		actual = downgraded
	}
	return actual
}

func locationSatisfied(assertion locationAssertion, locations []evalrunner.FindingLocation) bool {
	for _, loc := range locations {
		if loc.Category != assertion.Category {
			continue
		}
		if assertion.File != "" && filepath.ToSlash(loc.File) != filepath.ToSlash(assertion.File) {
			continue
		}
		if assertion.LineMin > 0 && loc.Line < assertion.LineMin {
			continue
		}
		if assertion.LineMax > 0 && loc.Line > assertion.LineMax {
			continue
		}
		return true
	}
	return false
}

// evaluateGap builds the report for one known-gap case. Only universe
// categories are considered, so always-present informational findings
// (e.g. MANIFEST_INFO from the injected stub manifest) stay out of the
// report. Failures are the documented gaps; an empty failure list means
// the gap was closed and the known_gap marker should be removed.
func evaluateGap(item testCase, expected, actual, universe map[string]bool) gapReport {
	gap := gapReport{ID: item.ID, Gap: item.KnownGap}
	for _, category := range sortedKeys(expected) {
		if !actual[category] {
			gap.MissingExpected = append(gap.MissingExpected, category)
		}
	}
	for _, category := range sortedKeys(actual) {
		if !expected[category] && universe[category] {
			gap.Unexpected = append(gap.Unexpected, category)
		}
	}
	gap.Resolved = len(gap.MissingExpected) == 0 && len(gap.Unexpected) == 0
	return gap
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func calculate(value counts) counts {
	if denominator := value.TruePositive + value.FalsePositive; denominator > 0 {
		value.Precision = float64(value.TruePositive) / float64(denominator)
	}
	if denominator := value.TruePositive + value.FalseNegative; denominator > 0 {
		value.Recall = float64(value.TruePositive) / float64(denominator)
	}
	if value.Precision+value.Recall > 0 {
		value.F1 = 2 * value.Precision * value.Recall / (value.Precision + value.Recall)
	}
	return value
}

// sortedKeys returns map keys in deterministic order for human-readable output.
func sortedKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
