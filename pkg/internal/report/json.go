package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"mega-analyzer/pkg/buildinfo"
	"mega-analyzer/pkg/internal/types"
)

// JSONReporter writes AnalysisResult without buffering the whole structure
// in memory. The previous implementation relied on json.Encoder.Encode, which
// builds the full JSON into an internal buffer before flushing. Large reports
// (e.g., 40k files, 180k matches, 380k call graph nodes) could exceed the
// available RAM when pretty-printed. We now stream field-by-field to keep the
// peak memory low.
type JSONReporter struct {
	result    *types.AnalysisResult
	artifacts *ArtifactsView
	compact   bool
}

func NewJSONReporter(result *types.AnalysisResult) *JSONReporter {
	return &JSONReporter{result: result}
}

// WithArtifacts attaches an opt-in artifacts view that will be serialised
// into the JSON output. nil disables the additional section.
func (r *JSONReporter) WithArtifacts(view *ArtifactsView) *JSONReporter {
	r.artifacts = view
	return r
}

// WithCompact drops smali method bodies from the files section. A paranoid
// APK scan embeds the decompiled sources verbatim (measured 128 of 153 MB on
// the 2026-11-03 corpus run), which makes analysis.json unusable for daily
// review. Findings, matches, evidence and coverage stay complete: they are
// the triage payload. Sources remain in the HTML report and the original
// binary. Bodies are dropped at write time via a shallow copy, so the shared
// result stays intact for every other consumer.
func (r *JSONReporter) WithCompact(compact bool) *JSONReporter {
	r.compact = compact
	return r
}

func (r *JSONReporter) Generate(outputDir string) error {
	return writeReportFile(outputDir, "analysis.json", r.GenerateStream)
}

func (r *JSONReporter) GenerateStream(dst io.Writer) error {
	if r == nil || r.result == nil {
		return fmt.Errorf("cannot export a nil analysis result")
	}
	w := bufio.NewWriterSize(dst, 1<<20) // 1MB buffer for fewer syscalls

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")

	written := make(map[string]bool)
	writeField := func(first *bool, name string, writeValue func() error) error {
		written[name] = true
		if !*first {
			if _, err := w.WriteString(",\n"); err != nil {
				return err
			}
		} else {
			if _, err := w.WriteString("\n"); err != nil {
				return err
			}
			*first = false
		}

		if _, err := w.WriteString(fmt.Sprintf("\"%s\": ", name)); err != nil {
			return err
		}
		return writeValue()
	}

	writeSlice := func(first *bool, name string, itemsLen int, next func(i int) (any, error)) error {
		return writeField(first, name, func() error {
			if _, err := w.WriteString("["); err != nil {
				return err
			}
			for i := 0; i < itemsLen; i++ {
				if i > 0 {
					if _, err := w.WriteString(","); err != nil {
						return err
					}
				}
				if _, err := w.WriteString("\n"); err != nil {
					return err
				}
				val, err := next(i)
				if err != nil {
					return err
				}
				if err := enc.Encode(val); err != nil {
					return err
				}
			}
			if itemsLen > 0 {
				if _, err := w.WriteString("\n"); err != nil {
					return err
				}
			}
			_, err := w.WriteString("]")
			return err
		})
	}

	firstField := true
	if _, err := w.WriteString("{"); err != nil {
		return err
	}

	if err := writeField(&firstField, "timestamp", func() error { return enc.Encode(r.result.Timestamp) }); err != nil {
		return err
	}
	if err := writeField(&firstField, "duration", func() error { return enc.Encode(r.result.Duration) }); err != nil {
		return err
	}
	if err := writeField(&firstField, "target_dir", func() error { return enc.Encode(r.result.ShareableTargetName()) }); err != nil {
		return err
	}
	if err := writeField(&firstField, "app_package", func() error { return enc.Encode(r.result.AppPackage) }); err != nil {
		return err
	}
	if err := writeField(&firstField, "stats", func() error { return enc.Encode(r.result.Stats) }); err != nil {
		return err
	}
	if err := writeField(&firstField, "files_by_type", func() error { return enc.Encode(r.result.FilesByType) }); err != nil {
		return err
	}
	if err := writeField(&firstField, "matches_by_category", func() error { return enc.Encode(r.result.MatchesByCategory) }); err != nil {
		return err
	}

	if len(r.result.Files) > 0 {
		if err := writeField(&firstField, "files", func() error {
			if _, err := w.WriteString("{"); err != nil {
				return err
			}

			keys := make([]string, 0, len(r.result.Files))
			for k := range r.result.Files {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for i, k := range keys {
				if i > 0 {
					if _, err := w.WriteString(",\n"); err != nil {
						return err
					}
				} else {
					if _, err := w.WriteString("\n"); err != nil {
						return err
					}
				}

				keyBytes, err := json.Marshal(k)
				if err != nil {
					return err
				}
				if _, err := w.Write(keyBytes); err != nil {
					return err
				}
				if _, err := w.WriteString(":"); err != nil {
					return err
				}
				if r.compact {
					entry := *r.result.Files[k]
					entry.SmaliClass = nil
					if err := enc.Encode(&entry); err != nil {
						return err
					}
					continue
				}
				if err := enc.Encode(r.result.Files[k]); err != nil {
					return err
				}
			}

			if len(keys) > 0 {
				if _, err := w.WriteString("\n"); err != nil {
					return err
				}
			}
			_, err := w.WriteString("}")
			return err
		}); err != nil {
			return err
		}
	}

	if r.result.CallGraph != nil && len(r.result.CallGraph.Nodes) > 0 {
		if err := writeField(&firstField, "call_graph", func() error {
			if _, err := w.WriteString("{\"nodes\":{"); err != nil {
				return err
			}

			keys := make([]string, 0, len(r.result.CallGraph.Nodes))
			for k := range r.result.CallGraph.Nodes {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for i, k := range keys {
				if i > 0 {
					if _, err := w.WriteString(",\n"); err != nil {
						return err
					}
				} else {
					if _, err := w.WriteString("\n"); err != nil {
						return err
					}
				}
				keyBytes, err := json.Marshal(k)
				if err != nil {
					return err
				}
				if _, err := w.Write(keyBytes); err != nil {
					return err
				}
				if _, err := w.WriteString(":"); err != nil {
					return err
				}
				if err := enc.Encode(r.result.CallGraph.Nodes[k]); err != nil {
					return err
				}
			}

			if len(keys) > 0 {
				if _, err := w.WriteString("\n"); err != nil {
					return err
				}
			}
			_, err := w.WriteString("}}")
			return err
		}); err != nil {
			return err
		}
	}

	if len(r.result.Correlations) > 0 {
		if err := writeSlice(&firstField, "correlations", len(r.result.Correlations), func(i int) (any, error) {
			return r.result.Correlations[i], nil
		}); err != nil {
			return err
		}
	}

	if len(r.result.Hotspots) > 0 {
		if err := writeSlice(&firstField, "hotspots", len(r.result.Hotspots), func(i int) (any, error) {
			return r.result.Hotspots[i], nil
		}); err != nil {
			return err
		}
	}

	if len(r.result.Recommendations) > 0 {
		if err := writeSlice(&firstField, "recommendations", len(r.result.Recommendations), func(i int) (any, error) {
			return r.result.Recommendations[i], nil
		}); err != nil {
			return err
		}
	}

	if len(r.result.RuleMatches) > 0 {
		if err := writeSlice(&firstField, "rule_matches", len(r.result.RuleMatches), func(i int) (any, error) {
			return r.result.RuleMatches[i], nil
		}); err != nil {
			return err
		}
	}

	// An explicit empty findings array distinguishes a clean typed report
	// from older exports that silently omitted the entire findings contract.
	if err := writeSlice(&firstField, "findings", len(r.result.Findings), func(i int) (any, error) {
		return r.result.Findings[i], nil
	}); err != nil {
		return err
	}
	if err := writeField(&firstField, "report_metadata", func() error {
		return enc.Encode(map[string]any{
			"schema_version":   1,
			"analyzer_version": buildinfo.Version,
			"commit":           buildinfo.CommitHash,
			"build_date":       buildinfo.BuildDate,
		})
	}); err != nil {
		return err
	}

	if r.result.Piracy != nil {
		if err := writeField(&firstField, "piracy", func() error { return enc.Encode(r.result.Piracy) }); err != nil {
			return err
		}
	}

	if len(r.result.MachineCodeReports) > 0 {
		if err := writeSlice(&firstField, "machine_code_reports", len(r.result.MachineCodeReports), func(i int) (any, error) {
			return r.result.MachineCodeReports[i], nil
		}); err != nil {
			return err
		}
	}

	if r.result.DecisionAI != nil {
		if err := writeField(&firstField, "decision_ai", func() error { return enc.Encode(r.result.DecisionAI) }); err != nil {
			return err
		}
	}
	if r.result.FPFilterResults != nil {
		if err := writeField(&firstField, "fp_filter_results", func() error { return enc.Encode(r.result.FPFilterResults) }); err != nil {
			return err
		}
	}

	if r.result.NcerResult != nil {
		if err := writeField(&firstField, "ncer", func() error { return enc.Encode(r.result.NcerResult) }); err != nil {
			return err
		}
	}

	// The result contract grows as detectors gain evidence and coverage data.
	// Preserve all exported fields, including ones absent from the original
	// streaming writer. Keep large slices streamed one item at a time.
	value := reflect.ValueOf(r.result).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		if !field.IsExported() || name == "-" || written[name] {
			continue
		}
		if name == "" {
			name = field.Name
		}
		v := value.Field(i)
		if strings.Contains(options, "omitempty") && emptyJSONValue(v) {
			continue
		}
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() != reflect.Uint8 {
			if err := writeSlice(&firstField, name, v.Len(), func(j int) (any, error) {
				return v.Index(j).Interface(), nil
			}); err != nil {
				return err
			}
		} else if err := writeField(&firstField, name, func() error { return enc.Encode(v.Interface()) }); err != nil {
			return err
		}
	}

	if r.artifacts != nil {
		if err := writeField(&firstField, "schema_version", func() error { return enc.Encode("2.1") }); err != nil {
			return err
		}
		if err := writeField(&firstField, "artifacts", func() error { return enc.Encode(r.artifacts) }); err != nil {
			return err
		}
	}

	if _, err := w.WriteString("\n}"); err != nil {
		return err
	}

	// Surface buffered-write/close errors instead of dropping them in a
	// deferred Flush: a full disk previously produced truncated JSON.
	return w.Flush()
}

// Match encoding/json's omitempty semantics (a zero struct is not empty).
func emptyJSONValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Interface, reflect.Pointer:
		return v.IsZero()
	}
	return false
}
