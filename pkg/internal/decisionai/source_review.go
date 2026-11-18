package decisionai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/sourceevidence"
)

type SourceReviewEntry struct {
	CheckID          string   `json:"check_id"`
	Kind             string   `json:"kind"`
	SourceChoice     string   `json:"source_choice"`
	StateSHA256      string   `json:"state_sha256"`
	SourceConsistent bool     `json:"source_consistent"`
	ReviewRoute      string   `json:"review_route"`
	Reason           string   `json:"reason,omitempty"`
	Response         Response `json:"response"`
}

type SourceReviewReport struct {
	SchemaVersion int                 `json:"schema_version"`
	AdvisoryOnly  bool                `json:"advisory_only"`
	StaticOnly    bool                `json:"static_only"`
	Status        string              `json:"status"`
	InputSHA256   string              `json:"input_sha256"`
	Total         int                 `json:"total_checks"`
	Processed     int                 `json:"processed_checks"`
	Consistent    int                 `json:"source_consistent_checks"`
	Unresolved    int                 `json:"unresolved_checks"`
	Error         string              `json:"error,omitempty"`
	Entries       []SourceReviewEntry `json:"entries"`
}

// ReviewSource submits whole, cited source snapshots with typed static checks.
// It preserves contradictory service responses and routes them to a human;
// neither a rule nor a neural answer is promoted to a runtime finding.
func ReviewSource(ctx context.Context, client *Client, source sourceevidence.Report, prior *SourceReviewReport) SourceReviewReport {
	r := SourceReviewReport{SchemaVersion: 1, AdvisoryOnly: true, StaticOnly: true, Status: "complete",
		InputSHA256: source.SHA256(), Total: len(source.Checks), Entries: []SourceReviewEntry{}}
	cached := map[string]SourceReviewEntry{}
	if prior != nil && prior.SchemaVersion == r.SchemaVersion && prior.AdvisoryOnly && prior.StaticOnly {
		for _, entry := range prior.Entries {
			cached[entry.CheckID+"\x00"+entry.StateSHA256] = entry
		}
	}
	for _, check := range source.Checks {
		req, err := sourceCheckRequest(check, source)
		if err != nil {
			r.Entries = append(r.Entries, SourceReviewEntry{CheckID: check.ID, Kind: check.Kind, SourceChoice: check.Choice, ReviewRoute: "human", Reason: err.Error()})
			r.Unresolved++
			r.Status = "partial"
			continue
		}
		digest := sha256.Sum256(req.State)
		stateHash := hex.EncodeToString(digest[:])
		entry, exists := cached[check.ID+"\x00"+stateHash]
		if !exists {
			if ctx.Err() != nil {
				r.Error = ctx.Err().Error()
				break
			}
			response, err := client.Decide(ctx, req)
			if err != nil {
				r.Error = err.Error()
				break
			}
			answer := response.Answers["source_check"]
			consistent := sourceAnswerConsistent(check, answer)
			route := "review"
			reason := ""
			if !consistent {
				route = "human"
				reason = "service_answer_not_supported_by_source_contract"
				if check.Status == "unresolved" && check.Choice == "unresolved" &&
					answer.Source == "source-evidence-rule" && answer.Choice == "unresolved" && answer.Abstained {
					reason = "source_check_unresolved"
				}
			}
			entry = SourceReviewEntry{CheckID: check.ID, Kind: check.Kind, SourceChoice: check.Choice, StateSHA256: stateHash,
				SourceConsistent: consistent, ReviewRoute: route, Response: response, Reason: reason}
		}
		r.Entries = append(r.Entries, entry)
		r.Processed++
		if entry.SourceConsistent {
			r.Consistent++
		} else {
			r.Unresolved++
		}
	}
	if r.Error != "" && r.Processed == 0 {
		r.Status = "unavailable"
	} else if r.Processed < r.Total || source.LimitReached || source.Cancelled {
		r.Status = "partial"
	}
	return r
}

func sourceCheckRequest(check sourceevidence.Check, report sourceevidence.Report) (Request, error) {
	sources := make([]sourceevidence.Source, 0, 4)
	for _, source := range report.Sources {
		for _, c := range check.Citations {
			if c.File == source.File && c.SHA256 == source.SHA256 && c.Method == source.Method {
				sources = append(sources, source)
				break
			}
		}
	}
	state, err := json.Marshal(map[string]any{"source_evidence": map[string]any{
		"schema_version": report.SchemaVersion, "static_only": report.StaticOnly, "check": check, "sources": sources,
	}})
	if err != nil {
		return Request{}, err
	}
	criteria := sourceCriteria(check.Kind)
	if len(criteria) == 0 {
		return Request{}, fmt.Errorf("unsupported source check %q", check.Kind)
	}
	encoded, _ := json.Marshal(criteria)
	req := Request{State: state, Questions: map[string]Question{"source_check": {
		Type: "choice", Task: "source_evidence", AbstainKey: "unresolved",
		Instructions: json.RawMessage(`"Which typed static source assessment is supported by the supplied cited scanner check and exact source snapshots? Execution and exploitability are not established."`),
		Criteria:     encoded,
	}}}
	return req, validateRequest(req)
}

func sourceAnswerConsistent(check sourceevidence.Check, answer Answer) bool {
	if answer.Source != "source-evidence-rule" || answer.Choice != check.Choice || answer.Abstained || check.Status == "unresolved" || len(check.Citations) == 0 ||
		len(answer.References) != len(check.Citations) {
		return false
	}
	for _, citation := range check.Citations {
		found := false
		for _, reference := range answer.References {
			if reference.Kind == "source" && reference.File == citation.File && reference.Line == citation.Line && reference.SHA256 == citation.SHA256 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func sourceCriteria(kind string) map[string]string {
	options := map[string]string{"unresolved": "The retained source does not resolve this check"}
	switch kind {
	case "native_load":
		options["static_call_path"] = "A native load call is reachable in the retained CFG; runtime execution is not established"
		options["unreachable_call"] = "The load instruction is unreachable in the retained CFG"
	case "path_origin":
		options["application_data_dir"] = "The retained caller expression uses ApplicationInfo.dataDir or a Context private-directory API"
		options["archive_entry_name"] = "The argument is derived from ZipEntry.getName"
		options["constant_path"] = "The argument expression contains only string constants"
		options["unbound_parameter"] = "The argument is a parameter without a retained matching caller"
	case "output_name":
		options["constant_filename"] = "The output argument has a statically fixed basename"
		options["archive_entry_name"] = "The output argument's name is derived from ZipEntry.getName"
	case "manifest_cleartext":
		options["explicit_true"] = "application declares android:usesCleartextTraffic=true; effective NSC policy requires separate review"
		options["explicit_false"] = "application declares android:usesCleartextTraffic=false; effective NSC policy requires separate review"
		options["not_declared"] = "application does not explicitly declare usesCleartextTraffic"
	case "component_surface":
		options["declared_component"] = "The manifest declares the component and its access attributes; implementation and exploitability are unknown"
	default:
		return nil
	}
	return options
}

func (r SourceReviewReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Проверка ответов по исходному коду: %s; обработано %d/%d; согласуется с источниками: %d; требует разбора: %d.\n",
		r.Status, r.Processed, r.Total, r.Consistent, r.Unresolved)
	b.WriteString("source-evidence-rule разбирает статические проверки сканера; это не независимое подтверждение и не наблюдение выполнения.\nПодробности кода: SOURCE_EVIDENCE.txt и SOURCE_EVIDENCE.json.\n")
	if r.Error != "" {
		fmt.Fprintf(&b, "Ошибка проверки источников: %s\n", r.Error)
	}
	for _, entry := range r.Entries {
		answer := entry.Response.Answers["source_check"]
		fmt.Fprintf(&b, "  %s: источник=%s; ответ=%s; маршрут=%s\n", entry.Kind, entry.SourceChoice, answer.Choice, entry.ReviewRoute)
	}
	b.WriteString("\n")
	return b.String()
}
