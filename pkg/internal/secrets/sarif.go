package secrets

import "encoding/json"

// ToSARIF renders findings as a SARIF 2.1.0 document - a plain, local JSON
// format understood by most IDEs and static-analysis result viewers. This is
// pure serialization: no network, no external services, no telemetry. The
// caller decides where the bytes go (usually a local file). Secrets are never
// embedded: message text uses the masked value only.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID              string     `json:"id"`
	Name            string     `json:"name,omitempty"`
	FullDescription *sarifText `json:"fullDescription,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// ToSARIF serializes findings for artifactURI (the scanned file path as it
// should appear in the report). toolName defaults to "secrets".
func ToSARIF(findings []ProviderFinding, toolName, artifactURI string) ([]byte, error) {
	if toolName == "" {
		toolName = "secrets"
	}
	ruleSeen := make(map[string]bool)
	rules := make([]sarifRule, 0, 8)
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		if !ruleSeen[f.RuleID] {
			ruleSeen[f.RuleID] = true
			r := sarifRule{ID: f.RuleID, Name: f.Name}
			if f.Remediation != "" {
				r.FullDescription = &sarifText{Text: f.Remediation}
			}
			rules = append(rules, r)
		}
		msg := f.Name + ": " + f.MaskedValue
		if f.Validation != "" {
			msg += " [" + f.Validation + "]"
		}
		res := sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: msg},
		}
		if artifactURI != "" {
			startLine := f.Line
			if startLine < 1 {
				startLine = 1
			}
			res.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: artifactURI},
					Region:           sarifRegion{StartLine: startLine, StartColumn: f.Column},
				},
			}}
		}
		results = append(results, res)
	}
	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: toolName, Rules: rules}},
			Results: results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}
