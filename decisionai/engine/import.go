package engine

import (
	"encoding/json"
	"fmt"
)

// ImportAnalyzer consumes Mega-Analyzer JSONExport. Unknown exporter metadata is allowed,
// while imported confidence/apply_safe are deliberately NOT reused as probabilities or authority.
func ImportAnalyzer(data []byte) ([]Request, error) {
	var doc struct {
		Schema  string `json:"schema_version"`
		Patches []struct {
			ID          string `json:"patch_id"`
			Original    string `json:"original_code"`
			Category    string `json:"category_name"`
			Description string `json:"description"`
			File        string `json:"file_path"`
		} `json:"patches"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Schema == "" || doc.Patches == nil {
		return nil, fmt.Errorf("expected Mega-Analyzer JSONExport (schema_version and patches)")
	}
	if len(doc.Patches) > 10000 {
		return nil, fmt.Errorf("too many patches")
	}
	out := []Request{}
	for i, p := range doc.Patches {
		id := p.ID
		if id == "" {
			id = fmt.Sprintf("import-%d", i)
		}
		r := Request{ID: id, Code: p.Original, Scope: "audit", State: map[string]any{"source": "Mega-Analyzer", "category": p.Category, "file": p.File}, Meta: Meta{Evidence: []string{}}}
		if err := ValidateRequest(r); err != nil {
			return nil, fmt.Errorf("patch %d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}
