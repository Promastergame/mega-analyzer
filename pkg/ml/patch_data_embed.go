package ml

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// The patcher's knowledge base lives in editable JSON files that are baked into
// the binary. To add or tweak a patch pattern, edit patch_patterns.json — no Go
// changes required. patch_templates.json holds the "how to fix" recipes.

//go:embed patch_patterns.json
var patchPatternsJSON []byte

//go:embed patch_templates.json
var patchTemplatesJSON []byte

func mustLoadVulnerablePatterns() []VulnerablePattern {
	var ps []VulnerablePattern
	if err := json.Unmarshal(patchPatternsJSON, &ps); err != nil {
		panic(fmt.Sprintf("ml: parse embedded patch_patterns.json: %v", err))
	}
	return ps
}

func mustLoadPatchTemplates() map[PatchType]PatchTemplate {
	m := make(map[PatchType]PatchTemplate)
	if err := json.Unmarshal(patchTemplatesJSON, &m); err != nil {
		panic(fmt.Sprintf("ml: parse embedded patch_templates.json: %v", err))
	}
	return m
}
