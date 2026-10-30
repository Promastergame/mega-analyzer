package correlation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteReports writes <dir>/correlation_report.json and
// <dir>/correlation_report.md side by side. Either or both may be
// disabled by passing an empty filename.
//
// The function is intentionally idempotent and easy to call from the
// runner — it returns the first error encountered but always tries to
// write both formats so a single I/O failure does not silently lose
// the other.
func WriteReports(r *Result, dir string) (jsonPath, mdPath string, err error) {
	if r == nil {
		return "", "", fmt.Errorf("nil correlation result")
	}
	if dir == "" {
		return "", "", fmt.Errorf("empty output directory")
	}
	if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
		return "", "", fmt.Errorf("create correlation report dir: %w", mkErr)
	}

	jsonPath = filepath.Join(dir, "correlation_report.json")
	mdPath = filepath.Join(dir, "correlation_report.md")

	if jsonErr := writeJSON(r, jsonPath); jsonErr != nil && err == nil {
		err = jsonErr
	}
	if mdErr := writeMarkdown(r, mdPath); mdErr != nil && err == nil {
		err = mdErr
	}
	return jsonPath, mdPath, err
}

func writeJSON(r *Result, path string) error {
	data, mErr := json.MarshalIndent(r, "", "  ")
	if mErr != nil {
		return fmt.Errorf("marshal correlation report: %w", mErr)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write correlation json: %w", err)
	}
	return nil
}

func writeMarkdown(r *Result, path string) error {
	if err := os.WriteFile(path, []byte(RenderMarkdown(r)), 0o644); err != nil {
		return fmt.Errorf("write correlation markdown: %w", err)
	}
	return nil
}
