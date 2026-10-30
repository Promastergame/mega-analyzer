package apkloader

import (
	"encoding/json"
	"fmt"
	"strings"
)

type DiagnosticSeverity string

const (
	DiagInfo  DiagnosticSeverity = "info"
	DiagWarn  DiagnosticSeverity = "warn"
	DiagError DiagnosticSeverity = "error"
	DiagFatal DiagnosticSeverity = "fatal"
)

type Diagnostic struct {
	Code     string             `json:"code"`
	Severity DiagnosticSeverity `json:"severity"`
	Stage    string             `json:"stage"`
	Path     string             `json:"path,omitempty"`
	Line     int                `json:"line,omitempty"`
	Column   int                `json:"column,omitempty"`
	Message  string             `json:"message"`
	Hint     string             `json:"hint,omitempty"`
	Cause    string             `json:"cause,omitempty"`
}

func (d Diagnostic) Error() string {
	loc := d.Path
	if d.Line > 0 {
		loc += fmt.Sprintf(":%d", d.Line)
	}
	if d.Column > 0 {
		loc += fmt.Sprintf(":%d", d.Column)
	}
	if loc != "" {
		return fmt.Sprintf("%s %s: %s", d.Code, loc, d.Message)
	}
	return fmt.Sprintf("%s: %s", d.Code, d.Message)
}

func diagnosticsError(stage string, diags []Diagnostic) error {
	var errs []string
	for _, d := range diags {
		if d.Severity == DiagError || d.Severity == DiagFatal {
			errs = append(errs, d.Error())
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s diagnostics failed: %s", stage, strings.Join(errs, "; "))
}

func diagnosticsJSON(diags []Diagnostic) string {
	b, _ := json.Marshal(diags)
	return string(b)
}
