package piracy

import (
	"context"
	"fmt"
	"mega-analyzer/pkg/internal/types"
)

// Detect checks if the content contains piracy indicators.
func (d *Detector) Detect(content string) bool {
	if d == nil {
		return false
	}
	ctx := context.Background()
	res, err := d.Analyze(ctx, "content.smali", []byte(content), types.FileTypeSmali)
	if err != nil {
		return false
	}
	return res.IsPirated
}

// GetIndicators returns the list of indicators used by the detector.
func (d *Detector) GetIndicators() []string {
	return []string{"crack", "patch", "keygen", "serial", "license"}
}

// GetRiskLevel returns a string representation of the risk level for the content.
func (d *Detector) GetRiskLevel(content string) string {
	if d == nil {
		return "NONE"
	}
	ctx := context.Background()
	res, err := d.Analyze(ctx, "content.smali", []byte(content), types.FileTypeSmali)
	if err != nil {
		return "NONE"
	}
	return res.RiskLevel
}

// AnalyzePackage analyzes a package name for piracy indicators.
func (d *Detector) AnalyzePackage(pkg string) (*Result, error) {
	if d == nil {
		return &Result{}, nil
	}
	if pkg == "" {
		return nil, fmt.Errorf("invalid input")
	}
	ctx := context.Background()
	return d.Analyze(ctx, pkg, nil, types.FileTypeSmali)
}

// GetScore returns a piracy score for the content.
func (d *Detector) GetScore(content string) float64 {
	if d == nil {
		return 0
	}
	ctx := context.Background()
	res, err := d.Analyze(ctx, "content.smali", []byte(content), types.FileTypeSmali)
	if err != nil {
		return 0
	}
	return res.Confidence * 100.0
}

// Reset resets the detector state.
func (d *Detector) Reset() {
}
