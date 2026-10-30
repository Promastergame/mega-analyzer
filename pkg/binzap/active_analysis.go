package binzap

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/binzap/analysis"
	"mega-analyzer/pkg/binzap/ir"
	"mega-analyzer/pkg/binzap/lex"
)

// TaintSeed injects taint on a register before analysis, used to carry external
// provenance (e.g. a hardcoded credential discovered by the secrets scanner)
// into the dataflow engine.
type TaintSeed struct {
	Register string
	Kind     string // one of analysis.SourceKind values
	Label    string
}

func adaptSeverity(s analysis.Severity) Severity {
	switch s {
	case analysis.SevCritical:
		return SeverityCritical
	case analysis.SevHigh:
		return SeverityHigh
	case analysis.SevMedium:
		return SeverityMedium
	case analysis.SevLow:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func adaptConfidence(c string) Confidence {
	switch strings.ToUpper(c) {
	case "CONFIRMED":
		return ConfidenceConfirmed
	case "HIGH":
		return ConfidenceHigh
	case "MEDIUM":
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

func adaptFinding(af analysis.Finding) Finding {
	f := Finding{
		RuleID:         af.RuleID,
		RuleName:       af.Title,
		Severity:       adaptSeverity(af.Severity),
		Confidence:     adaptConfidence(af.Confidence),
		Message:        af.Title,
		File:           af.File,
		Line:           af.Line,
		Column:         af.Column,
		Evidence:       af.Evidence,
		CWE:            af.CWE,
		Category:       af.Category,
		Remediation:    af.Remediation,
		Exploitability: af.Exploitability,
		DataSource:     af.DetectedBy,
		AttackPath:     af.Path,
	}
	return f.WithFingerprint()
}

// RunActiveAnalysis performs REAL static taint analysis over a token stream:
// tokens are lowered to IR, then an intra-procedural source-to-sink dataflow
// pass reports dangerous flows with a full attack path. This replaces the
// previous randomized "active fuzzer", which produced non-deterministic,
// evidence-free output (quarantined behind the `legacy_fuzzer` build tag).
func RunActiveAnalysis(ctx ScanContext, tokens []lex.Token, seeds ...TaintSeed) []Finding {
	prog := ir.LowerTokens(ctx.File, ctx.Dialect, tokens)
	engine := analysis.NewEngine()
	for _, s := range seeds {
		engine.SeedTaint(s.Register, analysis.SourceKind(s.Kind), s.Label)
	}
	var out []Finding
	for _, af := range engine.Analyze(prog) {
		out = append(out, adaptFinding(af))
	}
	return out
}

// AnalyzeProgramStats lowers tokens and returns IR statistics (diagnostics/tests).
func AnalyzeProgramStats(ctx ScanContext, tokens []lex.Token) ir.Stats {
	return ir.LowerTokens(ctx.File, ctx.Dialect, tokens).Stats()
}

// lexFile is a shared helper returning tokens + dialect for a supported file.
func lexFile(filePath string) ([]lex.Token, lex.Dialect, bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, "", false, err
	}
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".smali":
		return lex.LexSmali(string(data)), lex.DialectSmali, true, nil
	case ".asm", ".s":
		return lex.LexX86(string(data)), lex.DialectX86, true, nil
	default:
		return nil, "", false, nil
	}
}

// RunActiveFile lexes a single file and runs active (taint) analysis, including
// secrets-aware credential taint seeding (INC4).
func RunActiveFile(filePath string) ([]Finding, error) {
	if strings.EqualFold(filepath.Ext(filePath), ".dex") {
		return scanDEXFile(context.Background(), filePath, false, true)
	}
	tokens, dialect, ok, err := lexFile(filePath)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	ctx := ScanContext{File: filePath, Dialect: dialect}
	seeds := secretTaintSeeds(ctx, tokens)
	return RunActiveAnalysis(ctx, tokens, seeds...), nil
}
