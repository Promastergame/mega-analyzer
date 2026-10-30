# Writing BinZAP rules

## Pattern rules (passive / mobile)

Implement the `Rule` interface:

```go
type Rule interface {
    ID() string
    Name() string
    Severity() Severity
    Match(ctx ScanContext, tokens []lex.Token) []Finding
}
```

Emit enriched findings and always fingerprint them:

```go
return Finding{
    RuleID: "BZ-XXX-001", RuleName: "...",
    Severity: SeverityHigh, Confidence: ConfidenceHigh,
    Message: "...", File: ctx.File, Line: t.Line, Evidence: t.Value,
    CWE: "CWE-89", Category: "sqli", Remediation: "...",
}.WithFingerprint()
```

## Registering rules

Rules carry metadata in the registry (CWE, pack, severity, remediation):

```go
reg := DefaultRegistry()
reg.MustRegister(myRule, RuleMetadata{
    ID: myRule.ID(), Name: myRule.Name(),
    CWE: "CWE-89", Pack: "core", Severity: SeverityHigh,
})
```

## Packs, profiles, overrides

```go
reg.ApplyProfile(Profile{Packs: []string{"core", "mobile"}, MinSeverity: SeverityMedium})
sev := SeverityLow
reg.ApplyOverride("BZ-PASS-004", Override{Severity: &sev})
```

## Taint sources/sinks

Data-flow detection lives in `analysis`. Add entries to `DefaultSources()` /
`DefaultSinks()` in `analysis/catalog.go`; each sink declares its CWE, severity,
category and remediation. No code changes to the engine are required.

## Regression

Add a small `.smali` fixture plus a table-driven test asserting the expected
rule IDs/CWEs. The taint engine tests in `analysis/taint_test.go` show the
pattern, including a negative (no-source ⇒ no-finding) case.
