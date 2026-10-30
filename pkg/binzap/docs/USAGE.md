# Using BinZAP (library)

## Scan a directory (parallel, with progress)

```go
ctx := context.Background()
findings, err := binzap.RunScanDirectory(ctx, "./out", binzap.ScanOptions{
    Active:   true,               // enable taint-based active analysis
    Workers:  0,                  // 0 = NumCPU
    Progress: func(done, total int) { fmt.Printf("\r%d/%d", done, total) },
})
```

## Scan a single file

```go
passive, _ := binzap.RunPassiveFile("App.smali")
active,  _ := binzap.RunActiveFile("App.smali") // includes secrets→taint seeding
```

## Baseline (only report new issues)

```go
base, _ := binzap.LoadBaseline("binzap.baseline.json")
findings, _ := binzap.RunScanDirectory(ctx, "./out", binzap.ScanOptions{Baseline: base})
// After triage, snapshot the accepted set:
binzap.NewBaselineFromFindings(findings).Save("binzap.baseline.json")
```

## Reports

```go
binzap.GenerateFullReport(findings, "./reports", "myapp")
// -> myapp_binzap_report.{md,json,sarif,html}
```

## Rule selection

```go
reg := binzap.DefaultRegistry()
reg.ApplyProfile(binzap.Profile{Packs: []string{"core", "mobile"}})
rules := reg.EnabledRules()
```
