package ml

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"runtime"
	"sort"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/dataflow"
	"mega-analyzer/pkg/internal/types"
)

// SmaliAuditFile is analysis input, never a patch target. Content is borrowed
// read-only for the duration of Analyze; the caller retains ownership.
type SmaliAuditFile struct {
	Path    string
	Content []byte
}
type SmaliAuditConfig struct {
	Workers       int
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxMethods    int
	MaxFindings   int
	MaxSliceSteps int
	MaxSliceDepth int
	Timeout       time.Duration
	AppPackage    string
	NoHeuristics  bool
}

func DefaultSmaliAuditConfig() SmaliAuditConfig {
	return SmaliAuditConfig{Workers: max(1, runtime.GOMAXPROCS(0)), MaxFiles: 20000, MaxFileBytes: 8 << 20, MaxTotalBytes: 128 << 20, MaxMethods: 100000, MaxFindings: 2000, MaxSliceSteps: 500000, MaxSliceDepth: 48, Timeout: 2 * time.Minute}
}
func normalizeSmaliAuditConfig(c SmaliAuditConfig) SmaliAuditConfig {
	d := DefaultSmaliAuditConfig()
	if c.Workers <= 0 {
		c.Workers = d.Workers
	}
	if c.Workers > 64 {
		c.Workers = 64
	}
	if c.MaxFiles <= 0 {
		c.MaxFiles = d.MaxFiles
	}
	if c.MaxFileBytes <= 0 {
		c.MaxFileBytes = d.MaxFileBytes
	}
	if c.MaxTotalBytes <= 0 {
		c.MaxTotalBytes = d.MaxTotalBytes
	}
	if c.MaxMethods <= 0 {
		c.MaxMethods = d.MaxMethods
	}
	if c.MaxFindings <= 0 {
		c.MaxFindings = d.MaxFindings
	}
	if c.MaxSliceSteps <= 0 {
		c.MaxSliceSteps = d.MaxSliceSteps
	}
	if c.MaxSliceDepth <= 0 {
		c.MaxSliceDepth = d.MaxSliceDepth
	}
	if c.Timeout <= 0 {
		c.Timeout = d.Timeout
	}
	c.AppPackage = strings.Trim(strings.ReplaceAll(c.AppPackage, ".", "/"), "/")
	return c
}

type SmaliAuditLocation struct {
	File   string `json:"file"`
	Method string `json:"method"`
	Line   int    `json:"line"`
}
type SmaliAuditEvidence struct {
	Kind string `json:"kind"`
	SmaliAuditLocation
	Text string `json:"text"`
}
type SmaliAuditFinding struct {
	ID             string               `json:"id"`
	RuleID         string               `json:"rule_id"`
	Category       string               `json:"category"`
	EvidenceLevel  string               `json:"evidence_level"` // heuristic | static_flow; never runtime-confirmed
	Severity       string               `json:"severity"`
	Priority       int                  `json:"priority"`   // deterministic triage rank, NOT probability
	Confidence     float64              `json:"confidence"` // conservative evidence strength, NOT calibrated probability
	Message        string               `json:"message"`
	Origin         string               `json:"origin"` // app_package | known_library | unclassified
	Location       SmaliAuditLocation   `json:"location"`
	Source         string               `json:"source,omitempty"`
	Sink           string               `json:"sink,omitempty"`
	Evidence       []SmaliAuditEvidence `json:"evidence"`
	RelatedSignals []string             `json:"related_signals,omitempty"`
	ReviewRequired bool                 `json:"review_required"`
	Recommendation string               `json:"recommendation"`
}
type SmaliAuditCoverage struct {
	FilesInput         int   `json:"files_input"`
	FilesParsed        int   `json:"files_parsed"`
	FilesSkipped       int   `json:"files_skipped"`
	BytesParsed        int64 `json:"bytes_parsed"`
	MethodsDiscovered  int   `json:"methods_discovered"`
	MethodsAnalyzed    int   `json:"methods_analyzed"`
	MethodsWithoutCode int   `json:"methods_without_code"`
	DuplicateMethods   int   `json:"duplicate_methods"`
	SignalsDetected    int   `json:"signals_detected"`
	StaticFlows        int   `json:"static_flows"`
	InformationalFlows int   `json:"informational_flows"`
	FindingsOmitted    int   `json:"findings_omitted"`
}
type SmaliAuditReport struct {
	SchemaVersion     int                 `json:"schema_version"`
	RuleVersion       string              `json:"rule_version"`
	Mode              string              `json:"mode"`
	Verdict           string              `json:"verdict"`
	AnalysisComplete  bool                `json:"analysis_complete"` // within the declared static scope only
	ConfidenceMeaning string              `json:"confidence_meaning"`
	Coverage          SmaliAuditCoverage  `json:"coverage"`
	Stages            []StageMetrics      `json:"stages"`
	DataFlowStats     dataflow.Stats      `json:"dataflow_stats"`
	Findings          []SmaliAuditFinding `json:"findings"`
	Observations      []SmaliAuditFinding `json:"observations,omitempty"`
	Diagnostics       []string            `json:"diagnostics"`
	Limitations       []string            `json:"limitations"`
}

// SmaliAuditChain is separate from patch prediction: no candidate cutoff, gate
// whitelist, patch generation, model training or malware verdict is involved.
// Every invocation owns its parser, graph and metrics and is safe to run in
// parallel with another invocation. It does not read or write user history.
type SmaliAuditChain struct{ config SmaliAuditConfig }

func NewSmaliAuditChain(config SmaliAuditConfig) *SmaliAuditChain {
	return &SmaliAuditChain{config: normalizeSmaliAuditConfig(config)}
}
func (c *SmaliAuditChain) Analyze(ctx context.Context, input []SmaliAuditFile) *SmaliAuditReport {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg := c.config
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	report := &SmaliAuditReport{
		SchemaVersion: 1, RuleVersion: "smali-audit-v2-cfg", Mode: "read_only_static_audit", AnalysisComplete: true,
		ConfidenceMeaning: "Heuristic evidence strength, not a calibrated probability of vulnerability or maliciousness.",
		Findings:          []SmaliAuditFinding{}, Diagnostics: []string{}, Stages: []StageMetrics{},
		Limitations: []string{
			"Static flows are review candidates, not proof of exploitability, path feasibility or malicious intent.",
			"CFG-aware reaching definitions cover branches, loops and handlers; this is not path-feasibility/SMT proof. Heap, arrays and dispatch remain approximations.",
			"Reflection targets, runtime-loaded code, native/JNI bodies and server-side authorization are not resolved.",
			"Lifecycle sources are signature heuristics. Manifest export/permission policy and runtime reachability require review.",
			"Legacy method-level rules are correlated heuristics; their scores are not independent calibrated probabilities.",
			"Detector behavior was checked on a targeted synthetic corpus, not a representative application benchmark. No model training or APK execution was performed.",
		},
	}
	report.Coverage.FilesInput = len(input)
	diagnostic := func(message string) {
		report.AnalysisComplete = false
		if len(report.Diagnostics) < 100 {
			report.Diagnostics = append(report.Diagnostics, message)
		}
	}
	mark := func(name string, start time.Time, countIn, countOut int, err string) {
		elapsed := time.Since(start)
		report.Stages = append(report.Stages, StageMetrics{Name: name, InputCount: countIn, OutputCount: countOut, DurationMs: elapsed.Milliseconds(), Error: err, Throughput: float64(countIn) / maxFloat(elapsed.Seconds(), .000001)})
	}
	if len(input) == 0 {
		diagnostic("No smali input was supplied.")
	}
	files := append([]SmaliAuditFile(nil), input...)
	sort.SliceStable(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	if len(files) > cfg.MaxFiles {
		diagnostic("File budget reached.")
		files = files[:cfg.MaxFiles]
	}
	start := time.Now()
	analyzer := NewPatchAnalyzer() // sequential parse, no shared interning map
	flowConfig := dataflow.DefaultConfig()
	flowConfig.MaxMethods, flowConfig.MaxFindings = cfg.MaxMethods, cfg.MaxFindings
	flowConfig.MaxSliceSteps, flowConfig.MaxSliceDepth = cfg.MaxSliceSteps, cfg.MaxSliceDepth
	program := dataflow.NewProgram(flowConfig)
	methods := make([]ScoredMethod, 0, 1024)
	bySignature := make(map[string]int)
	parsedFiles := make(map[string]bool)
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			diagnostic("Parse cancelled: " + err.Error())
			break
		}
		if file.Path == "" || parsedFiles[file.Path] {
			diagnostic("Empty or duplicate input path: " + file.Path)
			continue
		}
		if int64(len(file.Content)) > cfg.MaxFileBytes {
			diagnostic("File exceeds byte budget: " + file.Path)
			continue
		}
		if int64(len(file.Content)) > cfg.MaxTotalBytes-report.Coverage.BytesParsed {
			diagnostic("Total smali byte budget reached.")
			break
		}
		declared, err := validateAuditSmali(file.Content)
		if err != nil {
			diagnostic(file.Path + ": " + err.Error())
			continue
		}
		ci := analyzer.AnalyzeSmaliContent(file.Path, file.Content)
		if ci.ClassName == "" || ci.TotalMethods != declared {
			diagnostic("Incomplete parse: " + file.Path)
			PutClassInfo(ci)
			continue
		}
		parsedFiles[file.Path] = true
		report.Coverage.FilesParsed++
		report.Coverage.BytesParsed += int64(len(file.Content))
		report.Coverage.MethodsDiscovered += ci.TotalMethods
		graphClass := &types.SmaliClass{Name: ci.ClassName, SuperClass: ci.SuperClass, Interfaces: append([]string(nil), ci.Interfaces...)}
		for i := range ci.Methods {
			mi := ci.Methods[i]
			signature := auditMethodSignature(mi)
			if _, ok := bySignature[signature]; ok {
				report.Coverage.DuplicateMethods++
				diagnostic("Duplicate method definition: " + signature)
				continue
			}
			if len(methods) >= cfg.MaxMethods {
				diagnostic("Method budget reached.")
				continue
			}
			bySignature[signature] = len(methods)
			methods = append(methods, ScoredMethod{Method: mi, ClassName: mi.ClassName, ClassPath: file.Path})
			if mi.InstructionCount == 0 {
				report.Coverage.MethodsWithoutCode++
				continue
			}
			access := types.AccessPublic
			if mi.IsStatic {
				access |= types.AccessStatic
			}
			// Keep payloads for branch address reconstruction. The shared CFG lexer
			// excludes annotation/payload contents from executable instructions.
			body := append([]string(nil), mi.RawBody...)

			graphClass.Methods = append(graphClass.Methods, types.SmaliMethod{Name: mi.Name, Params: extractParamsFromHeader(mi.MethodHeader), ReturnType: mi.ReturnType, Access: access, SourceRange: types.SourceRange{LineStart: mi.LineStart, LineEnd: mi.LineEnd}, Body: body})
		}
		program.AddClass(file.Path, graphClass)
		PutClassInfo(ci) // methods above own their slice headers and backing storage
	}
	report.Coverage.FilesSkipped = report.Coverage.FilesInput - report.Coverage.FilesParsed
	report.Coverage.MethodsAnalyzed = len(methods)
	mark("parse_and_index", start, len(input), len(methods), "")

	// This is a real executed MLPipeline stage, not the legacy placeholder.
	signalsPipeline := NewMLPipeline(cfg.Workers, ParallelMapStageContext("method_signals", cfg.Workers, func(ctx context.Context, sm *ScoredMethod) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		sm.Score = ScoreResult{VulnerabilitySignals: AnalyzeVulnerabilitySignals(&sm.Method)}
		return nil
	}))
	var metrics PipelineMetrics
	methods, metrics = signalsPipeline.Run(ctx, methods)
	report.Stages = append(report.Stages, metrics.Stages...)
	for _, err := range metrics.Errors {
		diagnostic(err)
	}

	start = time.Now()
	flows := program.Analyze(ctx)
	report.DataFlowStats = flows.Stats
	report.Coverage.StaticFlows = len(flows.Findings)
	report.Coverage.InformationalFlows = len(flows.Observations)
	if flows.Stats.LimitReached {
		diagnostic("Data-flow analysis is partial: cancellation, method/finding/slice budget or unsupported control flow.")
	}
	mark("source_to_sink_slicing", start, flows.Stats.MethodsAnalyzed, len(flows.Findings), "")

	start = time.Now()
	seen := make(map[string]bool)
	add := func(f SmaliAuditFinding) {
		if seen[f.ID] {
			return
		}
		seen[f.ID] = true
		report.Findings = append(report.Findings, f)
	}
	allFlows := append(append([]dataflow.Finding(nil), flows.Findings...), flows.Observations...)
	for _, flow := range allFlows {
		// A mobile URL flow alone is not server-side request forgery.
		if flow.Category == "ssrf" {
			flow.Category = "untrusted_network_destination"
		}
		miIndex, known := bySignature[flow.Location.Method]
		origin := "unclassified"
		if known {
			origin = auditOrigin(methods[miIndex].Method, cfg.AppPackage)
		}
		f := SmaliAuditFinding{RuleID: "flow/" + flow.Category, Category: flow.Category, EvidenceLevel: "static_flow", Severity: flow.Severity, Priority: auditPriority(flow.Severity, true), Confidence: auditConfidence(flow.Confidence, .85), Origin: origin, Location: SmaliAuditLocation{File: flow.Location.File, Method: flow.Location.Method, Line: max(1, flow.Location.Line)}, Source: flow.Source, Sink: flow.Sink, ReviewRequired: true, Message: "A static source-to-sink candidate was reconstructed; verify branch feasibility, trust boundaries and API semantics.", Recommendation: auditRecommendation(flow.Category)}
		for _, step := range flow.Path {
			location := SmaliAuditLocation{Method: step.Method, Line: max(1, step.Line)}
			text := step.Method
			if i, ok := bySignature[step.Method]; ok {
				mi := methods[i].Method
				location.File = mi.FilePath
				j := step.Line - mi.LineStart
				if j >= 0 && j < len(mi.RawBody) {
					text = auditSnippet(mi.RawBody[j])
				}
			}
			f.Evidence = append(f.Evidence, SmaliAuditEvidence{Kind: step.Type, SmaliAuditLocation: location, Text: text})
		}
		if known && methods[miIndex].Score.VulnerabilitySignals != nil {
			for _, s := range methods[miIndex].Score.VulnerabilitySignals.Signals {
				f.RelatedSignals = append(f.RelatedSignals, string(s.Kind))
			}
			sort.Strings(f.RelatedSignals)
			f.RelatedSignals = uniqueAuditStrings(f.RelatedSignals)
		}
		if flow.Category == "untrusted_log_input" {
			f.EvidenceLevel = "informational_flow"
			f.Message = "Data reaches a logging API, but the modeled source is not identified as sensitive. This is not proof of secret or personal-data exposure."
			f.Recommendation = "Review actual logged content and release logging policy; do not infer a secret from generic user input or a Bundle getter."
			f.ID = auditFindingID(f)
			report.Observations = append(report.Observations, f)
			continue
		}
		f.ID = auditFindingID(f)
		add(f)
	}
	for _, sm := range methods {
		signals := sm.Score.VulnerabilitySignals
		if signals == nil {
			continue
		}
		report.Coverage.SignalsDetected += len(signals.Signals)
		if cfg.NoHeuristics {
			continue
		}
		for _, signal := range signals.Signals {
			mi := sm.Method
			f := SmaliAuditFinding{RuleID: "heuristic/" + string(signal.Kind), Category: string(signal.Kind), EvidenceLevel: "heuristic", Severity: string(signal.Severity), Priority: auditPriority(string(signal.Severity), false), Confidence: auditConfidence(signal.Confidence, .65), Message: "Method-level heuristic: " + string(signal.Kind) + ". Context only; no source-to-sink proof is implied.", Origin: auditOrigin(mi, cfg.AppPackage), Location: SmaliAuditLocation{File: mi.FilePath, Method: auditMethodSignature(mi), Line: max(1, mi.LineStart)}, Evidence: auditMethodEvidence(mi), ReviewRequired: true, Recommendation: auditRecommendation(string(signal.Kind))}
			f.ID = auditFindingID(f)
			add(f)
		}
	}
	mark("evidence_merge", start, len(flows.Findings)+report.Coverage.SignalsDetected, len(report.Findings), "")
	start = time.Now()
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.EvidenceLevel != b.EvidenceLevel {
			return a.EvidenceLevel == "static_flow"
		}
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		return a.ID < b.ID
	})
	total := len(report.Findings)
	if total > cfg.MaxFindings {
		report.Coverage.FindingsOmitted = total - cfg.MaxFindings
		report.Findings = report.Findings[:cfg.MaxFindings]
		diagnostic("Report finding budget reached; output truncated AFTER evidence ranking.")
	}
	if err := ctx.Err(); err != nil {
		diagnostic("Audit deadline/cancellation: " + err.Error())
	}
	if !report.AnalysisComplete {
		report.Verdict = "incomplete_review_required"
	} else if len(report.Findings) > 0 {
		report.Verdict = "review_required"
	} else {
		report.Verdict = "no_findings_within_static_scope"
	}
	mark("rank_and_report", start, total, len(report.Findings), "")
	return report
}

func validateAuditSmali(content []byte) (int, error) {
	inMethod := false
	count, classes := 0, 0
	var state smaliNonCodeState
	for _, raw := range strings.Split(string(content), "\n") {
		line := smaliCodeLine(raw)
		if state.skip(line) {
			continue
		}
		if hasSmaliDirective(line, ".class") {
			classes++
		}
		if hasSmaliDirective(line, ".method") {
			if inMethod {
				return count, fmt.Errorf("nested/unclosed method")
			}
			inMethod = true
			open, close := strings.IndexByte(line, '('), strings.LastIndexByte(line, ')')
			if open < 0 || close <= open || close+1 >= len(line) {
				return count, fmt.Errorf("malformed method signature")
			}
		}
		if strings.Join(strings.Fields(line), " ") == ".end method" {
			if !inMethod {
				return count, fmt.Errorf("orphan .end method")
			}
			inMethod = false
			count++
		}
	}
	if inMethod || state.annotationDepth > 0 || state.payload != "" {
		return count, fmt.Errorf("unclosed method, annotation or payload")
	}
	if classes != 1 {
		return count, fmt.Errorf("expected one class declaration, got %d", classes)
	}
	return count, nil
}
func auditMethodSignature(mi MethodInfo) string {
	owner := mi.ClassName
	if !(strings.HasPrefix(owner, "L") && strings.HasSuffix(owner, ";")) {
		owner = "L" + strings.ReplaceAll(owner, ".", "/") + ";"
	}
	return owner + "->" + mi.FullSignature
}
func auditOrigin(mi MethodInfo, pkg string) string {
	owner := strings.TrimSuffix(strings.TrimPrefix(mi.ClassName, "L"), ";")
	if pkg != "" && strings.HasPrefix(owner, pkg+"/") {
		return "app_package"
	}
	if IsLibraryPath(owner + ".smali") {
		return "known_library"
	}
	return "unclassified"
}
func auditConfidence(value, capValue float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0
	}
	if value > capValue {
		return capValue
	}
	return value
}
func auditPriority(severity string, flow bool) int {
	n := 10
	switch severity {
	case "critical":
		n = 90
	case "high":
		n = 70
	case "medium":
		n = 45
	case "low":
		n = 20
	}
	if !flow {
		n = n / 2
	}
	return n
}
func auditFindingID(f SmaliAuditFinding) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s\x00%s", f.RuleID, f.Location.File, f.Location.Method, f.Location.Line, f.Source, f.Sink)))
	return hex.EncodeToString(sum[:16])
}
func auditSnippet(raw string) string {
	line := smaliCodeLine(raw)
	// String literal contents are not required to navigate evidence and may
	// contain credentials, PII or tokens. Never copy them into reports by default.
	if i := strings.IndexByte(line, '"'); i >= 0 {
		line = line[:i] + "\"<literal redacted>\""
	}
	if len(line) > 512 {
		line = line[:512] + "…"
	}
	return line
}
func auditMethodEvidence(mi MethodInfo) []SmaliAuditEvidence {
	out := []SmaliAuditEvidence{{Kind: "method_context", SmaliAuditLocation: SmaliAuditLocation{File: mi.FilePath, Method: auditMethodSignature(mi), Line: max(1, mi.LineStart)}, Text: auditSnippet(mi.MethodHeader)}}
	for _, call := range mi.Calls {
		if len(out) >= 5 {
			break
		}
		out = append(out, SmaliAuditEvidence{Kind: "call_context", SmaliAuditLocation: SmaliAuditLocation{File: mi.FilePath, Method: auditMethodSignature(mi), Line: max(1, call.Line)}, Text: call.Signature})
	}
	for i, raw := range mi.RawBody {
		if strings.HasPrefix(smaliCodeLine(raw), "const-string") {
			out = append(out, SmaliAuditEvidence{Kind: "literal_context", SmaliAuditLocation: SmaliAuditLocation{File: mi.FilePath, Method: auditMethodSignature(mi), Line: max(1, mi.LineStart+i)}, Text: auditSnippet(raw)})
			break
		}
	}
	return out
}
func uniqueAuditStrings(in []string) []string {
	out := in[:0]
	for _, v := range in {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}
func auditRecommendation(category string) string {
	switch category {
	case "untrusted_network_destination":
		return "Validate URL scheme and destination against a context-specific allowlist. This client-side flow is not evidence of server-side request forgery."
	case "sql_injection":
		return "Use bound query parameters; review whether the reported value reaches SQL syntax rather than a parameter slot."
	case "command_injection", "runtime_exec", "root_command_exec":
		return "Prefer a dedicated API over shell execution; allowlist commands and validate data separately from command syntax."
	case "path_traversal":
		return "Resolve the destination and enforce containment within an allowlisted base directory; canonicalization alone is not authorization."
	case "dynamic_code_loading", "dynamic_class_loading":
		return "Load only trusted, authenticated code from app-controlled storage; validate origin and integrity."
	case "webview_injection", "webview_untrusted_origin", "javascript_injection", "webview_unsafe_config", "webview_js_bridge":
		return "Allowlist WebView origins, minimize JavaScript bridges and file access, and do not evaluate untrusted script."
	case "intent_redirection", "pending_intent_injection":
		return "Validate the target component and nested Intent, restrict exports, enforce permissions and prefer immutable PendingIntent objects."
	case "hardcoded_secret", "password_leak", "log_data_exposure", "sensitive_data_exposure":
		return "Avoid embedding/logging secrets; verify actual sensitivity and use appropriate protected storage."
	case "weak_crypto":
		return "Review the cryptographic purpose before replacing primitives; checksums are not automatically security vulnerabilities."
	default:
		return "Review the exact method and its callers; verify trust boundaries and runtime configuration before treating this as a vulnerability."
	}
}
