package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/codescan"
	"mega-analyzer/pkg/internal/networkrefs"
	"mega-analyzer/pkg/internal/types"
)

const (
	maxRecoveredArtifactDepth    = 2
	maxRecoveredArtifactPayloads = 16
	maxRecoveredArtifactBytes    = 8 << 20
	maxRecoveredJSBytes          = 4 << 20
	maxRecoveredDEXBytes         = 8 << 20
)

var (
	dalvikClassArtifactPattern  = regexp.MustCompile(`^L[[:alnum:]_$/]+;$`)
	dalvikMethodArtifactPattern = regexp.MustCompile(`^L[[:alnum:]_$/]+;->[[:alnum:]_$<>]+\([^)]*\).+$`)
	domainArtifactPattern       = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	javaClassArtifactPattern    = regexp.MustCompile(`^(?:[a-zA-Z_][a-zA-Z0-9_]*\.)+[A-Z][a-zA-Z0-9_]*$`)
)

type recoveredArtifactPayload struct {
	artifact types.RecoveredArtifact
	data     []byte
}

type recoveredArtifactSession struct {
	seen     map[string]struct{}
	payloads int
	bytes    int
}

func newRecoveredArtifactSession() *recoveredArtifactSession {
	return &recoveredArtifactSession{seen: make(map[string]struct{})}
}

func (p *Pipeline) dispatchRecoveredArtifacts(ctx context.Context, analysis *types.FileAnalysis, job FileJob) {
	if analysis == nil || len(analysis.RecoveredStrings) == 0 {
		return
	}
	session := newRecoveredArtifactSession()
	queue := make([]recoveredArtifactPayload, 0, len(analysis.RecoveredStrings))
	for _, value := range analysis.RecoveredStrings {
		queue = append(queue, classifyRecoveredText(value, "", 0, 0)...)
	}
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return
		}
		payload := queue[0]
		queue = queue[1:]
		if analysis.RecoveredArtifactSummary == nil {
			analysis.RecoveredArtifactSummary = &types.RecoveredArtifactSummary{ByKind: make(map[string]int)}
		}
		summary := analysis.RecoveredArtifactSummary
		summary.Discovered++
		summary.ByKind[payload.artifact.Kind]++
		key := payload.artifact.Kind + ":" + payload.artifact.SHA256
		if _, duplicate := session.seen[key]; duplicate {
			summary.Deduped++
			continue
		}
		session.seen[key] = struct{}{}
		if payload.artifact.Depth > maxRecoveredArtifactDepth || session.payloads >= maxRecoveredArtifactPayloads || session.bytes+len(payload.data) > maxRecoveredArtifactBytes {
			payload.artifact.Status, payload.artifact.Reason = "budget_exhausted", "recovered artifact session budget"
			summary.Budgeted++
			analysis.RecoveredArtifacts = append(analysis.RecoveredArtifacts, payload.artifact)
			continue
		}
		session.payloads++
		session.bytes += len(payload.data)
		summary.Bytes += int64(len(payload.data))
		switch payload.artifact.Kind {
		case "javascript":
			if len(payload.data) > maxRecoveredJSBytes {
				payload.artifact.Status, payload.artifact.Reason = "budget_exhausted", "JavaScript payload too large"
				summary.Budgeted++
				break
			}
			p.scanRecoveredJavaScript(analysis, job, payload)
			payload.artifact.Status = "scanned"
			summary.Scanned++
		case "dex":
			if len(payload.data) > maxRecoveredDEXBytes {
				payload.artifact.Status, payload.artifact.Reason = "budget_exhausted", "DEX payload too large"
				summary.Budgeted++
				break
			}
			children, err := p.scanRecoveredDEX(ctx, analysis, job, payload)
			if err != nil {
				payload.artifact.Status, payload.artifact.Reason = "rejected", err.Error()
				summary.Skipped++
			} else {
				payload.artifact.Status = "scanned"
				summary.Scanned++
				queue = append(queue, children...)
			}
		default:
			payload.artifact.Status = "classified"
		}
		analysis.RecoveredArtifacts = append(analysis.RecoveredArtifacts, payload.artifact)
	}
	sort.Slice(analysis.RecoveredArtifacts, func(i, j int) bool { return analysis.RecoveredArtifacts[i].ID < analysis.RecoveredArtifacts[j].ID })
}

func classifyRecoveredText(value, method string, offset uint32, depth int) []recoveredArtifactPayload {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	artifacts := []recoveredArtifactPayload{newRecoveredArtifact("string", []byte(value), method, offset, depth, boundedPreview(value, 256))}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		artifacts = append(artifacts, newRecoveredArtifact("url", []byte(value), method, offset, depth, boundedPreview(value, 256)))
		artifacts = append(artifacts, newRecoveredArtifact("domain", []byte(strings.ToLower(parsed.Hostname())), method, offset, depth, strings.ToLower(parsed.Hostname())))
	} else if ip := net.ParseIP(value); ip != nil {
		artifacts = append(artifacts, newRecoveredArtifact("ip_address", []byte(ip.String()), method, offset, depth, ip.String()))
	} else if domainArtifactPattern.MatchString(value) && !javaClassArtifactPattern.MatchString(value) && networkrefs.IsRecoveredHostname(value) {
		artifacts = append(artifacts, newRecoveredArtifact("domain", []byte(strings.ToLower(value)), method, offset, depth, strings.ToLower(value)))
	}
	if dalvikMethodArtifactPattern.MatchString(value) {
		artifacts = append(artifacts, newRecoveredArtifact("method_name", []byte(value), method, offset, depth, value))
		artifacts = append(artifacts, newRecoveredArtifact("reflection_target", []byte(value), method, offset, depth, value))
	} else if dalvikClassArtifactPattern.MatchString(value) || javaClassArtifactPattern.MatchString(value) {
		artifacts = append(artifacts, newRecoveredArtifact("class_name", []byte(value), method, offset, depth, value))
		artifacts = append(artifacts, newRecoveredArtifact("reflection_target", []byte(value), method, offset, depth, value))
	}
	if strings.Contains(value, "Class.forName") || strings.Contains(value, "Method.invoke") || strings.Contains(value, "Field.get") || strings.Contains(value, "ClassLoader.loadClass") {
		artifacts = append(artifacts, newRecoveredArtifact("reflection_target", []byte(value), method, offset, depth, value))
	}
	if looksLikeRecoveredJavaScript([]byte(value)) {
		artifacts = append(artifacts, newRecoveredArtifact("javascript", []byte(value), method, offset, depth, boundedPreview(value, 256)))
	}
	if decoded, ok := decodeRecognizedRecoveredPayload(value); ok {
		kind := "javascript"
		if isDEXPayload(decoded) {
			kind = "dex"
		}
		artifacts = append(artifacts, newRecoveredArtifact(kind, decoded, method, offset, depth+1, boundedPreview(string(decoded), 128)))
	}
	return artifacts
}

func newRecoveredArtifact(kind string, data []byte, method string, offset uint32, depth int, preview string) recoveredArtifactPayload {
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	idSum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", kind, hash, method, offset)))
	return recoveredArtifactPayload{artifact: types.RecoveredArtifact{ID: "ra-" + hex.EncodeToString(idSum[:8]), Kind: kind, SHA256: hash, Size: len(data), Depth: depth, SourceMethod: method, SourceOffset: offset, Preview: preview}, data: append([]byte(nil), data...)}
}

func decodeRecognizedRecoveredPayload(value string) ([]byte, bool) {
	if len(value) < 16 || len(value) > maxRecoveredDEXBytes*2 {
		return nil, false
	}
	candidates := make([][]byte, 0, 2)
	if decoded, err := base64.StdEncoding.Strict().DecodeString(value); err == nil {
		candidates = append(candidates, decoded)
	}
	if len(value)%2 == 0 {
		if decoded, err := hex.DecodeString(value); err == nil {
			candidates = append(candidates, decoded)
		}
	}
	for _, decoded := range candidates {
		if isDEXPayload(decoded) || looksLikeRecoveredJavaScript(decoded) {
			return decoded, true
		}
	}
	return nil, false
}

func isDEXPayload(data []byte) bool {
	return len(data) >= 112 && string(data[:4]) == "dex\n" && data[7] == 0
}

func looksLikeRecoveredJavaScript(data []byte) bool {
	if len(data) < 16 || !utf8.Valid(data) || len(data) > maxRecoveredJSBytes {
		return false
	}
	text := string(data)
	tokens := 0
	for _, token := range []string{"function ", "=>", "eval(", "require(", "module.exports", "document.", "window.", "fetch("} {
		if strings.Contains(text, token) {
			tokens++
		}
	}
	return tokens >= 2
}

func boundedPreview(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func (p *Pipeline) scanRecoveredJavaScript(parent *types.FileAnalysis, job FileJob, payload recoveredArtifactPayload) {
	path := job.RelPath + "#recovered/" + payload.artifact.ID + ".js"
	result := codescan.Scan(path, "javascript", payload.data)
	for _, finding := range result.Findings {
		match := newMatch(types.CategoryMalware, path, finding.Line, finding.Title, finding.Detail, finding.Severity == codescan.SevCritical)
		match.ResolvedContext = "recovered javascript"
		match.Metadata = map[string]string{"recovered_artifact_id": payload.artifact.ID, "recovered_artifact_sha256": payload.artifact.SHA256, "code_rule": finding.ID}
		parent.Matches = append(parent.Matches, match)
	}
}

func (p *Pipeline) scanRecoveredDEX(ctx context.Context, parent *types.FileAnalysis, job FileJob, payload recoveredArtifactPayload) ([]recoveredArtifactPayload, error) {
	// Streaming: recovered DEXes are small, but there is no reason to retain
	// every class IR at once — process one class at a time like the main DEX
	// path does.
	var children []recoveredArtifactPayload
	hyperion := apkloader.NewDeobfuscationPipeline(apkloader.DefaultPipelineConfig())
	err := apkloader.StreamOwnedBundleBytes(ctx, payload.data, apkloader.OwnedDEXOptions{EnableHyperion: p.config.EnableDeobfuscation, MinCandidateScore: 2, MaxReachableDepth: 2, MaxReachableMethods: 64, MaxOwnedCodeUnits: 1 << 18, MaxStaticFields: 1024, MaxStaticArrayElements: 8192, MaxStaticBytes: 1 << 18}, func(class apkloader.DEXClassIR, env *apkloader.OwnedEnvironment) error {
		virtual := FileJob{Path: job.Path, RelPath: job.RelPath + "#recovered/" + payload.artifact.ID + "/" + strings.Trim(class.ClassName, "L;"), Type: types.FileTypeSmali, Size: int64(len(class.IR)), ForceAppCode: true}
		child := p.processContent(ctx, virtual, class.IR)
		if child == nil {
			return nil
		}
		child.Type = types.FileTypeDex
		if p.config.EnableDeobfuscation && len(class.Methods) > 0 {
			p.applyHyperionMethodsWithEnvironment(ctx, child, hyperion, class.Methods, env.Resolver, env.Statics)
		}
		for i := range child.Matches {
			if child.Matches[i].Metadata == nil {
				child.Matches[i].Metadata = make(map[string]string)
			}
			child.Matches[i].Metadata["recovered_artifact_id"] = payload.artifact.ID
			child.Matches[i].Metadata["recovered_artifact_sha256"] = payload.artifact.SHA256
			child.Matches[i].ResolvedContext = "recovered dex"
		}
		parent.Matches = append(parent.Matches, child.Matches...)
		parent.DecisionPoints = append(parent.DecisionPoints, child.DecisionPoints...)
		for _, value := range child.RecoveredStrings {
			children = append(children, classifyRecoveredText(value, class.ClassName, 0, payload.artifact.Depth+1)...)
		}
		return nil
	}, nil)
	if err != nil {
		return nil, err
	}
	return children, nil
}
