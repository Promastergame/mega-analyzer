package pipeline

import (
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

type VulnAndroidSurfaceDetector struct{}

func NewVulnAndroidSurfaceDetector() *VulnAndroidSurfaceDetector {
	return &VulnAndroidSurfaceDetector{}
}

func (*VulnAndroidSurfaceDetector) Name() string { return "vuln_android_surface" }
func (*VulnAndroidSurfaceDetector) SupportsFile(fileType types.FileType, _ string) bool {
	return fileType == types.FileTypeSmali
}

func (*VulnAndroidSurfaceDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx == nil || ctx.Class == nil || analysis == nil {
		return
	}
	contentStr := string(ctx.Content)
	detectJSBridgeInventory(ctx.Class, contentStr, analysis)
	detectProviderOpenFile(ctx.Class, contentStr, analysis)
}

func detectJSBridgeInventory(class *types.SmaliClass, content string, analysis *types.FileAnalysis) {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	for i := range class.Methods {
		method := &class.Methods[i]
		methodLines := extractMethodLines(method, lines)
		if !hasJavascriptInterfaceAnnotationInLines(methodLines) {
			continue
		}
		caps := bridgeCapabilitiesFromMethodLines(methodLines)
		pattern := "@JavascriptInterface exposed (no dangerous capability detected)"
		description := "JavaScript bridge method " + method.Name + " is callable from WebView content."
		severity := types.SeverityMedium
		critical := false
		confidence := "medium"
		if len(caps) > 0 {
			pattern = "@JavascriptInterface exposed: " + strings.Join(caps, ", ")
			description += " Native capabilities: " + strings.Join(caps, ", ") + "."
			severity = types.SeverityHigh
			critical = containsAny(caps, "command execution", "reflection", "file write")
			if critical {
				severity = types.SeverityCritical
			}
			confidence = "high"
		}
		match := newMatch(types.CategoryWebViewJSBridge, analysis.Path, method.LineStart, description, pattern, critical)
		match.Severity = severity
		match.Confidence = confidence
		match.ClassName = class.Name
		match.MethodName = method.Name
		match.EvidenceType = "smali_annotation_capability"
		analysis.Matches = append(analysis.Matches, match)
	}
}

func extractMethodLines(method *types.SmaliMethod, lines []string) []string {
	start := method.LineStart - 1
	end := method.LineEnd
	if start >= 0 && end > start && end <= len(lines) {
		return lines[start:end]
	}
	inMethod := false
	var methodLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ".method ") && strings.Contains(line, method.Name) {
			inMethod = true
			methodLines = append(methodLines, line)
			continue
		}
		if inMethod {
			methodLines = append(methodLines, line)
			if trimmed == ".end method" {
				break
			}
		}
	}
	return methodLines
}

func hasJavascriptInterfaceAnnotationInLines(methodLines []string) bool {
	for _, line := range methodLines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "javascriptinterface;") || strings.Contains(lower, "@javascriptinterface") {
			return true
		}
	}
	return false
}

func bridgeCapabilitiesFromMethodLines(methodLines []string) []string {
	caps := make(map[string]struct{})

	for _, line := range methodLines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "runtime;->exec") || strings.Contains(lower, "processbuilder") || strings.Contains(lower, "runtime.exec") {
			caps["command execution"] = struct{}{}
		}
		if strings.Contains(lower, "fileoutputstream") || strings.Contains(lower, "filewriter") || strings.Contains(lower, "openfileoutput") || strings.Contains(lower, "randomaccessfile") {
			caps["file write"] = struct{}{}
		}
		if strings.Contains(lower, "fileinputstream") || strings.Contains(lower, "filereader") || strings.Contains(lower, "openfileinput") {
			caps["file read"] = struct{}{}
		}
		if strings.Contains(lower, "execsql") || strings.Contains(lower, "rawquery") || strings.Contains(lower, "sqlitedatabase") {
			caps["database access"] = struct{}{}
		}
		if strings.Contains(lower, "method;->invoke") || strings.Contains(lower, "class;->forname") || strings.Contains(lower, "getdeclaredmethod") {
			caps["reflection"] = struct{}{}
		}
		if strings.Contains(lower, "webview;->loadurl") || strings.Contains(lower, "webview;->posturl") {
			caps["web navigation"] = struct{}{}
		}
		if strings.Contains(lower, "httpurlconnection") || strings.Contains(lower, "okhttpclient") {
			caps["network"] = struct{}{}
		}
	}

	out := make([]string, 0, len(caps))
	for cap := range caps {
		out = append(out, cap)
	}
	sort.Strings(out)
	return out
}

func detectProviderOpenFile(class *types.SmaliClass, content string, analysis *types.FileAnalysis) {
	if !isContentProviderClass(class) {
		return
	}
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	for i := range class.Methods {
		method := &class.Methods[i]
		if method.Name != "openFile" && method.Name != "openAssetFile" && method.Name != "openTypedAssetFile" {
			continue
		}
		methodLines := extractMethodLines(method, lines)
		if providerPathGuarded(methodLines) {
			continue
		}
		match := newMatch(types.CategoryExportedComponent, analysis.Path, method.LineStart,
			"ContentProvider "+method.Name+" consumes a caller-controlled Uri without a recognized canonical-path or segment validation guard (CWE-22).",
			"provider openFile path traversal: missing canonical-path validation", false)
		match.Severity = types.SeverityHigh
		match.Confidence = "medium"
		match.ClassName = class.Name
		match.MethodName = method.Name
		match.EvidenceType = "smali_provider_entrypoint"
		analysis.Matches = append(analysis.Matches, match)
	}
}

func isContentProviderClass(class *types.SmaliClass) bool {
	value := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(class.SuperClass), "l"), ";")
	value = strings.ReplaceAll(value, "/", ".")
	return value == "android.content.contentprovider"
}

func providerPathGuarded(methodLines []string) bool {
	segmentRegisters := make(map[string]struct{})
	awaitingSegmentResult := false

	for _, line := range methodLines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "ljava/io/file;->getcanonicalpath") ||
			strings.Contains(lower, "ljava/io/file;->getcanonicalfile") {
			return true
		}
		if strings.Contains(lower, "landroid/net/uri;->getpathsegments") ||
			strings.Contains(lower, "landroid/net/uri;->getlastpathsegment") {
			awaitingSegmentResult = true
			continue
		}
		if awaitingSegmentResult {
			if reg, ok := moveResultObjectRegister(trimmed); ok {
				segmentRegisters[reg] = struct{}{}
				awaitingSegmentResult = false
				continue
			}
			if trimmed != "" && !strings.HasPrefix(trimmed, ".") && !strings.HasPrefix(trimmed, ":") {
				awaitingSegmentResult = false
			}
		}
		if !isSegmentValidationCall(lower) {
			continue
		}
		call, ok := parseCryptoInvoke(trimmed)
		if !ok || len(call.registers) == 0 {
			continue
		}
		if _, ok := segmentRegisters[call.registers[0]]; ok {
			return true
		}
	}
	return false
}

func moveResultObjectRegister(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) != 2 || fields[0] != "move-result-object" {
		return "", false
	}
	return strings.TrimSuffix(fields[1], ","), true
}

func isSegmentValidationCall(lower string) bool {
	return strings.Contains(lower, "ljava/lang/string;->startswith") ||
		strings.Contains(lower, "ljava/lang/string;->contains") ||
		strings.Contains(lower, "ljava/util/list;->contains")
}

func containsAny(values []string, wanted ...string) bool {
	for _, value := range values {
		for _, candidate := range wanted {
			if value == candidate {
				return true
			}
		}
	}
	return false
}
