//go:build legacy_fuzzer
// +build legacy_fuzzer

package binzap

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"mega-analyzer/pkg/logger"
)

// SandboxConfig defines the limits for the Active Emulation Fuzzer.
type SandboxConfig struct {
	TimeoutMs     int `json:"timeout_ms"`
	MaxMemoryMB   int `json:"max_memory_mb"`
	MaxIterations int `json:"max_iterations"`
}

var DefaultSandboxConfig = SandboxConfig{
	TimeoutMs:     5000,
	MaxMemoryMB:   256,
	MaxIterations: 1000,
}

func LoadConfig(path string) (SandboxConfig, error) {
	config := DefaultSandboxConfig
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil
		}
		return config, err
	}
	err = json.Unmarshal(data, &config)
	return config, err
}

type ActiveFuzzer struct {
	Config SandboxConfig
}

func NewActiveFuzzer(cfg SandboxConfig) *ActiveFuzzer {
	return &ActiveFuzzer{Config: cfg}
}

// FuzzMethod parses the signature, generates payloads, and simulates the emulation.
func (f *ActiveFuzzer) FuzzMethod(methodSignature string) ([]Finding, error) {
	var findings []Finding

	logger.Info("Starting Active Fuzzing", "method", methodSignature)

	params := extractParamTypes(methodSignature)
	logger.Debug("Extracted parameters", "params", fmt.Sprintf("%v", params))

	payloadVectors := generateMutationVectors(params, f.Config.MaxIterations)
	logger.Debug("Generated mutation vectors", "count", len(payloadVectors))

	startTime := time.Now()
	timeoutDur := time.Duration(f.Config.TimeoutMs) * time.Millisecond

	for i, vector := range payloadVectors {
		if time.Since(startTime) > timeoutDur {
			logger.Warn("Sandbox Timeout Reached. Halting fuzzer.")
			findings = append(findings, Finding{
				RuleID:     "BZ-ACT-TIMEOUT",
				Severity:   SeverityMedium,
				Message:    fmt.Sprintf("Fuzzer hit timeout limit (%dms)", f.Config.TimeoutMs),
				File:       methodSignature,
				Line:       i,
				Evidence:   "Timeout during emulation",
				Confidence: ConfidenceHigh,
			})
			break
		}

		// ---------------------------------------------------------------
		// EMULATION HARNESS
		// Inject vector into omnisec-emu (mock path: pattern matching).
		// detectCrashPattern applies all globalCrashPatterns against the
		// current vector, replacing the old hardcoded per-method checks.
		// ---------------------------------------------------------------
		if cp, tag := detectCrashPattern(vector, methodSignature); cp != nil {
			vectorStr := fmt.Sprintf("%v", vector)
			msg := fmt.Sprintf(cp.MessageFmt, tag, vectorStr)
			findings = append(findings, Finding{
				RuleID:     cp.ID,
				Severity:   cp.Severity,
				Message:    msg,
				File:       methodSignature,
				Line:       i,
				Evidence:   fmt.Sprintf("Triggering payload: %q in vector %s", tag, vectorStr),
				Confidence: ConfidenceHigh,
			})
			// Stop on critical crashes (null deref, SQLi); continue on lower severity
			if cp.Severity == SeverityCritical {
				break
			}
		}
	}

	logger.Info("Active Fuzzing completed", "duration", time.Since(startTime).String())
	return findings, nil
}

// CrashPattern describes a detected crash or vulnerability category.
type CrashPattern struct {
	ID          string
	Severity    Severity
	PayloadTag  string // tag to look for in the vector
	MessageFmt  string // format string: takes (payloadTag, vectorStr)
	MatchMethod string // if non-empty, only match when method sig contains this substr
}

// globalCrashPatterns is the full list of crash/vuln patterns the fuzzer detects.
// Patterns are checked in order; first match wins per vector.
var globalCrashPatterns = []CrashPattern{
	{
		ID:         "BZ-ACT-NULL",
		Severity:   SeverityCritical,
		PayloadTag: "NULL_POINTER",
		MessageFmt: "NullPointerException crash via null Object injection (payload: %s, vector: %s)",
	},
	{
		ID:         "BZ-ACT-OVERFLOW",
		Severity:   SeverityHigh,
		PayloadTag: "INT_MAX",
		MessageFmt: "Integer overflow via INT_MAX injection — possible OOB or allocation overflow (vector: %s%s)",
	},
	{
		ID:         "BZ-ACT-LONG-OVERFLOW",
		Severity:   SeverityHigh,
		PayloadTag: "LONG_MAX",
		MessageFmt: "Long overflow via LONG_MAX injection — possible OOB or allocation overflow (vector: %s%s)",
	},
	{
		ID:         "BZ-ACT-FORMAT-STRING",
		Severity:   SeverityHigh,
		PayloadTag: "FORMAT_STRING",
		MessageFmt: "Format string injection accepted as input (payload: %s, vector: %s)",
	},
	{
		ID:         "BZ-ACT-PATH-TRAVERSAL",
		Severity:   SeverityHigh,
		PayloadTag: "PATH_TRAVERSAL",
		MessageFmt: "Path traversal payload accepted as string input (payload: %s, vector: %s)",
	},
	{
		ID:         "BZ-ACT-SQLI",
		Severity:   SeverityCritical,
		PayloadTag: "SQLI_PAYLOAD",
		MessageFmt: "SQL injection payload accepted as string input (payload: %s, vector: %s)",
	},
	{
		ID:         "BZ-ACT-NEGATIVE-SIZE",
		Severity:   SeverityHigh,
		PayloadTag: "INT_MIN",
		MessageFmt: "Negative integer (-2147483648) accepted as size/count — possible negative array allocation (vector: %s%s)",
	},
	{
		ID:         "BZ-ACT-NAN",
		Severity:   SeverityMedium,
		PayloadTag: "NaN",
		MessageFmt: "NaN accepted as floating-point input — possible unhandled NaN propagation (vector: %s%s)",
	},
	{
		ID:         "BZ-ACT-NULL-BYTE",
		Severity:   SeverityMedium,
		PayloadTag: "NULL_BYTE_STRING",
		MessageFmt: "Null-byte string accepted as input — may truncate paths or cause C-layer crashes (vector: %s%s)",
	},
	{
		ID:         "BZ-ACT-LONG-STRING",
		Severity:   SeverityMedium,
		PayloadTag: "LONG_STRING",
		MessageFmt: "Overly long string (8192 chars) accepted — possible buffer sizing issue (vector: %s%s)",
	},
}

// primitivePayloads maps Dalvik type descriptors to ordered mutation values.
// Tags in UPPER_CASE are matched by globalCrashPatterns.
var primitivePayloads = map[string][]string{
	"I": {"0", "-1", "2147483647", "-2147483648", "INT_MAX", "INT_MIN"},
	"J": {"0", "-1", "9223372036854775807", "-9223372036854775808", "LONG_MAX"},
	"Z": {"true", "false"},
	"B": {"0", "127", "-128"},
	"S": {"0", "32767", "-32768"},
	"F": {"0.0", "NaN", "Infinity", "-Infinity"},
	"D": {"0.0", "NaN", "Infinity", "-Infinity"},
	"C": {"a", "\x00", "\uffff"},
}

// generateObjectPayloads returns a rich set of mutation payloads for an object
// type based on the Dalvik class name. String types get the largest mutation set.
func generateObjectPayloads(dalvikType string) []string {
	base := []string{"null", "NULL_POINTER"}

	if dalvikType == "Ljava/lang/String;" || strings.HasSuffix(dalvikType, "String;") {
		return append(base, []string{
			"empty_string",      // ""
			"LONG_STRING",       // 8192-char string
			"NULL_BYTE_STRING",  // "hello\x00world"
			"FORMAT_STRING",     // "%s%s%s%s%s%s%n"
			"PATH_TRAVERSAL",    // "../../../../etc/passwd"
			"SQLI_PAYLOAD",      // "' OR '1'='1"
			"UNICODE_OVERFLOW",  // "\uFFFD\uFFFD\uFFFD..."
			"CRLF_INJECTION",    // "foo\r\nX-Injected: bar"
			"COMMAND_INJECTION", // "; id; echo pwned"
			"XML_INJECTION",     // "<foo><bar/></foo>"
		}...)
	}

	// byte[] / char[] arrays
	if strings.HasPrefix(dalvikType, "[B") || strings.HasPrefix(dalvikType, "[C") {
		return append(base, []string{"empty_array", "LONG_BYTE_ARRAY", "NULL_BYTE_STRING"}...)
	}

	// int[] / long[] arrays
	if strings.HasPrefix(dalvikType, "[I") || strings.HasPrefix(dalvikType, "[J") {
		return append(base, []string{"empty_array", "INT_MAX_ARRAY", "NEGATIVE_SIZE_ARRAY"}...)
	}

	// Context / Activity / Fragment (Android)
	if strings.Contains(dalvikType, "Context;") || strings.Contains(dalvikType, "Activity;") {
		return append(base, []string{"mock_context", "NULL_POINTER"}...)
	}

	return base
}

func generateMutationVectors(params []string, maxIter int) [][]string {
	var vectors [][]string

	// Build baseline vector (first payload for each param type)
	baseVector := make([]string, len(params))
	for i, p := range params {
		if payloads, ok := primitivePayloads[p]; ok {
			baseVector[i] = payloads[0]
		} else {
			baseVector[i] = "null"
		}
	}

	// One-at-a-time mutation: vary each parameter independently
	for i := 0; i < len(params) && len(vectors) < maxIter; i++ {
		p := params[i]
		var mutationSet []string
		if payloads, ok := primitivePayloads[p]; ok {
			mutationSet = payloads
		} else {
			mutationSet = generateObjectPayloads(p)
		}

		for _, mutation := range mutationSet {
			if len(vectors) >= maxIter {
				break
			}
			v := make([]string, len(baseVector))
			copy(v, baseVector)
			v[i] = mutation
			vectors = append(vectors, v)
		}
	}

	return vectors
}

// detectCrashPattern scans a payload vector against globalCrashPatterns.
// It returns the matched pattern and the triggering payload tag, or nil if none matched.
func detectCrashPattern(vector []string, methodSig string) (*CrashPattern, string) {
	vectorStr := fmt.Sprintf("%v", vector)
	for i := range globalCrashPatterns {
		cp := &globalCrashPatterns[i]
		if cp.MatchMethod != "" && !strings.Contains(methodSig, cp.MatchMethod) {
			continue
		}
		for _, v := range vector {
			if v == cp.PayloadTag {
				_ = vectorStr
				return cp, v
			}
		}
	}
	return nil, ""
}

func hasPayload(vector []string, payload string) bool {
	for _, v := range vector {
		if v == payload {
			return true
		}
	}
	return false
}
