package ml

import (
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// INTERESTING SCORER COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════

// InterestingScorer calculates how "interesting" a method is for analysis
type InterestingScorer interface {
	Calculate(mi *MethodInfo, callChain *CallChainInfo) *InterestingScore
}

// InterestingScore measures how interesting a method is for analysis
type InterestingScore struct {
	TotalScore float64 `json:"total_score"`

	ClientTrustScore       float64 `json:"client_trust_score"`
	ExternalInputScore     float64 `json:"external_input_score"`
	NetworkUsageScore      float64 `json:"network_usage_score"`
	ExportedComponentScore float64 `json:"exported_component_score"`
	HardcodedDataScore     float64 `json:"hardcoded_data_score"`
	CallDepthScore         float64 `json:"call_depth_score"`

	GenericMethodPenalty float64 `json:"generic_method_penalty"`
	LibraryCodePenalty   float64 `json:"library_code_penalty"`
	NoIOPenalty          float64 `json:"no_io_penalty"`

	IsEntryPoint  bool   `json:"is_entry_point"`
	IsInteresting bool   `json:"is_interesting"`
	Reason        string `json:"reason"`
}

// CallChainInfo contains information about the call chain context
type CallChainInfo struct {
	Depth                 int      `json:"depth"`
	CallerMethods         []string `json:"caller_methods"`
	IsEntryPoint          bool     `json:"is_entry_point"`
	FromExportedComponent bool     `json:"from_exported_component"`
	HasExternalInput      bool     `json:"has_external_input"`
	HasSecuritySink       bool     `json:"has_security_sink"`
	Path                  []string `json:"path"`
}

// DefaultInterestingScorer implements InterestingScorer interface
type DefaultInterestingScorer struct {
	// Scoring weights
	clientTrustWeight       float64
	externalInputWeight     float64
	networkUsageWeight      float64
	exportedComponentWeight float64
	hardcodedDataWeight     float64
	callDepthWeight         float64

	// Penalty weights
	genericMethodPenalty float64
	libraryCodePenalty   float64
	noIOPenalty          float64

	// Thresholds
	interestingThreshold float64
}

func NewInterestingScorer() InterestingScorer {
	return &DefaultInterestingScorer{
		// Positive scoring weights
		clientTrustWeight:       25.0,
		externalInputWeight:     20.0,
		networkUsageWeight:      15.0,
		exportedComponentWeight: 20.0,
		hardcodedDataWeight:     10.0,
		callDepthWeight:         10.0,

		// Penalty weights
		genericMethodPenalty: 15.0,
		libraryCodePenalty:   20.0,
		noIOPenalty:          5.0,

		// Threshold for "interesting"
		interestingThreshold: 20.0,
	}
}

func (is *DefaultInterestingScorer) Calculate(mi *MethodInfo, callChain *CallChainInfo) *InterestingScore {
	score := &InterestingScore{}

	if mi == nil {
		return score
	}

	// Calculate positive scores
	score.ClientTrustScore = is.calculateClientTrustScore(mi)
	score.ExternalInputScore = is.calculateExternalInputScore(mi)
	score.NetworkUsageScore = is.calculateNetworkUsageScore(mi)
	score.ExportedComponentScore = is.calculateExportedComponentScore(mi, callChain)
	score.HardcodedDataScore = is.calculateHardcodedDataScore(mi)
	score.CallDepthScore = is.calculateCallDepthScore(callChain)

	// Calculate penalties
	score.GenericMethodPenalty = is.calculateGenericMethodPenalty(mi)
	score.LibraryCodePenalty = is.calculateLibraryCodePenalty(mi)
	score.NoIOPenalty = is.calculateNoIOPenalty(mi)

	// Calculate total score
	positiveScore := score.ClientTrustScore + score.ExternalInputScore +
		score.NetworkUsageScore + score.ExportedComponentScore +
		score.HardcodedDataScore + score.CallDepthScore

	totalPenalty := score.GenericMethodPenalty + score.LibraryCodePenalty + score.NoIOPenalty

	score.TotalScore = positiveScore - totalPenalty
	if score.TotalScore < 0 {
		score.TotalScore = 0
	}

	// Determine if interesting
	score.IsInteresting = score.TotalScore >= is.interestingThreshold
	score.IsEntryPoint = callChain != nil && callChain.IsEntryPoint

	// Generate reason
	score.Reason = is.generateReason(score)

	return score
}

func (is *DefaultInterestingScorer) calculateClientTrustScore(mi *MethodInfo) float64 {
	score := 0.0

	// Check SecurityCalls and SecurityStrings first (they are already identified by the scanner)
	score += float64(len(mi.SecurityCalls)) * 5.0
	score += float64(len(mi.SecurityStrings)) * 4.0

	// Check method name
	nameLower := strings.ToLower(mi.Name)
	if strings.Contains(nameLower, "auth") || strings.Contains(nameLower, "login") || strings.Contains(nameLower, "token") {
		score += 15.0
	} else if strings.Contains(nameLower, "license") || strings.Contains(nameLower, "premium") || strings.Contains(nameLower, "payment") || strings.Contains(nameLower, "purchase") {
		score += 12.0
	}

	// Check raw calls for specific patterns if not already identified
	for _, call := range mi.Calls {
		callLower := strings.ToLower(call.FullCall)
		if strings.Contains(callLower, "certificate") || strings.Contains(callLower, "signature") {
			score += 8.0
		} else if strings.Contains(callLower, "license") || strings.Contains(callLower, "subscription") {
			score += 7.0
		} else if strings.Contains(callLower, "premium") || strings.Contains(callLower, "billing") {
			score += 6.0
		} else if strings.Contains(callLower, "root") || strings.Contains(callLower, "tamper") {
			score += 5.0
		}
	}

	// Check string constants
	for _, s := range mi.StringConsts {
		sLower := strings.ToLower(s)
		if strings.Contains(sLower, "license") || strings.Contains(sLower, "subscription") {
			score += 3.0
		} else if strings.Contains(sLower, "premium") || strings.Contains(sLower, "billing") {
			score += 3.0
		}
	}

	// Fallback to RawBody check
	for _, line := range mi.RawBody {
		line = strings.ToLower(line)
		if strings.Contains(line, "certificate") || strings.Contains(line, "signature") {
			score += 2.0
		}
	}

	if score > is.clientTrustWeight {
		score = is.clientTrustWeight
	}

	return score
}

func (is *DefaultInterestingScorer) calculateExternalInputScore(mi *MethodInfo) float64 {
	score := 0.0

	// Check method signature for input types
	sigLower := strings.ToLower(mi.FullSignature)
	if strings.Contains(sigLower, "android/content/intent") || strings.Contains(sigLower, "android/os/bundle") {
		score += 10.0
	}

	for _, call := range mi.Calls {
		callLower := strings.ToLower(call.FullCall)
		if strings.Contains(callLower, "intent") || strings.Contains(callLower, "bundle") {
			score += 4.0
		} else if strings.Contains(callLower, "file") || strings.Contains(callLower, "stream") {
			score += 3.0
		} else if strings.Contains(callLower, "url") || strings.Contains(callLower, "uri") {
			score += 4.0
		}
	}

	for _, s := range mi.StringConsts {
		sLower := strings.ToLower(s)
		if strings.Contains(sLower, "intent.") || strings.Contains(sLower, "extra_") {
			score += 5.0
		}
	}

	if score > is.externalInputWeight {
		score = is.externalInputWeight
	}

	return score
}

func (is *DefaultInterestingScorer) calculateNetworkUsageScore(mi *MethodInfo) float64 {
	score := 0.0

	// Check method name
	nameLower := strings.ToLower(mi.Name)
	if strings.Contains(nameLower, "request") || strings.Contains(nameLower, "network") || strings.Contains(nameLower, "api") {
		score += 10.0
	}

	for _, call := range mi.Calls {
		callLower := strings.ToLower(call.FullCall)
		if strings.Contains(callLower, "http") || strings.Contains(callLower, "url") {
			score += 8.0
		} else if strings.Contains(callLower, "socket") || strings.Contains(callLower, "connection") {
			score += 6.0
		}
	}

	for _, s := range mi.StringConsts {
		sLower := strings.ToLower(s)
		if strings.HasPrefix(sLower, "http://") || strings.HasPrefix(sLower, "https://") {
			score += 10.0
		}
	}

	if score > is.networkUsageWeight {
		score = is.networkUsageWeight
	}

	return score
}

func (is *DefaultInterestingScorer) calculateExportedComponentScore(mi *MethodInfo, callChain *CallChainInfo) float64 {
	score := 0.0

	// Check if this is an exported component entry point
	if callChain != nil && callChain.IsEntryPoint {
		score += 15.0
	}

	// Check method name for exported patterns
	methodName := strings.ToLower(mi.Name)
	exportedPatterns := []string{
		"oncreate", "onstart", "onresume", "onpause", "onstop", "ondestroy",
		"onclick", "ontouch", "onkey",
		"onreceive", "onbind", "onunbind",
	}

	for _, pattern := range exportedPatterns {
		if strings.Contains(methodName, pattern) {
			score += 3.0
			break
		}
	}

	if score > is.exportedComponentWeight {
		score = is.exportedComponentWeight
	}

	return score
}

func (is *DefaultInterestingScorer) calculateHardcodedDataScore(mi *MethodInfo) float64 {
	score := 0.0

	for _, line := range mi.RawBody {
		// Look for hardcoded strings/constants
		if strings.Contains(line, "const-string") {
			score += 2.0
		}

		// Look for hardcoded numbers that might be important
		if strings.Contains(line, "const/") &&
			(strings.Contains(line, "0x") || strings.Contains(line, "0L")) {
			score += 1.0
		}
	}

	if score > is.hardcodedDataWeight {
		score = is.hardcodedDataWeight
	}

	return score
}

func (is *DefaultInterestingScorer) calculateCallDepthScore(callChain *CallChainInfo) float64 {
	if callChain == nil {
		return 0.0
	}

	// Shallow call depth is more interesting (closer to entry points)
	depth := callChain.Depth
	if depth <= 2 {
		return is.callDepthWeight
	} else if depth <= 5 {
		return is.callDepthWeight * 0.7
	} else {
		return 0.0
	}
}

func (is *DefaultInterestingScorer) calculateGenericMethodPenalty(mi *MethodInfo) float64 {
	methodName := strings.ToLower(mi.Name)

	genericPatterns := []string{
		"tostring", "hashcode", "equals", "clone",
		"getclass", "notify", "wait", "finalize",
		"getter", "setter", "get", "set",
		"init", "constructor", "<init>", "<clinit>",
	}

	for _, pattern := range genericPatterns {
		if strings.Contains(methodName, pattern) || methodName == pattern {
			return is.genericMethodPenalty
		}
	}

	return 0.0
}

func (is *DefaultInterestingScorer) calculateLibraryCodePenalty(mi *MethodInfo) float64 {
	if !mi.IsAppCode {
		return is.libraryCodePenalty
	}
	return 0.0
}

func (is *DefaultInterestingScorer) calculateNoIOPenalty(mi *MethodInfo) float64 {
	hasIO := false

	if len(mi.Calls) > 0 {
		hasIO = true
	}

	if !hasIO {
		for _, line := range mi.RawBody {
			line = strings.ToLower(line)
			if strings.Contains(line, "invoke-") {
				hasIO = true
				break
			}
		}
	}

	if !hasIO {
		return is.noIOPenalty
	}

	return 0.0
}

func (is *DefaultInterestingScorer) generateReason(score *InterestingScore) string {
	if !score.IsInteresting {
		if score.LibraryCodePenalty > 0 {
			return "Library code - low priority"
		}
		if score.GenericMethodPenalty > 0 {
			return "Generic method - low priority"
		}
		return "Low interesting score"
	}

	reasons := make([]string, 0)

	if score.ClientTrustScore > 5 {
		reasons = append(reasons, "client trust logic")
	}
	if score.ExternalInputScore > 5 {
		reasons = append(reasons, "external input handling")
	}
	if score.NetworkUsageScore > 5 {
		reasons = append(reasons, "network operations")
	}
	if score.IsEntryPoint {
		reasons = append(reasons, "entry point")
	}

	if len(reasons) == 0 {
		return "High interesting score"
	}

	return "Interesting: " + strings.Join(reasons, ", ")
}
