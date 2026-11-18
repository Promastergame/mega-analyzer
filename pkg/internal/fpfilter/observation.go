package fpfilter

import (
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// Detector-provided semantics take precedence over a keyword score. A
// capability or protection remains useful inventory even at high severity.
func isObservation(match *types.Match) bool {
	if match == nil {
		return false
	}
	switch strings.ToLower(match.Metadata["finding_kind"]) {
	case "inventory", "hardening":
		return true
	case "malware", "vulnerability":
		return false
	}
	if match.Explanation != nil && match.Explanation.Status == "observation" {
		return true
	}
	switch match.Category {
	case types.CategorySecurity, types.CategorySignatureCheck,
		types.CategoryIntegrityCheck, types.CategoryTamperDetection,
		types.CategoryHashCheck, types.CategoryRootDetection,
		types.CategoryEmulatorDetection, types.CategoryDebugDetection,
		types.CategorySafetyNet, types.CategoryPlayIntegrity,
		types.CategorySSLPinning, types.CategoryCertCheck,
		types.CategoryAntiHook, types.CategoryAntiXposed:
		return true
	}
	return false
}
