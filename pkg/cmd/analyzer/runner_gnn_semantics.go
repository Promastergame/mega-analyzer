package main

import (
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// Graph shape cannot distinguish a license gate from UI or collection code.
// Require an independent code anchor; retain uncorroborated model outputs in
// diagnostics rather than presenting them as discovered license checks.
func gnnLicenseEvidence(files map[string]*types.FileAnalysis) map[string]string {
	direct := map[string]string{}
	for _, file := range files {
		if file == nil || file.SmaliClass == nil {
			continue
		}
		for _, method := range file.SmaliClass.Methods {
			if reason := gnnDirectLicenseEvidence(&method); reason != "" {
				direct[gnnSemanticKey(method.FullSignature(file.SmaliClass.Name))] = reason
			}
		}
	}
	result := make(map[string]string, len(direct))
	for key, reason := range direct {
		result[key] = reason
	}
	// One caller hop preserves wrappers around an obfuscated verifier. Do not
	// propagate a licensing label throughout constructors and the call graph.
	for _, file := range files {
		if file == nil || file.SmaliClass == nil {
			continue
		}
		for _, method := range file.SmaliClass.Methods {
			if !gnnHasBranch(&method) {
				continue
			}
			for _, invoke := range method.Invokes {
				if direct[gnnSemanticKey(invoke.FullSignature())] != "" {
					result[gnnSemanticKey(method.FullSignature(file.SmaliClass.Name))] = "calls_license_verifier"
					break
				}
			}
		}
	}
	return result
}

func gnnSemanticKey(signature string) string {
	signature = strings.ReplaceAll(signature, ".", "/")
	if arrow := strings.Index(signature, "->"); arrow >= 0 {
		class := signature[:arrow]
		if strings.HasPrefix(class, "L") && strings.HasSuffix(class, ";") {
			class = class[1 : len(class)-1]
		}
		return "L" + class + ";" + signature[arrow:]
	}
	return signature
}

func gnnHasBranch(method *types.SmaliMethod) bool {
	if len(method.Conditions) > 0 || len(method.Switches) > 0 {
		return true
	}
	for _, instruction := range method.Instructions {
		if strings.HasPrefix(instruction.Opcode, "if-") || strings.HasSuffix(instruction.Opcode, "-switch") {
			return true
		}
	}
	return false
}

func gnnDirectLicenseEvidence(method *types.SmaliMethod) string {
	verifiesSignature := false
	for _, invoke := range method.Invokes {
		class := strings.TrimSuffix(strings.TrimPrefix(gnnSemanticKey(invoke.Class), "L"), ";")
		if strings.HasPrefix(class, "com/google/android/vending/licensing/") &&
			(invoke.Method == "checkAccess" || invoke.Method == "verify" || invoke.Method == "processServerResponse") {
			return "android_licensing_api"
		}
		if class == "com/android/vending/licensing/ILicensingService" && invoke.Method == "checkLicense" {
			return "android_licensing_service"
		}
		verifiesSignature = verifiesSignature || class == "java/security/Signature" && invoke.Method == "verify"
	}
	for _, constant := range method.StringConsts {
		value := strings.ToUpper(constant.Value)
		if value == "INAPP_DATA_SIGNATURE" || value == "INAPP_PURCHASE_DATA" ||
			value == "LICENSED" || value == "NOT_LICENSED" ||
			strings.Contains(value, "COM.ANDROID.VENDING.LICENSING.ILICENSINGSERVICE") {
			if gnnHasBranch(method) || verifiesSignature {
				return "licensing_protocol_and_control_flow"
			}
		}
	}
	return ""
}
