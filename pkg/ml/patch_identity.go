package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// patchLookupKey is the canonical in-memory identity used by generators and
// exporters. The descriptor is mandatory for correctness with overloaded
// Dalvik methods; legacy callers with no descriptor still get a stable key.
func patchLookupKey(filePath, methodName, methodSignature string) string {
	path := filepath.ToSlash(filepath.Clean(strings.TrimSpace(filePath)))
	name := strings.TrimSpace(methodName)
	desc := canonicalMethodDescriptor(name, methodSignature)
	return path + "::" + name + "::" + desc
}

// PatchLookupKey identifies a method consistently across CLI filtering and
// exporters, including its Dalvik descriptor so overloads remain distinct.
func PatchLookupKey(filePath, methodName, methodSignature string) string {
	return patchLookupKey(filePath, methodName, methodSignature)
}

func legacyPatchLookupKey(filePath, methodName string) string {
	return patchLookupKey(filePath, methodName, "")
}

func canonicalMethodDescriptor(methodName, signature string) string {
	sig := strings.TrimSpace(signature)
	if i := strings.IndexByte(sig, '('); i >= 0 {
		return sig[i:]
	}
	if sig != "" {
		return sig
	}
	return "<legacy:" + strings.TrimSpace(methodName) + ">"
}

func stablePatchID(filePath, methodName, methodSignature, originalHash string) string {
	// Hash drift is validated separately. Keeping IDs bound to the method
	// identity lets IDE queue/history state survive analyzer reruns.
	_ = originalHash
	identity := patchLookupKey(filePath, methodName, methodSignature)
	sum := sha256.Sum256([]byte(identity))
	return "patch_" + hex.EncodeToString(sum[:12])
}
