package shared

import (
	"fmt"
	"strings"
)

// ReconstructStubHeader rebuilds a minimal but VALID smali method header for
// whole-body stubs when the original `.method` line was not captured in
// MethodInfo.MethodHeader. The parameter list is taken from FullSignature and
// never guessed as empty: a stub header that drops the descriptor produces
// invalid smali for any method with parameters (apktool/baksmali fail at
// rebuild time).
func ReconstructStubHeader(mi *MethodInfo) string {
	if mi == nil {
		return ""
	}
	access := "protected"
	if mi.IsPublic {
		access = "public"
	} else if mi.IsPrivate {
		access = "private"
	}
	if mi.IsStatic {
		access += " static"
	}
	if mi.IsFinal {
		access += " final"
	}

	open := strings.Index(mi.FullSignature, "(")
	closeIdx := strings.LastIndex(mi.FullSignature, ")")
	params := ""
	if open >= 0 && closeIdx > open {
		params = mi.FullSignature[open+1 : closeIdx]
	}
	return fmt.Sprintf(".method %s %s(%s)%s", access, mi.Name, params, mi.ReturnType)
}

// ShortClassName returns a class tail that is easier to read in reports.
func ShortClassName(fullName string) string {
	fullName = strings.TrimPrefix(fullName, "L")
	fullName = strings.TrimSuffix(fullName, ";")
	parts := strings.Split(fullName, "/")
	if len(parts) == 0 {
		return fullName
	}
	return parts[len(parts)-1]
}

// ShortFilePath truncates very long file paths for terminal output.
func ShortFilePath(path string) string {
	const maxLen = 60
	if len(path) <= maxLen {
		return path
	}
	return "..." + path[len(path)-(maxLen-3):]
}

// MethodSignatureShort renders a short human-readable signature.
func MethodSignatureShort(mi *MethodInfo) string {
	if mi == nil {
		return ""
	}
	ret := mi.ReturnType
	switch mi.ReturnType {
	case "Z":
		ret = "boolean"
	case "V":
		ret = "void"
	case "I":
		ret = "int"
	case "J":
		ret = "long"
	default:
		ret = strings.TrimPrefix(ret, "Ljava/lang/")
		ret = strings.TrimSuffix(ret, ";")
	}
	return mi.Name + "() → " + ret
}

// IsUpperCaseStart reports whether the string starts with an upper-case ASCII letter.
func IsUpperCaseStart(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	return c >= 'A' && c <= 'Z'
}
