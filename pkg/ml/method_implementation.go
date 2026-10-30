package ml

import (
	"fmt"
	"sort"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// methodDeclarationParts examines only access flags, never a method name,
// string literal or comment containing words such as "native".
func methodDeclarationParts(line string) (string, []string, bool) {
	fields := strings.Fields(smaliCodeLine(line))
	if len(fields) < 2 || fields[0] != ".method" {
		return "", nil, false
	}
	return fields[len(fields)-1], fields[1 : len(fields)-1], true
}

func nonConcreteMethodReason(mi *shared.MethodInfo) string {
	if mi == nil {
		return "missing_method"
	}
	if mi.IsAbstract {
		return "abstract_method_has_no_smali_implementation"
	}
	check := func(line string) string {
		_, flags, ok := methodDeclarationParts(line)
		if !ok {
			return ""
		}
		for _, flag := range flags {
			switch flag {
			case "native":
				return "native_method_requires_native_analysis"
			case "abstract":
				return "abstract_method_has_no_smali_implementation"
			}
		}
		return ""
	}
	if reason := check(mi.MethodHeader); reason != "" {
		return reason
	}
	var state smaliNonCodeState
	for _, raw := range mi.RawBody {
		line := smaliCodeLine(raw)
		if state.skip(line) {
			continue
		}
		if reason := check(line); reason != "" {
			return reason
		}
	}
	return ""
}

func hasConcreteMethodBody(body []string) bool {
	var state smaliNonCodeState
	for _, raw := range body {
		line := smaliCodeLine(raw)
		if state.skip(line) {
			continue
		}
		if _, ok := insnLine(line); ok {
			return true
		}
	}
	return false
}

// verifyMethodAccessFlags prevents an otherwise matching descriptor from
// silently changing static dispatch, visibility or synchronization semantics.
// Full-method patches are required by the planner's strict Smali validator;
// this helper also supports the older fragment-only Verify API.
func verifyMethodAccessFlags(mi *shared.MethodInfo, patched string) error {
	key := func(flags []string) string {
		copyFlags := append([]string(nil), flags...)
		sort.Strings(copyFlags)
		return strings.Join(copyFlags, " ")
	}
	_, flags, known := methodDeclarationParts(mi.MethodHeader)
	want := key(flags)
	var originalState smaliNonCodeState
	for _, raw := range mi.RawBody {
		line := smaliCodeLine(raw)
		if originalState.skip(line) {
			continue
		}
		if _, bodyFlags, ok := methodDeclarationParts(line); ok {
			bodyKey := key(bodyFlags)
			if known && bodyKey != want {
				return fmt.Errorf("inconsistent original method access flags")
			}
			want, known = bodyKey, true
		}
	}
	declarations := 0
	var patchedState smaliNonCodeState
	for _, raw := range strings.Split(patched, "\n") {
		line := smaliCodeLine(raw)
		if patchedState.skip(line) {
			continue
		}
		if _, gotFlags, ok := methodDeclarationParts(line); ok {
			declarations++
			for _, flag := range gotFlags {
				if flag == "native" || flag == "abstract" {
					return fmt.Errorf("generated method has no concrete implementation")
				}
			}
			if known && key(gotFlags) != want {
				return fmt.Errorf("generated method access flags changed")
			}
		}
	}
	if declarations > 1 {
		return fmt.Errorf("patch contains multiple method declarations")
	}
	return nil
}
