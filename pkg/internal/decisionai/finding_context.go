package decisionai

import (
	"strings"

	"mega-analyzer/pkg/internal/finding"
)

func findingLibraryHint(item finding.Finding) (string, bool) {
	paths := make(map[string]struct{})
	for _, location := range item.Locations {
		if location.File != "" {
			paths[location.File] = struct{}{}
		}
	}
	for _, evidence := range item.Evidence {
		if evidence.Location.File != "" {
			paths[evidence.Location.File] = struct{}{}
		}
	}
	for _, step := range item.Steps {
		if step.File != "" {
			paths[step.File] = struct{}{}
		}
	}
	hints := make(map[string]bool)
	allLibrary := len(paths) > 0
	for path := range paths {
		hint := sdkNamespaceHint(path)
		if hint == "" {
			allLibrary = false
			continue
		}
		hints[hint] = true
	}
	var ordered []string
	// Fixed order makes request hashing and cached advisory reuse deterministic.
	for _, name := range []string{"Android Support", "AndroidX", "Kotlin", "Google Play Services", "Firebase", "BeanShell", "iApp runtime", "LuaJava", "Android GIF"} {
		if hints[name] {
			ordered = append(ordered, name)
		}
	}
	return strings.Join(ordered, ", "), allLibrary
}

func sdkNamespaceHint(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	if index := strings.Index(path, "::L"); index >= 0 {
		path = strings.TrimSuffix(path[index+3:], ";")
	} else {
		if !strings.HasSuffix(path, ".smali") && !strings.HasSuffix(path, ".java") {
			return ""
		}
		parts := strings.Split(path, "/")
		for index, part := range parts {
			if part == "smali" || validMultidexRoot(part) {
				path = strings.Join(parts[index+1:], "/")
				break
			}
		}
	}
	for _, sdk := range []struct{ prefix, name string }{
		{"android/support/", "Android Support"}, {"androidx/", "AndroidX"},
		{"kotlin/", "Kotlin"}, {"kotlinx/", "Kotlin"},
		{"com/google/android/gms/", "Google Play Services"}, {"com/google/firebase/", "Firebase"},
		{"bsh/", "BeanShell"}, {"com/iapp/app/", "iApp runtime"},
		{"org/keplerproject/luajava/", "LuaJava"}, {"pl/droidsonroids/gif/", "Android GIF"},
	} {
		if strings.HasPrefix(path, sdk.prefix) {
			return sdk.name
		}
	}
	return ""
}

func validMultidexRoot(value string) bool {
	value, found := strings.CutPrefix(value, "smali_classes")
	if !found || value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func findingStaticSink(item finding.Finding) string {
	if item.Kind != finding.KindVulnerability && item.Kind != finding.KindMalware {
		return ""
	}
	if item.Explanation == nil || item.Explanation.Status != "static_flow" {
		return ""
	}
	hasSource := false
	for _, step := range item.Steps {
		if step.Type == "source" && step.Method != "" {
			hasSource = true
		}
		if hasSource && step.Type == "sink" && step.Method != "" {
			return step.Method
		}
	}
	return ""
}
