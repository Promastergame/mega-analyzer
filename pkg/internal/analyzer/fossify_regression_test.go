package analyzer

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestFossifyDecisionNames(t *testing.T) {
	finder := NewDecisionPointFinder()
	for _, name := range []string{"isProjected", "isProperAndroidRoot", "isProperOTGFolder", "isProvidingHint", "isFakeDragging"} {
		method := &types.SmaliMethod{Name: name, ReturnType: "Z", ReturnsBoolean: true}
		if got := finder.FindDecisionPoints(method, "app.UI", "UI.smali"); len(got) != 0 {
			t.Errorf("%s produced decisions: %+v", name, got)
		}
		if f := extractNameContainsPremium(method, nil, &extractorContext{nameLower: lowerName(name)}); f != nil {
			t.Errorf("%s produced premium feature", name)
		}
	}
	for _, name := range []string{"isPro", "isProUser", "isPremium", "isFakeApp"} {
		method := &types.SmaliMethod{Name: name, ReturnType: "Z", ReturnsBoolean: true}
		if got := finder.FindDecisionPoints(method, "app.Security", "Security.smali"); len(got) == 0 {
			t.Errorf("real predicate %s was lost", name)
		}
	}
}

func lowerName(name string) string {
	b := []byte(name)
	for i, v := range b {
		if v >= 'A' && v <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
