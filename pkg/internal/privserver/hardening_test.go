package privserver

import (
	"strings"
	"testing"
)

func TestDiscoverRejectsEmptyTarget(t *testing.T) {
	if _, err := Discover("", DiscoverOptions{}); err == nil {
		t.Fatal("expected error for empty target")
	}
	if _, err := Discover("   ", DiscoverOptions{}); err == nil {
		t.Fatal("expected error for whitespace target")
	}
}

func TestDiscoverWrapsLoadError(t *testing.T) {
	_, err := Discover("/nonexistent/path/does/not/exist.apk", DiscoverOptions{})
	if err == nil {
		t.Fatal("expected error for missing target")
	}
	if !strings.Contains(err.Error(), "privserver:") {
		t.Fatalf("error should be namespaced, got %q", err.Error())
	}
}

func TestPlanValidate(t *testing.T) {
	valid := &Plan{Module: "LabServer", Transport: TransportProfile{Protocol: "tcp"}, Listen: ListenProfile{Port: 9339, AdminPort: 8765}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}

	cases := map[string]*Plan{
		"nil":            nil,
		"empty module":   {Transport: TransportProfile{Protocol: "tcp"}, Listen: ListenProfile{Port: 1, AdminPort: 2}},
		"bad port":       {Module: "M", Transport: TransportProfile{Protocol: "tcp"}, Listen: ListenProfile{Port: 0, AdminPort: 2}},
		"bad admin port": {Module: "M", Transport: TransportProfile{Protocol: "tcp"}, Listen: ListenProfile{Port: 1, AdminPort: 70000}},
		"same ports":     {Module: "M", Transport: TransportProfile{Protocol: "tcp"}, Listen: ListenProfile{Port: 9339, AdminPort: 9339}},
		"empty protocol": {Module: "M", Listen: ListenProfile{Port: 1, AdminPort: 2}},
	}
	for name, p := range cases {
		if err := p.Validate(); err == nil {
			t.Errorf("case %q: expected validation error", name)
		}
	}
}

func TestGenerateRejectsInvalidPlan(t *testing.T) {
	_, err := Generate(&Plan{Module: ""}, t.TempDir())
	if err == nil {
		t.Fatal("Generate should reject an invalid plan")
	}
}
