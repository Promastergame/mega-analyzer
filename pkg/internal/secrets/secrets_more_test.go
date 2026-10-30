package secrets

import (
	"strings"
	"testing"
)

func TestMaskSecret_Empty(t *testing.T) {
	if got := MaskSecret(""); got != "" {
		t.Errorf("empty string: got %q", got)
	}
}

func TestMaskSecret_Short(t *testing.T) {
	got := MaskSecret("abc")
	if got != "***" {
		t.Errorf("short: got %q, want ***", got)
	}
}

func TestMaskSecret_Long(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	got := MaskSecret(secret)
	if got == secret {
		t.Error("long secret should be masked")
	}
	if strings.Count(got, "*") == 0 {
		t.Error("masked string should contain asterisks")
	}
}

func TestDetectProviders_AWSKey(t *testing.T) {
	content := "access_key = \"AKIAIOSFODNN7EXAMPLE\""
	findings := DetectProviders(content, "")
	_ = findings
}

func TestDetectProviders_Empty(t *testing.T) {
	findings := DetectProviders("no secrets here", "")
	_ = findings
}
