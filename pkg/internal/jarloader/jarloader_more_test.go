package jarloader

import (
	"testing"
)

func TestSemverString(t *testing.T) {
	v := semver{major: 1, minor: 2, patch: 3}
	if got := v.String(); got != "1.2.3" {
		t.Errorf("semver.String() = %q, want 1.2.3", got)
	}
	v4 := semver{major: 2, minor: 9, patch: 9, micro: 2}
	if got := v4.String(); got != "2.9.9.2" {
		t.Errorf("semver.String() = %q, want 2.9.9.2", got)
	}
}

func TestSemverLt(t *testing.T) {
	v := semver{major: 1, minor: 5, patch: 0}
	if !v.lt(2, 0, 0, 0) {
		t.Error("1.5.0 should be lt 2.0.0")
	}
	if !v.lt(1, 6, 0, 0) {
		t.Error("1.5.0 should be lt 1.6.0")
	}
	if v.lt(1, 4, 0, 0) {
		t.Error("1.5.0 should not be lt 1.4.0")
	}
	if v.lt(1, 5, 0, 0) {
		t.Error("1.5.0 should not be lt 1.5.0 (equal)")
	}
	if !v.lt(1, 5, 0, 1) {
		t.Error("1.5.0 should be lt 1.5.0.1 (missing micro sorts first)")
	}
}

func TestSemverGe(t *testing.T) {
	v := semver{major: 2, minor: 0, patch: 0}
	if !v.ge(2, 0, 0, 0) {
		t.Error("2.0.0 should be ge 2.0.0")
	}
	if !v.ge(1, 9, 9, 9) {
		t.Error("2.0.0 should be ge 1.9.9.9")
	}
	if v.ge(3, 0, 0, 0) {
		t.Error("2.0.0 should not be ge 3.0.0")
	}
}

func TestExtractVersion(t *testing.T) {
	cases := []struct {
		in        string
		wantMajor int
		wantMinor int
		wantFound bool
	}{
		{"log4j-2.14.1.jar", 2, 14, true},
		{"commons-lang3-3.12.jar", 3, 12, true},
		{"nover.jar", 0, 0, false},
		{"spring-core-5.3.20.jar", 5, 3, true},
	}
	for _, c := range cases {
		v, ok := extractVersion(c.in)
		if ok != c.wantFound {
			t.Errorf("extractVersion(%q) found=%v, want %v", c.in, ok, c.wantFound)
			continue
		}
		if ok {
			if v.major != c.wantMajor || v.minor != c.wantMinor {
				t.Errorf("extractVersion(%q) = %v, want major=%d minor=%d",
					c.in, v, c.wantMajor, c.wantMinor)
			}
		}
	}
}
