package buildinfo

import "testing"

func TestConfigureBuildIdentity(t *testing.T) {
	oldV, oldD, oldC := Version, BuildDate, CommitHash
	t.Cleanup(func() { Version, BuildDate, CommitHash = oldV, oldD, oldC })
	for _, version := range []string{"v1.2.3", "1.2.3", "v1.2.3-beta.1"} {
		Configure(version, "2026-10-23", "abc123")
		want := version
		if version[0] == 'v' {
			want = version[1:]
		}
		if Version != want || BuildDate != "2026-10-23" || CommitHash != "abc123" {
			t.Fatalf("identity = %q %q %q", Version, BuildDate, CommitHash)
		}
	}
	Configure("", "explicit-date", "explicit-commit")
	if Version != "1.2.3-beta.1" || BuildDate != "explicit-date" || CommitHash != "explicit-commit" {
		t.Fatal("empty version changed identity or explicit metadata lost")
	}
	Configure("", "", "")
	if Version != "1.2.3-beta.1" {
		t.Fatal("empty version must preserve configured version")
	}
}
