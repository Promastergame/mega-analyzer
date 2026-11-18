package permissionmap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUndecodedDEXDoesNotMakePermissionsUnused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "classes.dex"), []byte("dex\n035\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(dir, []string{"android.permission.CAMERA"})
	if err != nil {
		t.Fatal(err)
	}
	if r.UnusedCount != 0 || r.UnknownCount != 1 || r.Score != 0 || r.UnsupportedCode != 1 || r.Verdict != "unknown" {
		t.Fatalf("unread DEX created an unused-permission finding: %#v", r)
	}
}
