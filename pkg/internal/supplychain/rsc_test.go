package supplychain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectReact2ShellExactRanges(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "package.json"), []byte(`{"dependencies":{"react-server-dom-webpack":"19.1.1","react-server-dom-parcel":"19.2.1"}}`), 0644)
	x, e := DetectReactServerComponents(d)
	if e != nil {
		t.Fatal(e)
	}
	if len(x) != 1 || x[0].Package != "react-server-dom-webpack" {
		t.Fatalf("wrong findings: %+v", x)
	}
}
func TestRSCVersionPredicate(t *testing.T) {
	for _, v := range []string{"19.0.0", "19.1.0", "19.1.1", "19.2.0"} {
		if !vulnerableRSC(v) {
			t.Errorf("expected vulnerable %s", v)
		}
	}
	for _, v := range []string{"19.0.1", "19.1.2", "19.2.1", "18.3.0"} {
		if vulnerableRSC(v) {
			t.Errorf("expected patched %s", v)
		}
	}
}
