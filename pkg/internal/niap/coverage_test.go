package niap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUndecodedDEXCannotPassOrFailCodeControls(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "classes.dex"), []byte("dex\n035\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := AnalyzeWithRules(dir, []Rule{
		{ID: "positive", Type: "code", Choice: [][]string{{"SecureRandom"}}},
		{ID: "negative", Type: "code", Polarity: PolarityNegative, Choice: [][]string{{"TrustAll"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Passed != 0 || r.Failed != 0 || r.ManualReview != 2 || r.Verdict != "unknown" || r.Score != 0 {
		t.Fatalf("unread bytecode was evaluated as source: %#v", r)
	}
}
