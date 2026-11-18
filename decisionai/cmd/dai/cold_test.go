package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"decisionai/s1"
)

// TestColdRequest times the first (uncached) and warm calls on a request file:
// DAI_COLD=/path/request.json go test [-tags nim] ./cmd/dai -run ColdRequest -v
func TestColdRequest(t *testing.T) {
	path := os.Getenv("DAI_COLD")
	if path == "" {
		t.Skip("set DAI_COLD=request.json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	os.Chdir("../..")
	t0 := time.Now()
	eng, err := buildEngine("s1", "", "", "", 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("load %v", time.Since(t0))
	for i := 0; i < 3; i++ {
		var r s1.Request
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		t1 := time.Now()
		if _, err := eng.Decide(r); err != nil {
			t.Fatal(err)
		}
		t.Logf("call %d %v", i, time.Since(t1))
	}
}
