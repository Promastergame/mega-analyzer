package cicdaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeHighSignalWorkflowPaths(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, ".github", "workflows")
	os.MkdirAll(p, 0755)
	w := `name: dangerous
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
      - uses: vendor/action@main
`
	os.WriteFile(filepath.Join(p, "ci.yml"), []byte(w), 0644)
	r, e := Analyze(d)
	if e != nil {
		t.Fatal(e)
	}
	want := map[string]bool{"CICD-GHA-001": false, "CICD-GHA-002": false, "CICD-GHA-003": false, "CICD-PPE-001": false}
	for _, x := range r.Issues {
		if _, ok := want[x.ID]; ok {
			want[x.ID] = true
		}
	}
	for id, ok := range want {
		if !ok {
			t.Errorf("missing %s: %+v", id, r.Issues)
		}
	}
}
func TestSafeEnvBindingDoesNotTriggerShellInjection(t *testing.T) {
	x := scanWorkflow("safe.yml", `on: pull_request
jobs:
  x:
    env:
      TITLE: ${{ github.event.pull_request.title }}
    steps:
      - run: printf '%s' "$TITLE"
`)
	for _, i := range x {
		if i.ID == "CICD-GHA-001" {
			t.Fatalf("false positive: %+v", i)
		}
	}
}
