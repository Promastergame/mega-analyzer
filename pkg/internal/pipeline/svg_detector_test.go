package pipeline

import (
	"context"
	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
	"os"
	"path/filepath"
	"testing"
)

func TestSVGDetectorPipelineAndReportEvidence(t *testing.T) {
	p, err := NewPipeline(config.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("<svg>\n<animate onrepeat = \"ignored()\"/>\n</svg>")
	fa := p.processContent(context.Background(), FileJob{RelPath: "assets/logo.svg", Type: types.FileTypeResource, Size: int64(len(content))}, content)
	gateFileMatches(fa)
	for _, m := range fa.Matches {
		if m.Metadata["rule_id"] == "svg.active.event" {
			f := typedFindingFromMatch(m, "")
			if f.Severity != "high" || len(f.Locations) != 1 || f.Locations[0].Line != 2 || f.RuleID != "svg.active.event" {
				t.Fatalf("bad report evidence: %+v", f)
			}
			return
		}
	}
	t.Fatal("SVG detector did not run for a resource file")
}

func TestSVGBoundedReadVisible(t *testing.T) {
	p, err := NewPipeline(config.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "oversized.svg")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate((8 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	fa := p.processFile(context.Background(), FileJob{Path: path, RelPath: "assets/oversized.svg", Type: types.FileTypeResource, Size: (8 << 20) + 1})
	if fa == nil || fa.ParseError == "" || len(fa.Matches) != 1 {
		t.Fatalf("skipped content lost: %+v", fa)
	}
}
