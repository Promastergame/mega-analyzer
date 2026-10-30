package report

import (
	"mega-analyzer/pkg/internal/types"
	"os"
	"testing"
)

func TestGenerateFullHTML(t *testing.T) {
	res := &types.AnalysisResult{}
	r := NewHTMLReporter(res).WithArtifacts(&ArtifactsView{
		Summary: ArtifactsSummary{Total: 10},
	})
	os.MkdirAll("../../../test_out", 0755)
	if err := r.Generate("../../../test_out"); err != nil {
		t.Fatal(err)
	}
}
