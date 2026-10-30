package dataflow

import (
	"context"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestBackwardSliceBuildsEvidencePath(t *testing.T) {
	program := NewProgram(DefaultConfig())
	program.AddClass("Example.smali", &types.SmaliClass{
		Name: "com.example.Example",
		Methods: []types.SmaliMethod{{
			Name: "run", ReturnType: "V", LineStart: 10,
			Body: []string{
				"invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;",
				"move-result-object v0",
				"invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
				"move-result-object v2",
				"move-object v3, v2",
				"invoke-virtual {v4, v3}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
			},
		}},
	})
	result := program.Analyze(context.Background())
	if len(result.Findings) != 1 {
		t.Fatalf("findings=%d: %+v", len(result.Findings), result.Findings)
	}
	finding := result.Findings[0]
	if finding.Category != "command_injection" || len(finding.Path) < 3 {
		t.Fatalf("unexpected finding: %+v", finding)
	}
	if finding.Path[0].Type != "source" || finding.Path[len(finding.Path)-1].Type != "sink" {
		t.Fatalf("bad path: %+v", finding.Path)
	}
}

func TestMoveExceptionIsNotSource(t *testing.T) {
	program := NewProgram(DefaultConfig())
	program.AddClass("Example.smali", &types.SmaliClass{
		Name: "com.example.Example",
		Methods: []types.SmaliMethod{{
			Name: "run", ReturnType: "V",
			Body: []string{
				"move-exception v0",
				"invoke-virtual {v1, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
			},
		}},
	})
	if result := program.Analyze(context.Background()); len(result.Findings) != 0 {
		t.Fatalf("move-exception created false source: %+v", result.Findings)
	}
}

func TestBackwardSliceTracksArrayIndex(t *testing.T) {
	program := NewProgram(DefaultConfig())
	program.AddClass("Example.smali", &types.SmaliClass{
		Name: "com.example.Example",
		Methods: []types.SmaliMethod{{
			Name: "run", ReturnType: "V",
			Body: []string{
				"invoke-virtual {p0, v9}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
				"move-result-object v0",
				"const/4 v1, 0x0",
				"const/4 v2, 0x1",
				"aput-object v0, v5, v1",
				"const-string v3, \"safe\"",
				"aput-object v3, v5, v2",
				"aget-object v4, v5, v1",
				"invoke-virtual {v6, v4}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
			},
		}},
	})
	if result := program.Analyze(context.Background()); len(result.Findings) != 1 {
		t.Fatalf("indexed array flow missed: %+v", result.Findings)
	}
}
