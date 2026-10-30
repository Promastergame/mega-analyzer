package dataflow

import (
	"context"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// Taint must cross a declared native (JNI) method instead of dying at the
// call: the native body is opaque, so the bridge propagates conservatively
// and marks the step jni_bridge.
func TestProgramTaintCrossesNativeBridge(t *testing.T) {
	program := NewProgram(DefaultConfig())
	program.AddClass("smali/app/Bridge.smali", &types.SmaliClass{
		Name: "Lapp/Bridge;",
		Methods: []types.SmaliMethod{{
			Name: "scrub", Params: "Ljava/lang/String;", ReturnType: "Ljava/lang/String;",
			Access: types.AccessPublic | types.AccessStatic | types.AccessNative,
		}},
	})
	addMethod(program, "Lapp/Flow;", "run", "Landroid/content/Intent;Ljava/lang/String;", "V", true,
		".method public static run(Landroid/content/Intent;Ljava/lang/String;)V",
		"invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0",
		"invoke-static {v0}, Lapp/Bridge;->scrub(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v1",
		"invoke-virtual {v9, v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if len(result.Findings) == 0 {
		t.Fatalf("taint did not cross the native bridge: %+v", result.Stats)
	}
	bridged := false
	for _, step := range result.Findings[0].Path {
		if step.Type == "jni_bridge" {
			bridged = true
		}
	}
	if !bridged {
		t.Fatalf("flow has no jni_bridge step: %+v", result.Findings[0].Path)
	}
}
