package dataflow

import (
	"context"
	"testing"
)

func TestUriComponentsPreserveOrigin(t *testing.T) {
	for _, external := range []bool{false, true} {
		program := NewProgram(DefaultConfig())
		body := []string{".method public static open(Landroid/content/Intent;)V"}
		if external {
			body = append(body, "invoke-virtual {p0}, Landroid/content/Intent;->getData()Landroid/net/Uri;", "move-result-object v0")
		} else {
			body = append(body, "const-string v1, \"file:///sdcard/Pictures/photo.jpg\"", "invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;", "move-result-object v0")
		}
		body = append(body, "invoke-virtual {v0}, Landroid/net/Uri;->getPath()Ljava/lang/String;", "move-result-object v1", "new-instance v2, Ljava/io/File;", "invoke-direct {v2, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V", "new-instance v3, Ljava/io/FileInputStream;", "invoke-direct {v3, v2}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V", "return-void", ".end method")
		addMethod(program, "Lapp/Viewer;", "open", "Landroid/content/Intent;", "V", true, body...)
		result := program.Analyze(context.Background())
		foundIO := false
		for _, f := range result.Findings {
			if methodMatches("Ljava/io/FileInputStream;-><init>", f.Sink) {
				foundIO = true
			}
		}
		if foundIO != external {
			t.Errorf("external=%v: I/O findings=%v, paths=%+v", external, foundIO, result.Findings)
		}
		if !external && len(result.Findings) != 0 {
			t.Errorf("app-owned URI was seeded as attacker input: %+v", result.Findings)
		}
	}
}
