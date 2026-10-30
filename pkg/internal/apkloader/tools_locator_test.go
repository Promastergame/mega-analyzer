package apkloader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJarInvocation(t *testing.T) {
	a := jarInvocation("/x/mega-smali-tools.jar", "com.android.tools.smali.smali.Main")
	if strings.Join(a, " ") != "-cp /x/mega-smali-tools.jar com.android.tools.smali.smali.Main" {
		t.Fatalf("combined jar: %v", a)
	}
	b := jarInvocation("/x/smali.jar", "com.android.tools.smali.smali.Main")
	if len(b) != 2 || b[0] != "-jar" {
		t.Fatalf("plain jar: %v", b)
	}
}

func TestExplicitSmaliJarEnvWins(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "my-smali.jar")
	if err := os.WriteFile(jar, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEGA_SMALI_JAR", jar)
	p, src := LocateSmaliJar()
	if p != jar || src != ToolEnv {
		t.Fatalf("got %q %v", p, src)
	}
}

func TestEmbeddedToolsExtract(t *testing.T) {
	if len(embeddedSmaliTools) == 0 {
		t.Skip("built with noembed")
	}
	t.Setenv("MEGA_TOOLS_DIR", t.TempDir())
	t.Setenv("MEGA_SMALI_JAR", "")
	t.Setenv("SMALI_JAR", "")
	p, src := LocateBaksmaliJar()
	if p == "" || (src != ToolEmbedded && src != ToolLocal) {
		t.Fatalf("no jar: %q %v", p, src)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
}
