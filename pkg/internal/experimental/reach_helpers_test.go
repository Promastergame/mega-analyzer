package experimental

import (
	"path/filepath"
	"testing"
)

func TestExtractClassName(t *testing.T) {
	cases := map[string]string{
		".class public Lcom/foo/Bar;":      "Lcom/foo/Bar;",
		".class private Lcom/foo/Inner$1;": "Lcom/foo/Inner$1;",
		"no class here":                    "",
		".class public":                    "",
		".class public LMissingSemicolon":  "",
	}
	for in, want := range cases {
		if got := extractClassName(in); got != want {
			t.Errorf("extractClassName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassFromSmaliPath(t *testing.T) {
	cases := map[string]string{
		filepath.FromSlash("/tmp/decoded/smali/com/foo/Bar.smali"):    "Lcom/foo/Bar;",
		filepath.FromSlash("/tmp/decoded/smali_classes2/x/y/Z.smali"): "Lx/y/Z;",
		filepath.FromSlash("/tmp/no_match/here"):                      "",
		filepath.FromSlash("/tmp/empty"):                              "",
	}
	for in, want := range cases {
		if got := classFromSmaliPath(in); got != want {
			t.Errorf("classFromSmaliPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQualifySig(t *testing.T) {
	if got := qualifySig("Lfoo;", "bar()V"); got != "Lfoo;->bar()V" {
		t.Errorf("qualifySig owner+sig = %q", got)
	}
	if got := qualifySig("", "bar()V"); got != "bar()V" {
		t.Errorf("qualifySig empty owner = %q", got)
	}
}

func TestEnsureNodeCachesByKey(t *testing.T) {
	graph := make(map[string]*methodNode)
	a := ensureNode(graph, "sig", "Lfoo;", "/path/a.smali")
	b := ensureNode(graph, "sig", "Lother;", "/path/b.smali")
	if a != b {
		t.Errorf("ensureNode should return cached pointer for repeat key")
	}
	if a.Owner != "Lfoo;" {
		t.Errorf("first writer wins for Owner, got %q", a.Owner)
	}
	if len(graph) != 1 {
		t.Errorf("graph should have 1 entry, got %d", len(graph))
	}
}

func TestIsLikelyEntry(t *testing.T) {
	for _, sig := range []string{
		"Lfoo;->onCreate(Landroid/os/Bundle;)V",
		"Lfoo;->onStart()V",
		"Lfoo;->onClick(Landroid/view/View;)V",
		"Lfoo;->main([Ljava/lang/String;)V",
		"Lfoo;->run()V",
	} {
		if !isLikelyEntry(sig) {
			t.Errorf("isLikelyEntry(%q) should be true", sig)
		}
	}
	for _, sig := range []string{
		"Lfoo;->internalHelper()V",
		"Lfoo;->compute(I)I",
	} {
		if isLikelyEntry(sig) {
			t.Errorf("isLikelyEntry(%q) should be false", sig)
		}
	}
}

func TestDotToSmaliClass(t *testing.T) {
	if got := dotToSmaliClass("com.foo.Bar"); got != "Lcom/foo/Bar;" {
		t.Errorf("got %q", got)
	}
	if got := dotToSmaliClass(""); got != "" {
		t.Error("empty input must yield empty")
	}
	if got := dotToSmaliClass(".RelativeName"); got != "" {
		t.Error("relative names must be skipped")
	}
}

func TestScanExportedNames(t *testing.T) {
	xml := `
<manifest>
  <activity android:name="com.foo.Login" android:exported="true"/>
  <activity android:name="com.foo.Hidden"/>
  <service android:name="com.foo.SyncService">
    <intent-filter>
      <action android:name="android.intent.action.SYNC"/>
    </intent-filter>
  </service>
</manifest>`
	out := make(map[string]struct{})
	scanExportedNames(xml, out)

	if _, ok := out["Lcom/foo/Login;"]; !ok {
		t.Error("Login (exported=true) should be flagged")
	}
	if _, ok := out["Lcom/foo/Hidden;"]; ok {
		t.Error("Hidden component should NOT be exported")
	}
	if _, ok := out["Lcom/foo/SyncService;"]; !ok {
		t.Error("SyncService with intent-filter should be flagged")
	}
}

func TestSelectEntryPoints(t *testing.T) {
	graph := map[string]*methodNode{
		"a": {Sig: "a", IsEntry: true},
		"b": {Sig: "b"},
		"c": {Sig: "c", IsExport: true},
	}
	got := selectEntryPoints(graph)
	if len(got) != 2 {
		t.Fatalf("expected 2 entry points, got %d (%v)", len(got), got)
	}
	// Result is sorted.
	if got[0] >= got[1] {
		t.Errorf("entries not sorted: %v", got)
	}
}

func TestSelectEntryPointsFallbackToPublic(t *testing.T) {
	graph := map[string]*methodNode{
		"a": {Sig: "a", IsPublic: true},
		"b": {Sig: "b"},
	}
	got := selectEntryPoints(graph)
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("public fallback failed: %v", got)
	}
}

func TestBFSForward(t *testing.T) {
	graph := map[string]*methodNode{
		"entry":  {Sig: "entry", Edges: map[string]struct{}{"mid": {}}},
		"mid":    {Sig: "mid", Edges: map[string]struct{}{"leaf": {}}},
		"leaf":   {Sig: "leaf", Edges: map[string]struct{}{}},
		"unused": {Sig: "unused", Edges: map[string]struct{}{}},
	}
	seen := bfsForward(graph, []string{"entry"})
	if _, ok := seen["entry"]; !ok {
		t.Error("entry should be visited")
	}
	if _, ok := seen["mid"]; !ok {
		t.Error("mid should be visited")
	}
	if _, ok := seen["leaf"]; !ok {
		t.Error("leaf should be visited")
	}
	if _, ok := seen["unused"]; ok {
		t.Error("unused must not be visited")
	}

	// Duplicate entries should be deduped silently.
	seen2 := bfsForward(graph, []string{"entry", "entry", "leaf"})
	if len(seen2) != 3 {
		t.Errorf("dup entries should produce 3 visited, got %d", len(seen2))
	}

	// Missing node should not panic.
	bfsForward(graph, []string{"nope"})
}

func TestMinFloatHelper(t *testing.T) {
	if got := minFloat(1.5, 2.5); got != 1.5 {
		t.Errorf("got %v, want 1.5", got)
	}
	if got := minFloat(2.5, 1.5); got != 1.5 {
		t.Errorf("got %v, want 1.5", got)
	}
}

func TestLoadExportedComponentsMissing(t *testing.T) {
	got := loadExportedComponents(testTempDir(t))
	if len(got) != 0 {
		t.Errorf("missing manifest should yield empty, got %v", got)
	}
}
