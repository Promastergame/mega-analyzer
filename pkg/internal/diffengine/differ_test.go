package diffengine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChangeTypeString(t *testing.T) {
	cases := map[ChangeType]string{
		ChangeAdded:    "ADDED",
		ChangeRemoved:  "REMOVED",
		ChangeModified: "MODIFIED",
		ChangeType(99): "UNKNOWN",
	}
	for c, want := range cases {
		if got := c.String(); got != want {
			t.Errorf("ChangeType(%d).String() = %q, want %q", c, got, want)
		}
	}
}

func TestCategorize(t *testing.T) {
	cases := map[string]string{
		"smali/com/Foo.smali":   "code",
		"classes.dex":           "code",
		"Foo.java":              "code",
		"lib/arm64-v8a/libx.so": "native",
		"foo.dll":               "native",
		"foo.exe":               "native",
		"AndroidManifest.xml":   "manifest",
		"META-INF/CERT.MF":      "manifest",
		"res/strings.xml":       "config",
		"build.json":            "config",
		"a.properties":          "config",
		"icon.png":              "resource",
		"media/clip.mp4":        "resource",
	}
	for path, want := range cases {
		if got := categorize(path); got != want {
			t.Errorf("categorize(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestNewDifferDefaults(t *testing.T) {
	d := NewDiffer()
	if d == nil {
		t.Fatal("NewDiffer returned nil")
	}
	want := []string{".git", ".DS_Store", "Thumbs.db", "__MACOSX"}
	if len(d.IgnorePatterns) != len(want) {
		t.Fatalf("ignore pattern count mismatch: got %d, want %d", len(d.IgnorePatterns), len(want))
	}
	for i, p := range want {
		if d.IgnorePatterns[i] != p {
			t.Errorf("IgnorePatterns[%d] = %q, want %q", i, d.IgnorePatterns[i], p)
		}
	}
}

// makeTree writes the supplied path→content map under root.
func makeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
}

func TestCompareDetectsAddedRemovedModified(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")

	makeTree(t, a, map[string]string{
		"smali/Foo.smali":     "iget-object v0, p0",
		"AndroidManifest.xml": "<manifest/>",
		"removed.txt":         "byebye",
	})
	makeTree(t, b, map[string]string{
		"smali/Foo.smali":     "iget-object v0, p0\n# patched",
		"AndroidManifest.xml": "<manifest/>",
		"new/added.so":        "elfdata",
	})

	d := NewDiffer()
	r, err := d.Compare(a, b)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}

	wantStatus := map[string]ChangeType{
		"smali/Foo.smali": ChangeModified,
		"removed.txt":     ChangeRemoved,
		"new/added.so":    ChangeAdded,
	}
	got := map[string]ChangeType{}
	for _, fd := range r.Files {
		got[fd.Path] = fd.Change
	}
	for path, want := range wantStatus {
		if got[path] != want {
			t.Errorf("%s: got %s, want %s", path, got[path], want)
		}
	}
	if r.Summary.Added != 1 || r.Summary.Removed != 1 || r.Summary.Modified != 1 {
		t.Errorf("summary mismatch: %+v", r.Summary)
	}
	if r.Summary.TotalFiles != 4 || r.Summary.Unchanged != 1 {
		t.Errorf("summary must count the union of paths: %+v", r.Summary)
	}
	if r.Summary.NativeChanges != 1 {
		t.Errorf("native changes = %d, want 1", r.Summary.NativeChanges)
	}
	if r.Summary.CodeChanges != 1 {
		t.Errorf("code changes = %d, want 1", r.Summary.CodeChanges)
	}
}

func TestCompareIdenticalTrees(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	makeTree(t, a, map[string]string{"x.txt": "data", "sub/y.txt": "data"})
	makeTree(t, b, map[string]string{"x.txt": "data", "sub/y.txt": "data"})

	r, err := NewDiffer().Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Files) != 0 {
		t.Errorf("expected zero diffs, got %d", len(r.Files))
	}
	if r.Summary.Unchanged != 2 {
		t.Errorf("unchanged = %d, want 2", r.Summary.Unchanged)
	}
}

func TestCompareIgnorePatterns(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	makeTree(t, a, map[string]string{
		"file.txt":          "x",
		".git/HEAD":         "ignored",
		"__MACOSX/note.txt": "ignored",
	})
	makeTree(t, b, map[string]string{
		"file.txt":          "x",
		".git/HEAD":         "different",
		"__MACOSX/note.txt": "different",
	})

	r, err := NewDiffer().Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range r.Files {
		if strings.HasPrefix(fd.Path, ".git/") || strings.HasPrefix(fd.Path, "__MACOSX/") {
			t.Errorf("ignored path leaked into diff: %s", fd.Path)
		}
	}
}

func TestCompareMissingDirectoryReturnsError(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	makeTree(t, a, map[string]string{"x.txt": "data"})
	// Note: 'b' does not exist.

	d := NewDiffer()
	r, err := d.Compare(a, b)
	if err == nil || r != nil {
		t.Fatalf("missing input must not be reported as deleted files: report=%+v err=%v", r, err)
	}
}

func TestCompareDisjointTrees(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	makeTree(t, a, map[string]string{"old.txt": "old"})
	makeTree(t, b, map[string]string{"new.txt": "new"})
	r, err := NewDiffer().Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.TotalFiles != 2 || r.Summary.Added != 1 || r.Summary.Removed != 1 || r.Summary.Unchanged != 0 {
		t.Fatalf("incorrect disjoint summary: %+v", r.Summary)
	}
}

func TestCompareRejectsFileAsTree(t *testing.T) {
	dir := t.TempDir()
	makeTree(t, dir, map[string]string{"file.txt": "content"})
	if r, err := NewDiffer().Compare(filepath.Join(dir, "file.txt"), dir); err == nil || r != nil {
		t.Fatalf("a file is not a directory tree: report=%+v err=%v", r, err)
	}
}

func TestRenderMarkdown(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	makeTree(t, a, map[string]string{"only_a.smali": "old"})
	makeTree(t, b, map[string]string{"only_b.so": "new"})

	r, err := NewDiffer().Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	md := r.RenderMarkdown()
	must := []string{
		"Binary Diff Report",
		"Total files",
		"Added",
		"Removed",
		"only_a.smali",
		"only_b.so",
		"➕", "➖",
	}
	for _, w := range must {
		if !strings.Contains(md, w) {
			t.Errorf("rendered markdown missing %q\n%s", w, md)
		}
	}
}

func TestRenderMarkdownEmpty(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	makeTree(t, a, map[string]string{"x.txt": "same"})
	makeTree(t, b, map[string]string{"x.txt": "same"})

	r, err := NewDiffer().Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	md := r.RenderMarkdown()
	if strings.Contains(md, "## Changed Files") {
		t.Errorf("empty diff should not render Changed Files section, got: %s", md)
	}
}

func TestHashFileMissingReturnsError(t *testing.T) {
	if _, err := hashFile(filepath.Join(t.TempDir(), "nonexistent")); err == nil {
		t.Error("hashFile should fail on missing path")
	}
}
