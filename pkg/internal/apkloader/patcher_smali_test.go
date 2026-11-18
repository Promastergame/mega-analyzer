package apkloader

import (
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func TestSmaliRelPathForClass(t *testing.T) {
	sep := string(filepath.Separator)
	tests := []struct {
		class string
		want  string
		ok    bool
	}{
		{"Lcom/miniclip/plagueinc/PurchaseManager;", "com" + sep + "miniclip" + sep + "plagueinc" + sep + "PurchaseManager.smali", true},
		{"Landroid/app/Activity;", "android" + sep + "app" + sep + "Activity.smali", true},
		{"LFoo$Inner;", "Foo$Inner.smali", true},
		{"", "", false},
		{"L;", "", false},
		{"Lcom/../evil;", "", false},
	}
	for _, tc := range tests {
		got, ok := smaliRelPathForClass(tc.class)
		if ok != tc.ok || got != tc.want {
			t.Errorf("smaliRelPathForClass(%q) = (%q, %v), want (%q, %v)", tc.class, got, ok, tc.want, tc.ok)
		}
	}
}

func TestHasSmaliFilesAndFindDEXFiles(t *testing.T) {
	root := testutil.TempDir(t)
	if HasSmaliFiles(root) {
		t.Fatal("empty dir reports smali files")
	}
	if len(FindDEXFiles(root)) != 0 {
		t.Fatal("empty dir reports dex files")
	}
	sub := filepath.Join(root, "smali", "com", "x")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "A.smali"), []byte(".class Lx;"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "classes2.dex"), []byte("dex\n035"), 0644); err != nil {
		t.Fatal(err)
	}
	if !HasSmaliFiles(root) {
		t.Fatal("dir with A.smali not detected")
	}
	dex := FindDEXFiles(root)
	if len(dex) != 1 || filepath.Base(dex[0]) != "classes2.dex" {
		t.Fatalf("FindDEXFiles = %v, want [classes2.dex]", dex)
	}
}

func TestMaterializeSmaliTreeNoDEX(t *testing.T) {
	n, err := MaterializeSmaliTree(t.Context(), nil, filepath.Join(testutil.TempDir(t), "out"))
	if err != nil || n != 0 {
		t.Fatalf("empty input = (%d, %v), want (0, nil)", n, err)
	}
}

func TestPlanMaterializeClassSkip(t *testing.T) {
	skipLibs := func(rel string) bool {
		return len(rel) >= 11 && rel[:11] == "com/unity3d"
	}
	tests := []struct {
		class   string
		wantRel string
		wantOK  bool
	}{
		{"Lcom/kiloo/subwaysurf/Runner;", "com" + string(filepath.Separator) + "kiloo" + string(filepath.Separator) + "subwaysurf" + string(filepath.Separator) + "Runner.smali", true},
		{"Lcom/unity3d/ads/Ad;", "", false},
		{"", "", false},
		{"L;", "", false},
	}
	for _, tc := range tests {
		rel, ok := planMaterializeClass(tc.class, skipLibs)
		if ok != tc.wantOK || rel != tc.wantRel {
			t.Errorf("planMaterializeClass(%q) = (%q, %v), want (%q, %v)", tc.class, rel, ok, tc.wantRel, tc.wantOK)
		}
	}
	// Nil skip writes everything valid.
	if rel, ok := planMaterializeClass("Lcom/unity3d/ads/Ad;", nil); !ok || rel == "" {
		t.Fatalf("nil skip must not filter, got (%q, %v)", rel, ok)
	}
}

func TestPruneSkippedSmali(t *testing.T) {
	root := testutil.TempDir(t)
	lib := filepath.Join(root, "com", "unity3d")
	app := filepath.Join(root, "com", "kiloo")
	if err := os.MkdirAll(lib, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(app, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lib, "Ad.smali"), []byte(".class Lx;"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Runner.smali"), []byte(".class Ly;"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	skipLibs := func(rel string) bool {
		return len(rel) >= 11 && rel[:11] == "com/unity3d"
	}
	if removed := PruneSkippedSmali(root, skipLibs); removed != 1 {
		t.Fatalf("PruneSkippedSmali removed %d, want 1", removed)
	}
	if _, err := os.Stat(filepath.Join(lib, "Ad.smali")); !os.IsNotExist(err) {
		t.Fatal("library smali must be pruned")
	}
	if _, err := os.Stat(filepath.Join(app, "Runner.smali")); err != nil {
		t.Fatal("app smali must survive pruning")
	}
	if _, err := os.Stat(filepath.Join(root, "notes.txt")); err != nil {
		t.Fatal("non-smali files must survive pruning")
	}
	if removed := PruneSkippedSmali(root, nil); removed != 0 {
		t.Fatalf("nil skip must prune nothing, removed %d", removed)
	}
}
