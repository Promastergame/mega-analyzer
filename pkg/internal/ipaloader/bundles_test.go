package ipaloader

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestFindMainBundleRequiresExactlyOneApp(t *testing.T) {
	ctx := context.Background()

	empty := t.TempDir()
	mkdir(t, filepath.Join(empty, "Payload"))
	if _, err := FindMainBundle(ctx, empty); err == nil {
		t.Fatal("Payload without .app bundles accepted")
	}

	two := t.TempDir()
	mkdir(t, filepath.Join(two, "Payload", "Free.app"))
	mkdir(t, filepath.Join(two, "Payload", "Paid.app"))
	if _, err := FindMainBundle(ctx, two); err == nil {
		t.Fatal("Payload with two .app bundles accepted")
	}

	one := t.TempDir()
	mkdir(t, filepath.Join(one, "Payload", "Main.app", "PlugIns", "Widget.app"))
	got, err := FindMainBundle(ctx, one)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "Main.app" {
		t.Fatalf("selected %q, want the direct Payload/Main.app (nested bundles are not apps)", got)
	}
}

func TestBundlePlistsPutsMainFirst(t *testing.T) {
	appDir := t.TempDir()
	mkdir(t, filepath.Join(appDir, "Frameworks", "SDK.framework"))
	write := func(p, data string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(appDir, "Info.plist"), "main")
	write(filepath.Join(appDir, "Frameworks", "SDK.framework", "Info.plist"), "sdk")

	paths, err := BundlePlists(context.Background(), appDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("got %d plists, want 2: %v", len(paths), paths)
	}
	if filepath.Dir(paths[0]) != appDir {
		t.Fatalf("first plist %q is not the main bundle Info.plist", paths[0])
	}
	if filepath.Base(filepath.Dir(paths[1])) != "SDK.framework" {
		t.Fatalf("second plist %q is not the embedded framework plist", paths[1])
	}
}

func TestBundlePlistsRejectsMissingMain(t *testing.T) {
	appDir := t.TempDir()
	mkdir(t, filepath.Join(appDir, "Frameworks", "SDK.framework"))
	if err := os.WriteFile(filepath.Join(appDir, "Frameworks", "SDK.framework", "Info.plist"), []byte("sdk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BundlePlists(context.Background(), appDir); err == nil {
		t.Fatal("bundle without a main Info.plist accepted")
	}
}
