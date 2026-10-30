package artifacts

import "testing"

func TestBudgetUnlimited(t *testing.T) {
	b := NewBudget(0, 0)
	if !b.CanEmbed(1 << 30) {
		t.Fatal("unlimited budget rejected 1GB")
	}
}

func TestBudgetPerFileCap(t *testing.T) {
	b := NewBudget(10, 0) // 10MB per file
	if b.CanEmbed(11 * 1024 * 1024) {
		t.Fatal("expected reject for >10MB file")
	}
	if !b.CanEmbed(5 * 1024 * 1024) {
		t.Fatal("expected accept for 5MB file")
	}
}

func TestBudgetTotalCap(t *testing.T) {
	b := NewBudget(100, 10) // 100MB per file but only 10MB total
	if !b.CanEmbed(5 * 1024 * 1024) {
		t.Fatal("first 5MB should be allowed")
	}
	b.Charge(5 * 1024 * 1024)
	if !b.CanEmbed(5 * 1024 * 1024) {
		t.Fatal("second 5MB should fit exactly")
	}
	b.Charge(5 * 1024 * 1024)
	if b.CanEmbed(1) {
		t.Fatal("budget exhausted, but accepted more")
	}
}

func TestClassifyExcludesSmali(t *testing.T) {
	if Classify("smali/com/foo/Bar.smali", nil) != TypeIgnored {
		t.Fatal("smali should be excluded")
	}
	if Classify("res/drawable/icon.png", nil) != TypeImage {
		t.Fatal("png should classify as image")
	}
	if Classify("lib/arm64-v8a/libfoo.so", nil) != TypeNative {
		t.Fatal(".so should classify as native")
	}
	if Classify("assets/model.gltf", nil) != TypeModel3D {
		t.Fatal("gltf should classify as 3d")
	}
}
