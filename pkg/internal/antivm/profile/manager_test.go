package profile

import (
	"path/filepath"
	"testing"
)

func TestLoadValid_Fixtures(t *testing.T) {
	fixtures := []string{
		"pixel-7-api-34.json",
		"pixel-8-api-35.json",
		"pixel-9-api-36.json",
	}
	for _, f := range fixtures {
		t.Run(f, func(t *testing.T) {
			p, err := LoadValid(filepath.Join("..", "profiles", f))
			if err != nil {
				t.Fatalf("LoadValid(%s): %v", f, err)
			}
			if p.Model == "" || p.Fingerprint == "" {
				t.Errorf("fixture %s missing core fields", f)
			}
		})
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	p, _ := Generate(GenSpec{Mode: ModeSeeded, Model: "Pixel 8", API: 35, Seed: 3})
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	if err := Save(p, path); err != nil {
		t.Fatal(err)
	}
	back, err := LoadValid(path)
	if err != nil {
		t.Fatal(err)
	}
	if back != p {
		t.Error("save/load round trip changed the profile")
	}
}

func TestLoad_BadPath(t *testing.T) {
	if _, err := Load("does-not-exist.json"); err == nil {
		t.Error("expected error for missing file")
	}
}
