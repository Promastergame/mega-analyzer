package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func extractFixture(t *testing.T) *Report {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "com.example_lib.version"), []byte("2.0.0"), 0o644)
	os.WriteFile(filepath.Join(dir, "gson.version"), []byte("2.8.9"), 0o644)
	os.WriteFile(filepath.Join(dir, "task-based-lib.version"), []byte("task-generated"), 0o644)
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n\nrequire (\n\tgithub.com/Google/uuid v1.3.0\n)\n"), 0o644)
	rep, err := Extract(dir)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestDependenciesCarryPURL(t *testing.T) {
	rep := extractFixture(t)
	want := map[string]string{
		"lib":                    "pkg:maven/com.example/lib@2.0.0",
		"gson":                   "pkg:generic/gson@2.8.9",
		"task-based-lib":         "pkg:generic/task-based-lib",
		"github.com/Google/uuid": "",
	}
	for _, d := range rep.Deps {
		if d.Name == "github.com/Google/uuid" {
			if d.PURL != "pkg:golang/github.com/google/uuid@v1.3.0" {
				t.Errorf("go purl = %q", d.PURL)
			}
			continue
		}
		if w, ok := want[d.Name]; ok && d.PURL != w {
			t.Errorf("%s purl = %q, want %q", d.Name, d.PURL, w)
		}
	}
}

func TestSPDXIncludesPURLRef(t *testing.T) {
	out := ExportSPDX(extractFixture(t))
	if !strings.Contains(out, "ExternalRef: PACKAGE-MANAGER purl pkg:maven/com.example/lib@2.0.0") {
		t.Fatalf("SPDX lacks purl ref:\n%s", out)
	}
}

func TestCycloneDXIsValidAndDeterministic(t *testing.T) {
	rep := extractFixture(t)
	a, err := ExportCycloneDX(rep)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ExportCycloneDX(rep)
	if string(a) != string(b) {
		t.Fatal("export must be deterministic")
	}
	var doc struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Components   []struct {
			BOMRef string `json:"bom-ref"`
			PURL   string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" || !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") || len(doc.SerialNumber) != len("urn:uuid:")+36 {
		t.Fatalf("bad header: %+v", doc)
	}
	if len(doc.Components) != len(rep.Deps) {
		t.Fatalf("components = %d, deps = %d", len(doc.Components), len(rep.Deps))
	}
	refs := map[string]bool{}
	for _, c := range doc.Components {
		if refs[c.BOMRef] {
			t.Fatalf("duplicate bom-ref %q", c.BOMRef)
		}
		refs[c.BOMRef] = true
	}
}

func TestCycloneDXDuplicateComponentsGetUniqueRefs(t *testing.T) {
	rep := &Report{Target: "x", Deps: []Dependency{
		{Name: "a", Raw: "a", PURL: "pkg:generic/a@1"},
		{Name: "a", Raw: "a", PURL: "pkg:generic/a@1"},
	}}
	out, _ := ExportCycloneDX(rep)
	var doc struct {
		Components []struct {
			BOMRef string `json:"bom-ref"`
		} `json:"components"`
	}
	_ = json.Unmarshal(out, &doc)
	if len(doc.Components) != 2 || doc.Components[0].BOMRef == doc.Components[1].BOMRef {
		t.Fatalf("refs not unique: %+v", doc.Components)
	}
}
