package sbom

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInventoryCountIsNotAVulnerability(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 16; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("ordinary-%d.version", i)), []byte("1.0.0"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Extract(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Count != 16 || r.Score != 0 || r.Verdict != "inventory" {
		t.Fatalf("count became a vulnerability: %+v", r)
	}
}

func TestModuleRequirementsAndReplacements(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.org/app
require example.org/single v1.2.3 // indirect
require (
 example.org/local v1.0.0
 example.org/replaced v2.0.0
)
replace example.org/local => ../local
replace (
 example.org/replaced v2.0.0 => example.org/fork v2.0.1
)
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Extract(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Incomplete || r.Count != 3 {
		t.Fatalf("inventory: %+v", r)
	}
	versions := map[string]string{}
	for _, d := range r.Deps {
		versions[d.Name] = d.Version
		if len(d.Evidence) != 1 || d.Evidence[0] != "go.mod" {
			t.Fatalf("missing origin: %+v", d)
		}
	}
	if versions["example.org/single"] != "v1.2.3" || versions["example.org/fork"] != "v2.0.1" || versions["example.org/local"] != "" {
		t.Fatal(versions)
	}
}

func TestInventoryMetadataLimitsAndMavenCoordinates(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"pom.properties": "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.17.1\n",
		"large.version":  strings.Repeat("x", maxMetadataBytes+1),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Extract(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Incomplete || r.Verdict != "incomplete" || r.Count != 1 {
		t.Fatalf("%+v", r)
	}
	if r.Deps[0].PURL != "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1" {
		t.Fatal(r.Deps[0])
	}
}

func TestMalformedModuleIsIncomplete(t *testing.T) {
	_, ok := parseGoRequirements("require (\nexample.org/pkg v1.0.0\n")
	if ok {
		t.Fatal("unterminated block accepted as complete")
	}
}
