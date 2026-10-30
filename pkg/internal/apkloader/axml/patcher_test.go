package axml

import (
	"testing"
)

func TestDecodeMiniSandboxManifest(t *testing.T) {
	data := MinimalManifestXML()
	mf, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode manifest failed: %v", err)
	}
	if mf.Package != "com.example" {
		t.Fatalf("unexpected package: %q", mf.Package)
	}

	table, err := ParseARSC(MinimalARSC())
	if err != nil {
		t.Fatalf("ParseARSC failed: %v", err)
	}
	if len(table.Packages) != 0 {
		t.Fatalf("unexpected package count: %d", len(table.Packages))
	}
}
