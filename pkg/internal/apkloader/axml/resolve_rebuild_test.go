package axml

import (
	"strings"
	"testing"
)

func TestResolveManifestPreservesRebuildReferences(t *testing.T) {
	table := &ResourceTable{Packages: []ResourcePackage{{
		ID: 0x7f, Name: "example.icon", TypeIDs: map[string]uint32{"string": 1, "mipmap": 2},
		Types: []ResourceType{
			{ID: 1, Name: "string", Entries: []ResourceEntry{{ID: 0, Name: "app_name", Values: []ConfigValue{
				{Config: "default", RawType: typeString, Value: "Icon app"},
				{Config: "ru", RawType: typeString, Value: "Приложение"},
			}}}},
			{ID: 2, Name: "mipmap", Entries: []ResourceEntry{{ID: 0, Name: "ic_launcher", Values: []ConfigValue{
				{Config: "anydpi-v26", RawType: typeString, Value: "res/mipmap-anydpi-v26/ic_launcher.xml"},
			}}}},
		},
	}}}
	source := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.icon"><application android:icon="@mipmap/ic_launcher" android:label="@string/app_name"><meta-data android:name="display_label" android:resource="@string/app_name"/></application></manifest>`)
	original, err := CompileTextAXML(source, table)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := Decode(original)
	if err != nil {
		t.Fatal(err)
	}
	ResolveManifest(manifest, table)
	if manifest.Application.Label != "Icon app" {
		t.Fatalf("analysis label was not resolved: %q", manifest.Application.Label)
	}
	for _, want := range []string{`android:icon="@mipmap/ic_launcher"`, `android:label="@string/app_name"`, `android:resource="@string/app_name"`} {
		if !strings.Contains(string(manifest.XMLBytes), want) {
			t.Errorf("editable manifest lost %s: %s", want, manifest.XMLBytes)
		}
	}
	rebuilt, err := OverlayAXML(original, manifest.XMLBytes, table)
	if err != nil {
		t.Fatalf("cannot rebuild decoded manifest: %v", err)
	}
	dom, err := ParseBinaryAXML(rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	app := dom.Root.Kids[0]
	for _, check := range []struct {
		elem *DomElem
		name string
		id   uint32
	}{{app, "icon", 0x7f020000}, {app, "label", 0x7f010000}, {app.Kids[0], "resource", 0x7f010000}} {
		found := false
		for _, attr := range check.elem.Attrs {
			if attr.Name == check.name {
				found = true
				if attr.Type != typeReference || attr.Data != check.id {
					t.Errorf("%s lost resource identity: %+v", check.name, attr)
				}
			}
		}
		if !found {
			t.Errorf("missing %s after rebuild", check.name)
		}
	}
}
