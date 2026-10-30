package apkloader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/apkloader/axml"
)

func TestNativeResourceEditsDoNotSilentlyDropChanges(t *testing.T) {
	table := &axml.ResourceTable{Packages: []axml.ResourcePackage{{ID: 0x7f, Name: "example.app", Types: []axml.ResourceType{
		{ID: 1, Name: "string", Entries: []axml.ResourceEntry{{ID: 0, Name: "title", Values: []axml.ConfigValue{{Config: "default", Value: "Original", RawType: 3}}}}},
		{ID: 2, Name: "bool", Entries: []axml.ResourceEntry{{ID: 0, Name: "enabled", Values: []axml.ConfigValue{{Config: "default", Value: "true", RawType: 0x12}}}}},
		{ID: 3, Name: "style", Entries: []axml.ResourceEntry{{ID: 0, Name: "AppTheme", IsBag: true, Values: []axml.ConfigValue{{Config: "default", ComplexValues: []axml.ComplexValue{{NameID: 0x01010000, Value: "Original", RawType: 3}}}}}}},
	}}}}
	for _, change := range []string{"unchanged", "empty_string", "bool", "style", "added", "removed", "malformed", "removed_file"} {
		t.Run(change, func(t *testing.T) {
			source := t.TempDir()
			resDir := filepath.Join(source, "res")
			if err := axml.ExportTable(table, resDir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(resDir, "values", "strings.xml")
			if change == "style" {
				path = filepath.Join(resDir, "values", "styles.xml")
			}
			if change == "bool" {
				path = filepath.Join(resDir, "values", "bools.xml")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			switch change {
			case "empty_string":
				text = strings.ReplaceAll(text, "Original", "")
			case "bool":
				text = strings.ReplaceAll(text, ">true<", ">false<")
			case "style":
				text = strings.ReplaceAll(text, "Original", "Changed")
			case "added":
				text = strings.ReplaceAll(text, "</resources>", `<string name="new_name">new value</string></resources>`)
			case "removed":
				text = "<resources/>"
			case "malformed":
				text = "<resources><string"
			}
			if err := os.WriteFile(path, []byte(text), 0644); err != nil {
				t.Fatal(err)
			}
			if change == "removed_file" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			r := NewAPKRebuilder(source)
			edits, err := r.collectNativeResourceEdits(table)
			switch change {
			case "unchanged":
				if err != nil || len(edits) != 0 {
					t.Fatalf("unedited native exports rejected: %v %v", edits, err)
				}
			case "empty_string":
				if err != nil || len(edits) != 1 || edits[0].NewValue != "" {
					t.Fatalf("empty edit lost: %v %v", edits, err)
				}
			case "bool":
				if err != nil || len(edits) != 1 || edits[0].NewValue != "false" || edits[0].Type != "bool" {
					t.Fatalf("bool edit lost: %v %v", edits, err)
				}
			default:
				if err == nil {
					t.Fatalf("unsupported %s change was silently accepted: %v", change, edits)
				}
			}
		})
	}
}
