package axml

import (
	"strings"
	"testing"
)

func TestGeneratePublicXML(t *testing.T) {
	table := &ResourceTable{
		Packages: []ResourcePackage{{
			ID:   0x7f,
			Name: "com.example",
			Types: []ResourceType{{
				ID:   0x01,
				Name: "string",
				Entries: []ResourceEntry{
					{ID: 0x0001, Name: "app_name", Values: []ConfigValue{{Config: "default", Value: "Hello"}}},
					{ID: 0x0002, Name: "ok_btn", Values: []ConfigValue{{Config: "default", Value: "OK"}}},
				},
			}},
		}},
	}

	xml := table.GeneratePublicXML()
	if !strings.Contains(xml, `<?xml version="1.0" encoding="utf-8"?>`) {
		t.Error("missing XML declaration")
	}
	if !strings.Contains(xml, `<public type="string" name="app_name" id="0x7f010001"`) {
		t.Errorf("missing app_name entry: %s", xml)
	}
	if !strings.Contains(xml, `<public type="string" name="ok_btn" id="0x7f010002"`) {
		t.Errorf("missing ok_btn entry: %s", xml)
	}
}
