package axml

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ExportTable writes the ResourceTable to standard Android XML files
// in the specified output directory (e.g., "res/").
func ExportTable(table *ResourceTable, outDir string) error {
	// Group values by config, then by type, then store the entries.
	// Map: configName -> typeName -> list of XML elements
	configTypeValues := make(map[string]map[string][]xmlElement)

	// Collect public IDs
	// Map: typeName -> list of public entries
	var publicEntries []xmlPublic

	for _, pkg := range table.Packages {
		for _, typ := range pkg.Types {
			for _, entry := range typ.Entries {
				if entry.Name == "" {
					continue
				}

				// Build public entry
				publicEntries = append(publicEntries, xmlPublic{
					Type: typ.Name,
					Name: entry.Name,
					ID:   fmt.Sprintf("0x%08x", (pkg.ID<<24)|(typ.ID<<16)|entry.ID),
				})

				for _, val := range entry.Values {
					cfg := val.Config
					if cfg == "default" || cfg == "" {
						cfg = "" // "values" directory
					} else {
						cfg = "-" + cfg // "values-ru"
					}

					if configTypeValues[cfg] == nil {
						configTypeValues[cfg] = make(map[string][]xmlElement)
					}

					// Export both simple types and known bag types
					switch typ.Name {
					case "string", "color", "dimen", "bool", "integer", "style", "array", "plurals":
						elem := xmlElement{
							Name:          entry.Name,
							Value:         val.Value,
							Parent:        val.Parent,
							ComplexValues: val.ComplexValues,
						}
						configTypeValues[cfg][typ.Name] = append(configTypeValues[cfg][typ.Name], elem)
					}
				}
			}
		}
	}

	// Write public.xml
	if len(publicEntries) > 0 {
		valuesDir := filepath.Join(outDir, "values")
		if err := os.MkdirAll(valuesDir, 0755); err != nil {
			return err
		}
		if err := writePublicXml(filepath.Join(valuesDir, "public.xml"), publicEntries); err != nil {
			return err
		}
	}

	// Write typed XMLs
	for cfg, types := range configTypeValues {
		dirName := "values" + cfg
		targetDir := filepath.Join(outDir, dirName)

		if len(types) > 0 {
			if err := os.MkdirAll(targetDir, 0755); err != nil {
				return err
			}
		}

		for typeName, elements := range types {
			fileName := typeName + "s.xml" // e.g. "strings.xml"
			if typeName == "plurals" {
				fileName = "plurals.xml"
			}
			if err := writeValuesXml(filepath.Join(targetDir, fileName), typeName, elements); err != nil {
				return err
			}
		}
	}

	return nil
}

func resolveAttrName(id uint32) string {
	if name, ok := resourceID[id]; ok {
		return "android:" + name
	}
	return fmt.Sprintf("?0x%08x", id)
}

func resolvePluralQuantity(id uint32) string {
	switch id {
	case 0x01000004:
		return "other"
	case 0x01000005:
		return "zero"
	case 0x01000006:
		return "one"
	case 0x01000007:
		return "two"
	case 0x01000008:
		return "few"
	case 0x01000009:
		return "many"
	default:
		return fmt.Sprintf("0x%08x", id)
	}
}

type xmlPublic struct {
	Type string `xml:"type,attr"`
	Name string `xml:"name,attr"`
	ID   string `xml:"id,attr"`
}

type xmlElement struct {
	Name          string
	Value         string
	Parent        string
	ComplexValues []ComplexValue
}

func writePublicXml(path string, entries []xmlPublic) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Sort by ID to make it deterministic
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ID < entries[j].ID
	})

	f.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
	f.WriteString("<resources>\n")
	for _, e := range entries {
		f.WriteString(fmt.Sprintf("    <public type=%q name=%q id=%q />\n", e.Type, e.Name, e.ID))
	}
	f.WriteString("</resources>\n")
	return nil
}

func writeValuesXml(path string, typeName string, elements []xmlElement) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Sort by Name to make it deterministic
	sort.Slice(elements, func(i, j int) bool {
		return elements[i].Name < elements[j].Name
	})

	f.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
	f.WriteString("<resources>\n")

	tag := typeName
	if typeName == "string" || typeName == "color" || typeName == "dimen" || typeName == "bool" || typeName == "integer" {
		for _, e := range elements {
			f.WriteString(fmt.Sprintf("    <%s name=%q>%s</%s>\n", tag, e.Name, valueText(typeName, e.Value), tag))
		}
	} else if typeName == "style" {
		for _, e := range elements {
			if e.Parent != "" {
				f.WriteString(fmt.Sprintf("    <style name=%q parent=%q>\n", e.Name, escapeXML(e.Parent)))
			} else {
				f.WriteString(fmt.Sprintf("    <style name=%q>\n", e.Name))
			}
			for _, item := range e.ComplexValues {
				// We need to resolve NameID to an attribute name. For now, use the hex ID if we don't have the map.
				// But we do have resourceID in decoder.go! We can use it.
				itemName := resolveAttrName(item.NameID)
				f.WriteString(fmt.Sprintf("        <item name=%q>%s</item>\n", itemName, escapeXML(item.Value)))
			}
			f.WriteString("    </style>\n")
		}
	} else if typeName == "array" || typeName == "plurals" {
		for _, e := range elements {
			f.WriteString(fmt.Sprintf("    <%s name=%q>\n", tag, e.Name))
			for _, item := range e.ComplexValues {
				if typeName == "plurals" {
					quantity := resolvePluralQuantity(item.NameID)
					f.WriteString(fmt.Sprintf("        <item quantity=%q>%s</item>\n", quantity, escapeAndroidString(item.Value)))
				} else {
					f.WriteString(fmt.Sprintf("        <item>%s</item>\n", escapeAndroidString(item.Value)))
				}
			}
			f.WriteString(fmt.Sprintf("    </%s>\n", tag))
		}
	}

	f.WriteString("</resources>\n")
	return nil
}

// valueText escapes a <string>-like value the way aapt2 expects to read it back.
func valueText(typeName, v string) string {
	if typeName == "string" {
		return escapeAndroidString(v)
	}
	return escapeXML(v)
}

// escapeAndroidString escapes XML metacharacters and the Android resource
// string escapes. aapt2 rejects a bare apostrophe ("unescaped apostrophe in
// string") and treats &apos; as one, so it must be emitted as \' like apktool.
func escapeAndroidString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '\'':
			b.WriteString("\\'")
		case '"':
			b.WriteString("\\\"")
		case '\n':
			b.WriteString("\\n")
		case '\t':
			b.WriteString("\\t")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
