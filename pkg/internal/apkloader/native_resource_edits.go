package apkloader

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/apkloader/axml"
)

// collectNativeResourceEdits compares a native decoder's XML exports with
// their authoritative ARSC. Unsupported edits must not disappear from an APK
// that is reported as successfully rebuilt. Canonical exports also let older,
// unedited style/array/plural output pass without guessing its semantics.
func (r *APKRebuilder) collectNativeResourceEdits(table *axml.ResourceTable) ([]axml.ARSCEdit, error) {
	if table == nil {
		return nil, fmt.Errorf("cannot validate edited resource exports: resources.arsc is unreadable")
	}
	baseline, err := os.MkdirTemp("", "mega-native-values-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(baseline)
	if err := axml.ExportTable(table, baseline); err != nil {
		return nil, err
	}
	var edits []axml.ARSCEdit
	resDir := filepath.Join(r.SourceDir, "res")
	// The caller enters this validator only for projects carrying the
	// resources.arsc.json export marker. A --no-resources decode has no
	// marker and keeps its binary resources without requiring XML exports.
	// Check the baseline too: walking current files alone misses deletion
	// of an entire strings.xml, values locale folder or res directory.
	err = filepath.WalkDir(baseline, func(path string, de os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if de.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(baseline, path)
		if err != nil {
			return err
		}
		if !isExportedValuesXML("res/" + filepath.ToSlash(rel)) {
			return nil
		}
		info, err := os.Stat(filepath.Join(resDir, rel))
		if os.IsNotExist(err) {
			return fmt.Errorf("res/%s: deleting a resource export is not supported while preserving the original ARSC", filepath.ToSlash(rel))
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("res/%s: expected a resource export file", filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = filepath.WalkDir(resDir, func(path string, de os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path == resDir && os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if de.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(resDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !isExportedValuesXML("res/" + rel) {
			return nil
		}
		oldData, err := os.ReadFile(filepath.Join(baseline, filepath.FromSlash(rel)))
		if os.IsNotExist(err) {
			return fmt.Errorf("res/%s: adding new resource exports is not supported when preserving an existing ARSC", rel)
		}
		if err != nil {
			return err
		}
		newData, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Equal(oldData, newData) {
			return nil
		}
		oldValues, err := parseResourceExport(oldData)
		if err != nil {
			return fmt.Errorf("res/%s: canonical export invalid: %w", rel, err)
		}
		newValues, err := parseResourceExport(newData)
		if err != nil {
			return fmt.Errorf("res/%s: %w", rel, err)
		}
		if len(oldValues) != len(newValues) {
			return fmt.Errorf("res/%s: adding or deleting resource entries is not supported while preserving ARSC IDs", rel)
		}
		for key, newValue := range newValues {
			oldValue, ok := oldValues[key]
			if !ok {
				return fmt.Errorf("res/%s: new or renamed resource %s cannot be patched into the original ARSC", rel, key)
			}
			oldCanonical, err := canonicalResourceXML(oldValue.Inner)
			if err != nil {
				return err
			}
			newCanonical, err := canonicalResourceXML(newValue.Inner)
			if err != nil {
				return err
			}
			sameValue := oldCanonical == newCanonical
			if newValue.XMLName.Local == "string" {
				sameValue = unescapeAndroidResString(oldValue.Inner) == unescapeAndroidResString(newValue.Inner)
			}
			if resourceAttrsEqual(oldValue.Attrs, newValue.Attrs) && sameValue {
				continue
			}
			typ := newValue.XMLName.Local
			if !resourceAttrsEqual(oldValue.Attrs, newValue.Attrs) {
				return fmt.Errorf("res/%s: changed attributes on %s cannot be patched into ARSC", rel, key)
			}
			switch typ {
			case "string", "bool", "integer", "color":
			default:
				return fmt.Errorf("res/%s: editing %s is not supported by native ARSC patching", rel, key)
			}
			if strings.Contains(newValue.Inner, "<") {
				return fmt.Errorf("res/%s: styled or nested values cannot be patched into ARSC", rel)
			}
			name := ""
			for _, a := range newValue.Attrs {
				if a.Name.Local == "name" {
					name = a.Value
				}
			}
			newText := unescapeAndroidResString(newValue.Inner)
			if typ != "string" {
				newText = strings.TrimSpace(newText)
			}
			edits = append(edits, axml.ARSCEdit{Type: typ, Name: name, Config: configFromValuesFolder(strings.SplitN(rel, "/", 2)[0]), NewValue: newText})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(edits, func(i, j int) bool {
		a, b := edits[i], edits[j]
		return a.Type+"/"+a.Name+"/"+a.Config < b.Type+"/"+b.Name+"/"+b.Config
	})
	return edits, nil
}

type resourceExportElement struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Inner   string     `xml:",innerxml"`
}

func parseResourceExport(data []byte) (map[string]resourceExportElement, error) {
	var doc struct {
		XMLName xml.Name
		Items   []resourceExportElement `xml:",any"`
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if doc.XMLName.Local != "resources" {
		return nil, fmt.Errorf("expected <resources>")
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if text, ok := tok.(xml.CharData); !ok || strings.TrimSpace(string(text)) != "" {
			return nil, fmt.Errorf("unexpected XML after </resources>")
		}
	}
	out := map[string]resourceExportElement{}
	for _, el := range doc.Items {
		name, typ := "", el.XMLName.Local
		for _, a := range el.Attrs {
			if a.Name.Local == "name" {
				name = a.Value
			}
			if el.XMLName.Local == "public" && a.Name.Local == "type" {
				typ += "/" + a.Value
			}
		}
		if name == "" {
			return nil, fmt.Errorf("resource <%s> has no name", el.XMLName.Local)
		}
		key := typ + "/" + name
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("duplicate resource %s", key)
		}
		out[key] = el
	}
	return out, nil
}

func resourceAttrsEqual(a, b []xml.Attr) bool {
	canon := func(attrs []xml.Attr) string {
		items := make([]string, 0, len(attrs))
		for _, a := range attrs {
			items = append(items, a.Name.Space+"\x00"+a.Name.Local+"\x00"+a.Value)
		}
		sort.Strings(items)
		data, _ := json.Marshal(items)
		return string(data)
	}
	return canon(a) == canon(b)
}

func canonicalResourceXML(inner string) (string, error) {
	dec := xml.NewDecoder(strings.NewReader("<value>" + inner + "</value>"))
	var parts []string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			sort.Slice(t.Attr, func(i, j int) bool {
				return t.Attr[i].Name.Space+t.Attr[i].Name.Local < t.Attr[j].Name.Space+t.Attr[j].Name.Local
			})
			data, _ := json.Marshal(t)
			parts = append(parts, "start:"+string(data))
		case xml.EndElement:
			data, _ := json.Marshal(t)
			parts = append(parts, "end:"+string(data))
		case xml.CharData:
			s := string(t)
			if strings.TrimSpace(s) != "" {
				parts = append(parts, "text:"+s)
			}
		case xml.Comment:
		default:
			return "", fmt.Errorf("unsupported XML token in resource value")
		}
	}
	data, _ := json.Marshal(parts)
	return string(data), nil
}
