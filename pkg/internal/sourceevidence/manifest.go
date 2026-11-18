package sourceevidence

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

const androidNS = "http://schemas.android.com/apk/res/android"

// AddManifest checks namespace-aware declarations. It makes no claim that a
// permission guard is sufficient, that a declared component exists in DEX,
// or that a cleartext policy has actually been exercised.
func (r *Report) AddManifest(file, text, representation string, truncated bool) {
	digest := Digest(text)
	source := Source{File: file, Line: 1, Representation: representation, SHA256: digest, Code: text}
	if truncated || !r.AddSource(source) {
		r.LimitReached, r.Status = true, "partial"
		r.AddCheck(Check{ID: CheckID("manifest_cleartext", "", file, 1), Kind: "manifest_cleartext",
			Status: "unresolved", Choice: "unresolved", Basis: "xml_declaration", Scope: "retained_manifest",
			Summary: "Полный манифест недоступен.", Reason: "manifest_context_limit", Citations: []Citation{}})
		return
	}
	decoder := xml.NewDecoder(strings.NewReader(text))
	depth, root, appCount, appDepth := 0, false, 0, 0
	var cleartext, components []Check
	var parseErr error
	for {
		offset := decoder.InputOffset()
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			parseErr = err
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth++
			line := 1 + strings.Count(text[:int(offset)], "\n")
			citation := Citation{File: file, Line: line, SHA256: digest, Snippet: elementSnippet(text, int(offset))}
			if depth == 1 {
				if root || element.Name.Space != "" || element.Name.Local != "manifest" {
					parseErr = fmt.Errorf("expected a single manifest root")
					break
				}
				root = true
			}
			if depth == 2 && element.Name.Space == "" && element.Name.Local == "application" {
				appCount++
				appDepth = depth
				choice, status, summary, reason := "not_declared", "observed", "usesCleartextTraffic не задан явно; эффективная политика зависит от targetSdk и Network Security Config.", ""
				value, found, duplicate := androidAttr(element, "usesCleartextTraffic")
				if duplicate {
					choice, status, reason = "unresolved", "unresolved", "duplicate_android_attribute"
				} else if found {
					switch value {
					case "true":
						choice, status, summary = "explicit_true", "supported", "В application явно задано android:usesCleartextTraffic=\"true\"."
					case "false":
						choice, status, summary = "explicit_false", "supported", "В application явно задано android:usesCleartextTraffic=\"false\"."
					default:
						choice, status, summary, reason = "unresolved", "unresolved", "Значение usesCleartextTraffic не является явным boolean.", "nonliteral_policy_value"
					}
				}
				if nsc, exists, _ := androidAttr(element, "networkSecurityConfig"); exists && nsc != "" {
					summary += " Задан Network Security Config; на API 24+ требуется проверить его политику."
				}
				cleartext = append(cleartext, Check{ID: CheckID("manifest_cleartext", "", file, line), Kind: "manifest_cleartext",
					Status: status, Choice: choice, Basis: "xml_declaration", Scope: "declaration_only",
					Summary: summary, Reason: reason, Citations: []Citation{citation}})
			}
			if appDepth == 2 && depth == 3 && element.Name.Space == "" && isComponent(element.Name.Local) {
				name, present, duplicate := androidAttr(element, "name")
				exported, _, dupeExport := androidAttr(element, "exported")
				permission, _, dupePerm := androidAttr(element, "permission")
				status, choice, reason := "observed", "declared_component", ""
				if !present || name == "" || duplicate || dupeExport || dupePerm {
					status, choice, reason = "unresolved", "unresolved", "invalid_component_declaration"
				}
				summary := fmt.Sprintf("%s %s: exported=%s; permission=%s. Реализация и условия доступа требуют проверки.", element.Name.Local, name, displayAttr(exported), displayAttr(permission))
				components = append(components, Check{ID: CheckID("component_surface", name, file, line), Kind: "component_surface",
					Status: status, Choice: choice, Basis: "xml_declaration", Scope: "declaration_only",
					Summary: summary, Reason: reason, Method: name, Citations: []Citation{citation}})
			}
		case xml.EndElement:
			if depth == appDepth {
				appDepth = 0
			}
			depth--
		}
		if parseErr != nil {
			break
		}
	}
	if parseErr != nil || !root || appCount != 1 || depth != 0 {
		r.AddCheck(Check{ID: CheckID("manifest_cleartext", "", file, 1), Kind: "manifest_cleartext",
			Status: "unresolved", Choice: "unresolved", Basis: "xml_declaration", Scope: "retained_manifest",
			Summary: "Манифест повреждён или содержит неоднозначную структуру.", Reason: "invalid_manifest",
			Citations: []Citation{{File: file, Line: 1, Snippet: elementSnippet(text, 0), SHA256: digest}}})
		return
	}
	for _, check := range append(cleartext, components...) {
		r.AddCheck(check)
	}
}

func androidAttr(element xml.StartElement, name string) (string, bool, bool) {
	value, found := "", false
	for _, attr := range element.Attr {
		if attr.Name.Space == androidNS && attr.Name.Local == name {
			if found {
				return value, true, true
			}
			value, found = attr.Value, true
		}
	}
	return value, found, false
}

func isComponent(name string) bool {
	switch name {
	case "activity", "activity-alias", "service", "receiver", "provider":
		return true
	}
	return false
}

func displayAttr(value string) string {
	if value == "" {
		return "(не задано)"
	}
	return value
}

func elementSnippet(text string, start int) string {
	tail := strings.TrimLeft(text[start:], " \t\r\n")
	if end := strings.IndexByte(tail, '>'); end >= 0 {
		tail = tail[:end+1]
	}
	if len(tail) > 2048 {
		return tail[:2048]
	}
	return tail
}
