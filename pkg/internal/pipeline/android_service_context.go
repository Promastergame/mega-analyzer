package pipeline

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

const androidServiceNamespace = "http://schemas.android.com/apk/res/android"

type androidServiceDeclaration struct {
	class, permission, enabled, snippet string
	line                                int
}

type androidServiceContext struct {
	file     string
	known    bool
	services []androidServiceDeclaration
	classes  map[string]*types.SmaliClass
	byFile   map[string]string
}

func newAndroidServiceContext(result *types.AnalysisResult) *androidServiceContext {
	c := &androidServiceContext{classes: make(map[string]*types.SmaliClass), byFile: make(map[string]string)}
	for key, file := range result.Files {
		if file == nil || file.SmaliClass == nil {
			continue
		}
		name := serviceClassDescriptor(file.SmaliClass.Name)
		c.classes[name] = file.SmaliClass
		c.byFile[filepath.Clean(key)] = name
		c.byFile[filepath.Clean(file.Path)] = name
	}
	c.file = filepath.Join(result.TargetDir, "AndroidManifest.xml")
	if data, err := os.ReadFile(c.file); err == nil {
		c.services, c.known = parseAndroidServiceDeclarations(data)
	}
	return c
}

func serviceClassDescriptor(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "L") && strings.HasSuffix(name, ";") {
		name = name[1 : len(name)-1]
	}
	return strings.ReplaceAll(name, ".", "/")
}

// Absence is meaningful only for a complete, namespace-aware manifest with a
// single application. Invalid or resource-valued enabled states stay unknown.
func parseAndroidServiceDeclarations(data []byte) ([]androidServiceDeclaration, bool) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	depth, applications := 0, 0
	rootSeen, inApplication := false, false
	packageName := ""
	var services []androidServiceDeclaration
	seen := make(map[string]bool)
	for {
		offset := decoder.InputOffset()
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 {
				if rootSeen || element.Name.Space != "" || element.Name.Local != "manifest" {
					return nil, false
				}
				rootSeen = true
				for _, attr := range element.Attr {
					if attr.Name.Space == "" && attr.Name.Local == "package" {
						if packageName != "" {
							return nil, false
						}
						packageName = strings.TrimSpace(attr.Value)
					}
				}
			}
			if depth == 2 && element.Name.Space == "" && element.Name.Local == "application" {
				applications++
				inApplication = true
			}
			if element.Name.Space != "" || element.Name.Local != "service" {
				continue
			}
			if depth != 3 || !inApplication {
				return nil, false
			}
			name, permission, enabled := "", "", "true"
			attrs := make(map[string]bool)
			for _, attr := range element.Attr {
				if attr.Name.Space != androidServiceNamespace {
					continue
				}
				if attrs[attr.Name.Local] {
					return nil, false
				}
				attrs[attr.Name.Local] = true
				switch attr.Name.Local {
				case "name":
					name = strings.TrimSpace(attr.Value)
				case "permission":
					permission = attr.Value
				case "enabled":
					enabled = attr.Value
				}
			}
			if name == "" || strings.HasPrefix(name, "@") || strings.HasPrefix(name, "?") {
				return nil, false
			}
			if strings.HasPrefix(name, ".") {
				name = packageName + name
			} else if !strings.Contains(name, ".") {
				name = packageName + "." + name
			}
			name = serviceClassDescriptor(name)
			if seen[name] {
				return nil, false
			}
			seen[name] = true
			tail := bytes.TrimLeft(data[offset:], " \t\r\n")
			if end := bytes.IndexByte(tail, '>'); end >= 0 {
				tail = tail[:end+1]
			}
			services = append(services, androidServiceDeclaration{class: name, permission: permission,
				enabled: enabled, snippet: string(tail), line: bytes.Count(data[:offset], []byte{'\n'}) + 1})
		case xml.EndElement:
			if depth == 2 && element.Name.Space == "" && element.Name.Local == "application" {
				inApplication = false
			}
			depth--
		}
	}
	return services, rootSeen && packageName != "" && applications == 1 && depth == 0
}

func (c *androidServiceContext) serviceFamily(class string) (family, permission string) {
	seen := make(map[string]bool)
	for class != "" && !seen[class] {
		seen[class] = true
		switch class {
		case "android/service/notification/NotificationListenerService":
			return "notification listener", "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
		case "android/accessibilityservice/AccessibilityService":
			return "accessibility service", "android.permission.BIND_ACCESSIBILITY_SERVICE"
		case "android/app/Service", "android/app/IntentService", "androidx/core/app/JobIntentService":
			return "service", ""
		}
		parent := c.classes[class]
		if parent == nil {
			break
		}
		class = serviceClassDescriptor(parent.SuperClass)
	}
	return "", ""
}

func (c *androidServiceContext) isSubclass(child, ancestor string) bool {
	seen := make(map[string]bool)
	for child != "" && !seen[child] {
		if child == ancestor {
			return true
		}
		seen[child] = true
		parent := c.classes[child]
		if parent == nil {
			break
		}
		child = serviceClassDescriptor(parent.SuperClass)
	}
	return false
}

// Enrich API observations only. Independent vulnerability/data-flow findings
// keep their assessment; missing lifecycle declarations do not prove dead code.
func (c *androidServiceContext) annotate(item *finding.Finding, class string) {
	if item.Kind != finding.KindInventory {
		return
	}
	class = serviceClassDescriptor(class)
	family, binding := c.serviceFamily(class)
	if family == "" {
		return
	}
	limitation := "A complete canonical Android service declaration could not be verified; lifecycle activation and runtime grants remain unknown."
	condition := "Android service declaration: unknown"
	var declaration *androidServiceDeclaration
	if c.known {
		condition = "Android service declaration: no matching declared class or analyzed subclass"
		limitation = fmt.Sprintf("No manifest %s declaration matches this class or an analyzed subclass. Android lifecycle callback reachability is not established; code may still have other callers.", family)
		for i := range c.services {
			candidate := &c.services[i]
			if !c.isSubclass(candidate.class, class) {
				continue
			}
			if binding != "" && candidate.permission != binding {
				condition = "Android service declaration: required binding permission not verified"
				limitation = "A matching service lacks the required " + binding + " declaration; platform callback binding is not established."
				continue
			}
			declaration = candidate
			condition = "Android service declaration: " + strings.ReplaceAll(candidate.class, "/", ".") + "; enabled=" + candidate.enabled
			limitation = "A service declaration does not establish lifecycle activation, required user grants or the calling path."
			if candidate.enabled == "false" {
				limitation = "The matching service is declared with enabled=false. Code can enable it later; verify activation and the required runtime grants."
			} else if candidate.enabled != "true" {
				limitation = "The matching service's enabled value is unresolved; declaration, runtime activation and user grants are separate facts."
			}
			break
		}
	}
	if item.Explanation == nil {
		item.Explanation = &finding.Explanation{Status: "observation", Summary: item.Description}
	}
	// Match explanations may be shared with the retained raw result.
	explanation := *item.Explanation
	explanation.Conditions = appendServiceContextOnce(explanation.Conditions, condition)
	explanation.Limitations = appendServiceContextOnce(explanation.Limitations, limitation)
	explanation.NextChecks = appendServiceContextOnce(explanation.NextChecks, "Verify the manifest declaration, component activation, actual Android grants and reachable callers of the API.")
	item.Explanation = &explanation
	if declaration != nil {
		item.Evidence = append(item.Evidence, finding.NewEvidence("manifest_service_declaration",
			"Declared Android "+family, declaration.snippet, finding.Location{File: c.file, Line: declaration.line}))
	}
}

func appendServiceContextOnce(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(append([]string(nil), values...), value)
}
