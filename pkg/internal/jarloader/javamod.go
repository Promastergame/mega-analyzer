package jarloader

// Java mod-loader metadata (Fabric, Quilt, Forge, NeoForge, legacy Forge).
//
// Bedrock packs (.mcaddon/.mcpack) never carry these descriptors, and the
// Bedrock analyzer (pkg/minecraft) never reads them: mod metadata lives
// here, next to the JAR analyzer. Parsing is pure (no scanner state):
// malformed or partial descriptors come back as issue strings the caller
// records, never as silent drops.

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// JavaMod is one mod declared by a loader descriptor.
type JavaMod struct {
	Loader       string       `json:"loader,omitempty"`
	ID           string       `json:"id,omitempty"`
	Name         string       `json:"name,omitempty"`
	Version      string       `json:"version,omitempty"`
	Description  string       `json:"description,omitempty"`
	GameVersion  string       `json:"game_version,omitempty"`
	Authors      []string     `json:"authors,omitempty"`
	Dependencies []JavaModDep `json:"dependencies,omitempty"`
}

// JavaModDep is one declared mod dependency.
type JavaModDep struct {
	ID       string `json:"id"`
	Version  string `json:"version,omitempty"`
	Required bool   `json:"required"`
}

// DetectModDescriptor reports which Java mod loader owns a descriptor path.
// inner is the archive-relative path (nested "!/" prefixes are skipped).
func DetectModDescriptor(inner string) (string, bool) {
	if i := strings.LastIndex(inner, "!/"); i >= 0 {
		inner = inner[i+2:]
	}
	base := path.Base(inner)
	switch base {
	case "fabric.mod.json":
		return "Fabric", true
	case "quilt.mod.json":
		return "Quilt", true
	case "mcmod.info":
		return "LegacyForge", true
	case "mods.toml", "neoforge.mods.toml":
		if dir := path.Dir(inner); dir == "META-INF" {
			if base == "neoforge.mods.toml" {
				return "NeoForge", true
			}
			return "Forge", true
		}
	}
	return "", false
}

// ParseModMetadata parses one loader descriptor. It returns the declared
// mods plus human-readable issue strings for anything unrecognized or
// incomplete (invalid JSON, missing ids, compound expressions, TOML subset).
func ParseModMetadata(loader, data string, body []byte) ([]JavaMod, []string) {
	switch loader {
	case "Fabric":
		return parseFabricMod(data, body)
	case "Quilt":
		return parseQuiltMod(data, body)
	case "Forge", "NeoForge":
		return parseForgeTOML(loader, data, body)
	case "LegacyForge":
		return parseLegacyForgeMods(loader, data, body)
	}
	return nil, []string{"unknown mod loader " + loader + " for " + data}
}

func jmodIssue(format string, args ...interface{}) string {
	return "mod metadata: " + fmt.Sprintf(format, args...)
}

func parseFabricMod(name string, b []byte) ([]JavaMod, []string) {
	var m struct {
		ID, Name, Version, Description string
		Authors                        json.RawMessage
		Depends                        map[string]json.RawMessage
	}
	if err := json.Unmarshal(stripJSONComments(b), &m); err != nil {
		return nil, []string{jmodIssue("invalid-fabric %s: %s", name, err.Error())}
	}
	if m.ID == "" || m.Version == "" {
		return nil, []string{jmodIssue("invalid-fabric %s: descriptor requires id and version", name)}
	}
	mod := JavaMod{Loader: "Fabric", ID: m.ID, Name: m.Name, Version: m.Version, Description: m.Description}
	mod.Authors = jmodAuthors(m.Authors)
	mod.GameVersion = jmodRawString(m.Depends["minecraft"])
	mod.Dependencies = jmodSortedDeps(m.Depends)
	if path.Base(name) != name && !strings.Contains(name, "!/") {
		return []JavaMod{mod}, []string{jmodIssue("descriptor-location %s: Java mod descriptors normally belong at archive root", name)}
	}
	return []JavaMod{mod}, nil
}

func parseQuiltMod(name string, b []byte) ([]JavaMod, []string) {
	var m struct {
		Loader struct {
			ID, Version string
			Metadata    struct {
				Name, Description string
				Contributors      map[string]json.RawMessage
			}
			Depends []json.RawMessage
		} `json:"quilt_loader"`
	}
	if err := json.Unmarshal(stripJSONComments(b), &m); err != nil {
		return nil, []string{jmodIssue("invalid-quilt %s: %s", name, err.Error())}
	}
	if m.Loader.ID == "" || m.Loader.Version == "" {
		return nil, []string{jmodIssue("invalid-quilt %s: descriptor requires quilt_loader.id and version", name)}
	}
	q := m.Loader
	mod := JavaMod{Loader: "Quilt", ID: q.ID, Name: q.Metadata.Name, Version: q.Version, Description: q.Metadata.Description}
	for k := range q.Metadata.Contributors {
		mod.Authors = append(mod.Authors, k)
	}
	sort.Strings(mod.Authors)
	var issues []string
	for _, raw := range q.Depends {
		var d struct {
			ID       string
			Versions json.RawMessage
			Optional bool
		}
		if json.Unmarshal(raw, &d) != nil || d.ID == "" {
			issues = append(issues, jmodIssue("quilt-dependency-expression %s: compound dependency expression is not resolved; consult quilt.mod.json", name))
			continue
		}
		mod.Dependencies = append(mod.Dependencies, JavaModDep{ID: d.ID, Version: jmodRawString(d.Versions), Required: !d.Optional})
		if d.ID == "minecraft" {
			mod.GameVersion = jmodRawString(d.Versions)
		}
	}
	return []JavaMod{mod}, issues
}

func parseLegacyForgeMods(loader, name string, b []byte) ([]JavaMod, []string) {
	var mods []struct {
		ID                         string `json:"modid"`
		Name, Version, Description string
		MCVersion                  string   `json:"mcversion"`
		Authors                    []string `json:"authorList"`
	}
	clean := stripJSONComments(b)
	if len(strings.TrimSpace(string(clean))) > 0 && strings.HasPrefix(strings.TrimSpace(string(clean)), "{") {
		var wrapper struct {
			ModList json.RawMessage `json:"modList"`
		}
		if err := json.Unmarshal(clean, &wrapper); err != nil {
			return nil, []string{jmodIssue("legacy-forge %s: %s", name, err.Error())}
		}
		clean = wrapper.ModList
	}
	if err := json.Unmarshal(clean, &mods); err != nil {
		return nil, []string{jmodIssue("legacy-forge %s: %s", name, err.Error())}
	}
	var out []JavaMod
	var issues []string
	for _, m := range mods {
		if m.ID == "" {
			issues = append(issues, jmodIssue("legacy-forge %s: descriptor requires modid", name))
			continue
		}
		out = append(out, JavaMod{Loader: loader, ID: m.ID, Name: m.Name, Version: m.Version, Description: m.Description, GameVersion: m.MCVersion, Authors: m.Authors})
	}
	return out, issues
}

// parseForgeTOML extracts the common literal fields without pretending to
// implement or validate the full TOML language. Unsupported expressions
// remain visible as an issue; no interpolation is evaluated.
func parseForgeTOML(loader, name string, b []byte) ([]JavaMod, []string) {
	var mods []JavaMod
	current := -1
	section := ""
	var deps []JavaModDep
	var depOwners []string
	var dep *JavaModDep
	unsupported := false
	multiline := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if multiline != "" {
			if strings.Contains(line, multiline) {
				multiline = ""
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.TrimSpace(strings.Trim(line, "[]"))
			dep = nil
			if section == "mods" {
				mods = append(mods, JavaMod{Loader: loader})
				current = len(mods) - 1
			}
			if strings.HasPrefix(section, "dependencies.") {
				deps = append(deps, JavaModDep{Required: true})
				depOwners = append(depOwners, strings.Trim(strings.TrimPrefix(section, "dependencies."), "\"'"))
				dep = &deps[len(deps)-1]
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			unsupported = true
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, `"""`) || strings.HasPrefix(value, "'''") {
			unsupported = true
			if !strings.Contains(value[3:], value[:3]) {
				multiline = value[:3]
			}
			continue
		}
		val, ok := jmodTomlLiteral(value)
		if !ok {
			unsupported = true
			continue
		}
		if dep != nil {
			switch key {
			case "modId":
				dep.ID = val
			case "versionRange":
				dep.Version = val
			case "mandatory":
				dep.Required = val != "false"
			case "type":
				dep.Required = val == "required"
			}
			continue
		}
		if section == "mods" && current >= 0 {
			m := &mods[current]
			switch key {
			case "modId":
				m.ID = val
			case "displayName":
				m.Name = val
			case "version":
				m.Version = val
			case "description":
				m.Description = val
			case "authors":
				m.Authors = []string{val}
			}
		}
	}
	var out []JavaMod
	var issues []string
	if len(mods) == 0 {
		return nil, []string{jmodIssue("forge-descriptor %s: no [[mods]] section recognized", name)}
	}
	for i := range mods {
		if mods[i].ID == "" {
			issues = append(issues, jmodIssue("forge-descriptor %s: modId is missing or uses unsupported TOML syntax", name))
			continue
		}
		for j, d := range deps {
			if depOwners[j] != mods[i].ID {
				continue
			}
			mods[i].Dependencies = append(mods[i].Dependencies, d)
			if d.ID == "minecraft" {
				mods[i].GameVersion = d.Version
			}
		}
		out = append(out, mods[i])
	}
	if unsupported {
		issues = append(issues, jmodIssue("forge-toml-subset %s: only common single-line literal fields are extracted; read the original descriptor", name))
	}
	return out, issues
}

func jmodTomlLiteral(v string) (string, bool) {
	if strings.HasPrefix(v, `"""`) || strings.HasPrefix(v, "'''") {
		return "", false
	}
	if strings.HasPrefix(v, "'") {
		if end := strings.Index(v[1:], "'"); end >= 0 {
			return v[1 : 1+end], true
		}
		return "", false
	}
	if strings.HasPrefix(v, `"`) {
		escape := false
		for i := 1; i < len(v); i++ {
			if escape {
				escape = false
				continue
			}
			if v[i] == '\\' {
				escape = true
				continue
			}
			if v[i] == '"' {
				str, err := strconv.Unquote(v[:i+1])
				return str, err == nil
			}
		}
		return "", false
	}
	v = strings.TrimSpace(strings.SplitN(v, "#", 2)[0])
	if v == "true" || v == "false" {
		return v, true
	}
	return "", false
}

func jmodRawString(v json.RawMessage) string {
	if len(v) == 0 || string(v) == "null" {
		return ""
	}
	var str string
	if json.Unmarshal(v, &str) == nil {
		return str
	}
	return string(v)
}

// jmodVersion formats a Bedrock/Java triple, rejecting nulls and negatives.
func jmodVersion(v json.RawMessage) string {
	var raw []json.RawMessage
	if json.Unmarshal(v, &raw) == nil && len(raw) == 3 {
		var parts [3]int
		for i, item := range raw {
			if strings.TrimSpace(string(item)) == "null" || json.Unmarshal(item, &parts[i]) != nil || parts[i] < 0 {
				return ""
			}
		}
		return itoa3(parts[0], parts[1], parts[2])
	}
	return ""
}

func itoa3(a, b, c int) string {
	return strconv.Itoa(a) + "." + strconv.Itoa(b) + "." + strconv.Itoa(c)
}

func jmodAuthors(v json.RawMessage) []string {
	var values []json.RawMessage
	if json.Unmarshal(v, &values) != nil {
		return nil
	}
	var out []string
	for _, v := range values {
		var str string
		if json.Unmarshal(v, &str) == nil {
			out = append(out, str)
			continue
		}
		var p struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(v, &p) == nil && p.Name != "" {
			out = append(out, p.Name)
		}
	}
	return out
}

func jmodSortedDeps(m map[string]json.RawMessage) []JavaModDep {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]JavaModDep, 0, len(keys))
	for _, k := range keys {
		out = append(out, JavaModDep{ID: k, Version: jmodRawString(m[k]), Required: true})
	}
	return out
}

// stripJSONComments removes // and /* */ comments outside string literals.
func stripJSONComments(b []byte) []byte {
	var out []byte
	var quote byte
	i := 0
	for i < len(b) {
		c := b[i]
		if quote != 0 {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				out = append(out, b[i+1])
				i += 2
				continue
			}
			if c == quote {
				quote = 0
			}
			i++
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			out = append(out, c)
			i++
			continue
		}
		if c == '/' && i+1 < len(b) && b[i+1] == '/' {
			for i < len(b) && b[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(b) && b[i+1] == '*' {
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i += 2
			continue
		}
		out = append(out, c)
		i++
	}
	return out
}
