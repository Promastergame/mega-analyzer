package minecraft

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

func (s *scanner) decode(name string, b []byte, v any) bool {
	if err := json.Unmarshal(jsonComments(b), v); err != nil {
		s.skip("invalid-metadata", name, err.Error())
		return false
	}
	return true
}
func rawString(v json.RawMessage) string {
	if len(v) == 0 || string(v) == "null" {
		return ""
	}
	var str string
	if json.Unmarshal(v, &str) == nil {
		return str
	}
	return string(v)
}
func version(v json.RawMessage) string {
	var raw []json.RawMessage
	if json.Unmarshal(v, &raw) == nil && len(raw) == 3 {
		var parts [3]int
		for i, item := range raw {
			if strings.TrimSpace(string(item)) == "null" || json.Unmarshal(item, &parts[i]) != nil || parts[i] < 0 {
				return ""
			}
		}
		return fmt.Sprintf("%d.%d.%d", parts[0], parts[1], parts[2])
	}
	return ""
}
func authors(v json.RawMessage) []string {
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
func sortedDependencies(m map[string]json.RawMessage) []Dependency {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Dependency, 0, len(keys))
	for _, k := range keys {
		out = append(out, Dependency{ID: k, Version: rawString(m[k]), Required: true})
	}
	return out
}
func (s *scanner) parsePackMeta(name string, b []byte) {
	var m struct {
		Pack *struct {
			PackFormat  json.RawMessage `json:"pack_format"`
			Supported   json.RawMessage `json:"supported_formats"`
			Min         json.RawMessage `json:"min_format"`
			Max         json.RawMessage `json:"max_format"`
			Description json.RawMessage `json:"description"`
		} `json:"pack"`
	}
	if !s.decode(name, b, &m) {
		return
	}
	if m.Pack == nil {
		s.skip("invalid-pack", name, "pack.mcmeta requires a pack object")
		return
	}
	p := m.Pack
	if len(p.PackFormat) == 0 && (len(p.Min) == 0 || len(p.Max) == 0) {
		s.skip("invalid-pack-format", name, "pack requires pack_format or min_format/max_format")
		return
	}
	if len(p.PackFormat) > 0 {
		var n float64
		if strings.TrimSpace(string(p.PackFormat)) == "null" || json.Unmarshal(p.PackFormat, &n) != nil || n < 0 || n != float64(int64(n)) {
			s.skip("invalid-pack-format", name, "pack_format must be a non-negative integer")
			return
		}
	}
	supported := p.Supported
	if len(supported) == 0 && len(p.Min) > 0 {
		supported, _ = json.Marshal(map[string]json.RawMessage{"min_format": p.Min, "max_format": p.Max})
	}
	s.report.Packs = append(s.report.Packs, Pack{Path: name, Format: "java-resource-pack", Description: rawString(p.Description), PackFormat: p.PackFormat, SupportedFormats: supported})
}

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (s *scanner) parseManifest(name string, b []byte) {
	// A generic manifest.json (for a web app, for example) is not a Bedrock pack.
	var probe map[string]json.RawMessage
	if !s.decode(name, b, &probe) {
		return
	}
	if len(probe["header"]) == 0 || len(probe["modules"]) == 0 {
		return
	}
	var m struct {
		Format int `json:"format_version"`
		Header struct {
			Name, Description, UUID string
			Version                 json.RawMessage
			MinEngine               json.RawMessage `json:"min_engine_version"`
		}
		Modules []struct {
			Type, UUID, Entry, Language string
			Version                     json.RawMessage
		}
		Dependencies []struct {
			UUID    string
			Module  string `json:"module_name"`
			Version json.RawMessage
		}
		Capabilities []string
	}
	if !s.decode(name, b, &m) {
		return
	}
	if m.Header.Name == "" || len(m.Modules) == 0 {
		s.skip("invalid-bedrock", name, "Bedrock manifest needs a name and non-empty modules")
		return
	}
	p := Pack{Path: name, Format: "bedrock-pack", ID: strings.ToLower(m.Header.UUID), Name: m.Header.Name, Description: m.Header.Description, Version: version(m.Header.Version), GameVersion: version(m.Header.MinEngine)}
	if m.Format != 1 && m.Format != 2 {
		s.add("bedrock-format", "medium", "Unrecognized Bedrock manifest version", fmt.Sprintf("format_version=%d (supported: 1, 2)", m.Format), name, "Check the manifest specification for the target engine")
	}
	ids := map[string]bool{}
	checkID := func(id string) {
		id = strings.ToLower(id)
		if !uuidPattern.MatchString(id) {
			s.add("bedrock-uuid", "medium", "Invalid Bedrock UUID", "Header/module UUID must have canonical UUID syntax", name, "Generate unique UUIDs for each header and module")
		}
		if ids[id] {
			s.add("bedrock-uuid", "medium", "Repeated Bedrock UUID", "Header and modules must use different UUIDs", name, "Generate unique UUIDs for each header and module")
		}
		ids[id] = true
	}
	checkID(m.Header.UUID)
	if p.Version == "" {
		s.add("bedrock-version", "medium", "Invalid Bedrock version", "header.version must contain three non-negative integers", name, "Use [major, minor, patch]")
	}
	if len(m.Header.MinEngine) > 0 && p.GameVersion == "" {
		s.add("bedrock-engine-version", "medium", "Invalid minimum engine version", "min_engine_version must contain three non-negative integers", name, "Declare the minimum supported Bedrock release")
	}
	for _, mod := range m.Modules {
		checkID(mod.UUID)
		p.Modules = append(p.Modules, mod.Type)
		if version(mod.Version) == "" {
			s.add("bedrock-module-version", "medium", "Invalid module version", "modules[].version must contain three non-negative integers", name, "Use [major, minor, patch]")
		}
		switch mod.Type {
		case "resources", "data", "script", "world_template", "client_data", "interface":
		default:
			s.add("bedrock-module-type", "low", "Unrecognized module type", mod.Type, name, "Check support in the target Bedrock engine")
		}
		if mod.Type == "script" {
			if mod.Entry == "" || strings.Contains(mod.Entry, `\`) || strings.Contains(mod.Entry, "!/") || unsafePath(mod.Entry) {
				s.add("bedrock-script-entry", "medium", "Invalid script entry", "Script module requires a relative forward-slash entry path without archive separators", name, "Declare an existing script such as scripts/main.js")
			} else {
				// Defer file existence checks until all entries, including sibling packs,
				// have been read.
				s.scriptEntries = append(s.scriptEntries, scriptEntry{manifest: name, entry: path.Join(path.Dir(name), mod.Entry)})
			}
			s.add("bedrock-script", "info", "Bedrock Script API module", "Pack contains executable game scripts", name, "Review Script API behavior and requested dependencies")
		}
	}
	for _, d := range m.Dependencies {
		id := strings.ToLower(d.UUID)
		v := version(d.Version)
		if d.Module != "" {
			id = d.Module
			v = rawString(d.Version)
		} else {
			if !uuidPattern.MatchString(id) {
				s.add("bedrock-dependency-uuid", "medium", "Invalid dependency UUID", id, name, "Use a pack header UUID or a Script API module_name")
			}
			if v == "" {
				s.add("bedrock-dependency-version", "medium", "Invalid dependency version", "Pack dependency version must contain three non-negative integers", name, "Use [major, minor, patch]")
			}
		}
		p.Dependencies = append(p.Dependencies, Dependency{ID: id, Version: v, Required: true})
	}
	for _, c := range m.Capabilities {
		if c == "experimental_custom_ui" || c == "script_eval" {
			s.add("bedrock-capability", "medium", "Experimental or dynamic capability", c, name, "Confirm the capability is required and supported")
		}
	}
	s.report.Packs = append(s.report.Packs, p)
}

type scriptEntry struct{ manifest, entry string }

func (s *scanner) validateBedrockLinks() {
	ids := map[string]Pack{}
	for _, p := range s.report.Packs {
		if p.Format != "bedrock-pack" || p.ID == "" {
			continue
		}
		if prior, ok := ids[p.ID]; ok {
			s.add("bedrock-duplicate-pack", "medium", "Duplicate pack UUID", p.ID, p.Path, "Assign distinct header UUIDs to "+prior.Path+" and this pack")
		}
		ids[p.ID] = p
	}
	for _, p := range s.report.Packs {
		if p.Format != "bedrock-pack" {
			continue
		}
		for _, d := range p.Dependencies {
			if !uuidPattern.MatchString(d.ID) {
				continue
			}
			if strings.EqualFold(d.ID, p.ID) {
				s.add("bedrock-self-dependency", "medium", "Pack depends on itself", d.ID, p.Path, "Reference a different pack UUID")
				continue
			}
			target, ok := ids[strings.ToLower(d.ID)]
			if !ok {
				s.add("external-pack-dependency", "info", "Pack dependency is external", d.ID, p.Path, "Install the required pack separately; it may already exist in the game")
			} else if d.Version != "" && target.Version != "" && d.Version != target.Version {
				s.add("bedrock-dependency-version", "medium", "Bundled dependency version mismatch", fmt.Sprintf("%s requires %s; bundled %s", d.ID, d.Version, target.Version), p.Path, "Align the declared and bundled pack versions")
			}
		}
	}
	files := map[string]bool{}
	for _, f := range s.report.Files {
		files[f.Path] = true
	}
	for _, e := range s.scriptEntries {
		if !files[e.entry] {
			s.add("bedrock-script-missing", "medium", "Missing script entry", e.entry, e.manifest, "Include the script named by modules[].entry")
		}
	}
}
