package sbom

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxMetadataBytes = 256 << 10
const maxInventoryEntries = 100000

func extractInventory(root string) (*Report, error) {
	r := &Report{Target: root, GeneratedAt: time.Now().UTC().Format(time.RFC3339), Deps: []Dependency{}, Verdict: "no_components_identified"}
	seen := make(map[string]int)
	add := func(d Dependency, origin string) {
		key := d.PURL + "\x00" + d.Raw + "\x00" + d.Replacement
		if i, ok := seen[key]; ok {
			r.Deps[i].Evidence = append(r.Deps[i].Evidence, origin)
			return
		}
		d.Evidence = []string{origin}
		seen[key] = len(r.Deps)
		r.Deps = append(r.Deps, d)
	}
	warn := func(path, reason string) {
		r.Incomplete = true
		if len(r.Warnings) < 100 {
			r.Warnings = append(r.Warnings, filepath.ToSlash(path)+": "+reason)
		}
	}
	entries := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			warn(path, "metadata could not be inspected")
			return nil
		}
		entries++
		if entries > maxInventoryEntries {
			warn("inventory", "entry limit reached")
			return fs.SkipAll
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".version") && name != "go.mod" && name != "pom.properties" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() {
			warn(rel, "non-regular metadata skipped")
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			warn(rel, "metadata could not be read")
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(f, maxMetadataBytes+1))
		f.Close()
		if err != nil || len(data) > maxMetadataBytes {
			warn(rel, "metadata unreadable or exceeds 256 KiB")
			return nil
		}
		text := strings.TrimPrefix(string(data), "\ufeff")
		switch {
		case name == "go.mod":
			deps, complete := parseGoRequirements(text)
			if !complete {
				warn(rel, "unsupported or incomplete module metadata")
			}
			for _, dep := range deps {
				add(dep, rel)
			}
		case name == "pom.properties":
			values := make(map[string]string)
			for _, line := range strings.Split(text, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
					continue
				}
				if key, value, ok := strings.Cut(line, "="); ok {
					values[strings.TrimSpace(key)] = strings.TrimSpace(value)
				}
			}
			if values["artifactId"] != "" {
				add(javaDependency(values["groupId"], values["artifactId"], values["version"]), rel)
			}
		default:
			version := strings.TrimSpace(text)
			if strings.HasPrefix(version, "task") {
				version = "dynamic"
			}
			group, name := getGroupName(strings.TrimSuffix(name, ".version"))
			add(javaDependency(group, name, version), rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(r.Deps, func(i, j int) bool { return r.Deps[i].Raw < r.Deps[j].Raw })
	r.Count = len(r.Deps)
	if r.Count > 0 {
		r.Verdict = "inventory"
	}
	if r.Incomplete {
		r.Verdict = "incomplete"
	}
	return r, nil
}

func javaDependency(group, name, version string) Dependency {
	return Dependency{Group: group, Name: name, Version: version, Raw: fmt.Sprintf("%s:%s@%s", group, name, version), PURL: versionFilePURL(group, name, version)}
}

// Go modules need no downloaded parser. This reader handles single and block
// require/replace directives and records local replacements as unknown versions.
// It inventories declared requirements; it does not claim to resolve MVS.
func parseGoRequirements(text string) ([]Dependency, bool) {
	type replacement struct{ name, version, target, targetVersion string }
	var deps []Dependency
	var replacements []replacement
	block, complete := "", true
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(stripModuleComment(raw))
		if line == "" {
			continue
		}
		if line == ")" {
			block = ""
			continue
		}
		parts := strings.Fields(line)
		directive := block
		if directive == "" {
			directive, parts = parts[0], parts[1:]
		}
		if len(parts) > 0 && parts[0] == "(" {
			block, parts = directive, parts[1:]
		}
		if len(parts) > 0 && parts[len(parts)-1] == ")" {
			block, parts = "", parts[:len(parts)-1]
		}
		for i, p := range parts {
			if v, err := strconv.Unquote(p); err == nil {
				parts[i] = v
			}
		}
		switch directive {
		case "require":
			if len(parts) == 0 {
				continue
			}
			if len(parts) != 2 {
				complete = false
				continue
			}
			deps = append(deps, Dependency{Group: "go", Name: parts[0], Version: parts[1]})
		case "replace":
			if len(parts) == 0 {
				continue
			}
			arrow := -1
			for i, p := range parts {
				if p == "=>" {
					arrow = i
					break
				}
			}
			if arrow < 1 || arrow > 2 || len(parts)-arrow < 2 || len(parts)-arrow > 3 {
				complete = false
				continue
			}
			r := replacement{name: parts[0], target: parts[arrow+1]}
			if arrow == 2 {
				r.version = parts[1]
			}
			if len(parts) == arrow+3 {
				r.targetVersion = parts[arrow+2]
			}
			replacements = append(replacements, r)
		}
	}
	if block != "" {
		complete = false
	}
	for i := range deps {
		d := &deps[i]
		for _, r := range replacements {
			if d.Name != r.name || (r.version != "" && d.Version != r.version) {
				continue
			}
			d.Replacement = d.Name + "@" + d.Version + " => " + r.target
			if r.targetVersion == "" {
				d.Version = ""
			} else {
				d.Name, d.Version = r.target, r.targetVersion
				d.Replacement += "@" + r.targetVersion
			}
			break
		}
		d.PURL = goModulePURL(d.Name, d.Version)
		d.Raw = "go:" + d.Name + "@" + d.Version
	}
	return deps, complete
}

func stripModuleComment(line string) string {
	quoted, escaped := false, false
	for i := 0; i < len(line); i++ {
		if escaped {
			escaped = false
			continue
		}
		if line[i] == '\\' && quoted {
			escaped = true
			continue
		}
		if line[i] == '"' {
			quoted = !quoted
		}
		if !quoted && i+1 < len(line) && line[i:i+2] == "//" {
			return line[:i]
		}
	}
	return line
}
