package apkloader

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// atomicWriteFile leaves the previous result intact if writing or publication
// fails. All temporary files stay on the destination filesystem.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".native-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if closeErr := f.Close(); closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}

func planSmaliClassPaths(classes []*ClassDef) (map[string]string, error) {
	paths := make(map[string]string, len(classes))
	counts := map[string]int{}
	var names []string
	for _, c := range classes {
		if c == nil || c.ClassName == "" { continue }
		if _, exists := paths[c.ClassName]; exists { return nil, fmt.Errorf("duplicate DEX class %s", c.ClassName) }
		p := classSmaliRelPath(c.ClassName)
		if p == "" { return nil, fmt.Errorf("invalid smali class path: %q", c.ClassName) }
		paths[c.ClassName] = p
		counts[strings.ToLower(p)]++
		names = append(names, c.ClassName)
	}
	sort.Strings(names)
	used := map[string]bool{}
	// Reserve unambiguous original names before allocating collision suffixes.
	for _, name := range names {
		p := paths[name]
		if counts[strings.ToLower(p)] == 1 { used[strings.ToLower(p)] = true }
	}
	for _, name := range names {
		base := paths[name]
		if counts[strings.ToLower(base)] == 1 { continue }
		h := sha256.Sum256([]byte(name))
		suffix := hex.EncodeToString(h[:])
		for n := 0; ; n++ {
			p := base + "__" + suffix[:12]
			if n > 0 { p += fmt.Sprintf("_%d", n) }
			if used[strings.ToLower(p)] { continue }
			used[strings.ToLower(p)] = true
			paths[name] = p
			break
		}
	}
	return paths, nil
}

func saveSmaliClassPaths(dir string, paths map[string]string) error {
	names := make(map[string]string, len(paths))
	for name, path := range paths { names[name] = filepath.ToSlash(path) + ".smali" }
	data, err := json.MarshalIndent(names, "", "  ")
	if err != nil { return err }
	return atomicWriteFile(filepath.Join(dir, ".mega-analyzer-class-paths.json"), data, 0644)
}
