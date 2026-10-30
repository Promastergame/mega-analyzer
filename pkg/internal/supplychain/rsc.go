package supplychain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type SecurityFinding struct {
	ID, Package, Version, File, Severity, Description, Remediation string
	Confidence                                                     float64
}

var rscPackages = map[string]bool{"react-server-dom-webpack": true, "react-server-dom-parcel": true, "react-server-dom-turbopack": true}

func DetectReactServerComponents(root string) ([]SecurityFinding, error) {
	var out []SecurityFinding
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "package.json" {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil
		}
		var doc struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(b, &doc) != nil {
			return nil
		}
		for name, raw := range mergeDeps(doc.Dependencies, doc.DevDependencies) {
			if !rscPackages[name] {
				continue
			}
			v := normalizeSemver(raw)
			if vulnerableRSC(v) {
				rel, _ := filepath.Rel(root, path)
				out = append(out, SecurityFinding{ID: "WS-RSC-001", Package: name, Version: v, File: filepath.ToSlash(rel), Severity: "critical", Confidence: .99, Description: fmt.Sprintf("%s %s is affected by CVE-2025-55182 React Server Components pre-authentication RCE.", name, v), Remediation: "Upgrade to 19.0.1, 19.1.2, 19.2.1 or a newer vendor-patched release and rebuild the deployment."})
			}
		}
		return nil
	})
	return out, err
}
func mergeDeps(a, b map[string]string) map[string]string {
	o := map[string]string{}
	for k, v := range a {
		o[k] = v
	}
	for k, v := range b {
		o[k] = v
	}
	return o
}
func normalizeSemver(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "~^=v >=<")
	if i := strings.IndexAny(v, " -|"); i >= 0 {
		v = v[:i]
	}
	return v
}
func vulnerableRSC(v string) bool {
	p := strings.Split(v, ".")
	if len(p) < 3 {
		return false
	}
	a, e1 := strconv.Atoi(p[0])
	b, e2 := strconv.Atoi(p[1])
	c, e3 := strconv.Atoi(p[2])
	if e1 != nil || e2 != nil || e3 != nil || a != 19 {
		return false
	}
	return (b == 0 && c == 0) || (b == 1 && (c == 0 || c == 1)) || (b == 2 && c == 0)
}
