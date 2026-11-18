package smalirole

import (
	"crypto/sha1"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"decisionai/gnn"
)

// GraphExample is one weakly-labelled const site as a graph (the labelling use is masked).
type GraphExample struct {
	App   string
	Label int
	Graph *gnn.Graph // masked
	Full  *gnn.Graph // unmasked (agreement with the rules)
	Feats []string   // LR masked features, same site (for a paired comparison)
}

// GraphDataset walks the same corpus as BuildDataset and returns graphs instead of JSONL rows.
func GraphDataset(root string, perAppCap int) ([]GraphExample, error) {
	apps, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	li := map[string]int{}
	for i, l := range Labels {
		li[l] = i
	}
	var out []GraphExample
	seen := map[[20]byte]bool{}
	for _, a := range apps {
		if !a.IsDir() {
			continue
		}
		dir := filepath.Join(root, a.Name())
		res := map[uint64]bool{}
		if b, err := os.ReadFile(filepath.Join(dir, "res/values/public.xml")); err == nil {
			for _, m := range publicIDRE.FindAllStringSubmatch(string(b), -1) {
				v, _ := strconv.ParseUint(m[1], 16, 32)
				res[v] = true
			}
		}
		var methods []*Method
		app := &App{Methods: map[string]*Method{}, Reads: map[string][]FieldRead{}}
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".smali") {
				return nil
			}
			rel, _ := filepath.Rel(dir, p)
			parts := strings.SplitN(filepath.ToSlash(rel), "/", 2)
			if len(parts) < 2 || !strings.HasPrefix(parts[0], "smali") || isLibraryPath(parts[1]) {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			for _, m := range ParseFile(string(b)) {
				methods = append(methods, m)
				app.Add(m)
			}
			return nil
		})
		ctx := app.Ctx()
		perLabel := map[string]int{}
		for _, m := range methods {
			h := sha1.Sum([]byte(m.Class[strings.LastIndex(m.Class, "/")+1:] + m.Text))
			if seen[h] {
				continue
			}
			seen[h] = true
			for i, in := range m.Insns {
				if !strings.HasPrefix(in.Op, "const") || strings.Contains(in.Op, "string") || strings.Contains(in.Op, "class") || strings.Contains(in.Op, "method") {
					continue
				}
				s, ok := NewSiteCtx(m, i, ctx)
				if !ok {
					continue
				}
				label, by := Oracle(s.Sigs, s.V, res[s.U] && s.U>>24 == 0x7f, m)
				if label == "" || perLabel[label] >= perAppCap {
					continue
				}
				perLabel[label]++
				g, full := s.Graph(by), s.Graph(-1)
				g.Labels, full.Labels = []int{li[label]}, []int{li[label]}
				out = append(out, GraphExample{App: a.Name(), Label: li[label], Graph: g, Full: full, Feats: s.Features(by)})
			}
		}
	}
	return out, nil
}
