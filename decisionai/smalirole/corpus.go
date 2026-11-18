package smalirole

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// LibraryPrefixes are skipped so the corpus measures app code and shared SDKs cannot leak across the split.
var LibraryPrefixes = []string{"android/", "androidx/", "kotlin/", "kotlinx/", "java/", "javax/", "j$/", "com/google/", "okhttp3/", "okio/",
	"org/", "dagger/", "io/reactivex/", "com/squareup/", "com/fasterxml/", "butterknife/", "timber/", "coil/", "retrofit2/", "com/bumptech/",
	"net/sqlcipher/", "com/jakewharton/", "io/noties/", "com/airbnb/", "com/mikepenz/", "de/greenrobot/", "com/journeyapps/", "_COROUTINE/",
	"com/caverock/", "info/guardianproject/", "ch/qos/", "com/github/", "me/zhanghai/", "net/i2p/", "com/afollestad/", "io/github/"}

var publicIDRE = regexp.MustCompile(`id="0x([0-9a-fA-F]{8})"`)

type CorpusStats struct {
	Apps, Files, Methods, DupMethods, Consts, Labelled int
	PerLabel                                           map[string]int
}

// BuildDataset walks apktool output directories (one per app) and writes weakly-labelled JSONL examples.
func BuildDataset(root string, out *bufio.Writer, perAppCap int) (CorpusStats, error) {
	st := CorpusStats{PerLabel: map[string]int{}}
	apps, err := os.ReadDir(root)
	if err != nil {
		return st, err
	}
	seen := map[[20]byte]bool{}
	enc := json.NewEncoder(out)
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
			if len(parts) < 2 || !strings.HasPrefix(parts[0], "smali") {
				return nil
			}
			for _, lp := range LibraryPrefixes {
				if strings.HasPrefix(parts[1], lp) {
					return nil
				}
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			st.Files++
			for _, m := range ParseFile(string(b)) {
				methods = append(methods, m)
				app.Add(m)
			}
			return nil
		})
		if len(methods) == 0 {
			continue
		}
		st.Apps++
		ctx := app.Ctx()
		perLabel := map[string]int{}
		for _, m := range methods {
			st.Methods++
			h := sha1.Sum([]byte(m.Class[strings.LastIndex(m.Class, "/")+1:] + m.Text))
			if seen[h] {
				st.DupMethods++
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
				st.Consts++
				label, by := Oracle(s.Sigs, s.V, res[s.U] && s.U>>24 == 0x7f, m)
				if label == "" || perLabel[label] >= perAppCap {
					continue
				}
				perLabel[label]++
				st.Labelled++
				st.PerLabel[label]++
				ev := "public.xml"
				if by >= 0 {
					ev = s.Uses[by].Insn.Raw
				}
				_ = enc.Encode(Example{App: a.Name(), Label: label, Masked: s.Features(by), Full: s.Features(-1), Literal: s.Literal,
					Where: m.Class + "->" + m.Name, Line: in.Line, Evidence: ev})
			}
		}
	}
	return st, out.Flush()
}
