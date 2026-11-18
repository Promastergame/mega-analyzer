package smalirole

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// App is an index over all app-owned methods of one decompiled APK (apktool output dir).
type App struct {
	Methods map[string]*Method     // "Lcls;->name(params)" -> method
	Reads   map[string][]FieldRead // "Lcls;->field:Type" -> reads
	Writes  map[string][]FieldRead // "Lcls;->field:Type" -> iput/sput sites
	Files   int
}

func isLibraryPath(rel string) bool {
	for _, lp := range LibraryPrefixes {
		if strings.HasPrefix(rel, lp) {
			return true
		}
	}
	return false
}

// MethodKey is the lookup key used by App.Methods.
func MethodKey(m *Method) string {
	return m.Class + "->" + m.Name + "(" + strings.Join(m.Params, "") + ")"
}

// LoadApp indexes every smali* folder under dir (library packages skipped unless keepLibs).
func LoadApp(dir string, keepLibs bool) (*App, error) {
	a := &App{Methods: map[string]*Method{}, Reads: map[string][]FieldRead{}, Writes: map[string][]FieldRead{}}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".smali") {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		parts := strings.SplitN(filepath.ToSlash(rel), "/", 2)
		if len(parts) == 2 && strings.HasPrefix(parts[0], "smali") {
			if !keepLibs && isLibraryPath(parts[1]) {
				return nil
			}
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		a.Files++
		for _, m := range ParseFile(string(b)) {
			a.Add(m)
		}
		return nil
	})
	return a, err
}

// Add indexes one method (exported so callers can build an App from memory).
func (a *App) Add(m *Method) {
	a.Methods[MethodKey(m)] = m
	for i, in := range m.Insns {
		if strings.HasPrefix(in.Op, "iget") || strings.HasPrefix(in.Op, "sget") {
			if fr := fieldRefRE.FindStringSubmatch(in.Raw); fr != nil {
				a.Reads[fr[1]] = append(a.Reads[fr[1]], FieldRead{Method: m, Index: i})
			}
		} else if strings.HasPrefix(in.Op, "iput") || strings.HasPrefix(in.Op, "sput") {
			if fr := fieldRefRE.FindStringSubmatch(in.Raw); fr != nil {
				if a.Writes == nil {
					a.Writes = map[string][]FieldRead{}
				}
				a.Writes[fr[1]] = append(a.Writes[fr[1]], FieldRead{Method: m, Index: i})
			}
		}
	}
}

// Ctx returns lookups for tracing inside this app.
func (a *App) Ctx() *Ctx {
	if a == nil {
		return nil
	}
	return &Ctx{
		Resolve: func(class, name, params string) *Method { return a.Methods[class+"->"+name+"("+params+")"] },
		Fields:  func(ref string) []FieldRead { return a.Reads[ref] },
		Writers: func(ref string) []FieldRead { return a.Writes[ref] },
	}
}

// Find locates the method whose text contains the given 1-based line of a file (for CLI use with -app).
func (a *App) FindByText(text string) *Method {
	for _, m := range a.Methods {
		if m.Text == text {
			return m
		}
	}
	return nil
}

func normText(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, ".line") && !strings.HasPrefix(l, "#") {
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// Locate finds the class of a pasted method: exact text (ignoring blank, .line and comment lines)
// first, then a unique name+descriptor match. Returns "" when the method is not in the app.
func (a *App) Locate(code string) string {
	if a == nil {
		return ""
	}
	q := ParseMethod("", code)
	want := normText(code)
	var byName []*Method
	for _, m := range a.Methods {
		if m.Name != q.Name || strings.Join(m.Params, "") != strings.Join(q.Params, "") || m.Ret != q.Ret {
			continue
		}
		if normText(m.Text) == want {
			return m.Class
		}
		byName = append(byName, m)
	}
	if len(byName) == 1 {
		return byName[0].Class
	}
	return ""
}

// StoredFields lists the fields the traced literal is written to directly in its own method.
func (s *Site) StoredFields() []string {
	var out []string
	for _, u := range s.Uses {
		if u.Depth == 0 && (strings.HasPrefix(u.Insn.Op, "iput") || strings.HasPrefix(u.Insn.Op, "sput")) {
			if fr := fieldRefRE.FindStringSubmatch(u.Insn.Raw); fr != nil && !contains(out, fr[1]) {
				out = append(out, fr[1])
			}
		}
	}
	return out
}
