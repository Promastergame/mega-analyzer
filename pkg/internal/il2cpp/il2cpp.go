package il2cpp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Result summarizes one IL2CPP recovery run for reporting and the web UI.
type Result struct {
	AssemblyCount   int      `json:"assembly_count"`
	TypeCount       int      `json:"type_count"`
	MethodCount     int      `json:"method_count"`
	FieldCount      int      `json:"field_count"`
	StringCount     int      `json:"string_count"`
	MetadataVersion int      `json:"metadata_version"`
	MetadataLayout  string   `json:"metadata_layout"`
	UnityVersion    string   `json:"unity_version,omitempty"`
	BinaryAttached  bool     `json:"binary_attached"`
	CodeGenModules  int      `json:"codegen_modules"`
	Assemblies      []string `json:"assemblies"`
	Diagnostics     []string `json:"diagnostics,omitempty"`
	DumpPath        string   `json:"dump_path,omitempty"`
	StringsPath     string   `json:"strings_path,omitempty"`
}

// AnalyzeFiles parses global-metadata.dat and (when found) the best matching
// libil2cpp.so, returning the combined view.
func AnalyzeFiles(metaPath, binPath string) (*Analyzed, error) {
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("read metadata: %w", err)
	}
	unity := DetectUnityVersion(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(metaPath)))))
	var binData []byte
	if binPath != "" {
		if bd, err := os.ReadFile(binPath); err == nil {
			binData = bd
		}
	}
	return Analyze(metaData, binData, unity)
}

// DumpToDir runs the full recovery and writes dump.cs, string-literals.txt
// and summary.json into dir. It never fails the whole scan when the dump
// cannot be produced: callers decide how to surface the error.
func DumpToDir(dir, metaPath, binPath string) (*Result, error) {
	a, err := AnalyzeFiles(metaPath, binPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	res := a.Summary()
	dumpPath := filepath.Join(dir, "dump.cs")
	f, err := os.Create(dumpPath)
	if err != nil {
		return nil, err
	}
	a.WriteDump(f)
	f.Close()
	res.DumpPath = dumpPath

	strPath := filepath.Join(dir, "string-literals.txt")
	sf, err := os.Create(strPath)
	if err == nil {
		a.WriteStrings(sf)
		sf.Close()
		res.StringsPath = strPath
	}

	sumPath := filepath.Join(dir, "summary.json")
	if data, jerr := json.MarshalIndent(res, "", "  "); jerr == nil {
		_ = os.WriteFile(sumPath, data, 0o644)
	}
	return res, nil
}

// Summary builds the reporting view of the analysis.
func (a *Analyzed) Summary() *Result {
	m := a.Meta
	res := &Result{
		AssemblyCount:   len(m.Assemblies),
		TypeCount:       len(m.TypeDefs),
		MethodCount:     len(m.Methods),
		FieldCount:      len(m.Fields),
		StringCount:     len(m.StringLiterals),
		MetadataVersion: int(m.RawVersion),
		MetadataLayout:  fmt.Sprintf("%.2f", m.Version),
		UnityVersion:    m.Unity,
		BinaryAttached:  a.Bin != nil,
	}
	if a.Bin != nil {
		for _, mod := range a.Bin.Modules() {
			if mod != nil {
				res.CodeGenModules++
			}
		}
		res.Diagnostics = a.Bin.Diagnostics
	}
	seen := make([]string, 0, len(m.Images))
	for i := range m.Images {
		seen = append(seen, m.Str.Get(m.Images[i].NameIdx))
		if len(seen) >= 40 {
			break
		}
	}
	res.Assemblies = seen
	return res
}

// Modules exposes located codegen modules for summary purposes.
func (b *Binary) Modules() []*codegenModule { return b.modules }

var unityVersionRe = regexp.MustCompile(`(20\d{2}\.\d+\.\d+[fpb]\d*|5\.\d+\.\d+[fpb]\d*)`)

// DetectUnityVersion scans typical decoded-APK locations for the engine
// version string (globalgamemanagers, data.unity3d, libunity.so).
func DetectUnityVersion(decodeRoot string) string {
	if decodeRoot == "" {
		return ""
	}
	candidates := []string{
		filepath.Join(decodeRoot, "assets", "bin", "Data", "globalgamemanagers"),
		filepath.Join(decodeRoot, "assets", "bin", "Data", "data.unity3d"),
		filepath.Join(decodeRoot, "bin", "Data", "globalgamemanagers"),
	}
	for _, p := range candidates {
		if v := unityVersionFromFile(p, 64); v != "" {
			return v
		}
	}
	// libunity.so keeps the version string in its rodata.
	libs, _ := filepath.Glob(filepath.Join(decodeRoot, "lib", "*", "libunity.so"))
	for _, p := range libs {
		if v := unityVersionFromFile(p, 1<<20); v != "" {
			return v
		}
	}
	return ""
}

func unityVersionFromFile(path string, readN int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if readN < 256 {
		readN = 256
	}
	buf := make([]byte, readN)
	n, err := io.ReadFull(f, buf)
	if err != nil && n == 0 {
		return ""
	}
	if match := unityVersionRe.Find(buf[:n]); match != nil {
		return string(match)
	}
	return ""
}

// FindPair locates global-metadata.dat and the preferred libil2cpp.so inside
// a decoded APK tree. It prefers arm64, then armeabi-v7a, then any ABI.
func FindPair(root string) (metaPath, binPath string, err error) {
	metaPath = findFile(root, "global-metadata.dat", 6)
	if metaPath == "" {
		return "", "", fmt.Errorf("global-metadata.dat not found under %s", root)
	}
	binPath = findLibil2cpp(root)
	return metaPath, binPath, nil
}

func findLibil2cpp(root string) string {
	prefer := []string{"arm64-v8a", "armeabi-v7a", "x86_64", "x86", "arm64", "arm"}
	var fallback string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "libil2cpp.so") {
			return nil
		}
		if fallback == "" {
			fallback = path
		}
		for _, abi := range prefer {
			if strings.Contains(filepath.ToSlash(path), "/lib/"+abi+"/") {
				fallback = path
				return filepath.SkipAll
			}
		}
		return nil
	})
	return fallback
}

// findFile walks at most depth levels looking for an exact file name.
func findFile(root, name string, depth int) string {
	var found string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || found != "" {
			return filepath.SkipAll
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(root, path)
			if strings.Count(filepath.ToSlash(rel), "/") >= depth {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == name {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// NewScanWriter wraps a file for buffered dumping.
func NewScanWriter(f *os.File) *bufio.Writer { return bufio.NewWriterSize(f, 1<<20) }
