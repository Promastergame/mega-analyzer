// Package minecraft inspects Minecraft archives without executing their code
// or extracting their entries to disk.
package minecraft

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Options are shared by the outer archive and all nested archives. Zero uses
// defaults: 50,000 entries, 512 MiB expanded, 256 MiB input, 32 MiB per entry,
// and three levels of nested archives.
type Options struct {
	MaxEntries      int64
	MaxUncompressed int64
	MaxInputBytes   int64
	MaxEntryBytes   int64
	MaxDepth        int
}

func (o Options) defaults() Options {
	if o.MaxEntries <= 0 {
		o.MaxEntries = 50000
	}
	if o.MaxUncompressed <= 0 {
		o.MaxUncompressed = 512 << 20
	}
	if o.MaxInputBytes <= 0 {
		o.MaxInputBytes = 256 << 20
	}
	if o.MaxEntryBytes <= 0 {
		o.MaxEntryBytes = 32 << 20
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 3
	}
	return o
}

type Finding struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	Title          string   `json:"title"`
	Detail         string   `json:"detail"`
	Evidence       []string `json:"evidence,omitempty"`
	Recommendation string   `json:"recommendation"`
}
type Dependency struct {
	ID       string `json:"id"`
	Version  string `json:"version,omitempty"`
	Required bool   `json:"required"`
}
type Pack struct {
	Path             string          `json:"path"`
	Format           string          `json:"format"`
	Loader           string          `json:"loader,omitempty"`
	ID               string          `json:"id,omitempty"`
	Name             string          `json:"name,omitempty"`
	Version          string          `json:"version,omitempty"`
	Description      string          `json:"description,omitempty"`
	Authors          []string        `json:"authors,omitempty"`
	GameVersion      string          `json:"game_version,omitempty"`
	PackFormat       json.RawMessage `json:"pack_format,omitempty"`
	SupportedFormats json.RawMessage `json:"supported_formats,omitempty"`
	Modules          []string        `json:"modules,omitempty"`
	Dependencies     []Dependency    `json:"dependencies,omitempty"`
}
type FileStat struct {
	Path        string `json:"path"`
	Size        uint64 `json:"size"`
	Kind        string `json:"kind"`
	Width       int    `json:"width,omitempty"`
	Height      int    `json:"height,omitempty"`
	JavaVersion int    `json:"java_version,omitempty"`
}
type Stats struct {
	Entries           int64  `json:"entries"`
	UncompressedBytes uint64 `json:"uncompressed_bytes"`
	BytesRead         int64  `json:"bytes_read"`
	Classes           int    `json:"classes"`
	Scripts           int    `json:"scripts"`
	Textures          int    `json:"textures"`
	Models            int    `json:"models"`
	Sounds            int    `json:"sounds"`
	Languages         int    `json:"languages"`
	NestedArchives    int    `json:"nested_archives"`
	Skipped           int    `json:"skipped"`
}
type Report struct {
	Path        string     `json:"path"`
	SHA256      string     `json:"sha256,omitempty"`
	Format      string     `json:"format"`
	Complete    bool       `json:"complete"`
	Packs       []Pack     `json:"packs"`
	Stats       Stats      `json:"stats"`
	Files       []FileStat `json:"files"`
	Findings    []Finding  `json:"findings"`
	RiskScore   int        `json:"risk_score"`
	Limitations []string   `json:"limitations"`
}

func (r Report) JSON(w io.Writer) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(r)
}

type scanner struct {
	ctx           context.Context
	opts          Options
	report        Report
	names         map[string]bool
	findings      map[string]int
	declared      uint64
	scriptEntries []scriptEntry
}

func newScanner(ctx context.Context, name string, opts Options) *scanner {
	return &scanner{ctx: ctx, opts: opts.defaults(), names: map[string]bool{}, findings: map[string]int{}, report: Report{
		Path: name, Format: "unknown", Complete: true, Packs: []Pack{}, Files: []FileStat{}, Findings: []Finding{},
		Limitations: []string{"Static inspection only: findings are capabilities or indicators, not proof of malware or runtime reachability.", "No game launch, dependency download, signature trust verification, or native-code emulation is performed.", "Version constraints are reported as declared; compatibility with an installed game/mod set is not resolved."},
	}}
}

// AnalyzePath accepts a ZIP/JAR/MCPACK/MCADDON archive or an extracted pack.
// Directory links are never followed. A SHA-256 is provided for archive inputs.
func AnalyzePath(ctx context.Context, name string, opts Options) (Report, error) {
	s := newScanner(ctx, name, opts)
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	st, err := os.Lstat(name)
	if err != nil {
		return Report{}, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return Report{}, fmt.Errorf("input must not be a symbolic link")
	}
	if st.IsDir() {
		root, openErr := os.OpenRoot(name)
		if openErr != nil {
			return Report{}, openErr
		}
		defer root.Close()
		err = filepath.WalkDir(name, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if err = s.ctx.Err(); err != nil {
				return err
			}
			if p == name {
				return nil
			}
			rel, e := filepath.Rel(name, p)
			if e != nil {
				return e
			}
			rel = filepath.ToSlash(rel)
			if s.report.Stats.Entries >= s.opts.MaxEntries {
				s.skip("entry-limit", rel, "Shared entry limit reached")
				return fs.SkipAll
			}
			s.report.Stats.Entries++
			if d.Type()&os.ModeSymlink != 0 {
				s.skip("symbolic-link", rel, "Symbolic links are not followed")
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, e := d.Info()
			if e != nil {
				return e
			}
			if !info.Mode().IsRegular() {
				s.skip("special-file", rel, "Special files are not read")
				return nil
			}
			return s.entry(rel, rel, uint64(info.Size()), 0, info.Mode(), 0, func() (io.ReadCloser, error) { return root.Open(rel) })
		})
	} else {
		if !st.Mode().IsRegular() {
			return Report{}, fmt.Errorf("input must be a regular file or directory")
		}
		if st.Size() > s.opts.MaxInputBytes {
			return Report{}, fmt.Errorf("input exceeds %d byte limit", s.opts.MaxInputBytes)
		}
		f, e := os.Open(name)
		if e != nil {
			return Report{}, e
		}
		defer f.Close()
		b, e := readBounded(ctx, f, s.opts.MaxInputBytes)
		if e != nil {
			return Report{}, e
		}
		h := sha256.Sum256(b)
		s.report.SHA256 = hex.EncodeToString(h[:])
		err = s.archive(b, "", 0)
	}
	if err != nil {
		return Report{}, err
	}
	s.finish()
	return s.report, nil
}

// AnalyzeBytes is useful for upload handlers; the same limits apply as the CLI.
func AnalyzeBytes(ctx context.Context, name string, b []byte, opts Options) (Report, error) {
	s := newScanner(ctx, name, opts)
	if int64(len(b)) > s.opts.MaxInputBytes {
		return Report{}, fmt.Errorf("input size limit exceeded")
	}
	h := sha256.Sum256(b)
	s.report.SHA256 = hex.EncodeToString(h[:])
	if err := s.archive(b, "", 0); err != nil {
		return Report{}, err
	}
	s.finish()
	return s.report, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
func readBounded(ctx context.Context, r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, fmt.Errorf("read budget exhausted")
	}
	// Avoid limit+1 overflow for caller-supplied limits.
	if limit > 1<<40 {
		limit = 1 << 40
	}
	b, err := io.ReadAll(io.LimitReader(contextReader{ctx, r}, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("content exceeds %d byte limit", limit)
	}
	return b, nil
}

func (s *scanner) archive(b []byte, prefix string, depth int) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil && err != zip.ErrInsecurePath {
		return fmt.Errorf("invalid ZIP archive: %w", err)
	}
	if zr == nil {
		return fmt.Errorf("invalid ZIP directory")
	}
	for _, f := range zr.File {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		name := prefix + strings.ReplaceAll(f.Name, `\`, "/")
		if s.report.Stats.Entries >= s.opts.MaxEntries {
			s.skip("entry-limit", name, "Shared entry limit reached")
			break
		}
		s.report.Stats.Entries++
		if err := s.entry(name, strings.ReplaceAll(f.Name, `\`, "/"), f.UncompressedSize64, f.CompressedSize64, f.Mode(), depth, f.Open); err != nil {
			return err
		}
	}
	return nil
}
func unsafePath(n string) bool {
	if strings.HasPrefix(n, "/") || strings.ContainsAny(n, ":\x00") {
		return true
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
func (s *scanner) entry(name, local string, size, compressed uint64, mode fs.FileMode, depth int, open func() (io.ReadCloser, error)) error {
	if strings.Contains(local, "!/") {
		s.skip("ambiguous-archive-path", name, "Entry uses the reserved nested-archive path separator")
		return nil
	}
	if unsafePath(local) {
		s.add("unsafe-path", "critical", "Unsafe archive path", "Absolute, parent-traversal, drive or stream path", name, "Reject the original archive before extraction")
		s.report.Complete = false
		return nil
	}
	canonical := strings.ToLower(path.Clean(name))
	if s.names[canonical] {
		s.add("duplicate-path", "medium", "Colliding archive paths", "Duplicate or case-colliding paths can extract differently across platforms", name, "Keep one unambiguous entry per path")
		s.report.Complete = false
	} else {
		s.names[canonical] = true
	}
	if mode&os.ModeSymlink != 0 {
		s.skip("symbolic-link", name, "Symbolic link entry was skipped")
		return nil
	}
	if mode.IsDir() {
		return nil
	}
	if !mode.IsRegular() {
		s.skip("special-file", name, "Non-regular entry was skipped")
		return nil
	}
	// Subtraction avoids unsigned overflow on malicious ZIP64 sizes.
	if size > uint64(s.opts.MaxUncompressed)-s.declared {
		s.skip("expanded-limit", name, "Shared expanded-size limit exceeded")
		return nil
	}
	s.declared += size
	s.report.Stats.UncompressedBytes = s.declared
	idx := len(s.report.Files)
	s.report.Files = append(s.report.Files, FileStat{Path: name, Size: size, Kind: fileKind(local)})
	s.count(s.report.Files[idx].Kind)
	if compressed > 0 && size/compressed > 1000 {
		s.add("compression-ratio", "medium", "Extreme compression ratio", "Entry expands more than 1000 times", name, "Review before extraction")
	}
	if size > uint64(s.opts.MaxEntryBytes) {
		s.skip("entry-size-limit", name, "Entry exceeds inspection size limit")
		return nil
	}
	remaining := s.opts.MaxUncompressed - s.report.Stats.BytesRead
	if size > uint64(remaining) {
		s.skip("read-budget", name, "Shared content read budget exceeded")
		return nil
	}
	rc, err := open()
	if err != nil {
		s.skip("entry-read", name, err.Error())
		return nil
	}
	limit := min(s.opts.MaxEntryBytes, remaining, int64(size))
	data, err := readBounded(s.ctx, rc, limit)
	rc.Close()
	// Charge attempted reads as well as successful ones (including CRC failures).
	s.report.Stats.BytesRead += limit
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	if err != nil {
		s.skip("entry-read", name, err.Error())
		return nil
	}
	if uint64(len(data)) != size {
		s.skip("entry-size", name, "Actual size differs from archive header")
		return nil
	}
	ext := strings.ToLower(path.Ext(local))
	if ext == ".jar" {
		// Java archives belong to the JAR analyzer (pkg/internal/jarloader),
		// not to the Bedrock pack scanner.
		s.skip("java-archive", name, "Java archive: analyze with the JAR analyzer instead of the Bedrock pack scanner")
		return nil
	}
	archiveExtension := ext == ".zip" || ext == ".mcpack" || ext == ".mcaddon"
	archiveMagic := bytes.HasPrefix(data, []byte{'P', 'K', 3, 4}) || bytes.HasPrefix(data, []byte{'P', 'K', 5, 6})
	if archiveExtension || archiveMagic {
		if !archiveExtension {
			s.add("disguised-archive", "info", "ZIP content behind a different extension", "Archive signature detected; nested contents inspected using the same limits", name, "Verify why an archive is stored as an asset or binary resource")
			s.adjustCount(s.report.Files[idx].Kind, -1)
			s.report.Files[idx].Kind = "archive"
		}
		if depth >= s.opts.MaxDepth {
			s.skip("depth-limit", name, "Nested archive depth limit reached")
			return nil
		}
		s.report.Stats.NestedArchives++
		if err := s.archive(data, name+"!/", depth+1); err != nil {
			if s.ctx.Err() != nil {
				return s.ctx.Err()
			}
			s.skip("nested-archive", name, err.Error())
		}
		return nil
	}
	s.inspect(name, local, data, &s.report.Files[idx])
	return nil
}
func (s *scanner) skip(id, name, detail string) {
	s.report.Complete = false
	s.report.Stats.Skipped++
	s.add(id, "medium", "Inspection incomplete", detail, name, "Review skipped content or rerun with appropriate limits")
}
func (s *scanner) add(id, severity, title, detail, name, recommendation string) {
	key := id + "\x00" + detail
	if i, ok := s.findings[key]; ok {
		f := &s.report.Findings[i]
		if len(f.Evidence) < 20 {
			for _, p := range f.Evidence {
				if p == name {
					return
				}
			}
			f.Evidence = append(f.Evidence, name)
		}
		return
	}
	if len(s.report.Findings) >= 2000 {
		s.report.Complete = false
		return
	}
	s.findings[key] = len(s.report.Findings)
	s.report.Findings = append(s.report.Findings, Finding{id, severity, title, detail, []string{name}, recommendation})
}
func fileKind(n string) string {
	n = strings.ToLower(n)
	switch path.Ext(n) {
	case ".js", ".mjs", ".cjs", ".ps1", ".bat", ".cmd", ".sh", ".mcfunction":
		return "script"
	case ".png", ".jpg", ".jpeg", ".tga":
		return "texture"
	case ".ogg", ".wav", ".mp3":
		return "sound"
	case ".lang":
		return "language"
	case ".json":
		if strings.Contains("/"+n, "/models/") || strings.Contains(n, ".geo.") {
			return "model"
		}
		if strings.Contains("/"+n, "/lang/") {
			return "language"
		}
	case ".jar", ".zip", ".mcpack", ".mcaddon":
		return "archive"
	}
	return "other"
}
func (s *scanner) count(k string) { s.adjustCount(k, 1) }

func (s *scanner) adjustCount(k string, delta int) {
	switch k {
	case "script":
		s.report.Stats.Scripts += delta
	case "texture":
		s.report.Stats.Textures += delta
	case "model":
		s.report.Stats.Models += delta
	case "sound":
		s.report.Stats.Sounds += delta
	case "language":
		s.report.Stats.Languages += delta
	}
}
func (s *scanner) finish() {
	// pack.mcmeta lives at the root; the sibling data/ tree identifies data packs.
	contentRoots := map[string]uint8{}
	for _, f := range s.report.Files {
		parts := strings.Split(f.Path, "/")
		for i, part := range parts[:len(parts)-1] {
			if part != "data" && part != "assets" {
				continue
			}
			root := strings.Join(parts[:i], "/")
			if root != "" {
				root += "/"
			}
			if part == "data" {
				contentRoots[root] |= 1
			} else {
				contentRoots[root] |= 2
			}
		}
	}
	for i := range s.report.Packs {
		p := &s.report.Packs[i]
		if p.Format != "java-resource-pack" {
			continue
		}
		prefix := strings.TrimSuffix(p.Path, "pack.mcmeta")
		if contentRoots[prefix] == 1 {
			p.Format = "java-data-pack"
		}
	}
	sort.SliceStable(s.report.Packs, func(i, j int) bool { return s.report.Packs[i].Path < s.report.Packs[j].Path })
	bedrock := 0
	javaPack, dataPack := false, false
	for _, p := range s.report.Packs {
		switch p.Format {
		case "java-resource-pack":
			javaPack = true
		case "java-data-pack":
			dataPack = true
		case "bedrock-pack":
			bedrock++
		}
	}
	switch {
	case bedrock > 1:
		s.report.Format = "bedrock-addon"
	case bedrock == 1:
		s.report.Format = "bedrock-pack"
	case javaPack:
		s.report.Format = "java-resource-pack"
	case dataPack:
		s.report.Format = "java-data-pack"
	}
	if s.report.Format == "unknown" {
		s.add("unrecognized-pack", "info", "No recognized Minecraft metadata", "No valid supported pack or mod descriptor found", s.report.Path, "Verify the package type and inspect descriptors")
	}
	s.validateBedrockLinks()
	weights := map[string]int{"critical": 40, "high": 20, "medium": 8, "low": 2}
	scored := map[string]int{}
	for _, f := range s.report.Findings {
		if weight := weights[f.Severity]; weight > scored[f.ID] {
			scored[f.ID] = weight
		}
	}
	for _, weight := range scored {
		s.report.RiskScore += weight
	}
	if s.report.RiskScore > 100 {
		s.report.RiskScore = 100
	}
	sort.Slice(s.report.Files, func(i, j int) bool { return s.report.Files[i].Path < s.report.Files[j].Path })
	sort.Slice(s.report.Findings, func(i, j int) bool {
		a, b := s.report.Findings[i], s.report.Findings[j]
		if weights[a.Severity] != weights[b.Severity] {
			return weights[a.Severity] > weights[b.Severity]
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Detail < b.Detail
	})
}
