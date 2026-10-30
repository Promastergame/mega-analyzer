// Package evalrunner is the narrow public boundary used by cmd/eval. Keeping
// internal pipeline types behind this API prevents evaluation tooling from
// becoming coupled to implementation details.
//
// The primary entry point is Run. Analyze and AnalyzeDetailed are thin
// backward‑compatible wrappers around it.
package evalrunner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/pipeline"
	"mega-analyzer/pkg/logger"
)

// ManifestFile is the corpus‑relative path of the Android manifest. If the
// corpus does not contain it, DefaultManifest is injected so the pipeline
// always has a valid application root.
const ManifestFile = "AndroidManifest.xml"

// DefaultManifest is the minimal manifest injected when the corpus lacks one.
const DefaultManifest = `<manifest package="eval.app"><application /></manifest>`

// ErrEmptyCorpus is returned when Run is invoked with no files.
var ErrEmptyCorpus = errors.New("evalrunner: empty corpus")

// FindingLocation is one detected finding's category plus its source
// location. Line numbers are 1-based and refer to the corpus file content
// (for smali AST detectors this is the physical line of the call site).
//
// File is always corpus‑relative and slash‑separated, regardless of the OS
// the pipeline ran on, so golden files stay portable.
type FindingLocation struct {
	Category string
	File     string
	Line     int
	Method   string
}

// String renders the location in a grep‑friendly "file:line category [method]" form.
func (l FindingLocation) String() string {
	var b strings.Builder
	if l.File != "" {
		b.WriteString(l.File)
		if l.Line > 0 {
			fmt.Fprintf(&b, ":%d", l.Line)
		}
		b.WriteByte(' ')
	}
	b.WriteString(l.Category)
	if l.Method != "" {
		fmt.Fprintf(&b, " [%s]", l.Method)
	}
	return b.String()
}

// Result is the outcome of one pipeline run over a corpus.
type Result struct {
	// Categories is the set of detected categories.
	Categories map[string]bool
	// Locations lists every (category, location) pair, sorted deterministically
	// by category, file, line, method. Findings without a location contribute
	// one entry with empty File/Line/Method.
	Locations []FindingLocation
	// FindingCount is the raw number of findings reported by the pipeline
	// (a single finding may produce several Locations).
	FindingCount int
	// Duration is wall‑clock time of the pipeline run (excluding corpus setup).
	Duration time.Duration
}

// Has reports whether the category was detected.
func (r *Result) Has(category string) bool {
	return r != nil && r.Categories[category]
}

// CategoryList returns detected categories in sorted order.
func (r *Result) CategoryList() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.Categories))
	for c := range r.Categories {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// LocationsFor returns all locations where the category fired.
func (r *Result) LocationsFor(category string) []FindingLocation {
	if r == nil {
		return nil
	}
	var out []FindingLocation
	for _, l := range r.Locations {
		if l.Category == category {
			out = append(out, l)
		}
	}
	return out
}

// FiredAt reports whether the category fired in file within the inclusive
// line range [from, to]. A to value <= 0 means "no upper bound"; from <= 0
// means "no lower bound". file is matched after slash normalisation.
func (r *Result) FiredAt(category, file string, from, to int) bool {
	if r == nil {
		return false
	}
	file = filepath.ToSlash(file)
	for _, l := range r.Locations {
		if l.Category != category || l.File != file {
			continue
		}
		if from > 0 && l.Line < from {
			continue
		}
		if to > 0 && l.Line > to {
			continue
		}
		return true
	}
	return false
}

// Option customises a Run.
type Option func(*options)

type options struct {
	workers   int
	manifest  string
	tempRoot  string
	verbose   bool
	configure []func(*config.Config)
}

// WithWorkers sets the pipeline worker count (default 1 for determinism).
func WithWorkers(n int) Option {
	return func(o *options) {
		if n > 0 {
			o.workers = n
		}
	}
}

// WithManifest overrides the manifest injected when the corpus lacks one.
func WithManifest(xml string) Option {
	return func(o *options) { o.manifest = xml }
}

// WithTempRoot places the scratch corpus directory under dir instead of the
// OS temp directory (useful for tmpfs or debugging).
func WithTempRoot(dir string) Option {
	return func(o *options) { o.tempRoot = dir }
}

// WithVerboseLogging leaves the global logger level untouched. By default the
// runner silences everything below ErrorLevel to keep eval output clean.
func WithVerboseLogging() Option {
	return func(o *options) { o.verbose = true }
}

// WithConfig applies fn to the pipeline config after the eval defaults have
// been set, allowing individual features (call graph, deobfuscation, …) to be
// re‑enabled for targeted evaluations.
func WithConfig(fn func(*config.Config)) Option {
	return func(o *options) {
		if fn != nil {
			o.configure = append(o.configure, fn)
		}
	}
}

// Analyze runs the pipeline over the given corpus files and reports which
// categories were detected. Kept for backward compatibility; prefer Run.
func Analyze(files map[string]string) (map[string]bool, error) {
	res, err := Run(context.Background(), files)
	if err != nil {
		return nil, err
	}
	return res.Categories, nil
}

// AnalyzeDetailed runs the pipeline and returns both the detected category
// set and the per-finding locations. Kept for backward compatibility; prefer Run.
func AnalyzeDetailed(files map[string]string) (map[string]bool, []FindingLocation, error) {
	res, err := Run(context.Background(), files)
	if err != nil {
		return nil, nil, err
	}
	return res.Categories, res.Locations, nil
}

// Run materialises files (corpus‑relative slash paths → content) into a
// scratch directory, executes the pipeline with evaluation‑friendly defaults
// and returns a normalised Result. The scratch directory is always removed.
func Run(ctx context.Context, files map[string]string, opts ...Option) (*Result, error) {
	if len(files) == 0 {
		return nil, ErrEmptyCorpus
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	o := options{workers: 1, manifest: DefaultManifest}
	for _, opt := range opts {
		opt(&o)
	}

	root, err := os.MkdirTemp(o.tempRoot, "mega-analyzer-eval-*")
	if err != nil {
		return nil, fmt.Errorf("evalrunner: create scratch dir: %w", err)
	}
	defer os.RemoveAll(root)

	if err := materialize(root, files, o.manifest); err != nil {
		return nil, err
	}

	if !o.verbose {
		logger.Get().SetLevel(logger.ErrorLevel)
	}

	cfg := config.DefaultConfig()
	cfg.Workers = o.workers
	cfg.EnableContentCache = false
	cfg.EnableCallGraph = false
	cfg.EnableDeobfuscation = false
	cfg.EnableCrackPointAnalysis = false
	cfg.EnableAnomalyDetection = false
	for _, fn := range o.configure {
		fn(cfg)
	}

	scanner, err := pipeline.NewPipeline(cfg)
	if err != nil {
		return nil, fmt.Errorf("evalrunner: build pipeline: %w", err)
	}

	start := time.Now()
	out, err := scanner.Run(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("evalrunner: pipeline run: %w", err)
	}

	res := &Result{
		Categories:   make(map[string]bool, len(out.Findings)),
		Locations:    make([]FindingLocation, 0, len(out.Findings)),
		FindingCount: len(out.Findings),
		Duration:     time.Since(start),
	}
	for _, f := range out.Findings {
		res.Categories[f.Category] = true
		if len(f.Locations) == 0 {
			res.Locations = append(res.Locations, FindingLocation{Category: f.Category})
			continue
		}
		for _, loc := range f.Locations {
			res.Locations = append(res.Locations, FindingLocation{
				Category: f.Category,
				File:     relativize(root, loc.File),
				Line:     loc.Line,
				Method:   loc.Method,
			})
		}
	}
	sortLocations(res.Locations)
	return res, nil
}

// LoadCorpus reads every regular file under dir into a corpus map keyed by
// slash‑separated relative path, ready to be passed to Run. Hidden entries
// (dot‑prefixed) are skipped.
func LoadCorpus(dir string) (map[string]string, error) {
	files := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if path != dir && strings.HasPrefix(name, ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = string(body)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("evalrunner: load corpus %q: %w", dir, err)
	}
	return files, nil
}

// materialize writes the corpus under root in deterministic order, rejecting
// any path that would escape root, and injects the manifest if absent.
func materialize(root string, files map[string]string, manifest string) error {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	hasManifest := false
	for _, name := range names {
		path, err := safeJoin(root, name)
		if err != nil {
			return err
		}
		if filepath.ToSlash(filepath.Clean(name)) == ManifestFile {
			hasManifest = true
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("evalrunner: mkdir for %q: %w", name, err)
		}
		if err := os.WriteFile(path, []byte(files[name]), 0o644); err != nil {
			return fmt.Errorf("evalrunner: write %q: %w", name, err)
		}
	}
	if !hasManifest && manifest != "" {
		path := filepath.Join(root, ManifestFile)
		if err := os.WriteFile(path, []byte(manifest), 0o644); err != nil {
			return fmt.Errorf("evalrunner: write default manifest: %w", err)
		}
	}
	return nil
}

// safeJoin joins rel onto root, guaranteeing the result stays inside root.
func safeJoin(root, rel string) (string, error) {
	if strings.TrimSpace(rel) == "" {
		return "", errors.New("evalrunner: empty corpus path")
	}
	// Corpus keys can come from either Windows or Unix. Treat both separators
	// consistently even when evaluating a Windows corpus on a Unix host.
	portable := strings.ReplaceAll(rel, `\`, "/")
	// filepath.VolumeName only recognises drive prefixes on Windows. Reject
	// both drive-absolute and drive-relative keys on every host instead.
	if len(portable) >= 2 && portable[1] == ':' &&
		(portable[0] >= 'A' && portable[0] <= 'Z' || portable[0] >= 'a' && portable[0] <= 'z') {
		return "", fmt.Errorf("evalrunner: corpus path %q escapes root", rel)
	}
	clean := filepath.Clean(filepath.FromSlash(portable))
	sep := string(filepath.Separator)
	if filepath.IsAbs(clean) ||
		// Volume-less rooted paths ("\x" on Windows): IsAbs reports false
		// for them, and Join would silently fold "/x" and "x" onto the same
		// file. Reject instead of aliasing two corpus keys to one path.
		strings.HasPrefix(clean, sep) ||
		filepath.VolumeName(clean) != "" ||
		clean == ".." ||
		strings.HasPrefix(clean, ".."+sep) {
		return "", fmt.Errorf("evalrunner: corpus path %q escapes root", rel)
	}
	return filepath.Join(root, clean), nil
}

// relativize converts a pipeline‑reported path into a corpus‑relative,
// slash‑separated path. Paths outside root are returned slash‑normalised as is.
func relativize(root, file string) string {
	if file == "" {
		return ""
	}
	if filepath.IsAbs(file) {
		if rel, err := filepath.Rel(root, file); err == nil &&
			rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(file)
}

func sortLocations(locs []FindingLocation) {
	sort.Slice(locs, func(i, j int) bool {
		a, b := locs[i], locs[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Method < b.Method
	})
}
