package assetscan

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// This file walks targets and owns the scanner state. Everything that actually
// looks at bytes - imagedec, media3d and preview - is reached from classify.go,
// which is where those imports live.

// ═══════════════════════════════════════════════════════════════════════════════
// ASSET SCAN
//
// One entry point for the three shapes a target actually comes in: a single
// file, a directory tree, or an archive. APKs, OBBs and nested zips are walked
// in place - unpacking a 400 MB APK to disk just to look at four .glb files is
// the slow way to get the same answer.
//
// Classification order is deliberate. glTF is checked first because a vendor
// .glb can also look like an encrypted blob to a signature scanner, and the
// 3D verdict is strictly more informative. Everything else goes through
// imagedec, so a texture that has been XORed or byte-swapped is reported as
// what it really is rather than as "unknown data".
// ═══════════════════════════════════════════════════════════════════════════════

// Options controls a scan. The zero value is valid.
type Options struct {
	// MaxFileMB skips any single entry larger than this. Default 64.
	MaxFileMB int
	// MaxEntries caps how many assets are reported. Default 5000.
	MaxEntries int
	// MaxDepth limits nested-archive recursion. Default 2.
	MaxDepth int
	// PreviewDir receives rendered PNGs. Empty disables preview rendering.
	PreviewDir string
	// MaxPreviews caps how many PNGs get written. Default 256.
	MaxPreviews int
	// MaxDim caps the longest side of a preview. Default 512.
	MaxDim int
	// Deep widens the recovery search and the embedded-frame scan window.
	Deep bool
	// All reports every file walked, not just the asset-like ones.
	All bool

	// ── suppression switches ────────────────────────────────────────────
	// These exist because an asset scan is exploratory: on a large APK the
	// useful signal is often one of these four layers, and the other three
	// are noise that costs time and disk.

	// NoTextures skips embedded textures inside 3D models. The material map
	// is still reported, so you still learn where the textures would go.
	NoTextures bool
	// MaxTextures caps how many embedded textures one model renders.
	// Default 4.
	MaxTextures int
	// NoBytemap suppresses the byte-map fallback visualisation. Those images
	// are a picture of the bytes, not a decode, and on a scan full of
	// encrypted blobs they crowd out the real decodes.
	NoBytemap bool
	// NoZstd skips inflating zstd payloads, leaving them reported as
	// compressed streams. Useful when a target is mostly large archives.
	NoZstd bool
	// NoASTC skips block-compressed texture decoding. Those payloads have no
	// header, so identifying them means reading the block modes of the whole
	// buffer; on a scan that is already finding what it needs, that work can
	// be turned off.
	NoASTC bool
}

// Normalize fills defaults without mutating the receiver.
func (o Options) Normalize() Options {
	if o.MaxFileMB <= 0 {
		o.MaxFileMB = 64
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 5000
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 2
	}
	if o.MaxPreviews <= 0 {
		o.MaxPreviews = 256
	}
	if o.MaxDim <= 0 {
		o.MaxDim = 512
	}
	if o.MaxTextures <= 0 {
		o.MaxTextures = maxTexturesPerModel
	}
	if o.NoTextures {
		// An explicit suppression beats a cap: keep the two from disagreeing
		// so callers only have to read one of them.
		o.MaxTextures = 0
	}
	return o
}

func (o Options) maxBytes() int64 { return int64(o.MaxFileMB) << 20 }

var threeDExts = map[string]bool{
	".glb": true, ".gltf": true, ".vrm": true, ".vci": true,
}

var archiveExts = map[string]bool{
	".apk": true, ".zip": true, ".obb": true, ".jar": true,
	".aar": true, ".apks": true, ".xapk": true, ".ipa": true,
}

type scanner struct {
	opts     Options
	rep      *Report
	previews int
	slugs    map[string]int
}

// Scan walks target and returns everything it recognises.
func Scan(target string, opts Options) (*Report, error) {
	opts = opts.Normalize()

	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}

	rep := &Report{
		Target:     target,
		ByClass:    map[string]int{},
		Items:      []Item{},
		PreviewDir: opts.PreviewDir,
	}
	s := &scanner{opts: opts, rep: rep, slugs: map[string]int{}}

	if opts.PreviewDir != "" {
		if err := os.MkdirAll(opts.PreviewDir, 0o755); err != nil {
			return nil, fmt.Errorf("preview dir %s: %w", opts.PreviewDir, err)
		}
	}

	if info.IsDir() {
		rep.Root = target
		s.walkDir(target)
	} else {
		rep.Root = filepath.Dir(target)
		name := filepath.Base(target)
		if archiveExts[strings.ToLower(filepath.Ext(name))] || fileStartsWithZip(target) {
			s.walkZipFile(target, name, 0)
		} else if data, tooBig, rerr := readCapped(target, opts.maxBytes()); rerr != nil {
			s.fail(name, rerr)
		} else if tooBig {
			rep.Skipped++
		} else {
			s.consider(name, "", data)
		}
	}

	sort.SliceStable(rep.Items, func(i, j int) bool {
		ai, aj := classRank(rep.Items[i].Class), classRank(rep.Items[j].Class)
		if ai != aj {
			return ai < aj
		}
		return rep.Items[i].Display() < rep.Items[j].Display()
	})
	return rep, nil
}

func classRank(c string) int {
	for i, k := range ClassOrder {
		if k == c {
			return i
		}
	}
	return len(ClassOrder)
}

func (s *scanner) full() bool { return s.rep.Matched >= s.opts.MaxEntries }

func (s *scanner) fail(name string, err error) {
	const maxErrors = 50
	if len(s.rep.Errors) < maxErrors {
		s.rep.Errors = append(s.rep.Errors, fmt.Sprintf("%s: %v", name, err))
	}
}

// readCapped reads a file, refusing rather than truncating when it exceeds the
// cap. A truncated buffer would still produce a confident-looking verdict from
// a header-driven scanner, which is worse than reporting nothing.
func readCapped(p string, max int64) (data []byte, tooBig bool, err error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, false, err
	}
	if st.Size() > max {
		return nil, true, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false, err
	}
	return b, false, nil
}

func fileStartsWithZip(p string) bool {
	fh, err := os.Open(p)
	if err != nil {
		return false
	}
	defer func() { _ = fh.Close() }()
	var head [4]byte
	if _, err := io.ReadFull(fh, head[:]); err != nil {
		return false
	}
	return head[0] == 'P' && head[1] == 'K' && head[2] == 0x03 && head[3] == 0x04
}

func (s *scanner) walkDir(root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			s.fail(p, err)
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".gradle":
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if s.full() {
			return filepath.SkipAll
		}

		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			rel = p
		}
		rel = filepath.ToSlash(rel)

		if archiveExts[strings.ToLower(path.Ext(rel))] {
			s.walkZipFile(p, rel, 0)
			return nil
		}
		data, tooBig, rerr := readCapped(p, s.opts.maxBytes())
		switch {
		case rerr != nil:
			s.fail(rel, rerr)
		case tooBig:
			s.rep.Skipped++
		default:
			s.consider(rel, "", data)
		}
		return nil
	})
}

func (s *scanner) walkZipFile(p, display string, depth int) {
	zr, err := zip.OpenReader(p)
	if err != nil {
		s.fail(display, err)
		return
	}
	defer func() { _ = zr.Close() }()
	s.walkZipEntries(&zr.Reader, display, depth)
}

func (s *scanner) walkZipBytes(data []byte, display string, depth int) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		s.fail(display, err)
		return
	}
	s.walkZipEntries(zr, display, depth)
}

func (s *scanner) walkZipEntries(zr *zip.Reader, container string, depth int) {
	for _, f := range zr.File {
		if s.full() {
			return
		}
		if f.FileInfo().IsDir() {
			continue
		}
		// The declared size is a cheap filter and a lie in a zip bomb, so the
		// actual read below is capped independently.
		if f.UncompressedSize64 > uint64(s.opts.maxBytes()) {
			s.rep.Skipped++
			continue
		}
		data, err := readZipEntry(f, s.opts.maxBytes())
		if err != nil {
			s.fail(container+"!"+f.Name, err)
			continue
		}
		if archiveExts[strings.ToLower(path.Ext(f.Name))] && depth+1 < s.opts.MaxDepth {
			s.walkZipBytes(data, container+"!"+f.Name, depth+1)
			continue
		}
		s.consider(f.Name, container, data)
	}
}

func readZipEntry(f *zip.File, max int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(io.LimitReader(rc, max))
}

func (s *scanner) consider(name, container string, data []byte) {
	s.rep.Scanned++
	it, keep := s.classify(name, container, data)
	if !keep && !s.opts.All {
		return
	}
	s.rep.Matched++
	s.rep.ByClass[it.Class]++
	s.rep.Items = append(s.rep.Items, it)
}
