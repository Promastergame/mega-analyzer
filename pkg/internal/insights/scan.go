package insights

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type LoadOptions struct {
	MaxBytesPerFile int64
	MaxTotalBytes   int64
	MaxFiles        int
	IncludeBinary   bool
	// RequireComplete fails instead of comparing a silently truncated sample.
	RequireComplete bool
}

type ScannedFile struct {
	Path string
	Data []byte
	Size int64
}

var urlPattern = regexp.MustCompile(`https?://[^\s"'<>\)]+`)
var permissionPattern = regexp.MustCompile(`android\.permission\.[A-Z0-9_]+`)

const (
	defaultMaxBytesPerFile int64 = 8 << 20
	defaultMaxTotalBytes   int64 = 256 << 20
	defaultMaxFiles              = 4096
)

var errLoadBudgetExhausted = errors.New("insights load budget exhausted")
var ErrIncompleteInput = errors.New("insights input is incomplete")

func normalizedLoadOptions(opts LoadOptions) LoadOptions {
	if opts.MaxBytesPerFile <= 0 {
		opts.MaxBytesPerFile = defaultMaxBytesPerFile
	}
	if opts.MaxTotalBytes <= 0 {
		opts.MaxTotalBytes = defaultMaxTotalBytes
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = defaultMaxFiles
	}
	return opts
}

func LoadFiles(root string, opts LoadOptions) ([]ScannedFile, error) {
	opts = normalizedLoadOptions(opts)
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return loadDir(root, opts)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("insights requires a regular file or directory: %s", root)
	}
	prefix, err := readPrefix(root, 4)
	if err != nil {
		return nil, err
	}
	if looksZip(root, prefix) {
		return loadZip(root, opts)
	}
	if looksTar(root) || looksTarGZ(root) {
		return loadTar(root, opts)
	}
	data, truncated, err := readCapped(root, min64(opts.MaxBytesPerFile, opts.MaxTotalBytes))
	if err != nil {
		return nil, err
	}
	if truncated && opts.RequireComplete {
		return nil, fmt.Errorf("%w: size limit for %s", ErrIncompleteInput, root)
	}
	return []ScannedFile{{Path: filepath.ToSlash(filepath.Base(root)), Data: data, Size: info.Size()}}, nil
}

func loadDir(root string, opts LoadOptions) ([]ScannedFile, error) {
	var out []ScannedFile
	var used int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if opts.RequireComplete {
				return err
			}
			return nil
		}
		if info.IsDir() {
			name := strings.ToLower(info.Name())
			if name == ".git" || name == "target" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			if opts.RequireComplete {
				return fmt.Errorf("%w: non-regular file %s", ErrIncompleteInput, path)
			}
			return nil
		}
		if len(out) >= opts.MaxFiles || used >= opts.MaxTotalBytes {
			return errLoadBudgetExhausted
		}
		if info.Size() > opts.MaxBytesPerFile && !opts.IncludeBinary {
			if opts.RequireComplete {
				return fmt.Errorf("%w: size limit for %s", ErrIncompleteInput, path)
			}
			return nil
		}
		data, truncated, err := readCapped(path, min64(opts.MaxBytesPerFile, opts.MaxTotalBytes-used))
		if err != nil {
			if opts.RequireComplete {
				return err
			}
			return nil
		}
		if truncated && opts.RequireComplete {
			return fmt.Errorf("%w: size limit for %s", ErrIncompleteInput, path)
		}
		if !opts.IncludeBinary && !isLikelyText(data) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		out = append(out, ScannedFile{Path: filepath.ToSlash(rel), Data: data, Size: info.Size()})
		used += int64(len(data))
		return nil
	})
	if errors.Is(err, errLoadBudgetExhausted) {
		if opts.RequireComplete {
			err = fmt.Errorf("%w: file count or total byte limit", ErrIncompleteInput)
		} else {
			err = nil
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}

func loadZip(path string, opts LoadOptions) ([]ScannedFile, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out := make([]ScannedFile, 0, min(len(zr.File), opts.MaxFiles))
	var used int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if len(out) >= opts.MaxFiles || used >= opts.MaxTotalBytes {
			if opts.RequireComplete {
				return out, fmt.Errorf("%w: file count or total byte limit", ErrIncompleteInput)
			}
			break
		}
		if f.UncompressedSize64 > uint64(opts.MaxBytesPerFile) && !opts.IncludeBinary {
			if opts.RequireComplete {
				return out, fmt.Errorf("%w: size limit for %s", ErrIncompleteInput, f.Name)
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			if opts.RequireComplete {
				return out, err
			}
			continue
		}
		data, truncated, readErr := readReaderCapped(rc, min64(opts.MaxBytesPerFile, opts.MaxTotalBytes-used))
		rc.Close()
		if readErr != nil {
			if opts.RequireComplete {
				return out, readErr
			}
			continue
		}
		if truncated && opts.RequireComplete {
			return out, fmt.Errorf("%w: size limit for %s", ErrIncompleteInput, f.Name)
		}
		if !opts.IncludeBinary && !isLikelyText(data) {
			continue
		}
		out = append(out, ScannedFile{Path: filepath.ToSlash(f.Name), Data: data, Size: int64(f.UncompressedSize64)})
		used += int64(len(data))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func loadTar(path string, opts LoadOptions) ([]ScannedFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if looksTarGZ(path) {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	var out []ScannedFile
	var used int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		if hdr.FileInfo().IsDir() || hdr.Size <= 0 {
			continue
		}
		if len(out) >= opts.MaxFiles || used >= opts.MaxTotalBytes {
			if opts.RequireComplete {
				return out, fmt.Errorf("%w: file count or total byte limit", ErrIncompleteInput)
			}
			break
		}
		if hdr.Size > opts.MaxBytesPerFile && !opts.IncludeBinary {
			if opts.RequireComplete {
				return out, fmt.Errorf("%w: size limit for %s", ErrIncompleteInput, hdr.Name)
			}
			continue
		}
		data, truncated, readErr := readReaderCapped(tr, min64(opts.MaxBytesPerFile, opts.MaxTotalBytes-used))
		if readErr != nil {
			if opts.RequireComplete {
				return out, readErr
			}
			continue
		}
		if truncated && opts.RequireComplete {
			return out, fmt.Errorf("%w: size limit for %s", ErrIncompleteInput, hdr.Name)
		}
		if !opts.IncludeBinary && !isLikelyText(data) {
			continue
		}
		out = append(out, ScannedFile{Path: filepath.ToSlash(hdr.Name), Data: data, Size: hdr.Size})
		used += int64(len(data))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func readPrefix(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// readCapped never allocates based on the source file's declared size.
func readCapped(path string, limit int64) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	return readReaderCapped(f, limit)
}

func readReaderCapped(r io.Reader, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		return nil, true, nil
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

func looksZip(path string, data []byte) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".apk" || ext == ".zip" || ext == ".jar" || ext == ".aar" {
		return true
	}
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K'
}

func looksTar(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".tar"
}

func looksTarGZ(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
}

func isLikelyText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	limit := len(data)
	if limit > 4096 {
		limit = 4096
	}
	if bytes.IndexByte(data[:limit], 0) >= 0 {
		return false
	}
	bad := 0
	for _, b := range data[:limit] {
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			bad++
		}
	}
	return bad*100/limit < 10
}

func lineNumber(data []byte, idx int) int {
	if idx < 0 {
		return 0
	}
	if idx > len(data) {
		idx = len(data)
	}
	return 1 + bytes.Count(data[:idx], []byte{'\n'})
}

func lineAt(data []byte, n int) string {
	if n <= 0 {
		return ""
	}
	lines := bytes.Split(data, []byte{'\n'})
	if n > len(lines) {
		return ""
	}
	return strings.TrimSpace(string(lines[n-1]))
}

func extractURLs(data []byte) []string {
	matches := urlPattern.FindAll(data, -1)
	out := make([]string, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		s := strings.TrimRight(string(m), `.,;]}`)
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func extractPermissions(data []byte) []string {
	matches := permissionPattern.FindAll(data, -1)
	out := make([]string, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		s := string(m)
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func extractASCIIStrings(data []byte, minLen int) []string {
	if minLen <= 0 {
		minLen = 4
	}
	var out []string
	start := -1
	for i, b := range data {
		if b >= 32 && b <= 126 {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minLen {
			out = append(out, string(data[start:i]))
		}
		start = -1
	}
	if start >= 0 && len(data)-start >= minLen {
		out = append(out, string(data[start:]))
	}
	return out
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func setDiff(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, s := range b {
		mb[s] = struct{}{}
	}
	var out []string
	for _, s := range a {
		if _, ok := mb[s]; !ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func limitStrings(in []string, n int) []string {
	if n <= 0 || len(in) <= n {
		return in
	}
	out := make([]string, n)
	copy(out, in[:n])
	return out
}
