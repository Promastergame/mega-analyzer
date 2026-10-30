package apkloader

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// Magic byte sequences for supported formats.
var (
	magicDEX  = []byte{'d', 'e', 'x', '\n'}
	magicODEX = []byte{'d', 'e', 'y', '\n'}
	magicVDEX = []byte{'v', 'd', 'e', 'x'}
	magicART  = []byte{'a', 'r', 't', '\n'}
	magicZIP  = []byte{'P', 'K', 0x03, 0x04}
	magicEOCD = []byte{'P', 'K', 0x05, 0x06}
	magicSpan = []byte{'P', 'K', 0x07, 0x08}
)

// cacheSystemDirs — known Android runtime directories.
// Checked by exact path segment match — not substring.
var cacheSystemDirs = map[string]struct{}{
	"dalvik-cache": {},
	"code_cache":   {},
	"oat":          {},
	"odex":         {},
}

// cacheExtensions — compiled runtime artifacts.
var cacheExtensions = map[string]struct{}{
	".vdex": {},
	".odex": {},
	".oat":  {},
	".art":  {},
	".prof": {},
}

// DetectInputType determines the type of the given path.
func DetectInputType(path string) (InputType, error) {
	info, err := os.Stat(path)
	if err != nil {
		return InputTypeUnknown, &LoaderError{Op: "detect", Path: path, err: err}
	}

	if info.IsDir() {
		return detectDirectory(path)
	}

	return detectFile(path)
}

func detectDirectory(path string) (InputType, error) {
	if hasSmaliFiles(path) {
		return InputTypeSmaliFolder, nil
	}
	if hasCacheArtifacts(path, 0) {
		return InputTypeCacheFolder, nil
	}
	return InputTypeUnknown, &LoaderError{Op: "detect", Path: path, err: errNoSmali}
}

func detectFile(path string) (InputType, error) {
	if ft, err := detectByMagic(path); err == nil && ft != InputTypeUnknown {
		return normalizeArchiveType(strings.ToLower(path), ft), nil
	}

	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".apk"),
		strings.HasSuffix(lower, ".xapk"),
		strings.HasSuffix(lower, ".apks"),
		strings.HasSuffix(lower, ".apkm"),
		strings.HasSuffix(lower, ".aab"):
		return InputTypeAPKFile, nil

	case strings.HasSuffix(lower, ".obb"),
		strings.HasSuffix(lower, ".ipa"),
		strings.HasSuffix(lower, ".zip"),
		strings.HasSuffix(lower, ".jar"),
		strings.HasSuffix(lower, ".war"),
		strings.HasSuffix(lower, ".ear"),
		strings.HasSuffix(lower, ".aar"):
		return InputTypeArchiveFile, nil

	case strings.HasSuffix(lower, ".dex"):
		return InputTypeDEXFile, nil

	case strings.HasSuffix(lower, ".vdex"),
		strings.HasSuffix(lower, ".odex"),
		strings.HasSuffix(lower, ".art"),
		strings.HasSuffix(lower, ".oat"):
		return InputTypeDEXFile, nil

	case strings.HasSuffix(lower, ".patch"),
		strings.HasSuffix(lower, ".diff"):
		return InputTypePatchFile, nil
	}

	return InputTypeUnknown, &LoaderError{Op: "detect", Path: path, err: errUnknownFormat}
}

// detectByMagic identifies file type by magic bytes.
// Returns (InputTypeUnknown, nil) when file is valid but unrecognized,
// or when file is too small — caller falls back to extension detection.
func detectByMagic(path string) (InputType, error) {
	f, err := os.Open(path)
	if err != nil {
		return InputTypeUnknown, err
	}
	defer f.Close()

	buf := make([]byte, 4)
	n, err := f.Read(buf)
	if err != nil || n < 4 {
		return InputTypeUnknown, nil
	}

	switch {
	case bytes.Equal(buf, magicDEX):
		return InputTypeDEXFile, nil
	case bytes.Equal(buf, magicODEX):
		return InputTypeDEXFile, nil
	case bytes.Equal(buf, magicVDEX):
		return InputTypeDEXFile, nil
	case bytes.Equal(buf, magicART):
		return InputTypeDEXFile, nil
	case bytes.Equal(buf, magicZIP),
		bytes.Equal(buf, magicEOCD),
		bytes.Equal(buf, magicSpan):
		return InputTypeArchiveFile, nil
	}

	return InputTypeUnknown, nil
}

func normalizeArchiveType(pathLower string, detected InputType) InputType {
	if detected != InputTypeArchiveFile {
		return detected
	}
	switch {
	case strings.HasSuffix(pathLower, ".apk"),
		strings.HasSuffix(pathLower, ".xapk"),
		strings.HasSuffix(pathLower, ".apks"),
		strings.HasSuffix(pathLower, ".apkm"),
		strings.HasSuffix(pathLower, ".aab"):
		return InputTypeAPKFile
	default:
		return InputTypeArchiveFile
	}
}

// hasSmaliFiles reports whether dir contains smali sources.
// Uses WalkDir with early exit; depth bounded by maxSmaliDepth.
func hasSmaliFiles(dir string) bool {
	const maxSmaliDepth = 4

	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}

		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return nil
		}
		depth := strings.Count(rel, string(os.PathSeparator))

		if d.IsDir() {
			if depth >= maxSmaliDepth {
				return filepath.SkipDir
			}
			name := d.Name()
			if name == "smali" || strings.HasPrefix(name, "smali_") {
				found = true
				return filepath.SkipAll
			}
			return nil
		}

		if strings.HasSuffix(d.Name(), ".smali") {
			found = true
			return filepath.SkipAll
		}

		return nil
	})

	return found
}

// hasCacheArtifacts reports whether dir contains Android runtime cache
// artifacts. Bounded to maxDepth levels to avoid expensive traversals.
func hasCacheArtifacts(dir string, depth int) bool {
	const maxDepth = 3
	if depth > maxDepth {
		return false
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	for _, e := range entries {
		name := strings.ToLower(e.Name())

		if e.IsDir() {
			if _, known := cacheSystemDirs[name]; known {
				return true
			}
			if hasCacheArtifacts(filepath.Join(dir, e.Name()), depth+1) {
				return true
			}
			continue
		}

		ext := strings.ToLower(filepath.Ext(name))
		if _, known := cacheExtensions[ext]; known {
			return true
		}
	}

	return false
}

// isCachePath reports whether the given absolute path passes through
// a known Android cache directory segment.
// Normalizes separators to forward slashes before splitting —
// required for correct behaviour on Windows.
func isCachePath(absPath string) bool {
	// Replace both slash styles so Windows paths work on any host OS.
	normalized := strings.ReplaceAll(strings.ToLower(absPath), "\\", "/")
	segments := strings.Split(normalized, "/")
	for _, seg := range segments {
		if _, ok := cacheSystemDirs[seg]; ok {
			return true
		}
	}
	return false
}

// isCacheExtension reports whether the filename carries a cache artifact extension.
func isCacheExtension(lname string) bool {
	_, ok := cacheExtensions[strings.ToLower(filepath.Ext(lname))]
	return ok
}
