package apkloader

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const smaliBuildCacheFile = ".mega-analyzer-build-cache.json"

type SmaliBuildCache struct {
	Version int                             `json:"version"`
	Entries map[string]SmaliBuildCacheEntry `json:"entries"`
}

type SmaliBuildCacheEntry struct {
	Hash    string `json:"hash"`
	DexPath string `json:"dexPath"`
	Tool    string `json:"tool"`
}

func loadSmaliBuildCache(sourceDir string) SmaliBuildCache {
	c := SmaliBuildCache{Version: 1, Entries: map[string]SmaliBuildCacheEntry{}}
	b, err := os.ReadFile(filepath.Join(sourceDir, smaliBuildCacheFile))
	if err != nil {
		return c
	}
	_ = json.Unmarshal(b, &c)
	if c.Entries == nil {
		c.Entries = map[string]SmaliBuildCacheEntry{}
	}
	return c
}

func saveSmaliBuildCache(sourceDir string, c SmaliBuildCache) {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Entries == nil {
		c.Entries = map[string]SmaliBuildCacheEntry{}
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	_ = os.WriteFile(filepath.Join(sourceDir, smaliBuildCacheFile), b, 0644)
}

func hashSmaliDir(dir string) (string, error) {
	h := sha256.New()
	var files []string
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".smali") {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return "", err
	}
	sort.Strings(files)
	for _, p := range files {
		rel, _ := filepath.Rel(dir, p)
		_, _ = h.Write([]byte(filepath.ToSlash(rel)))
		_, _ = h.Write([]byte{0})
		f, err := os.Open(p)
		if err != nil {
			return "", err
		}
		_, err = io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			return "", err
		}
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
