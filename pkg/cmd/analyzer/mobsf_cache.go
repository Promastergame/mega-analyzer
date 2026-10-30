package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const mobSFCacheSchema = "mobsf-results-v2"

type mobSFCache struct {
	dir string
}

type mobSFCacheEnvelope struct {
	Schema  string          `json:"schema"`
	Module  string          `json:"module"`
	Payload json.RawMessage `json:"payload"`
}

// newMobSFCache enables safe content-addressed caching when an immutable APK
// is available. Extracted-directory-only runs stay uncached to avoid an extra
// full tree read before the first scan.
func newMobSFCache(outputDir, originalAPKPath, target string) *mobSFCache {
	source := originalAPKPath
	if source == "" {
		if info, err := os.Stat(target); err == nil && !info.IsDir() {
			source = target
		}
	}
	if source == "" {
		return nil
	}
	digest, err := hashFile(source)
	if err != nil {
		return nil
	}
	keyMaterial := append([]byte(mobSFCacheSchema+":"), digest[:]...)
	key := sha256.Sum256(keyMaterial)
	return &mobSFCache{dir: filepath.Join(outputDir, ".cache", "mobsf", hex.EncodeToString(key[:]))}
}

func hashFile(path string) ([32]byte, error) {
	var zero [32]byte
	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, 256<<10)); err != nil {
		return zero, err
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func (c *mobSFCache) load(module string, target any) bool {
	if c == nil || target == nil {
		return false
	}
	data, err := os.ReadFile(filepath.Join(c.dir, module+".json"))
	if err != nil {
		return false
	}
	var envelope mobSFCacheEnvelope
	if json.Unmarshal(data, &envelope) != nil || envelope.Schema != mobSFCacheSchema || envelope.Module != module {
		return false
	}
	return json.Unmarshal(envelope.Payload, target) == nil
}

func (c *mobSFCache) has(module string) bool {
	if c == nil {
		return false
	}
	_, err := os.Stat(filepath.Join(c.dir, module+".json"))
	return err == nil
}

func (c *mobSFCache) save(module string, value any) error {
	if c == nil {
		return nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data, err := json.Marshal(mobSFCacheEnvelope{Schema: mobSFCacheSchema, Module: module, Payload: payload})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(c.dir, module+".json")
	tmp, err := os.CreateTemp(c.dir, module+"-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		// Windows does not replace an existing destination with os.Rename.
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("replace cache: %w", err)
		}
		if retryErr := os.Rename(tmpPath, path); retryErr != nil {
			return fmt.Errorf("commit cache: %w", retryErr)
		}
	}
	return nil
}
