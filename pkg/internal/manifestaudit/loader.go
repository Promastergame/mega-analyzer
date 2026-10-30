package manifestaudit

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"mega-analyzer/pkg/internal/apkloader/axml"
)

// LoadManifest reads AndroidManifest.xml from either an APK file or
// an extracted directory and decodes it (binary AXML or plain text).
func LoadManifest(target string) (*axml.Manifest, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("stat target: %w", err)
	}
	if info.IsDir() {
		return loadFromDir(target)
	}
	return loadFromAPK(target)
}

func loadFromDir(root string) (*axml.Manifest, error) {
	candidates := []string{
		filepath.Join(root, "AndroidManifest.xml"),
		filepath.Join(root, "apktool_out", "AndroidManifest.xml"),
		filepath.Join(root, "app", "src", "main", "AndroidManifest.xml"),
	}
	var lastErr error
	for _, c := range candidates {
		data, err := os.ReadFile(c)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			lastErr = err
			continue
		}
		return decodeManifest(data)
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no AndroidManifest.xml found under %s", root)
}

func loadFromAPK(path string) (*axml.Manifest, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open apk: %w", err)
	}
	defer r.Close()
	for _, f := range r.File {
		if filepath.ToSlash(f.Name) != "AndroidManifest.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open manifest entry: %w", err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, 16<<20))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read manifest entry: %w", err)
		}
		return decodeManifest(data)
	}
	return nil, fmt.Errorf("AndroidManifest.xml not found inside %s", path)
}

func decodeManifest(data []byte) (*axml.Manifest, error) {
	if axml.IsBinaryXML(data) {
		return axml.Decode(data)
	}
	return axml.DecodePlainXML(data)
}
