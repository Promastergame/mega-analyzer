package ipaloader

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FindMainBundle selects only direct Payload/*.app directories. Embedded
// frameworks and extensions cannot supply the application's identity.
func FindMainBundle(ctx context.Context, extractedDir string) (string, error) {
	if err := ctx.Err(); err != nil { return "", err }
	payload := filepath.Join(extractedDir, "Payload")
	entries, err := os.ReadDir(payload)
	if err != nil { return "", fmt.Errorf("read IPA Payload: %w", err) }
	var apps []string
	for _, entry := range entries {
		if err := ctx.Err(); err != nil { return "", err }
		if entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".app") {
			apps = append(apps, filepath.Join(payload, entry.Name()))
		}
	}
	if len(apps) != 1 {
		return "", fmt.Errorf("IPA must contain exactly one main Payload/*.app bundle, found %d", len(apps))
	}
	return apps[0], nil
}

// BundlePlists returns the main plist first, then embedded bundle plists in
// deterministic order. Paths retain their owning bundle for report attribution.
func BundlePlists(ctx context.Context, appDir string) ([]string, error) {
	if err := ctx.Err(); err != nil { return nil, err }
	main := filepath.Join(appDir, "Info.plist")
	info, err := os.Lstat(main)
	if err != nil { return nil, fmt.Errorf("main bundle Info.plist: %w", err) }
	if !info.Mode().IsRegular() { return nil, fmt.Errorf("main bundle Info.plist is not a regular file") }
	paths := []string{main}
	err = filepath.WalkDir(appDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil { return err }
		if walkErr != nil { return walkErr }
		if path != main && entry.Type().IsRegular() && strings.EqualFold(entry.Name(), "Info.plist") {
			paths = append(paths, path)
		}
		return nil
	})
	return paths, err
}
