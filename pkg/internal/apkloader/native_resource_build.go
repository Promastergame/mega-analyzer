package apkloader

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"sort"

	"mega-analyzer/pkg/internal/apkloader/axml"
)

func (r *APKRebuilder) compileNativeResources(ctx context.Context, linkedPath string) error {
	compiled, err := axml.CompileResourceDirectory(ctx, r.SourceDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(linkedPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(linkedPath), "R.txt"), []byte(compiled.Symbols), 0644); err != nil {
		return err
	}
	f, err := os.Create(linkedPath)
	if err != nil {
		return err
	}
	defer f.Close()
	z := zip.NewWriter(f)
	defer z.Close()
	paths := make([]string, 0, len(compiled.Binary))
	for path := range compiled.Binary {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := addBytesToZip(z, compiled.Binary[path], path, r.shouldCompressFile(path)); err != nil {
			return err
		}
	}
	for _, path := range compiled.Copy {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := addFileToZip(z, filepath.Join(r.SourceDir, filepath.FromSlash(path)), path, r.shouldCompressFile(path)); err != nil {
			return err
		}
	}
	if err := z.Close(); err != nil {
		return err
	}
	return f.Close()
}
