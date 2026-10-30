// Package scanbus reads an extracted tree or APK once and broadcasts bounded,
// immutable file buffers to multiple analysis consumers.
package scanbus

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const MaxFileBytes int64 = 16 << 20

type File struct {
	Path   string
	Data   []byte
	SHA256 [32]byte
}

// Stream broadcasts every interesting file to every consumer. The same byte
// slice is shared read-only and stays alive until all consumers release it.
// All consumer channels are closed before Stream returns.
func Stream(ctx context.Context, target string, consumers ...chan<- File) error {
	defer func() {
		for _, consumer := range consumers {
			close(consumer)
		}
	}()
	if len(consumers) == 0 {
		return nil
	}
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stat scan target: %w", err)
	}
	files := make(chan File, workerCount()*2)
	errCh := make(chan error, 1)
	go func() {
		defer close(files)
		if info.IsDir() {
			errCh <- streamDirectory(ctx, target, files)
		} else {
			errCh <- streamArchive(ctx, target, files)
		}
	}()

	for file := range files {
		for _, consumer := range consumers {
			select {
			case consumer <- file:
			case <-ctx.Done():
				// Join the producer before callers clean up the input tree or
				// archive (in particular, open ZIP handles on Windows).
				<-errCh
				return ctx.Err()
			}
		}
	}
	if err := <-errCh; err != nil {
		return err
	}
	// A canceled producer can stop without emitting any files. Do not
	// misreport that path as a successful, empty scan.
	return ctx.Err()
}

func streamDirectory(ctx context.Context, root string, out chan<- File) error {
	type job struct{ absolute, relative string }
	jobs := make(chan job, workerCount()*2)
	var wg sync.WaitGroup
	for i := 0; i < workerCount(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				data, err := os.ReadFile(item.absolute)
				if err != nil {
					continue
				}
				file := File{Path: filepath.ToSlash(item.relative), Data: data, SHA256: sha256.Sum256(data)}
				select {
				case out <- file:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > MaxFileBytes || !InterestingPath(path) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		select {
		case jobs <- job{absolute: path, relative: rel}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	close(jobs)
	wg.Wait()
	return walkErr
}

func streamArchive(ctx context.Context, path string, out chan<- File) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("open scan archive: %w", err)
	}
	defer r.Close()
	jobs := make(chan *zip.File, workerCount()*2)
	var wg sync.WaitGroup
	for i := 0; i < workerCount(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range jobs {
				rc, err := entry.Open()
				if err != nil {
					continue
				}
				data, readErr := io.ReadAll(io.LimitReader(rc, MaxFileBytes+1))
				rc.Close()
				if readErr != nil || int64(len(data)) > MaxFileBytes {
					continue
				}
				file := File{Path: filepath.ToSlash(entry.Name), Data: data, SHA256: sha256.Sum256(data)}
				select {
				case out <- file:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	for _, entry := range r.File {
		if entry.FileInfo().IsDir() || int64(entry.UncompressedSize64) > MaxFileBytes || !InterestingPath(entry.Name) {
			continue
		}
		select {
		case jobs <- entry:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	return nil
}

func InterestingPath(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{
		".smali", ".java", ".kt", ".dex", ".xml", ".json", ".txt",
		".properties", ".so", ".html", ".js", ".jsx", ".bundle",
	} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func workerCount() int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 2 {
		workers = 2
	}
	if workers > 8 {
		workers = 8
	}
	return workers
}
