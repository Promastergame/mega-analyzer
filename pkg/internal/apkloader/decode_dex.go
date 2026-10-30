package apkloader

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// parseMultiDEXParallel is used only by explicit DecodeAPK operations.
// Normal analysis never calls it and keeps classes*.dex intact.
func (e *Extractor) parseMultiDEXParallel(ctx context.Context, dexFiles []string, outputDir string) error {
	return e.parseMultiDEXWithOptions(ctx, dexFiles, outputDir, smaliOutputOptions{
		cache: true, headers: !DisableSmaliHeaders.Load(),
	})
}

func (e *Extractor) parseMultiDEXWithOptions(ctx context.Context, dexFiles []string, outputDir string, opts smaliOutputOptions) error {
	if len(dexFiles) == 0 {
		return ctx.Err()
	}
	var failuresMu sync.Mutex
	var failures []error
	recordFailure := func(err error) { failuresMu.Lock(); failures = append(failures, err); failuresMu.Unlock() }
	ncpu := runtime.GOMAXPROCS(0)
	if ncpu < 1 {
		ncpu = 1
	}
	parseWorkers := ncpu
	if parseWorkers > len(dexFiles) {
		parseWorkers = len(dexFiles)
	}
	if parseWorkers > 8 {
		parseWorkers = 8
	}
	genWorkers := ncpu / 2
	if genWorkers < 1 {
		genWorkers = 1
	}
	if genWorkers > len(dexFiles) {
		genWorkers = len(dexFiles)
	}
	if genWorkers > 4 {
		genWorkers = 4
	}
	classWorkers := ncpu / genWorkers
	if classWorkers < 2 {
		classWorkers = 2
	}
	if classWorkers > 16 {
		classWorkers = 16
	}

	var cacheDB *smaliCacheDBHandle
	if opts.cache {
		cacheDB = openSmaliCacheDB(outputDir)
		opts.cacheDB = cacheDB
	}

	type dexResult struct {
		parser *DEXParser
		path   string
		name   string
	}

	jobs := make(chan string, len(dexFiles))
	for _, f := range dexFiles {
		jobs <- f
	}
	close(jobs)
	parsed := make(chan dexResult, parseWorkers)

	var parseWG sync.WaitGroup
	for w := 0; w < parseWorkers; w++ {
		parseWG.Add(1)
		go func() {
			defer parseWG.Done()
			for path := range jobs {
				if ctx.Err() != nil {
					return
				}
				parser, err := ParseDEXContext(ctx, path)
				if err != nil {
					e.warn("skip DEX %s: %v", filepath.Base(path), err)
					recordFailure(fmt.Errorf("decode %s: %w", filepath.Base(path), err))
					continue
				}
				parsed <- dexResult{parser: parser, path: path, name: filepath.Base(path)}
			}
		}()
	}
	go func() {
		parseWG.Wait()
		close(parsed)
	}()

	var genWG sync.WaitGroup
	for w := 0; w < genWorkers; w++ {
		genWG.Add(1)
		go func() {
			defer genWG.Done()
			for result := range parsed {
				smaliDir := filepath.Join(outputDir, smaliDirNameForDEX(result.name))
				err := e.generateSmaliOutput(ctx, result.parser, smaliDir, classWorkers, opts)
				if err != nil {
					e.warn("smali gen from %s: %v", result.name, err)
					recordFailure(fmt.Errorf("generate %s: %w", result.name, err))
				}
				_ = result.parser.Close()
			}
		}()
	}
	genWG.Wait()
	if cacheDB != nil {
		if err := cacheDB.Save(0, 0); err != nil {
			e.warn("smali cache save: %v", err)
		}
	}
	e.ensurePlaceholderManifest(outputDir)
	return errors.Join(append(failures, ctx.Err())...)
}

func (e *Extractor) parseMultiDEXParallelCached(ctx context.Context, dexFiles []string, outputDir string, useCache bool) error {
	return e.parseMultiDEXWithOptions(ctx, dexFiles, outputDir, smaliOutputOptions{
		cache: useCache, headers: !DisableSmaliHeaders.Load(),
	})
}

func smaliDirNameForDEX(name string) string {
	name = strings.ToLower(filepath.Base(name))
	if name == "classes.dex" {
		return "smali"
	}
	if strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex") {
		suffix := strings.TrimSuffix(strings.TrimPrefix(name, "classes"), ".dex")
		if suffix != "" {
			return "smali_classes" + suffix
		}
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	return "smali_" + sanitizeWindowsPath(base)
}
