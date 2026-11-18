package apkloader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
)

type DecompileBackend string

const (
	DecompileBackendAuto   DecompileBackend = "auto"
	DecompileBackendNative DecompileBackend = "native"
)

const nativeSmaliEmitterVersion = "native-smali-v5"

type smaliOutputOptions struct {
	cache   bool
	headers bool
	java    bool // emit per-class .java pseudocode sidecars
	cacheDB *smaliCacheDBHandle
}

func (e *Extractor) generateSmaliIntoCached(ctx context.Context, parser *DEXParser, smaliDir string, workersCount int, useCache bool) error {
	return e.generateSmaliOutput(ctx, parser, smaliDir, workersCount, smaliOutputOptions{
		cache: useCache, headers: !DisableSmaliHeaders.Load(),
	})
}

func (e *Extractor) generateSmaliOutput(ctx context.Context, parser *DEXParser, smaliDir string, workersCount int, opts smaliOutputOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if parser == nil {
		return fmt.Errorf("nil DEX parser")
	}
	if err := os.MkdirAll(smaliDir, 0755); err != nil {
		return err
	}
	classes := parser.GetClasses()
	if len(classes) == 0 {
		return fmt.Errorf("no classes found in DEX")
	}
	classPaths, err := planSmaliClassPaths(classes)
	if err != nil {
		return err
	}
	var dexHash string
	var cacheDB *smaliCacheDBHandle
	if opts.cache {
		dexHash = parserContentHash(parser)
		// Synthetic parsers without source bytes have no reliable cache identity.
		if dexHash != "" {
			if opts.headers {
				dexHash += ":headers"
			}
			if opts.cacheDB != nil {
				cacheDB = opts.cacheDB
			} else {
				cacheDB = openSmaliCacheDB(filepath.Dir(smaliDir))
			}
		}
	}
	if workersCount <= 0 {
		workersCount = runtime.GOMAXPROCS(0)
	}
	if workersCount > 16 {
		workersCount = 16
	}
	if workersCount > len(classes) {
		workersCount = len(classes)
	}

	jobs := make(chan *ClassDef, len(classes))
	for _, class := range classes {
		if class != nil && class.ClassName != "" {
			jobs <- class
		}
	}
	close(jobs)
	var wg sync.WaitGroup
	var filesWritten int64
	var filesFailed atomic.Int64
	var firstError error
	var errorOnce sync.Once
	recordError := func(err error) {
		filesFailed.Add(1)
		errorOnce.Do(func() { firstError = err })
	}
	// Classes in the same package share one directory creation, including
	// workers arriving concurrently. Failed creation is reported to every job.
	type directoryState struct {
		once sync.Once
		err  error
	}
	var directories sync.Map
	for i := 0; i < workersCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for class := range jobs {
				if ctx.Err() != nil {
					return
				}
				classPath := classPaths[class.ClassName]
				if classPath == "" {
					recordError(fmt.Errorf("invalid smali class path: %q", class.ClassName))
					continue
				}
				filePath := filepath.Join(smaliDir, classPath+".smali")
				dir := filepath.Dir(filePath)
				state, _ := directories.LoadOrStore(dir, &directoryState{})
				directory := state.(*directoryState)
				directory.once.Do(func() { directory.err = os.MkdirAll(dir, 0755) })
				if directory.err != nil {
					recordError(directory.err)
					continue
				}
				var content string
				var hit bool
				if cacheDB != nil {
					content, hit = cacheDB.Get(dexHash, class.ClassName)
				}
				if !hit {
					content = string(generateSmaliClassBytesWithHeaders(class, parser, opts.headers))
				}
				if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
					recordError(err)
					continue
				}
				if cacheDB != nil && !hit {
					cacheDB.Put(dexHash, class.ClassName, content)
				}
				if opts.java {
					javaPath := filepath.Join(smaliDir, classPath+".java")
					if err := os.WriteFile(javaPath, []byte(GenerateJavaClass(class, parser)), 0644); err != nil {
						e.warn("java view for %s: %v", class.ClassName, err)
					}
				}
				atomic.AddInt64(&filesWritten, 1)
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if failed := filesFailed.Load(); failed > 0 {
		return fmt.Errorf("failed to write %d smali files (%d written): %w", failed, filesWritten, firstError)
	}
	if cacheDB != nil && opts.cacheDB == nil {
		if err := cacheDB.Save(0, 0); err != nil {
			e.warn("smali cache save: %v", err)
		}
	}
	if filesWritten == 0 {
		return fmt.Errorf("failed to write any smali files (%d classes found)", len(classes))
	}
	return saveSmaliClassPaths(smaliDir, classPaths)
}

func classSmaliRelPath(className string) string {
	classPath := strings.TrimPrefix(className, "L")
	classPath = strings.TrimSuffix(classPath, ";")
	// Validate before sanitizing reserved Windows names. A DEX descriptor
	// must not escape the output tree or resolve to a parent directory.
	for _, part := range strings.Split(strings.ReplaceAll(classPath, "\\", "/"), "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, ":\x00") {
			return ""
		}
	}
	classPath = sanitizeWindowsPath(classPath)
	if !filepath.IsLocal(classPath) {
		return ""
	}
	return filepath.FromSlash(classPath)
}

func parserContentHash(parser *DEXParser) string {
	if parser == nil {
		return ""
	}
	return parser.GetDEXHashHex()
}
