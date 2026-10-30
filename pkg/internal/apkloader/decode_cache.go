package apkloader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	decodeCacheSchema = 4
	decodeCacheFile   = ".mega-analyzer-decode-cache.json"
)

var decodeCacheWriteMu sync.Mutex

type decodeCacheMetadata struct {
	Schema         int              `json:"schema"`
	APKHash        string           `json:"apk_sha256"`
	NoResources    bool             `json:"no_resources"`
	NoSmali        bool             `json:"no_smali"`
	CopyOriginal   bool             `json:"copy_original"`
	FrameworkDir   string           `json:"framework_dir,omitempty"`
	BaksmaliJar    string           `json:"baksmali_jar,omitempty"`
	DexBackend     DecompileBackend `json:"dex_backend,omitempty"`
	NoSmaliHeaders bool             `json:"no_smali_headers"`
	SmaliHeaders   bool             `json:"smali_headers"`
	JavaView       bool             `json:"java_view,omitempty"`
	EmitterVersion string           `json:"emitter_version"`
	SmaliConfig    SmaliToolConfig  `json:"smali_config"`
}

func buildDecodeCacheMetadata(apkPath string, opts DecodeOptions) (decodeCacheMetadata, error) {
	return buildDecodeCacheMetadataContext(context.Background(), apkPath, opts)
}

func buildDecodeCacheMetadataContext(ctx context.Context, apkPath string, opts DecodeOptions) (decodeCacheMetadata, error) {
	f, err := os.Open(apkPath)
	if err != nil {
		return decodeCacheMetadata{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, decodeReader{ctx: ctx, r: f}); err != nil {
		return decodeCacheMetadata{}, err
	}
	return decodeCacheMetadata{
		Schema:         decodeCacheSchema,
		APKHash:        hex.EncodeToString(h.Sum(nil)),
		NoResources:    opts.NoResources,
		NoSmali:        opts.NoSmali,
		CopyOriginal:   opts.CopyOriginal,
		FrameworkDir:   opts.FrameworkDir,
		BaksmaliJar:    opts.SmaliCfg.BaksmaliJar,
		DexBackend:     opts.DexBackend,
		NoSmaliHeaders: opts.NoSmaliHeaders,
		SmaliHeaders:   opts.SmaliHeaders,
		JavaView:       opts.JavaView,
		EmitterVersion: nativeSmaliEmitterVersion,
		SmaliConfig:    opts.SmaliCfg,
	}, nil
}

func decodeCacheHit(outDir string, expected decodeCacheMetadata, opts DecodeOptions) bool {
	data, err := os.ReadFile(filepath.Join(outDir, decodeCacheFile))
	if err != nil {
		return false
	}
	var actual decodeCacheMetadata
	if json.Unmarshal(data, &actual) != nil || actual != expected {
		return false
	}
	if !opts.NoResources {
		if info, err := os.Stat(filepath.Join(outDir, "AndroidManifest.xml")); err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	if !opts.NoSmali && !hasSmaliFiles(outDir) {
		return false
	}
	return true
}

func writeDecodeCacheMetadata(outDir string, meta decodeCacheMetadata) error {
	decodeCacheWriteMu.Lock()
	defer decodeCacheWriteMu.Unlock()

	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(outDir, decodeCacheFile+"-*.tmp")
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
	destination := filepath.Join(outDir, decodeCacheFile)
	if err := os.Rename(tmpPath, destination); err == nil {
		return nil
	}
	// os.Rename cannot replace an existing file on Windows.
	if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(tmpPath, destination)
}
