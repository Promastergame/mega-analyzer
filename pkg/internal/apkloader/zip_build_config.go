package apkloader

import (
	"compress/flate"
	"path/filepath"
	"strings"
)

type CompressionMode string

const (
	CompressionFast     CompressionMode = "fast"
	CompressionBalanced CompressionMode = "balanced"
	CompressionBest     CompressionMode = "best"
)

type zipBuildConfig struct {
	mode           CompressionMode
	spoolThreshold int64
}

const defaultLargeFileSpoolThreshold int64 = 128 * 1024 * 1024

func (m CompressionMode) flateLevel() int {
	switch m {
	case CompressionFast:
		return flate.BestSpeed
	case CompressionBest:
		return flate.BestCompression
	default:
		return flate.DefaultCompression
	}
}

func (r *APKRebuilder) effectiveCompressionMode() CompressionMode {
	if r.CompressionMode == "" {
		return CompressionBalanced
	}
	return r.CompressionMode
}

func (r *APKRebuilder) effectiveSpoolThreshold() int64 {
	if r.LargeFileSpoolThreshold <= 0 {
		return defaultLargeFileSpoolThreshold
	}
	return r.LargeFileSpoolThreshold
}

func (r *APKRebuilder) zipBuildConfig() zipBuildConfig {
	return zipBuildConfig{mode: r.effectiveCompressionMode(), spoolThreshold: r.effectiveSpoolThreshold()}
}

// shouldStoreForSpeed avoids wasting CPU on formats that are already compressed
// or entropy-heavy. APK install size can grow slightly, but rebuilds become much
// faster for large game/mobile assets. Critical runtime entries are already
// handled by shouldCompressFile.
func shouldStoreForSpeed(relPath string, size int64) bool {
	if size < 256*1024 {
		return false
	}
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(relPath)), ".")
	switch ext {
	case "zip", "jar", "apk", "xapk", "apks", "apkm", "gz", "tgz", "xz", "zst", "lz4", "7z", "rar", "obb", "pak", "mp4", "m4v", "mov", "avi", "webm", "mkv", "mp3", "ogg", "opus", "aac", "m4a", "jpg", "jpeg", "png", "webp", "gif", "wasm", "hbc":
		return true
	default:
		return false
	}
}
