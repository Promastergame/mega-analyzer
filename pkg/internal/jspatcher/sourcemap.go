package jspatcher

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxLocalSourceMapBytes = 32 << 20
	maxMappedSources       = 4096
	maxMappedSourceBytes   = 4 << 20
	maxMappedTotalBytes    = 32 << 20
)

var (
	lineSourceMapRE  = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)\s*$`)
	blockSourceMapRE = regexp.MustCompile(`/\*[#@]\s*sourceMappingURL\s*=\s*([^*\s]+)\s*\*/`)
)

type mappedSource struct {
	MapDigest string
	Mappings  []sourceMapping
	Name      string
	Content   string
	MapPath   string
	Truncated bool
}

type sourceMapDocument struct {
	Version        int                `json:"version"`
	Mappings       string             `json:"mappings"`
	Sections       []sourceMapSection `json:"sections"`
	SourceRoot     string             `json:"sourceRoot"`
	Sources        []string           `json:"sources"`
	SourcesContent []*string          `json:"sourcesContent"`
}

func loadMappedSources(bundlePath, bundleSource string) ([]mappedSource, error) {
	sources, _, err := loadMappedSourcesDetailed(bundlePath, bundleSource)
	return sources, err
}

func sourceMapReference(src string) string {
	var ref string
	last := -1
	for _, pattern := range []*regexp.Regexp{lineSourceMapRE, blockSourceMapRE} {
		for _, match := range pattern.FindAllStringSubmatchIndex(src, -1) {
			if len(match) >= 4 && match[0] > last {
				last = match[0]
				ref = strings.TrimSpace(src[match[2]:match[3]])
			}
		}
	}
	return ref
}

func readSourceMapReference(bundlePath, ref string) ([]byte, string, error) {
	if strings.HasPrefix(strings.ToLower(ref), "data:") {
		data, err := decodeSourceMapDataURL(ref)
		return data, bundlePath + "#inline-source-map", err
	}

	u, err := url.Parse(ref)
	if err != nil {
		return nil, "", fmt.Errorf("invalid source map reference: %w", err)
	}
	if u.IsAbs() || u.Host != "" {
		return nil, "", fmt.Errorf("remote source map reference is not loaded: %s", ref)
	}
	pathPart, err := url.PathUnescape(u.Path)
	if err != nil {
		return nil, "", fmt.Errorf("decode source map path: %w", err)
	}
	if pathPart == "" || filepath.IsAbs(filepath.FromSlash(pathPart)) {
		return nil, "", fmt.Errorf("source map path must be relative: %s", ref)
	}
	baseDir := filepath.Clean(filepath.Dir(bundlePath))
	mapPath := filepath.Clean(filepath.Join(baseDir, filepath.FromSlash(pathPart)))
	rel, relErr := filepath.Rel(baseDir, mapPath)
	if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, "", fmt.Errorf("source map path escapes bundle directory: %s", ref)
	}
	info, err := os.Stat(mapPath)
	if err != nil {
		return nil, mapPath, fmt.Errorf("open source map %s: %w", mapPath, err)
	}
	if info.Size() > maxLocalSourceMapBytes {
		return nil, mapPath, fmt.Errorf("source map %s exceeds %d bytes", mapPath, maxLocalSourceMapBytes)
	}
	file, err := os.Open(mapPath)
	if err != nil {
		return nil, mapPath, fmt.Errorf("open source map %s: %w", mapPath, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxLocalSourceMapBytes+1))
	if err != nil {
		return nil, mapPath, fmt.Errorf("read source map %s: %w", mapPath, err)
	}
	if len(data) > maxLocalSourceMapBytes {
		return nil, mapPath, fmt.Errorf("source map %s grew past the byte budget", mapPath)
	}
	return data, mapPath, nil
}

func decodeSourceMapDataURL(ref string) ([]byte, error) {
	comma := strings.IndexByte(ref, ',')
	if comma < 0 {
		return nil, fmt.Errorf("invalid inline source map data URL")
	}
	meta, payload := strings.ToLower(ref[:comma]), ref[comma+1:]
	if len(payload) > maxLocalSourceMapBytes*3 {
		return nil, fmt.Errorf("inline source map encoded payload exceeds limit")
	}
	var data []byte
	var err error
	if strings.Contains(meta, ";base64") {
		data, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			data, err = base64.RawStdEncoding.DecodeString(payload)
		}
	} else {
		var decoded string
		decoded, err = url.PathUnescape(payload)
		data = []byte(decoded)
	}
	if err != nil {
		return nil, fmt.Errorf("decode inline source map: %w", err)
	}
	if len(data) > maxLocalSourceMapBytes {
		return nil, fmt.Errorf("inline source map exceeds %d bytes", maxLocalSourceMapBytes)
	}
	return data, nil
}

func trimJSONPrefix(data []byte) []byte {
	text := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if strings.HasPrefix(text, ")]}'") {
		if nl := strings.IndexByte(text, '\n'); nl >= 0 {
			text = strings.TrimSpace(text[nl+1:])
		}
	}
	return []byte(text)
}
