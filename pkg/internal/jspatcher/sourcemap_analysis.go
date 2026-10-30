package jspatcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// SourceMapCoverage distinguishes embedded-source discovery from bundle coverage.
type SourceMapCoverage struct {
	Status           string   `json:"status"`
	Maps             int      `json:"maps"`
	TotalSources     int      `json:"total_sources"`
	ScannedSources   int      `json:"scanned_sources"`
	SkippedSources   int      `json:"skipped_sources"`
	TruncatedSources int      `json:"truncated_sources"`
	TotalBytes       int64    `json:"total_bytes"`
	ScannedBytes     int64    `json:"scanned_bytes"`
	Diagnostics      []string `json:"diagnostics,omitempty"`
}

func (c *SourceMapCoverage) partial(message string) {
	c.Status = "partial"
	if len(c.Diagnostics) < 64 {
		c.Diagnostics = append(c.Diagnostics, message)
	}
}

func (c *SourceMapCoverage) merge(other SourceMapCoverage) {
	if c.Status == "" || c.Status == "absent" {
		c.Status = other.Status
	}
	if other.Status == "partial" || other.Status == "failed" {
		c.Status = "partial"
	}
	c.Maps += other.Maps
	c.TotalSources += other.TotalSources
	c.ScannedSources += other.ScannedSources
	c.SkippedSources += other.SkippedSources
	c.TruncatedSources += other.TruncatedSources
	c.TotalBytes += other.TotalBytes
	c.ScannedBytes += other.ScannedBytes
	for _, diagnostic := range other.Diagnostics {
		c.partial(diagnostic)
	}
}

type sourceMapSection struct {
	Offset struct {
		Line   int `json:"line"`
		Column int `json:"column"`
	} `json:"offset"`
	Map *sourceMapDocument `json:"map"`
	URL string             `json:"url"`
}

func loadMappedSourcesDetailed(bundlePath, bundleSource string) ([]mappedSource, SourceMapCoverage, error) {
	coverage := SourceMapCoverage{Status: "absent"}
	ref := sourceMapReference(bundleSource)
	if ref == "" {
		return nil, coverage, nil
	}
	data, mapPath, err := readSourceMapReference(bundlePath, ref)
	if err != nil {
		coverage.Status = "failed"
		return nil, coverage, err
	}
	var doc sourceMapDocument
	if err := json.Unmarshal(trimJSONPrefix(data), &doc); err != nil {
		coverage.Status = "failed"
		return nil, coverage, fmt.Errorf("parse source map %s: %w", mapPath, err)
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	coverage.Status = "complete"
	var all []mappedSource
	var collect func(*sourceMapDocument, int, int, int)
	collect = func(document *sourceMapDocument, baseLine, baseColumn, depth int) {
		if depth > 8 || coverage.Maps >= 1024 {
			coverage.partial("indexed source map depth/map limit reached")
			return
		}
		coverage.Maps++
		if document.Version != 0 && document.Version != 3 {
			coverage.partial(fmt.Sprintf("unsupported source map version %d", document.Version))
			return
		}
		if len(document.Sections) > 0 {
			previousLine, previousColumn := -1, -1
			for _, section := range document.Sections {
				line, column := section.Offset.Line, section.Offset.Column
				if line < 0 || column < 0 || line < previousLine || (line == previousLine && column <= previousColumn) {
					coverage.partial("indexed source map sections have invalid offsets")
					continue
				}
				previousLine, previousColumn = line, column
				if section.Map == nil {
					coverage.partial("external indexed source map section is not embedded")
					continue
				}
				if line == 0 {
					column += baseColumn
				}
				collect(section.Map, baseLine+line, column, depth+1)
			}
			return
		}
		count := max(len(document.Sources), len(document.SourcesContent))
		coverage.TotalSources += count
		mappings, mapErr := decodeSourceMappings(document.Mappings, count, baseLine, baseColumn)
		if mapErr != nil {
			coverage.partial(mapErr.Error())
		}
		for i := 0; i < count; i++ {
			if i >= len(document.SourcesContent) || document.SourcesContent[i] == nil {
				continue
			}
			content := *document.SourcesContent[i]
			coverage.TotalBytes += int64(len(content))
			name := fmt.Sprintf("source-%d.js", i+1)
			if i < len(document.Sources) && document.Sources[i] != "" {
				name = document.Sources[i]
			}
			if document.SourceRoot != "" && !strings.Contains(name, "://") {
				name = strings.TrimRight(document.SourceRoot, "/\\") + "/" + strings.TrimLeft(name, "/\\")
			}
			all = append(all, mappedSource{Name: "sourcemap://" + filepath.ToSlash(name), Content: content, MapPath: mapPath, MapDigest: digest, Mappings: mappings[i]})
		}
	}
	collect(&doc, 0, 0, 0)
	// Keep application code ahead of dependencies if a resource limit is reached.
	sort.SliceStable(all, func(i, j int) bool { return sourcePriority(all[i].Name) < sourcePriority(all[j].Name) })
	result := make([]mappedSource, 0, min(len(all), maxMappedSources))
	remaining := maxMappedTotalBytes
	for _, source := range all {
		if len(result) >= maxMappedSources || remaining == 0 {
			break
		}
		limit := min(maxMappedSourceBytes, remaining)
		if len(source.Content) > limit {
			source.Content = source.Content[:limit]
			source.Truncated = true
			coverage.TruncatedSources++
		}
		remaining -= len(source.Content)
		coverage.ScannedBytes += int64(len(source.Content))
		result = append(result, source)
	}
	coverage.ScannedSources = len(result)
	coverage.SkippedSources = coverage.TotalSources - coverage.ScannedSources
	if coverage.SkippedSources > 0 || coverage.TruncatedSources > 0 {
		coverage.partial(fmt.Sprintf("Source map coverage: %d/%d sources, %d omitted (missing content or budget), %d truncated; %d/%d embedded bytes scanned", coverage.ScannedSources, coverage.TotalSources, coverage.SkippedSources, coverage.TruncatedSources, coverage.ScannedBytes, coverage.TotalBytes))
	}
	return result, coverage, nil
}

func sourcePriority(name string) int {
	name = strings.ToLower(strings.ReplaceAll(name, "\\", "/"))
	for _, token := range []string{"node_modules/", "/vendor/", "webpack/bootstrap", "reactnativerenderer", "/polyfills/"} {
		if strings.Contains(name, token) {
			return 1
		}
	}
	return 0
}
