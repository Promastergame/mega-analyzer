package jspatcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const jsPatchCacheSchema = "jspatcher-v7"

type jsPatchCacheKeyConfig struct {
	HermesBudget  string
	Schema        string
	MinConfidence int
	NewServerIP   string
	Categories    []JSPatchCategory
}

func (p *Patcher) loadCache(filePath string, data []byte, sources []mappedSource) *JSPatchResult {
	path := p.cachePath(data, sources)
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var result JSPatchResult
	if json.Unmarshal(raw, &result) != nil {
		return nil
	}
	result.CacheHit = true
	remapCachedResult(&result, filePath, sources)
	return &result
}

func (p *Patcher) saveCache(result *JSPatchResult, data []byte, sources []mappedSource) {
	if result == nil || result.AnalysisStatus != "complete" {
		return
	}
	path := p.cachePath(data, sources)
	if path == "" {
		return
	}
	result.CacheHit = false
	raw, err := json.Marshal(result)
	if err != nil || os.MkdirAll(filepath.Dir(path), 0o755) != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "jspatch-*.tmp")
	if err != nil {
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err = tmp.Write(raw); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return
	}
	if err := os.Rename(tmpPath, path); err == nil {
		return
	}
	_ = os.Remove(path)
	_ = os.Rename(tmpPath, path)
}

func (p *Patcher) cachePath(data []byte, sources []mappedSource) string {
	if p == nil || p.cfg.Apply != ApplyDryRun || p.cfg.OutputDir == "" {
		return ""
	}
	categories := append([]JSPatchCategory(nil), p.cfg.Categories...)
	sort.Slice(categories, func(i, j int) bool { return categories[i] < categories[j] })
	cfg, _ := json.Marshal(jsPatchCacheKeyConfig{
		HermesBudget: p.cfg.HermesBudget, Schema: jsPatchCacheSchema, MinConfidence: p.cfg.MinConfidence,
		NewServerIP: p.cfg.NewServerIP, Categories: categories,
	})
	h := sha256.New()
	h.Write(cfg)
	h.Write([]byte{0})
	h.Write(data)
	for _, source := range sources {
		h.Write([]byte{0})
		h.Write([]byte(source.Name))
		h.Write([]byte{0})
		h.Write([]byte(source.Content))
		h.Write([]byte(source.MapDigest))
	}
	root := p.cfg.OutputDir
	if strings.EqualFold(filepath.Base(filepath.Clean(root)), "jspatcher") {
		root = filepath.Dir(root)
	}
	return filepath.Join(root, ".cache", "jspatcher", hex.EncodeToString(h.Sum(nil))+".json")
}

func remapCachedResult(result *JSPatchResult, filePath string, sources []mappedSource) {
	result.Target = filePath
	for _, h := range result.Hermes {
		if h != nil {
			h.Path = filePath
		}
	}
	mapPaths := make(map[string]string, len(sources))
	for _, source := range sources {
		mapPaths[source.Name] = source.MapPath
	}
	remapMatch := func(match *JSPatchMatch) {
		if match == nil {
			return
		}
		if match.FromSourceMap {
			if path := mapPaths[match.FilePath]; path != "" {
				match.SourceMapPath = path
			}
		} else {
			match.FilePath = filePath
		}
		if match.ProposedPatch != nil {
			match.ProposedPatch.FilePath = filePath
		}
	}
	for _, match := range result.Matches {
		remapMatch(match)
	}
	for _, group := range result.Groups {
		if group == nil {
			continue
		}
		remapMatch(group.BestMatch)
		for _, match := range group.AllMatches {
			remapMatch(match)
		}
	}
	for _, patch := range result.Patches {
		if patch != nil {
			patch.FilePath = filePath
		}
	}
}
