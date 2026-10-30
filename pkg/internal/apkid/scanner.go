package apkid

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	dexpkg "mega-analyzer/pkg/internal/apkid/dex"
	elfpkg "mega-analyzer/pkg/internal/apkid/elf"
)

// ─── Public API ──────────────────────────────────────────────────────────────

// ScanOptions tunes the scan behaviour. Zero value gives sensible defaults.
type ScanOptions struct {
	// MaxFileBytes is the per-file memory cap (default 32 MiB).
	MaxFileBytes int64
	// MaxTotalBytes is the global scan budget across all files (default 256 MiB).
	MaxTotalBytes int64
	// MaxDepth is the recursive archive nesting limit (default 2).
	MaxDepth int
	// ExtraRules are caller-supplied rules merged with the built-in database.
	ExtraRules []Rule
}

func (o ScanOptions) maxFile() int64 {
	if o.MaxFileBytes <= 0 {
		return 32 << 20 // 32 MiB
	}
	return o.MaxFileBytes
}

func (o ScanOptions) maxTotal() int64 {
	if o.MaxTotalBytes <= 0 {
		return 256 << 20 // 256 MiB
	}
	return o.MaxTotalBytes
}

func (o ScanOptions) maxDepth() int {
	if o.MaxDepth <= 0 {
		return 2
	}
	return o.MaxDepth
}

// Scan analyses an APK file or extracted directory and returns a fingerprint
// report. It is a convenience wrapper around ScanWithContext.
func Scan(target string) (*Report, error) {
	return ScanWithContext(context.Background(), target, ScanOptions{})
}

// ScanWithContext is the full-featured entry point. It honours ctx for
// cancellation and timeout, and accepts ScanOptions for resource limits.
func ScanWithContext(ctx context.Context, target string, opts ScanOptions) (*Report, error) {
	start := time.Now()

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("stat target %q: %w", target, err)
	}

	// Merge built-in and caller rules, compile matchers.
	rules := append(allRules, compileMatchers(opts.ExtraRules)...)
	engine := newRuleEngine(rules)

	rep := &Report{
		SchemaVersion: SchemaVersion,
		RulesVersion:  RulesVersion,
		GeneratedAt:   time.Now().UTC(),
		Target:        target,
		Categories:    map[Category][]string{},
	}

	// Budget semaphore: how many max-size file loads can be in flight at once.
	maxConcurrent := int(opts.maxTotal() / opts.maxFile())
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	budget := make(chan struct{}, maxConcurrent)

	// Aggregator state — written only from the aggregator goroutine.
	var (
		matchedFileIDs = map[string]struct{}{} // "ruleID|entryPath" → dedup per file
		uniqueRuleIDs  = map[string]struct{}{} // ruleID → for inflation-safe scoring
		acc            []Match
		warnings       []string
		stats          Stats
	)

	type fileResult struct {
		matches  []EvalResult
		entry    string
		warnings []string
		bytes    int64
		skipped  bool
	}

	resultCh := make(chan fileResult, 64)

	// Aggregator goroutine — serialises all writes to rep.
	var wgAgg sync.WaitGroup
	wgAgg.Add(1)
	go func() {
		defer wgAgg.Done()
		for res := range resultCh {
			warnings = append(warnings, res.warnings...)
			if res.skipped {
				stats.FilesSkipped++
				continue
			}
			stats.FilesScanned++
			stats.BytesScanned += res.bytes
			for _, er := range res.matches {
				key := er.Rule.ID + "|" + res.entry
				if _, dup := matchedFileIDs[key]; dup {
					continue
				}
				matchedFileIDs[key] = struct{}{}
				acc = append(acc, Match{
					ID:          er.Rule.ID,
					Name:        er.Rule.Name,
					Category:    er.Rule.Category,
					Description: er.Rule.Description,
					File:        res.entry,
					Confidence:  er.Rule.Confidence,
					Evidence:    truncEvidence(er.Evidence, 200),
				})
				// Score: count each rule only once (no per-file inflation).
				if _, seen := uniqueRuleIDs[er.Rule.ID]; !seen {
					uniqueRuleIDs[er.Rule.ID] = struct{}{}
					// Find original score (allRules might differ from merged slice).
					for _, r := range rules {
						if r.ID == er.Rule.ID {
							stats.FilesScanned-- // compensate for non-file score op
							stats.FilesScanned++
							_ = r.Score // used below via uniqueRuleIDs
							break
						}
					}
				}
			}
		}
	}()

	// Score accumulation (done after aggregation to keep it simple).
	// We'll compute from uniqueRuleIDs after the aggregator finishes.

	var wgScan sync.WaitGroup

	consumeFile := func(entryPath, kind string, data []byte) {
		defer wgScan.Done()
		// Release budget slot when done.
		defer func() { <-budget }()

		select {
		case <-ctx.Done():
			resultCh <- fileResult{skipped: true, warnings: []string{"context cancelled"}}
			return
		default:
		}

		res := fileResult{entry: entryPath, bytes: int64(len(data))}

		// Parse DEX if applicable.
		var dexInfo *dexpkg.DEXInfo
		if kind == "dex" {
			di, parseErr := dexpkg.ParseDEX(data)
			if parseErr == nil || di != nil {
				dexInfo = di
				if di != nil {
					for _, w := range di.Warnings {
						res.warnings = append(res.warnings, fmt.Sprintf("[dex:%s] %s", entryPath, w))
					}
				}
			}
		}

		// Parse ELF if applicable.
		var elfInfo *elfpkg.ELFInfo
		if kind == "elf" {
			ei, _ := elfpkg.ScanELF(data)
			elfInfo = ei
		}

		// Run rule engine.
		hits := engine.EvalFile(rules, kind, entryPath, data, dexInfo)

		// Entropy check for packer.encrypted_asset (rule has no byte matchers).
		if kind == "asset" && len(data) >= 50*1024 {
			if isHighEntropy(data, 64*1024, 7.8) {
				// Find the rule and inject a synthetic match.
				for i := range rules {
					if rules[i].ID == "packer.encrypted_asset" {
						hits = append(hits, EvalResult{
							Rule:     &rules[i],
							Evidence: fmt.Sprintf("entropy=%.2f", ShannonEntropy(data[:64*1024])),
						})
						break
					}
				}
			}
		}

		// ELF UPX: if ELF scanner found UPX, inject packer.upx_native hit.
		if elfInfo != nil && elfInfo.HasUPX {
			for i := range rules {
				if rules[i].ID == "packer.upx_native" {
					hits = append(hits, EvalResult{
						Rule:     &rules[i],
						Evidence: "UPX! magic detected",
					})
					break
				}
			}
		}

		// DEX compiler from structural heuristics.
		if dexInfo != nil && dexInfo.Compiler != "" {
			// Map inferred compiler to a rule ID.
			compilerRuleID := ""
			switch dexInfo.Compiler {
			case "d8/r8":
				compilerRuleID = "compiler.d8_r8"
			case "dx":
				compilerRuleID = "compiler.dx"
			case "dexlib2":
				compilerRuleID = "compiler.dexlib2"
			case "jack":
				compilerRuleID = "compiler.jack"
			}
			if compilerRuleID != "" {
				// Only inject if no content-based match already hit this rule.
				alreadyHit := false
				for _, h := range hits {
					if h.Rule.ID == compilerRuleID {
						alreadyHit = true
						break
					}
				}
				if !alreadyHit {
					for i := range rules {
						if rules[i].ID == compilerRuleID {
							hits = append(hits, EvalResult{
								Rule:     &rules[i],
								Evidence: fmt.Sprintf("structural heuristic: %s", dexInfo.Compiler),
							})
							break
						}
					}
				}
			}
		}

		res.matches = hits
		resultCh <- res
	}

	// Worker: scan a single file entry.
	scanEntry := func(entryPath, kind string, data []byte) {
		wgScan.Add(1)
		budget <- struct{}{} // acquire slot (blocks if budget exhausted)
		go consumeFile(entryPath, kind, data)
	}

	// Recursive archive scanner.
	var scanArchiveAt func(path, prefix string, depth int) error

	scanArchiveAt = func(path, prefix string, depth int) error {
		stats.ArchivesOpened++
		r, err := zip.OpenReader(path)
		if err != nil {
			return fmt.Errorf("open zip %q: %w", path, err)
		}
		defer r.Close()

		for _, f := range r.File {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if f.FileInfo().IsDir() {
				continue
			}

			entryPath := prefix + filepath.ToSlash(f.Name)
			kind := classify(f.Name)

			// Check if this is a nested archive we should recurse into.
			if depth > 0 && isNestedArchive(f.Name) && f.UncompressedSize64 <= uint64(opts.maxFile()) {
				rc, openErr := f.Open()
				if openErr != nil {
					warnings = append(warnings, fmt.Sprintf("skip nested archive %q: %v", entryPath, openErr))
					continue
				}
				nestedData, readErr := io.ReadAll(io.LimitReader(rc, opts.maxFile()))
				rc.Close()
				if readErr != nil {
					warnings = append(warnings, fmt.Sprintf("read nested archive %q: %v", entryPath, readErr))
					continue
				}
				// Write to a temp file for zip.OpenReader.
				tmp, tmpErr := os.CreateTemp("", "apkid-nested-*.zip")
				if tmpErr != nil {
					warnings = append(warnings, fmt.Sprintf("tmp file for %q: %v", entryPath, tmpErr))
					continue
				}
				tmpName := tmp.Name()
				_, writeErr := tmp.Write(nestedData)
				tmp.Close()
				if writeErr != nil {
					os.Remove(tmpName)
					warnings = append(warnings, fmt.Sprintf("write tmp for %q: %v", entryPath, writeErr))
					continue
				}
				if recursErr := scanArchiveAt(tmpName, entryPath+"!", depth-1); recursErr != nil {
					warnings = append(warnings, fmt.Sprintf("scan nested %q: %v", entryPath, recursErr))
				}
				os.Remove(tmpName)
				continue
			}

			if kind == "" {
				// Still check entry_name rules against all entries (even unclassified).
				entryNameHits := evalEntryNameRules(rules, entryPath)
				if len(entryNameHits) > 0 {
					resultCh <- fileResult{
						entry:   entryPath,
						matches: entryNameHits,
					}
					stats.FilesScanned++
				}
				continue
			}

			if int64(f.UncompressedSize64) > opts.maxFile() {
				warnings = append(warnings, fmt.Sprintf("skip large entry %q (%d bytes > %d limit)",
					entryPath, f.UncompressedSize64, opts.maxFile()))
				resultCh <- fileResult{skipped: true}
				continue
			}

			rc, openErr := f.Open()
			if openErr != nil {
				warnings = append(warnings, fmt.Sprintf("open entry %q: %v", entryPath, openErr))
				resultCh <- fileResult{skipped: true}
				continue
			}
			data, readErr := io.ReadAll(io.LimitReader(rc, opts.maxFile()))
			rc.Close()
			if readErr != nil {
				warnings = append(warnings, fmt.Sprintf("read entry %q: %v", entryPath, readErr))
				resultCh <- fileResult{skipped: true}
				continue
			}

			scanEntry(entryPath, kind, data)
		}
		return nil
	}

	// Directory walker.
	walkDir := func(root string) error {
		return filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("walk %q: %v", path, err))
				return nil
			}
			if fi.IsDir() {
				return nil
			}
			kind := classify(path)
			if kind == "" {
				return nil
			}
			if fi.Size() > opts.maxFile() {
				warnings = append(warnings, fmt.Sprintf("skip large file %q (%d bytes)", path, fi.Size()))
				resultCh <- fileResult{skipped: true}
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				warnings = append(warnings, fmt.Sprintf("read %q: %v", path, readErr))
				resultCh <- fileResult{skipped: true}
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			scanEntry(filepath.ToSlash(rel), kind, data)
			return nil
		})
	}

	// Launch scanning.
	var scanErr error
	if info.IsDir() {
		scanErr = walkDir(target)
	} else {
		scanErr = scanArchiveAt(target, "", opts.maxDepth())
	}

	// Wait for all file goroutines to finish, then close result channel.
	wgScan.Wait()
	close(resultCh)
	wgAgg.Wait()

	if scanErr != nil && scanErr != context.Canceled && scanErr != context.DeadlineExceeded {
		return nil, scanErr
	}
	if scanErr != nil {
		warnings = append(warnings, "scan interrupted: "+scanErr.Error())
	}

	// Compute score from unique rule hits.
	score := 0
	for ruleID := range uniqueRuleIDs {
		for _, r := range rules {
			if r.ID == ruleID {
				score += r.Score
				break
			}
		}
	}

	// Populate report.
	rep.Matches = dedupeMatches(acc)
	sort.Slice(rep.Matches, func(i, j int) bool {
		if rep.Matches[i].Confidence != rep.Matches[j].Confidence {
			return rep.Matches[i].Confidence > rep.Matches[j].Confidence
		}
		return rep.Matches[i].ID < rep.Matches[j].ID
	})
	for _, m := range rep.Matches {
		rep.Categories[m.Category] = append(rep.Categories[m.Category], m.ID)
	}
	for k := range rep.Categories {
		sort.Strings(rep.Categories[k])
	}

	rep.PrimaryCompiler = pickPrimaryCompiler(rep.Matches)
	rep.Score = clamp(score, 0, 100)
	rep.Summary = renderSummary(rep)
	rep.Warnings = warnings

	stats.Duration = time.Since(start)
	rep.Stats = stats

	return rep, nil
}

// ─── Entry-name only evaluation ──────────────────────────────────────────────

// evalEntryNameRules runs only the KindEntryName matchers against an entry path.
// This lets us detect packed SO files even when the entry's content isn't
// classified (e.g. an unrecognised extension).
func evalEntryNameRules(rules []Rule, entryPath string) []EvalResult {
	var out []EvalResult
	for ri := range rules {
		r := &rules[ri]
		for _, m := range r.Matchers {
			if m.Kind != KindEntryName {
				continue
			}
			if matcherContains(entryPath, m.Pattern) {
				out = append(out, EvalResult{Rule: r, Evidence: entryPath})
				break // one match per rule is enough
			}
		}
	}
	return out
}

// ─── classify ────────────────────────────────────────────────────────────────

// classify decides the scope kind for a file path.
// Returns "" to skip entirely uninteresting files.
func classify(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".dex"):
		return "dex"
	case strings.HasSuffix(lower, ".smali"):
		return "smali"
	case strings.HasSuffix(lower, ".so"):
		return "elf"
	case strings.HasSuffix(lower, ".xml"),
		strings.HasSuffix(lower, ".json"),
		strings.HasSuffix(lower, ".properties"),
		strings.HasSuffix(lower, ".txt"),
		strings.HasSuffix(lower, ".kotlin_module"),
		strings.HasSuffix(lower, ".version"):
		return "text"
	}
	// Assets that are large blobs — check entropy.
	if strings.HasPrefix(lower, "assets/") || strings.Contains(lower, "/assets/") {
		return "asset"
	}
	// Native lib directories — treat as ELF for entry-name matching.
	if strings.HasPrefix(lower, "lib/") || strings.Contains(lower, "/lib/") {
		return "elf"
	}
	return ""
}

// isNestedArchive returns true for file names that look like archives.
func isNestedArchive(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".apk") ||
		strings.HasSuffix(lower, ".zip") ||
		strings.HasSuffix(lower, ".jar") ||
		strings.HasSuffix(lower, ".aar")
}

// ─── Dedup ───────────────────────────────────────────────────────────────────

func dedupeMatches(in []Match) []Match {
	seen := make(map[string]struct{}, len(in))
	out := make([]Match, 0, len(in))
	for _, m := range in {
		key := m.ID + "|" + m.File
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, m)
	}
	return out
}

// ─── Compiler picking ────────────────────────────────────────────────────────

func pickPrimaryCompiler(ms []Match) string {
	for _, m := range ms {
		if m.Category != CategoryCompiler {
			continue
		}
		switch m.ID {
		case "compiler.dexlib2":
			return "dexlib2 (smali / apktool round-trip)"
		case "compiler.d8_r8":
			return "d8 / r8"
		case "compiler.dx":
			return "dx (legacy)"
		case "compiler.jack":
			return "jack (deprecated)"
		case "compiler.dexmerge":
			return "dexmerge"
		}
	}
	return "unknown"
}

// ─── Summary ─────────────────────────────────────────────────────────────────

func renderSummary(r *Report) string {
	parts := []string{}
	if r.PrimaryCompiler != "" {
		parts = append(parts, "compiler: "+r.PrimaryCompiler)
	}
	if obfs := names(r, CategoryObfuscator); len(obfs) > 0 {
		parts = append(parts, "obfuscator: "+strings.Join(obfs, ", "))
	} else {
		parts = append(parts, "obfuscator: none")
	}
	if pcks := names(r, CategoryPacker); len(pcks) > 0 {
		parts = append(parts, "packer: "+strings.Join(pcks, ", "))
	} else {
		parts = append(parts, "packer: none")
	}
	if av := names(r, CategoryAntiVM); len(av) > 0 {
		parts = append(parts, "anti_vm: yes")
	}
	if ad := names(r, CategoryAntiDebug); len(ad) > 0 {
		parts = append(parts, "anti_debug: yes")
	}
	return strings.Join(parts, "; ")
}

func names(r *Report, cat Category) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range r.Matches {
		if m.Category != cat {
			continue
		}
		if _, ok := seen[m.Name]; ok {
			continue
		}
		seen[m.Name] = struct{}{}
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out
}

// ─── Misc helpers ────────────────────────────────────────────────────────────

// truncEvidence truncates s to at most n runes (not bytes), avoiding broken
// UTF-8 sequences.
func truncEvidence(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

func clamp(x, lo, hi int) int {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}
