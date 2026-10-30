package apkloader

import (
	"archive/zip"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// xmlnsRe matches an XML namespace declaration for the android prefix,
// so we can use whatever prefix the base manifest defines.
var xmlnsRe = regexp.MustCompile(`xmlns:(\w+)\s*=\s*"http://schemas\.android\.com/apk/res/android"`)

// SplitMerger orchestrates the merging of multiple split APK files.
type SplitMerger struct {
	tempDir string
}

// NewSplitMerger creates a SplitMerger using the specified temporary directory.
func NewSplitMerger(tempDir string) *SplitMerger {
	return &SplitMerger{tempDir: tempDir}
}

// Merge combines the base APK and split APKs inside apkFiles into destDir.
func (sm *SplitMerger) Merge(ctx context.Context, extractor *Extractor, apkFiles []string, destDir string) error {
	if len(apkFiles) == 0 {
		return fmt.Errorf("no APK files provided for merging")
	}

	// 1. Identify the base APK
	baseAPK := sm.identifyBaseAPK(apkFiles)
	if baseAPK == "" {
		return fmt.Errorf("failed to identify base APK among files: %v", apkFiles)
	}

	// 2. Extract base APK into destDir
	extractor.warn("[merger] selected base APK: %s", filepath.Base(baseAPK))
	if err := extractor.extractZipSafe(ctx, baseAPK, destDir); err != nil {
		return fmt.Errorf("failed to extract base APK: %w", err)
	}

	// Decode resources and manifest in the base APK first
	if err := extractor.decodeResourcesInPlace(ctx, destDir); err != nil {
		return fmt.Errorf("decode base APK resources: %w", err)
	}

	// 3. Extract and merge each split APK
	for _, splitAPK := range apkFiles {
		if splitAPK == baseAPK {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		extractor.warn("[merger] merging split APK: %s", filepath.Base(splitAPK))

		splitExtractDir, err := os.MkdirTemp(sm.tempDir, "split_extract_*")
		if err != nil {
			return fmt.Errorf("create split temp dir: %w", err)
		}
		defer os.RemoveAll(splitExtractDir)

		if err := extractor.extractZipSafe(ctx, splitAPK, splitExtractDir); err != nil {
			return fmt.Errorf("extract split %s: %w", filepath.Base(splitAPK), err)
		}

		if err := extractor.decodeResourcesInPlace(ctx, splitExtractDir); err != nil {
			return fmt.Errorf("decode split %s resources: %w", filepath.Base(splitAPK), err)
		}

		// Merge components from the split APK
		if err := sm.mergeSplitDir(destDir, splitExtractDir, extractor); err != nil {
			return fmt.Errorf("merge split %s: %w", filepath.Base(splitAPK), err)
		}
	}

	return nil
}

func (sm *SplitMerger) hasManifestAndDex(apkPath string) bool {
	r, err := zip.OpenReader(apkPath)
	if err != nil {
		return false
	}
	defer r.Close()

	hasManifest := false
	hasDex := false
	for _, f := range r.File {
		if f.Name == "AndroidManifest.xml" {
			hasManifest = true
		}
		if strings.HasSuffix(f.Name, ".dex") {
			hasDex = true
		}
		if hasManifest && hasDex {
			return true
		}
	}
	return hasManifest && hasDex
}

func (sm *SplitMerger) identifyBaseAPK(apkFiles []string) string {
	// 1. Prefer explicit base/master filenames if not an asset pack
	for _, f := range apkFiles {
		lower := strings.ToLower(filepath.Base(f))
		if strings.Contains(lower, "asset_pack") || strings.Contains(lower, "assetpack") {
			continue
		}
		if strings.Contains(lower, "base") || strings.Contains(lower, "master") {
			return f
		}
	}

	// 2. Check which APK contains both AndroidManifest.xml and .dex code
	var bestCodeAPK string
	var bestCodeSize int64 = -1
	for _, f := range apkFiles {
		lower := strings.ToLower(filepath.Base(f))
		if strings.Contains(lower, "asset_pack") || strings.Contains(lower, "assetpack") {
			continue
		}
		if sm.hasManifestAndDex(f) {
			info, err := os.Stat(f)
			if err == nil && info.Size() > bestCodeSize {
				bestCodeSize = info.Size()
				bestCodeAPK = f
			}
		}
	}
	if bestCodeAPK != "" {
		return bestCodeAPK
	}

	// 3. Fallback: pick largest non-asset-pack APK
	var (
		largestPath string
		largestSize int64 = -1
	)
	for _, f := range apkFiles {
		lower := strings.ToLower(filepath.Base(f))
		if strings.Contains(lower, "asset_pack") || strings.Contains(lower, "assetpack") {
			continue
		}
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		if info.Size() > largestSize {
			largestSize = info.Size()
			largestPath = f
		}
	}
	if largestPath != "" {
		return largestPath
	}

	// 4. Absolute fallback: pick largest APK regardless
	for _, f := range apkFiles {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		if info.Size() > largestSize {
			largestSize = info.Size()
			largestPath = f
		}
	}
	return largestPath
}

func (sm *SplitMerger) mergeSplitDir(destDir, splitDir string, extractor *Extractor) error {
	// 1. Merge DEX files (renaming them classesN.dex sequentially)
	if err := sm.mergeDEXFiles(destDir, splitDir, extractor); err != nil {
		return err
	}

	// 2. Merge native libraries (.so)
	if err := sm.mergeNativeLibs(destDir, splitDir, extractor); err != nil {
		return err
	}

	// 3. Merge AndroidManifest.xml
	if err := sm.mergeManifests(destDir, splitDir, extractor); err != nil {
		return err
	}

	// 4. Merge assets & resource configs
	if err := sm.mergeAssetsAndResources(destDir, splitDir, extractor); err != nil {
		return err
	}

	return nil
}

func (sm *SplitMerger) mergeDEXFiles(destDir, splitDir string, extractor *Extractor) error {
	splitDex := extractor.findDEXFiles(splitDir)
	if len(splitDex) == 0 {
		return nil
	}

	// Find the next available classesN.dex number in destDir
	baseDex := extractor.findDEXFiles(destDir)
	nextIdx := 2
	for _, f := range baseDex {
		base := strings.ToLower(filepath.Base(f))
		if base == "classes.dex" {
			continue
		}
		// Match classes(\d+).dex
		r := regexp.MustCompile(`^classes(\d+)\.dex$`)
		m := r.FindStringSubmatch(base)
		if len(m) == 2 {
			idx, err := strconv.Atoi(m[1])
			if err == nil && idx >= nextIdx {
				nextIdx = idx + 1
			}
		}
	}

	for _, dexPath := range splitDex {
		var newName string
		if nextIdx == 1 {
			newName = "classes.dex"
		} else {
			newName = fmt.Sprintf("classes%d.dex", nextIdx)
		}
		nextIdx++

		dstPath := filepath.Join(destDir, newName)
		if err := copyFile(dexPath, dstPath); err != nil {
			return fmt.Errorf("copy split dex: %w", err)
		}
		extractor.warn("[merger] copied split DEX as %s", newName)
	}

	return nil
}

func (sm *SplitMerger) mergeNativeLibs(destDir, splitDir string, extractor *Extractor) error {
	splitLibDir := filepath.Join(splitDir, "lib")
	if _, err := os.Stat(splitLibDir); os.IsNotExist(err) {
		return nil
	}

	destLibDir := filepath.Join(destDir, "lib")
	return filepath.WalkDir(splitLibDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(splitLibDir, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(destLibDir, rel)
		if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
			return err
		}

		if err := copyFile(path, dstPath); err != nil {
			return err
		}
		return nil
	})
}

func (sm *SplitMerger) mergeAssetsAndResources(destDir, splitDir string, extractor *Extractor) error {
	for _, folder := range []string{"assets", "res"} {
		srcFolder := filepath.Join(splitDir, folder)
		if _, err := os.Stat(srcFolder); os.IsNotExist(err) {
			continue
		}

		destFolder := filepath.Join(destDir, folder)
		err := filepath.WalkDir(srcFolder, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}

			rel, err := filepath.Rel(srcFolder, path)
			if err != nil {
				return err
			}

			dstPath := filepath.Join(destFolder, rel)
			// Skip resource duplicates to avoid collisions, preserving base
			if _, err := os.Stat(dstPath); err == nil {
				return nil
			}

			if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
				return err
			}

			return copyFile(path, dstPath)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// SplitManifest models a minimal structure for unmarshaling a split manifest.
type SplitManifest struct {
	XMLName     xml.Name     `xml:"manifest"`
	Permissions []Permission `xml:"uses-permission"`
	Application *Application `xml:"application"`
}

type Permission struct {
	Name string `xml:"name,attr"`
}

type Application struct {
	Activities []RawElement `xml:"activity"`
	Services   []RawElement `xml:"service"`
	Receivers  []RawElement `xml:"receiver"`
	Providers  []RawElement `xml:"provider"`
}

type RawElement struct {
	XMLName xml.Name
	Content string     `xml:",innerxml"`
	Attrs   []xml.Attr `xml:",any,attr"`
}

func (sm *SplitMerger) mergeManifests(destDir, splitDir string, extractor *Extractor) error {
	baseManifestPath := filepath.Join(destDir, "AndroidManifest.xml")
	splitManifestPath := filepath.Join(splitDir, "AndroidManifest.xml")

	if _, err := os.Stat(baseManifestPath); os.IsNotExist(err) {
		return nil
	}
	if _, err := os.Stat(splitManifestPath); os.IsNotExist(err) {
		return nil
	}

	baseContent, err := os.ReadFile(baseManifestPath)
	if err != nil {
		return err
	}
	splitContent, err := os.ReadFile(splitManifestPath)
	if err != nil {
		return err
	}

	// Both manifest contents are already decoded to plaintext strings.
	// 1. Unmarshal split manifest to extract elements.
	var splitManifest SplitManifest
	if err := xml.Unmarshal(splitContent, &splitManifest); err != nil {
		return fmt.Errorf("unmarshal split manifest: %w", err)
	}

	mergedXML := string(baseContent)

	// 2. Merge Permissions
	for _, perm := range splitManifest.Permissions {
		if perm.Name == "" {
			continue
		}
		// Namespace-agnostic check: match any prefix (android:, custom:, etc.)
		pattern := fmt.Sprintf(`uses-permission[^>]*name\s*=\s*["'][^"']*%s["']`, regexp.QuoteMeta(perm.Name))
		re := regexp.MustCompile(pattern)
		if re.MatchString(mergedXML) {
			continue // permission already declared in base
		}

		// Find the namespace prefix used in the base manifest for "android:"
		nsPrefix := "android"
		if m := xmlnsRe.FindStringSubmatch(mergedXML); len(m) > 1 {
			nsPrefix = m[1]
		}

		// Insert new permission right before <application or </manifest>
		permTag := fmt.Sprintf("\n    <uses-permission %s:name=\"%s\" />", nsPrefix, perm.Name)
		if idx := strings.Index(mergedXML, "<application"); idx >= 0 {
			mergedXML = mergedXML[:idx] + permTag + "\n    " + mergedXML[idx:]
		} else if idx := strings.Index(mergedXML, "</manifest>"); idx >= 0 {
			mergedXML = mergedXML[:idx] + permTag + "\n" + mergedXML[idx:]
		}
	}

	// 3. Merge Application Components
	if splitManifest.Application != nil {
		// Collect all raw component blocks
		var components []string

		collectRaw := func(elements []RawElement, name string) {
			for _, elem := range elements {
				// Reconstruct XML tag
				var attrsStr strings.Builder
				for _, attr := range elem.Attrs {
					space := attr.Name.Space
					if space == "http://schemas.android.com/apk/res/android" {
						space = "android"
					}
					if space != "" {
						attrsStr.WriteString(fmt.Sprintf(" %s:%s=\"%s\"", space, attr.Name.Local, attr.Value))
					} else {
						attrsStr.WriteString(fmt.Sprintf(" %s=\"%s\"", attr.Name.Local, attr.Value))
					}
				}

				var tag string
				if elem.Content != "" {
					tag = fmt.Sprintf("\n        <%s%s>%s</%s>", name, attrsStr.String(), elem.Content, name)
				} else {
					tag = fmt.Sprintf("\n        <%s%s />", name, attrsStr.String())
				}
				components = append(components, tag)
			}
		}

		collectRaw(splitManifest.Application.Activities, "activity")
		collectRaw(splitManifest.Application.Services, "service")
		collectRaw(splitManifest.Application.Receivers, "receiver")
		collectRaw(splitManifest.Application.Providers, "provider")

		if len(components) > 0 {
			// Find closing </application> tag in base manifest
			if idx := strings.LastIndex(mergedXML, "</application>"); idx >= 0 {
				mergedTags := strings.Join(components, "")
				mergedXML = mergedXML[:idx] + mergedTags + "\n    " + mergedXML[idx:]
			}
		}
	}

	// Write back the merged manifest
	return os.WriteFile(baseManifestPath, []byte(mergedXML), 0644)
}
