package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/pipeline"
)

var (
	manifestPackageRe    = regexp.MustCompile(`(?is)<manifest[^>]*\bpackage\s*=\s*"([^"]+)"`)
	manifestLabelRe      = regexp.MustCompile(`(?is)<application[^>]*\bandroid:label\s*=\s*"([^"]+)"`)
	manifestVersionCode  = regexp.MustCompile(`(?is)<manifest[^>]*\bandroid:versionCode\s*=\s*"([^"]+)"`)
	manifestVersionName  = regexp.MustCompile(`(?is)<manifest[^>]*\bandroid:versionName\s*=\s*"([^"]+)"`)
	manifestMinSDKRe     = regexp.MustCompile(`(?is)<uses-sdk[^>]*\bandroid:minSdkVersion\s*=\s*"([^"]+)"`)
	manifestTargetSDKRe  = regexp.MustCompile(`(?is)<uses-sdk[^>]*\bandroid:targetSdkVersion\s*=\s*"([^"]+)"`)
	manifestPermissionRe = regexp.MustCompile(`(?is)<uses-permission(?:-sdk-23)?\s[^>]*\bandroid:name\s*=\s*"([^"]+)"`)
	manifestComponentRe  = regexp.MustCompile(`(?is)<(activity|service|receiver|provider)(\s[^>]*)/?>`)
	componentNameAttrRe  = regexp.MustCompile(`(?i)\bandroid:name\s*=\s*"([^"]+)"`)
	componentExportedRe  = regexp.MustCompile(`(?i)\bandroid:exported\s*=\s*"true"`)
)

func collectAndroidProfile(ctx context.Context, target string, workspaceRoot string) (*AndroidProfile, []string, error) {
	inputType, err := apkloader.DetectInputType(target)
	if err != nil {
		// DetectInputType also returns an error for inputs that are simply
		// not Android artifacts (unrecognized format, no smali files) — that
		// is expected for the majority of non-Android samples and must stay
		// silent. Only surface genuine I/O failures (missing file, no
		// permission) so those aren't mistaken for "not Android".
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return nil, nil, fmt.Errorf("detect input type: %w", err)
		}
		return nil, nil, nil
	}

	switch inputType {
	case apkloader.InputTypeSmaliFolder, apkloader.InputTypeCacheFolder,
		apkloader.InputTypeAPKFile, apkloader.InputTypeArchiveFile, apkloader.InputTypeDEXFile:
	default:
		return nil, nil, nil
	}

	root := target
	var warnings []string

	switch inputType {
	case apkloader.InputTypeAPKFile, apkloader.InputTypeArchiveFile, apkloader.InputTypeDEXFile:
		extractor := apkloader.NewExtractor()
		extractor.TempDir = workspaceRoot

		prepared, err := extractor.PrepareInput(ctx, target)
		if err != nil {
			return nil, nil, fmt.Errorf("prepare android artifact for sandbox profile: %w", err)
		}
		root = prepared
		for _, warning := range extractor.GetWarnings() {
			warnings = append(warnings, "android profile extractor: "+warning)
		}
		for _, finding := range extractor.GetFindings() {
			warnings = append(warnings, fmt.Sprintf("android artifact %s: %s", finding.Severity, finding.Reason))
		}
	}

	manifestPath, err := findManifestPath(root)
	if err != nil || manifestPath == "" {
		return nil, warnings, err
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, warnings, fmt.Errorf("read AndroidManifest.xml: %w", err)
	}

	profile := &AndroidProfile{
		InputType:          inputType.String(),
		ManifestPath:       manifestPath,
		PackageName:        firstSubmatch(data, manifestPackageRe),
		AppLabel:           firstSubmatch(data, manifestLabelRe),
		VersionCode:        firstSubmatch(data, manifestVersionCode),
		VersionName:        firstSubmatch(data, manifestVersionName),
		MinSDK:             firstSubmatch(data, manifestMinSDKRe),
		TargetSDK:          firstSubmatch(data, manifestTargetSDKRe),
		Permissions:        extractAndroidPermissions(data),
		ExportedComponents: extractAndroidComponents(data),
	}

	for _, permission := range profile.Permissions {
		switch permission.Risk {
		case "high-risk":
			profile.HighRiskPermissionCount++
		case "dangerous":
			profile.DangerousPermissionCount++
		}
	}

	return profile, warnings, nil
}

func firstSubmatch(data []byte, re *regexp.Regexp) string {
	match := re.FindSubmatch(data)
	if len(match) < 2 {
		return ""
	}
	return string(match[1])
}

func extractAndroidPermissions(data []byte) []AndroidPermission {
	matches := manifestPermissionRe.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(matches))
	permissions := make([]AndroidPermission, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		name := string(match[1])
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}

		risk, suspicious := pipeline.ClassifyAndroidPermission(name)
		permissions = append(permissions, AndroidPermission{
			Name:       name,
			Risk:       risk,
			Suspicious: suspicious,
		})
	}

	sort.Slice(permissions, func(i, j int) bool { return permissions[i].Name < permissions[j].Name })
	return permissions
}

func extractAndroidComponents(data []byte) []AndroidComponent {
	matches := manifestComponentRe.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return nil
	}

	components := make([]AndroidComponent, 0, len(matches))
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		attrs := string(match[2])
		nameMatch := componentNameAttrRe.FindStringSubmatch(attrs)
		name := ""
		if len(nameMatch) >= 2 {
			name = nameMatch[1]
		}
		components = append(components, AndroidComponent{
			Kind:     strings.ToLower(string(match[1])),
			Name:     name,
			Exported: componentExportedRe.MatchString(attrs),
		})
	}

	sort.Slice(components, func(i, j int) bool {
		if components[i].Kind == components[j].Kind {
			return components[i].Name < components[j].Name
		}
		return components[i].Kind < components[j].Kind
	})
	return components
}

func findManifestPath(root string) (string, error) {
	direct := filepath.Join(root, "AndroidManifest.xml")
	if info, err := os.Stat(direct); err == nil && !info.IsDir() {
		return direct, nil
	}

	var manifestPath string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Base(path), "AndroidManifest.xml") {
			manifestPath = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil && err != filepath.SkipAll {
		return "", err
	}
	return manifestPath, nil
}
