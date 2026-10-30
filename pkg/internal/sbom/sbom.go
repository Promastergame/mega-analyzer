package sbom

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/purl"
)

// Dependency represents a single extracted library dependency.
type Dependency struct {
	Group   string `json:"group"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Raw     string `json:"raw"`
	// PURL — канонический Package URL (pkg:maven/..., pkg:golang/...). Пустой,
	// если координату нельзя выразить корректно. Это ключ для связи с базами
	// уязвимостей и наборами известных SDK.
	PURL        string   `json:"purl,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Replacement string   `json:"replacement,omitempty"`
}

// Report holds the SBOM extraction results.
type Report struct {
	GeneratedAt string       `json:"generated_at"`
	Target      string       `json:"target"`
	Count       int          `json:"count"`
	Deps        []Dependency `json:"dependencies"`
	Score       int          `json:"score"`
	Verdict     string       `json:"verdict"`
	Incomplete  bool         `json:"incomplete,omitempty"`
	Warnings    []string     `json:"warnings,omitempty"`
}

// getGroupName maps a .version file stem to Maven-style group:name.
func getGroupName(stem string) (group, name string) {
	// Some .version files include version in filename, e.g. androidx-fragment_1.3.6.version
	// Remove trailing numeric version segments.
	clean := stem
	if idx := strings.LastIndex(stem, "_"); idx != -1 {
		suffix := stem[idx+1:]
		// if suffix looks like a version (starts with digit), strip it
		if len(suffix) > 0 && suffix[0] >= '0' && suffix[0] <= '9' {
			clean = stem[:idx]
		}
	}
	parts := strings.Split(clean, "_")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	name = strings.ReplaceAll(clean, "_", "-")
	if strings.HasPrefix(name, "kotlinx-") {
		group = "org.jetbrains.kotlinx"
	}
	return group, name
}

// Extract inventories supported dependency metadata. Inventory alone does not
// establish whether a component is vulnerable.
func Extract(appDir string) (*Report, error) {
	return extractInventory(appDir)
}

// versionFilePURL строит PURL для зависимости из *.version. Если группа
// известна, это Maven-координата. Иначе группу угадывать нельзя (выдуманная
// координата хуже отсутствующей: по ней найдётся чужой пакет), поэтому берём
// нейтральный pkg:generic. Версия "dynamic" — не версия, в PURL не попадает.
func versionFilePURL(group, name, version string) string {
	if name == "" {
		return ""
	}
	if version == "dynamic" {
		version = ""
	}
	var (
		p   purl.PURL
		err error
	)
	if group != "" {
		p, err = purl.Maven(group, name, version)
	} else {
		p, err = purl.New("generic", "", name, version)
	}
	if err != nil {
		return ""
	}
	return p.String()
}

func goModulePURL(module, version string) string {
	p, err := purl.Golang(module, strings.TrimSpace(version))
	if err != nil {
		return ""
	}
	return p.String()
}

// ExportSPDX generates a basic SPDX 2.3 formatted document from an SBOM report.
func ExportSPDX(r *Report) string {
	var sb strings.Builder
	sb.WriteString("SPDXVersion: SPDX-2.3\n")
	sb.WriteString("DataLicense: CC0-1.0\n")
	sb.WriteString("SPDXID: SPDXRef-DOCUMENT\n")
	sb.WriteString(fmt.Sprintf("DocumentName: %s\n", filepath.Base(r.Target)))
	sb.WriteString(fmt.Sprintf("DocumentNamespace: https://mega-analyzer.local/sbom/%d\n", time.Now().Unix()))
	sb.WriteString(fmt.Sprintf("Created: %s\n", r.GeneratedAt))
	sb.WriteString("Creator: Tool: mega-analyzer\n\n")
	for i, dep := range r.Deps {
		sb.WriteString(fmt.Sprintf("PackageName: %s\n", dep.Name))
		sb.WriteString(fmt.Sprintf("SPDXID: SPDXRef-Package-%d\n", i))
		sb.WriteString(fmt.Sprintf("PackageVersion: %s\n", dep.Version))
		sb.WriteString("PackageDownloadLocation: NOASSERTION\n")
		sb.WriteString("FilesAnalyzed: false\n")
		if dep.PURL != "" {
			sb.WriteString(fmt.Sprintf("ExternalRef: PACKAGE-MANAGER purl %s\n", dep.PURL))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
