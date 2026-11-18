package pipeline

import (
	"fmt"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

func systemNamespaceObservation(result *types.AnalysisResult) *finding.Finding {
	if result == nil {
		return nil
	}
	paths := make([]string, 0, len(result.Files))
	for path := range result.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var evidence []finding.Evidence
	count := 0
	for _, path := range paths {
		file := result.Files[path]
		if file == nil || file.SmaliClass == nil {
			continue
		}
		class := file.SmaliClass.Name
		name := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(class, "L"), ";"), "/", ".")
		if !strings.HasPrefix(name, "com.system.framework.") {
			continue
		}
		count++
		if len(evidence) < 8 {
			loc := finding.Location{File: file.Path, Line: 1, Class: class}
			evidence = append(evidence, finding.NewEvidence("class_declaration", "Internal class namespace", class, loc))
		}
	}
	if count == 0 {
		return nil
	}
	desc := fmt.Sprintf("%d classes use the internal namespace com.system.framework.*. Application ID: %s. These names resemble system components and can contribute to masquerading, but class namespaces are separate from APK identity and Android privileges.", count, firstNonEmpty(result.AppPackage, "unknown"))
	item := finding.FromLegacy(finding.LegacyInput{RuleID: "android.system_like_namespace", Detector: "namespace_observation", Kind: finding.KindInventory,
		Category: string(types.CategoryNamespaceObservation), Title: "System-like internal namespace: com.system.framework.*", Description: desc,
		Severity: "info", Confidence: 0.99, EvidenceType: "class_declaration", Evidence: evidence[0].Snippet, Location: evidence[0].Location})
	item.Evidence = evidence
	item.Explanation = &finding.Explanation{Status: "observation", Summary: desc,
		Limitations: []string{"Naming does not establish system UID, platform signing, privileged installation or malicious intent."},
		NextChecks:  []string{"Compare manifest application ID and component names with the displayed app identity, signing certificate and installation/UID evidence."}}
	return &item
}
