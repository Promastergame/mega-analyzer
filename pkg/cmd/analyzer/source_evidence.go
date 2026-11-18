package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/dataflow"
	"mega-analyzer/pkg/internal/sourceevidence"
	"mega-analyzer/pkg/internal/types"
)

func collectSourceEvidence(ctx context.Context, result *types.AnalysisResult) sourceevidence.Report {
	program := dataflow.NewProgram(dataflow.DefaultConfig())
	paths := make([]string, 0, len(result.Files))
	for path := range result.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	visible, added, bytesUsed := 0, 0, 0
	limited := false
	for _, path := range paths {
		file := result.Files[path]
		if file != nil && file.SmaliClass != nil {
			visible += len(file.SmaliClass.Methods)
		}
	}
	// Bound before AddClass copies method bodies. Sink-bearing methods have
	// priority; omitted callers/callees remain unknown in the source analysis.
	for _, priority := range []bool{true, false} {
		for _, path := range paths {
			file := result.Files[path]
			if file == nil || file.SmaliClass == nil {
				continue
			}
			selected := *file.SmaliClass
			selected.Methods = nil
			for _, method := range file.SmaliClass.Methods {
				if method.Access.IsNative() || method.Access.IsAbstract() || len(method.Body) == 0 ||
					sourceSensitiveMethod(&method) != priority {
					continue
				}
				if ctx.Err() != nil {
					limited = true
					break
				}
				if len(method.Body) > 4096 {
					limited = true
					continue
				}
				bodyBytes := 0
				for _, line := range method.Body {
					bodyBytes += len(line) + 1
				}
				if added >= 4096 || len(method.Body) > 4096 || bodyBytes > (8<<20)-bytesUsed {
					limited = true
					continue
				}
				selected.Methods = append(selected.Methods, method)
				added++
				bytesUsed += bodyBytes
			}
			program.AddClass(path, &selected)
		}
	}
	report := program.InspectSource(ctx)
	report.MethodsDiscovered = visible
	report.MethodsSkipped = visible - report.MethodsAnalyzed
	report.LimitReached = report.LimitReached || limited
	if report.MethodsSkipped > 0 || limited {
		report.Status = "partial"
	}
	for _, path := range paths {
		file := result.Files[path]
		if file == nil || file.XMLData == nil {
			continue
		}
		x := file.XMLData
		if x.ManifestSource == "" && !x.ManifestSourceTruncated {
			continue
		}
		report.AddManifest(path, x.ManifestSource, "retained_decoded_manifest", x.ManifestSourceTruncated)
	}
	return report
}

func sourceSensitiveMethod(method *types.SmaliMethod) bool {
	for _, call := range method.Invokes {
		class := strings.TrimSuffix(strings.TrimPrefix(call.Class, "L"), ";")
		class = strings.ReplaceAll(class, ".", "/")
		signature := "L" + class + ";->" + call.Method + "(" + call.Params + ")" + call.ReturnType
		if signature == "Ljava/lang/System;->load(Ljava/lang/String;)V" ||
			signature == "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V" ||
			strings.HasPrefix(signature, "Ljava/io/FileOutputStream;-><init>(Ljava/io/File;") ||
			strings.HasPrefix(signature, "Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;") {
			return true
		}
	}
	return false
}

func writeSourceEvidenceReports(dir string, report sourceevidence.Report) error {
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "SOURCE_EVIDENCE.json"), append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "SOURCE_EVIDENCE.txt"), []byte(report.Text()), 0600)
}

func writeGNNDiagnosticsReport(dir string, result *types.AnalysisResult) error {
	if result.GNNDiagnostics == nil {
		return nil
	}
	b, err := json.MarshalIndent(result.GNNDiagnostics, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "GNN_DIAGNOSTICS.json"), append(b, '\n'), 0600)
}
