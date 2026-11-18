package apkloader

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func TestBundleBudgetPresets(t *testing.T) {
	compact, _ := BundleBudget("compact")
	large, _ := BundleBudget("large")
	if compact.MaxFunctions != 5000 || large.MaxFunctions != 100000 || large.MaxOutputBytes != 512<<20 {
		t.Fatal(compact, large)
	}
	if _, err := BundleBudget("unlimited"); err == nil {
		t.Fatal("must reject unbounded preset")
	}
}

func TestBundleExportMeasuredCoverageAndLimits(t *testing.T) {
	data := buildTestHBC(t, 96, []string{"main", "moduleA", strings.Repeat("x", 254)})
	input := filepath.Join(testutil.TempDir(t), "test.hbc")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	opts, _ := BundleBudget("large")
	for _, tc := range []struct {
		name, reason string
		modify       func(*BundleExportOptions)
	}{
		{"complete", "", func(*BundleExportOptions) {}},
		{"functions", "functions", func(o *BundleExportOptions) { o.MaxFunctions = 1 }},
		{"instructions", "instructions", func(o *BundleExportOptions) { o.MaxInstructions = 1 }},
		{"bytes", "bytecode_bytes", func(o *BundleExportOptions) { o.MaxBytecodeBytes = 1 }},
		{"output", "output_bytes", func(o *BundleExportOptions) { o.MaxOutputBytes = 80 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := opts
			tc.modify(&limits)
			out := testutil.TempDir(t)
			c, err := ExportBundleWithOptions(context.Background(), input, out, limits)
			if err != nil || c.Export == nil {
				t.Fatalf("%+v %v", c, err)
			}
			if c.Export.LimitReason != tc.reason {
				t.Fatalf("%+v", c.Export)
			}
			if (c.Status == "complete") != (tc.reason == "") {
				t.Fatal(c.Status)
			}
			text, err := os.ReadFile(filepath.Join(out, "hermes.disasm.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(text)) != c.Export.OutputBytes || int64(len(text)) > limits.MaxOutputBytes {
				t.Fatal("incorrect text budget accounting")
			}
			metadata, err := os.ReadFile(filepath.Join(out, "hermes.json"))
			if err != nil {
				t.Fatal(err)
			}
			var parsed map[string]any
			if err = json.Unmarshal(metadata, &parsed); err != nil {
				t.Fatal(err)
			}
			values := parsed["strings"].([]any)
			if len(values) != 3 || !strings.Contains(string(metadata), strings.Repeat("x", 254)) {
				t.Fatal("full metadata strings were clipped")
			}
			if tc.reason == "" && c.Export.DecodedFunctions != c.Export.TotalFunctions {
				t.Fatal(c.Export)
			}
			// Decode limits must not truncate full header/string metadata.
			if c.ScannedStrings != 3 {
				t.Fatal(c)
			}
		})
	}
}

func TestHermesGraphCancellationCoverage(t *testing.T) {
	index, err := ParseHermesBytecode(buildTestHBC(t, 96, []string{"main", "moduleA", "url"}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g := index.BuildFunctionGraphContext(ctx, 100000, 64<<20, 250000)
	if g.Coverage.Status != "partial" || g.Coverage.DecodedFunctions != 0 || g.Coverage.SkippedFunctions != len(index.Functions) {
		t.Fatal(g.Coverage)
	}
}

func TestHermesStringPreviewBounded(t *testing.T) {
	value := strings.Repeat("x", 4096)
	preview := hermesStringPreview(value)
	if len(preview) > 320 || !strings.Contains(preview, "4096 bytes total") {
		t.Fatal("unbounded preview")
	}
}
