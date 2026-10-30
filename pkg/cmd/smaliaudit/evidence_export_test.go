package smaliaudit

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/ml"
	"os"
	"strings"
	"testing"
)

func TestAuditV2EvidenceExport(t *testing.T) {
	input := os.Getenv("AUDIT_INPUT_APK")
	if input == "" {
		t.Skip("manual read-only inspection")
	}
	data, err := os.ReadFile(os.Getenv("AUDIT_REPORT_JSON"))
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if err = json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	wanted := map[string]string{}
	classFiles := map[string]string{}
	want := func(method, file string) {
		wanted[method] = file
		if i := strings.Index(method, ";->"); i >= 0 {
			classFiles[method[:i+1]] = file
		}
	}
	for _, f := range append(append([]ml.SmaliAuditFinding(nil), report.Audit.Findings...), report.Audit.Observations...) {
		if f.EvidenceLevel == "static_flow" || f.EvidenceLevel == "informational_flow" {
			want(f.Location.Method, f.Location.File)
			for _, e := range f.Evidence {
				want(e.Method, e.File)
			}
		}
	}
	for _, class := range []string{"Landroidx/media/session/MediaButtonReceiver;", "Lcom/google/games/bridge/NativeBridgeActivity;", "Lcom/facebook/FacebookContentProvider;", "Lcom/facebook/internal/NativeAppCallAttachmentStore;", "Lcom/unity3d/ads/api/Cache;", "Lcom/unity3d/ads/cache/CacheThread;"} {
		classFiles[class] = "dex/classes/" + strings.TrimSuffix(strings.TrimPrefix(class, "L"), ";") + ".smali"
	}
	type methodDump struct {
		Method    string   `json:"method"`
		File      string   `json:"file"`
		LineStart int      `json:"line_start"`
		Lines     []string `json:"lines"`
	}
	dumps := map[string]methodDump{}
	z, err := zip.OpenReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	pa := ml.NewPatchAnalyzer()
	for _, entry := range z.File {
		if !strings.HasSuffix(entry.Name, ".dex") {
			continue
		}
		reader, e := entry.Open()
		if e != nil {
			t.Fatal(e)
		}
		bytes, e := io.ReadAll(io.LimitReader(reader, 128<<20))
		reader.Close()
		if e != nil {
			t.Fatal(e)
		}
		dex, e := apkloader.ParseDEXBytesContext(context.Background(), bytes)
		if e != nil {
			t.Fatal(e)
		}
		for _, class := range dex.GetClasses() {
			file, ok := classFiles[class.ClassName]
			if !ok {
				continue
			}
			parsed := pa.AnalyzeSmaliContent(file, apkloader.GenerateSmaliClass(class, dex))
			for _, method := range parsed.Methods {
				signature := method.ClassName + "->" + method.FullSignature

				lines := make([]string, len(method.RawBody))
				for i, line := range method.RawBody {
					if quote := strings.IndexByte(line, '"'); quote >= 0 && os.Getenv("AUDIT_PRIVATE_LITERALS") != "1" {
						line = line[:quote] + "\"<literal redacted>\""
					}
					lines[i] = line
				}
				dumps[signature] = methodDump{Method: signature, File: file, LineStart: method.LineStart, Lines: lines}
			}
			ml.PutClassInfo(parsed)
		}
		dex.Close()
	}
	verified := 0
	for _, f := range append(append([]ml.SmaliAuditFinding(nil), report.Audit.Findings...), report.Audit.Observations...) {
		if f.EvidenceLevel != "static_flow" && f.EvidenceLevel != "informational_flow" {
			continue
		}
		m, ok := dumps[f.Location.Method]
		if !ok {
			t.Errorf("missing sink method %s", f.Location.Method)
			continue
		}
		offset := f.Location.Line - m.LineStart
		if offset < 0 || offset >= len(m.Lines) || !strings.Contains(m.Lines[offset], f.Sink) {
			t.Errorf("sink line mismatch: %s:%d", f.Location.Method, f.Location.Line)
			continue
		}
		verified++
	}
	if verified != report.Audit.Coverage.StaticFlows+report.Audit.Coverage.InformationalFlows {
		t.Fatalf("verified %d of %d sink locations", verified, report.Audit.Coverage.StaticFlows)
	}
	result := map[string]any{"verified_sink_locations": verified, "methods": dumps, "note": "Read-only disassembly excerpts; literals redacted; this checks evidence locations, not path feasibility or exploitability."}
	if err := WriteJSON(os.Getenv("AUDIT_EVIDENCE_JSON"), result); err != nil {
		t.Fatal(err)
	}
}
