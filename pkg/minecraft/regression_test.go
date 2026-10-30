package minecraft

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const resourceUUID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
const behaviorUUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

func manifest(id, kind string, dependencies string) string {
	return fmt.Sprintf(`{"format_version":2,"header":{"name":"Test pack","uuid":%q,"version":[1,0,0],"min_engine_version":[1,21,0]},"modules":[{"type":%q,"uuid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","version":[1,0,0]}],"dependencies":%s}`, id, kind, dependencies)
}
func scan(t *testing.T, b []byte, opts Options) Report {
	t.Helper()
	r, err := AnalyzeBytes(context.Background(), "fixture.zip", b, opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func hasFinding(r Report, id string) bool {
	for _, f := range r.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestNestedBedrockLinks(t *testing.T) {
	for _, v := range []string{"[1,0,0]", "[2,0,0]"} {
		t.Run(v, func(t *testing.T) {
			resources := archiveFixture(t, map[string]string{"manifest.json": manifest(resourceUUID, "resources", "[]")})
			behavior := archiveFixture(t, map[string]string{"manifest.json": manifest(behaviorUUID, "data", fmt.Sprintf(`[{"uuid":%q,"version":%s}]`, resourceUUID, v))})
			r := scan(t, archiveFixture(t, map[string]string{"resource.mcpack": string(resources), "behavior.mcpack": string(behavior)}), Options{})
			if r.Format != "bedrock-addon" || !r.Complete || r.Stats.NestedArchives != 2 || len(r.Packs) != 2 {
				t.Fatalf("unexpected report %+v", r)
			}
			if hasFinding(r, "external-pack-dependency") {
				t.Fatal("bundled UUID reported external")
			}
			if hasFinding(r, "bedrock-dependency-version") != (v == "[2,0,0]") {
				t.Fatalf("version findings %+v", r.Findings)
			}
		})
	}
}
func TestJSONCAndScriptEntry(t *testing.T) {
	m := strings.Replace(manifest(behaviorUUID, "script", "[]"), `"type":"script"`, `"type":"script","entry":"scripts/main.js"`, 1)
	m = "\xef\xbb\xbf// manifest comment\n" + m
	r := scan(t, archiveFixture(t, map[string]string{"BP/manifest.json": m, "BP/scripts/main.js": "import {world} from '@minecraft/server'; // https://example.org"}), Options{})
	if !r.Complete || hasFinding(r, "bedrock-script-missing") || r.RiskScore != 0 {
		t.Fatalf("normal Script API should not imply malware %+v", r)
	}
	r = scan(t, archiveFixture(t, map[string]string{"BP/manifest.json": m, "BP/scripts/Main.js": ""}), Options{})
	if !hasFinding(r, "bedrock-script-missing") {
		t.Fatal("case mismatch went unnoticed")
	}
}
func TestGenericManifestIsNotBedrock(t *testing.T) {
	r := scan(t, archiveFixture(t, map[string]string{"manifest.json": `{"name":"Web app","version":"1.0.0"}`}), Options{})
	if len(r.Packs) != 0 || r.Format != "unknown" {
		t.Fatalf("misclassified: %+v", r)
	}
}
func TestDataPackAndTextureDimensions(t *testing.T) {
	var pngBytes bytes.Buffer
	if err := png.Encode(&pngBytes, image.NewRGBA(image.Rect(0, 0, 16, 32))); err != nil {
		t.Fatal(err)
	}
	r := scan(t, archiveFixture(t, map[string]string{"pack.mcmeta": `{"pack":{"pack_format":15,"description":[{"text":"test"}]}}`, "assets/demo/textures/test.png": pngBytes.String()}), Options{})
	if !r.Complete || r.Stats.Textures != 1 {
		t.Fatalf("texture report %+v", r)
	}
	for _, f := range r.Files {
		if f.Kind == "texture" && (f.Width != 16 || f.Height != 32) {
			t.Fatalf("dimensions %+v", f)
		}
	}
	r = scan(t, archiveFixture(t, map[string]string{"pack.mcmeta": `{"pack":{"pack_format":15,"description":"data"}}`, "data/demo/function/tick.mcfunction": "say hello"}), Options{})
	if r.Format != "java-data-pack" {
		t.Fatal(r.Format)
	}
}
func TestArchiveLimitsAndCorruption(t *testing.T) {
	small := archiveFixture(t, map[string]string{"x": "hello", "y": "world"})
	for _, tc := range []struct {
		name, id string
		opts     Options
	}{{"entries", "entry-limit", Options{MaxEntries: 1}}, {"expanded", "expanded-limit", Options{MaxUncompressed: 4}}, {"entrysize", "entry-size-limit", Options{MaxEntryBytes: 3}}} {
		t.Run(tc.name, func(t *testing.T) {
			r := scan(t, small, tc.opts)
			if r.Complete || !hasFinding(r, tc.id) {
				t.Fatalf("limit ignored %+v", r)
			}
		})
	}
	nested := archiveFixture(t, map[string]string{"nested.mcpack": string(small)})
	r := scan(t, archiveFixture(t, map[string]string{"outer.mcaddon": string(nested)}), Options{MaxDepth: 1})
	if r.Complete || !hasFinding(r, "depth-limit") {
		t.Fatal("depth ignored")
	}
	if _, err := AnalyzeBytes(context.Background(), "bad.zip", []byte("not a zip"), Options{}); err == nil {
		t.Fatal("invalid ZIP accepted")
	}
	if _, err := AnalyzeBytes(context.Background(), "large.zip", small, Options{MaxInputBytes: 2}); err == nil {
		t.Fatal("input limit ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AnalyzeBytes(ctx, "x.zip", small, Options{}); err != context.Canceled {
		t.Fatalf("cancel: %v", err)
	}
	var z bytes.Buffer
	zw := zip.NewWriter(&z)
	entry, err := zw.CreateHeader(&zip.FileHeader{Name: "x.txt", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	entry.Write([]byte("unique-marker"))
	zw.Close()
	bad := z.Bytes()
	i := bytes.Index(bad, []byte("unique-marker"))
	bad[i] = 'X'
	r = scan(t, bad, Options{})
	if r.Complete || !hasFinding(r, "entry-read") {
		t.Fatal("CRC failure silently ignored")
	}
}
func TestPathsAndLinks(t *testing.T) {
	for _, name := range []string{"../escape", "a/../../escape", `..\escape`, "/absolute", `C:\Windows\x`, "file:stream"} {
		t.Run(name, func(t *testing.T) {
			r := scan(t, archiveFixture(t, map[string]string{name: "x"}), Options{})
			if !hasFinding(r, "unsafe-path") {
				t.Fatal("unsafe path accepted")
			}
		})
	}
	r := scan(t, archiveFixture(t, map[string]string{"A.txt": "a", "a.txt": "b"}), Options{})
	if !hasFinding(r, "duplicate-path") {
		t.Fatal("collision missed")
	}
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	h := &zip.FileHeader{Name: "link"}
	h.SetMode(os.ModeSymlink | 0777)
	f, err := w.CreateHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("../../outside"))
	w.Close()
	r = scan(t, b.Bytes(), Options{})
	if r.Complete || !hasFinding(r, "symbolic-link") {
		t.Fatal("symlink ignored")
	}
}
func TestDirectoryAndSHA(t *testing.T) {
	root := t.TempDir()
	descriptor := manifest(behaviorUUID, "data", "[]")
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(descriptor), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := AnalyzePath(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Format != "bedrock-pack" || r.SHA256 != "" || r.Stats.UncompressedBytes != uint64(len(descriptor)) {
		t.Fatalf("directory %+v", r)
	}
	b := archiveFixture(t, map[string]string{"manifest.json": descriptor})
	target := filepath.Join(t.TempDir(), "pack.mcaddon")
	os.WriteFile(target, b, 0600)
	r, err = AnalyzePath(context.Background(), target, Options{})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if r.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("archive hash mismatch")
	}
	original, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(original, b) {
		t.Fatal("input changed")
	}
}
func TestReportEscapesAndWrites(t *testing.T) {
	r := scan(t, archiveFixture(t, map[string]string{"pack.mcmeta": `{"pack":{"pack_format":15,"description":"<script>alert(1)</script>"}}`}), Options{})
	var b bytes.Buffer
	if err := r.HTML(&b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "<script>alert(1)</script>") || !strings.Contains(b.String(), "&lt;script&gt;") {
		t.Fatal("unescaped report")
	}
	out := t.TempDir()
	if err := WriteReports(out, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteReports(out, r); err != nil {
		t.Fatal("report replacement", err)
	}
	for _, name := range []string{"analysis.json", "REPORT.html"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestZIP64SizeDoesNotOverflow(t *testing.T) {
	s := newScanner(context.Background(), "huge.zip", Options{})
	err := s.entry("huge", "huge", ^uint64(0), 1, 0600, 0, func() (io.ReadCloser, error) {
		t.Fatal("oversized entry must not be opened")
		return nil, nil
	})
	if err != nil || s.report.Complete || !hasFinding(s.report, "expanded-limit") {
		t.Fatalf("overflow guard: %v %+v", err, s.report)
	}
}

func TestReportDoesNotOverwriteInput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "analysis.json")
	if err := os.WriteFile(input, []byte("original input"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteReports(dir, Report{Path: input}); err == nil {
		t.Fatal("input collision accepted")
	}
	data, err := os.ReadFile(input)
	if err != nil || string(data) != "original input" {
		t.Fatal("input overwritten")
	}
}
