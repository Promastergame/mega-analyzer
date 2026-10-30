package minecraft

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func archiveFixture(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for n, v := range entries {
		f, e := w.Create(n)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write([]byte(v)); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestAnalyzeBedrockAddonAndMissingScript(t *testing.T) {
	b := archiveFixture(t, map[string]string{"behavior/manifest.json": `{"format_version":2,"header":{"name":"Sky","uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","version":[1,0,0],"min_engine_version":[1,20,0]},"modules":[{"type":"script","uuid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","version":[1,0,0],"entry":"scripts/main.js"}],"dependencies":[{"uuid":"cccccccc-cccc-cccc-cccc-cccccccccccc","version":[1,0,0]}]}`})
	r, e := AnalyzeBytes(context.Background(), "addon.mcaddon", b, Options{})
	if e != nil {
		t.Fatal(e)
	}
	if r.Format != "bedrock-pack" {
		t.Fatalf("format=%s", r.Format)
	}
	found := false
	for _, f := range r.Findings {
		if f.ID == "bedrock-script-missing" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing script finding")
	}
}
func TestAnalyzeBedrockPack(t *testing.T) {
	b := archiveFixture(t, map[string]string{"manifest.json": manifest(behaviorUUID, "data", "[]")})
	r, e := AnalyzeBytes(context.Background(), "pack.mcaddon", b, Options{})
	if e != nil {
		t.Fatal(e)
	}
	if r.Format != "bedrock-pack" || len(r.Packs) != 1 || r.Packs[0].ID != behaviorUUID {
		t.Fatalf("report=%+v", r)
	}
}
func TestAnalyzeRejectsUnsafePath(t *testing.T) {
	r, e := AnalyzeBytes(context.Background(), "x.zip", archiveFixture(t, map[string]string{"../evil.txt": "x"}), Options{})
	if e != nil {
		t.Fatal(e)
	}
	if r.Complete {
		t.Fatal("unsafe archive reported complete")
	}
	ok := false
	for _, f := range r.Findings {
		if f.ID == "unsafe-path" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("unsafe path finding missing")
	}
}
func TestReportJSON(t *testing.T) {
	r, e := AnalyzeBytes(context.Background(), "x.zip", archiveFixture(t, map[string]string{"pack.mcmeta": `{"pack":{"pack_format":15,"description":"hi"}}`}), Options{})
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	var b bytes.Buffer
	if e = r.JSON(&b); e != nil {
		t.Fatal(e)
	}
	if e = json.NewDecoder(&b).Decode(&v); e != nil {
		t.Fatal(e)
	}
	if v["format"] != "java-resource-pack" {
		t.Fatalf("json format=%v", v["format"])
	}
}
