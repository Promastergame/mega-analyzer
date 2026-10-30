package minecraft

import (
	"context"
	"encoding/json"
	"testing"
)

func TestPrivilegedCommandBoundaries(t *testing.T) {
	cases := map[string]string{
		"op Alice":                                      "op",
		"/minecraft:op Alice":                           "op",
		"execute as @a run op Alice":                    "op",
		"execute as @a run minecraft:ban Alice":         "ban",
		"execute as @a run execute at @s run stop":      "stop",
		"# op Alice":                                    "",
		"say run op Alice":                              "",
		"execute as @a run say run op Alice":            "",
		`execute as @a[name="run op Alice"] run say ok`: "",
		`execute as @a[name="run op Alice"] run op Bob`: "op",
	}
	for input, want := range cases {
		if got := privilegedCommand(input); got != want {
			t.Errorf("%q => %q, want %q", input, got, want)
		}
	}
}

func TestDisguisedZIPIsInspected(t *testing.T) {
	inner := archiveFixture(t, map[string]string{"manifest.json": manifest(resourceUUID, "resources", "[]")})
	r := scan(t, archiveFixture(t, map[string]string{"assets/data.bin": string(inner)}), Options{})
	if !r.Complete || !hasFinding(r, "disguised-archive") || r.Stats.NestedArchives != 1 || len(r.Packs) != 1 {
		t.Fatalf("hidden archive not inspected: %+v", r)
	}
}

func TestDisguisedZIPHonorsDepth(t *testing.T) {
	inner := archiveFixture(t, map[string]string{"x.txt": "x"})
	middle := archiveFixture(t, map[string]string{"inner.bin": string(inner)})
	r := scan(t, archiveFixture(t, map[string]string{"middle.bin": string(middle)}), Options{MaxDepth: 1})
	if r.Complete || !hasFinding(r, "depth-limit") {
		t.Fatal("signature-based recursion bypassed depth budget")
	}
}

func TestBedrockVersionNullIsNotZero(t *testing.T) {
	for _, raw := range []string{"[null,0,0]", "[0,null,0]", "[0,0,null]", "null", "[1,-1,0]"} {
		if version(json.RawMessage(raw)) != "" {
			t.Errorf("invalid version accepted: %s", raw)
		}
	}
	if version(json.RawMessage("[1,2,3]")) != "1.2.3" {
		t.Fatal("valid version rejected")
	}
}

func TestPackFormatNullIsInvalid(t *testing.T) {
	r := scan(t, archiveFixture(t, map[string]string{"pack.mcmeta": `{"pack":{"pack_format":null,"description":"x"}}`}), Options{})
	if r.Complete || !hasFinding(r, "invalid-pack-format") {
		t.Fatal("null pack_format accepted as zero")
	}
}

func TestBedrockSelfDependency(t *testing.T) {
	body := manifest(behaviorUUID, "data", `[{"uuid":"`+behaviorUUID+`","version":[1,0,0]}]`)
	r := scan(t, archiveFixture(t, map[string]string{"manifest.json": body}), Options{})
	if !hasFinding(r, "bedrock-self-dependency") {
		t.Fatal("self-dependency missed")
	}
}

func TestBedrockInvalidDependencyVersion(t *testing.T) {
	body := manifest(behaviorUUID, "data", `[{"uuid":"`+resourceUUID+`","version":[null,0,0]}]`)
	r := scan(t, archiveFixture(t, map[string]string{"manifest.json": body}), Options{})
	if !hasFinding(r, "bedrock-dependency-version") {
		t.Fatal("invalid dependency version missed")
	}
}

func TestArchiveBoundaryCannotBeForged(t *testing.T) {
	r := scan(t, archiveFixture(t, map[string]string{"outer.zip!/manifest.json": manifest(resourceUUID, "resources", "[]")}), Options{})
	if r.Complete || !hasFinding(r, "ambiguous-archive-path") || len(r.Packs) != 0 {
		t.Fatal("physical file masqueraded as nested archive contents")
	}
}

func TestScoreUsesMaximumSeverityPerCategory(t *testing.T) {
	s := newScanner(context.Background(), "fixture.zip", Options{})
	s.add("same", "info", "one", "first", "a", "review")
	s.add("same", "high", "two", "second", "b", "review")
	s.finish()
	if s.report.RiskScore != 20 {
		t.Fatalf("first low-severity finding hid later high severity: %d", s.report.RiskScore)
	}
}

func TestDisguisedTextureInventory(t *testing.T) {
	inner := archiveFixture(t, map[string]string{"x.txt": "x"})
	r := scan(t, archiveFixture(t, map[string]string{"texture.png": string(inner)}), Options{})
	if r.Stats.Textures != 0 || r.Stats.NestedArchives != 1 {
		t.Fatalf("signature reclassification left inaccurate inventory: %+v", r.Stats)
	}
}

func TestPrivilegedChatTextDoesNotIncreaseRisk(t *testing.T) {
	r := scan(t, archiveFixture(t, map[string]string{"data/demo/function/chat.mcfunction": "say run op Alice\nexecute as @a run say run op Alice"}), Options{})
	if hasFinding(r, "privileged-game-command") || r.RiskScore != 0 {
		t.Fatalf("ordinary chat text increased score: %+v", r)
	}
}
