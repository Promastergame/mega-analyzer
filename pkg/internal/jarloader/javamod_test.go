package jarloader

import (
	"strings"
	"testing"
)

func TestJavaModDescriptors(t *testing.T) {
	cases := []struct {
		name, body, loader, id string
	}{
		{"fabric.mod.json", `{"id":"fabricdemo","version":"1","depends":{"minecraft":">=1.20","fabricloader":">=0.15"},"authors":["Jane",{"name":"Alex"}]}`, "Fabric", "fabricdemo"},
		{"quilt.mod.json", `{"quilt_loader":{"id":"quiltdemo","version":"1","metadata":{"name":"Quilt demo"},"depends":[{"id":"minecraft","versions":">=1.20"}]}}`, "Quilt", "quiltdemo"},
		{"META-INF/mods.toml", "modLoader=\"javafml\"\n[[mods]]\nmodId='forgedemo'\nversion='1'\n[[dependencies.forgedemo]]\nmodId='minecraft'\nversionRange='[1.20,1.21)'\nmandatory=true", "Forge", "forgedemo"},
		{"META-INF/neoforge.mods.toml", "[[mods]]\nmodId='neodemo'\nversion='1'", "NeoForge", "neodemo"},
		{"mcmod.info", `[{"modid":"legacy","name":"Legacy","version":"1","mcversion":"1.12.2"}]`, "LegacyForge", "legacy"},
	}
	for _, tc := range cases {
		t.Run(tc.loader+tc.id, func(t *testing.T) {
			loader, ok := DetectModDescriptor(tc.name)
			if !ok || loader != tc.loader {
				t.Fatalf("DetectModDescriptor(%q) = %q,%v", tc.name, loader, ok)
			}
			mods, issues := ParseModMetadata(loader, tc.name, []byte(tc.body))
			if len(mods) != 1 || mods[0].ID != tc.id || mods[0].Loader != tc.loader {
				t.Fatalf("mods=%+v issues=%v", mods, issues)
			}
			if len(issues) != 0 {
				t.Errorf("unexpected issues: %v", issues)
			}
		})
	}
	if loader, ok := DetectModDescriptor("assets/data.txt"); ok {
		t.Errorf("non-descriptor detected as %s", loader)
	}
	// mods.toml outside META-INF is not a Forge descriptor.
	if _, ok := DetectModDescriptor("docs/mods.toml"); ok {
		t.Error("stray mods.toml detected as Forge descriptor")
	}
}

func TestForgeDependenciesStayWithOwner(t *testing.T) {
	body := "[[mods]]\nmodId='one'\n[[mods]]\nmodId='two'\n[[dependencies.one]]\nmodId='minecraft'\nversionRange='[1.20,1.21)'\n[[dependencies.two]]\nmodId='other'\nmandatory=false"
	mods, issues := ParseModMetadata("Forge", "META-INF/mods.toml", []byte(body))
	if len(mods) != 2 || len(mods[0].Dependencies) != 1 || len(mods[1].Dependencies) != 1 || mods[1].Dependencies[0].Required {
		t.Fatalf("dependencies %+v issues %v", mods, issues)
	}
}

func TestForgeMultilineDoesNotInventMods(t *testing.T) {
	text := "[[mods]]\nmodId='real'\ndescription='''\n[[mods]]\nmodId='fake'\n'''\nversion='1'"
	mods, issues := ParseModMetadata("Forge", "META-INF/mods.toml", []byte(text))
	if len(mods) != 1 || mods[0].ID != "real" {
		t.Fatalf("multiline handling mods=%+v issues=%v", mods, issues)
	}
	joined := strings.Join(issues, ";")
	if !strings.Contains(joined, "forge-toml-subset") {
		t.Errorf("missing subset issue: %v", issues)
	}
}

func TestCompoundQuiltDependencyIsIssue(t *testing.T) {
	body := `{"quilt_loader":{"id":"demo","version":"1","depends":[[{"id":"a"},{"id":"b"}]]}}`
	mods, issues := ParseModMetadata("Quilt", "quilt.mod.json", []byte(body))
	if len(mods) != 1 {
		t.Fatalf("mods=%+v", mods)
	}
	joined := strings.Join(issues, ";")
	if !strings.Contains(joined, "quilt-dependency-expression") {
		t.Errorf("missing compound-expression issue: %v", issues)
	}
}

func TestPoolRefOnlyStillFlagsExec(t *testing.T) {
	// A bare constant-pool reference with no method bodies must still flag:
	// presence in the pool is a capability, proven by call sites only.
	cf := &ClassFile{
		ThisClass:  "com.example.Tool",
		MethodRefs: []MethodRef{{Class: "java.lang.Runtime", Name: "exec", Descriptor: "(Ljava/lang/String;)Ljava/lang/Process;"}},
	}
	found := false
	for _, m := range analyzeClass(cf, "Tool.class") {
		if m.Category == "COMMAND_EXECUTION" {
			found = true
		}
	}
	if !found {
		t.Fatal("pool-only Runtime.exec reference not flagged")
	}
}

func TestTextNamedClassIsSkipped(t *testing.T) {
	// Text bytes under a .class name must not be treated as bytecode.
	dir := t.TempDir()
	p := writeJar(t, dir, "fake.jar", map[string][]byte{
		"fake.class": []byte("ProcessBuilder.exec"),
	})
	rep, err := Analyze(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range rep.Findings {
		if m.Category == "COMMAND_EXECUTION" {
			t.Fatalf("text treated as bytecode: %+v", m)
		}
	}
	if rep.UnparseableClasses != 1 {
		t.Errorf("UnparseableClasses = %d, want 1", rep.UnparseableClasses)
	}
}

func TestFilenameDepDemotedWithoutPom(t *testing.T) {
	// A bare filename guess with no pom corroboration drops one notch.
	inner := zipBytes(t, map[string][]byte{
		"org/example/App.class": buildMinimalClass(t, "org.example.App", "java.lang.String", "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;"),
	})
	p := writeJar(t, t.TempDir(), "outer.jar", map[string][]byte{
		"BOOT-INF/lib/log4j-core-2.14.1.jar": inner,
	})
	rep, err := Analyze(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range rep.VulnDeps {
		if d.CVE != "CVE-2021-44228" {
			continue
		}
		found = true
		if d.Severity != "high" {
			t.Errorf("uncorroborated filename guess keeps critical: %+v", d)
		}
		if d.Evidence != "filename" {
			t.Errorf("evidence = %q, want filename", d.Evidence)
		}
	}
	if !found {
		t.Fatalf("missing Log4Shell candidate: %+v", rep.VulnDeps)
	}
}

func TestPomCorroboratedDepKeepsSeverity(t *testing.T) {
	inner := zipBytes(t, map[string][]byte{
		"org/apache/logging/log4j/Foo.class":                                buildMinimalClass(t, "org.apache.logging.log4j.Foo", "java.lang.String", "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;"),
		"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": []byte("groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.0\n"),
	})
	p := writeJar(t, t.TempDir(), "outer.jar", map[string][]byte{
		"BOOT-INF/lib/bundle.jar": inner,
	})
	rep, err := Analyze(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range rep.VulnDeps {
		if d.CVE == "CVE-2021-44228" && d.Severity == "critical" && d.Evidence == "maven-coordinates" {
			found = true
		}
	}
	if !found {
		t.Errorf("pom-corroborated dep must keep critical: %+v", rep.VulnDeps)
	}
}

func TestPreciseArgsEndToEndAnalyze(t *testing.T) {
	// ldc "MD5"; invokestatic MessageDigest.getInstance; return — through Analyze.
	code := []byte{0x12, 0x0c, 0xb8, 0x00, 0x0a, 0xb1}
	cls := buildFlowClass(t, "com.example.C", "java.security.MessageDigest", "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;", []string{"MD5"}, code)
	p := writeJar(t, t.TempDir(), "crypto.jar", map[string][]byte{
		"com/example/C.class": cls,
	})
	rep, err := Analyze(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range rep.Findings {
		if m.Category == "CRYPTO_WEAK_HASH" && m.Confidence == "0.95" && m.EvidenceType == "dataflow_argument" {
			found = true
		}
		if m.Category == "CRYPTO_WEAK_HASH" && m.Confidence == "0.50" {
			t.Errorf("generic duplicate alongside precise: %+v", m)
		}
	}
	if !found {
		t.Fatalf("missing precise finding: %#v", rep.Findings)
	}
	if rep.InstructionCount == 0 || rep.MethodCount == 0 || rep.InvocationCount == 0 {
		t.Errorf("counters not accumulated: %+v", rep)
	}
}

func TestAnalyzeModInventoryStable(t *testing.T) {
	// A real-world scan once returned zero Mods for a jar that declares
	// sixteen; reruns were stable. Hammer Analyze on one fixture jar so a
	// flake in the descriptor path fails loudly instead of shipping silent
	// inventory loss. Run with -race: the class pass is parallel.
	p := writeJar(t, t.TempDir(), "probe.jar", map[string][]byte{
		"fabric.mod.json": []byte(`{"schemaVersion":1,"id":"probe","name":"Probe","version":"1.0","depends":{"minecraft":"~1.21"}}`),
		"com/example/A.class": buildMinimalClass(t, "com.example.A",
			"java.lang.Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;"),
	})
	for i := 0; i < 10; i++ {
		rep, err := Analyze(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Mods) != 1 || rep.Mods[0].ID != "probe" {
			t.Fatalf("run %d: Mods=%+v, want exactly [probe]", i, rep.Mods)
		}
	}
}
