package jarloader

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// zipBytes builds an in-memory zip from name->content.
func zipBytes(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range sortedKeys(entries) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entries[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func writeJar(t *testing.T, dir, name string, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, zipBytes(t, entries), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// buildClassWithStrings is buildMinimalClass plus genuine cpString literals.
func buildClassWithStrings(t *testing.T, thisClass, refClass, refMethod, refDesc string, literals ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := func(v interface{}) {
		if err := binary.Write(&b, binary.BigEndian, v); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	utf8 := func(s string) {
		w(uint8(cpUtf8))
		w(uint16(len(s)))
		b.WriteString(s)
	}
	toInternal := func(dotted string) string {
		var o []byte
		for i := 0; i < len(dotted); i++ {
			if dotted[i] == '.' {
				o = append(o, '/')
			} else {
				o = append(o, dotted[i])
			}
		}
		return string(o)
	}

	// Manual layout to keep indices predictable:
	// 1: utf8 this, 2: Class->1, 3: utf8 Object, 4: Class->3,
	// 5: utf8 refClass, 6: Class->5, 7: utf8 refMethod, 8: utf8 refDesc,
	// 9: NameAndType->7,8, 10: Methodref->6,9, then per literal: utf8, String.
	w(uint32(classMagic))
	w(uint16(0))
	w(uint16(52))
	countPos := b.Len()
	w(uint16(0)) // placeholder for count; patched below
	n := 0
	utf8(toInternal(thisClass)) // 1
	n++
	w(uint8(cpClass)) // 2
	w(uint16(1))
	n++
	utf8("java/lang/Object") // 3
	n++
	w(uint8(cpClass)) // 4
	w(uint16(3))
	n++
	utf8(toInternal(refClass)) // 5
	n++
	w(uint8(cpClass)) // 6
	w(uint16(5))
	n++
	utf8(refMethod) // 7
	n++
	utf8(refDesc) // 8
	n++
	w(uint8(cpNameAndType)) // 9
	w(uint16(7))
	w(uint16(8))
	n++
	w(uint8(cpMethodref)) // 10
	w(uint16(6))
	w(uint16(9))
	n++
	for _, lit := range literals {
		utf8idx := n + 1
		utf8(lit)
		n++
		w(uint8(cpString)) // -> utf8idx
		w(uint16(utf8idx))
		n++
	}
	raw := b.Bytes()
	binary.BigEndian.PutUint16(raw[countPos:], uint16(n+1))
	raw = append(raw,
		0x00, 0x21, // access_flags
		0x00, 0x02, // this_class -> 2
		0x00, 0x04, // super_class -> 4
		0x00, 0x00, // interfaces
		0x00, 0x00, // fields
		0x00, 0x00, // methods
		0x00, 0x00, // attributes
	)
	return raw
}

func TestNestedJarRecursion(t *testing.T) {
	inner := zipBytes(t, map[string][]byte{
		"com/evil/Inner.class": buildMinimalClass(t, "com.evil.Inner", "java.lang.Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;"),
	})
	outer := writeJar(t, t.TempDir(), "app.jar", map[string][]byte{
		"META-INF/MANIFEST.MF":                 []byte("Manifest-Version: 1.0\r\nMain-Class: com.evil.Boot\r\n"),
		"BOOT-INF/lib/inner.jar":               inner,
		"BOOT-INF/classes/com/evil/Boot.class": buildMinimalClass(t, "com.evil.Boot", "java.lang.String", "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;"),
	})
	rep, err := Analyze(outer)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if rep.ClassCount != 2 {
		t.Errorf("ClassCount = %d, want 2 (outer + nested)", rep.ClassCount)
	}
	if len(rep.NestedJars) != 1 || rep.NestedJars[0] != "BOOT-INF/lib/inner.jar" {
		t.Errorf("NestedJars = %v", rep.NestedJars)
	}
	found := false
	for _, m := range rep.Findings {
		if m.Category == "COMMAND_EXECUTION" && m.SourceLocation.File == "BOOT-INF/lib/inner.jar!/com/evil/Inner.class" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing nested COMMAND_EXECUTION with prefixed location; findings: %#v", rep.Findings)
	}
}

func TestShadedPomCoords(t *testing.T) {
	// No log4j-core-*.jar filename anywhere: shaded classes + pom.properties.
	outer := writeJar(t, t.TempDir(), "shaded-app.jar", map[string][]byte{
		"org/apache/logging/log4j/Foo.class":                                buildMinimalClass(t, "org.apache.logging.log4j.Foo", "javax.naming.InitialContext", "lookup", "(Ljava/lang/String;)Ljava/lang/Object;"),
		"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": []byte("groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.0\n"),
	})
	rep, err := Analyze(outer)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	hit := false
	for _, d := range rep.VulnDeps {
		if d.CVE == "CVE-2021-44228" {
			hit = true
		}
	}
	if !hit {
		t.Errorf("shaded log4j-core 2.14.0 via pom.properties not flagged; deps: %#v", rep.VulnDeps)
	}
	if rep.ClassCount != 1 {
		t.Errorf("ClassCount = %d, want 1 (shaded class scanned)", rep.ClassCount)
	}
}

func TestManifestContinuation(t *testing.T) {
	outer := writeJar(t, t.TempDir(), "wrap.jar", map[string][]byte{
		// Header wraps at 72 bytes: continuation starts with one space.
		"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\r\nMain-Class: com.exa\r\n mple.Evil\r\n"),
	})
	rep, err := Analyze(outer)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if rep.MainClass != "com.example.Evil" {
		t.Errorf("MainClass = %q, want unfolded com.example.Evil", rep.MainClass)
	}
}

func TestStringConstantsResolution(t *testing.T) {
	data := buildClassWithStrings(t, "com.example.K", "java.lang.Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", "AKIAIOSFODNN7EXAMPLE")
	cf, err := ParseClass(data)
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	if len(cf.StringConstants) != 1 || cf.StringConstants[0] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("StringConstants = %q, want the literal", cf.StringConstants)
	}
	for _, s := range cf.StringConstants {
		if strings.Contains(s, "Ljava/lang") {
			t.Errorf("descriptor leaked into StringConstants: %q", s)
		}
	}
	// Fallback for hand-built fixtures without literal resolution.
	fixture := &ClassFile{Strings: []string{"x"}}
	if got := secretScanStrings(fixture); len(got) != 1 || got[0] != "x" {
		t.Errorf("fallback secretScanStrings = %v", got)
	}
}

func TestWeakHashComposite(t *testing.T) {
	cf := &ClassFile{ThisClass: "com.example.C", Strings: []string{"MD5withRSA", "HmacMD5", "SHA1withRSA"}}
	got := 0
	for _, m := range analyzeClass(cf, "C.class") {
		if m.Category == "CRYPTO_WEAK_HASH" {
			got++
		}
	}
	if got != 3 {
		t.Errorf("composite weak-hash findings = %d, want 3", got)
	}
	prose := &ClassFile{ThisClass: "com.example.C", Strings: []string{"MD5 is a hash function used here", "(Ljava/lang/String;)V"}}
	for _, m := range analyzeClass(prose, "C.class") {
		if m.Category == "CRYPTO_WEAK_HASH" {
			t.Errorf("prose/descriptor must not match weak hash: %q", m.Text)
		}
	}
}

func TestSemverBoundaryAndQualifiers(t *testing.T) {
	if got := matchVulnDep("commons-collections4-4.4.jar"); len(filterSev(got)) != 0 {
		t.Errorf("commons-collections4 must not match commons-collections rule: %#v", got)
	}
	got := matchVulnDep("jackson-databind-2.9.9.2.jar")
	if hasCVE(got, "CVE-2019-12384") {
		t.Errorf("jackson 2.9.9.2 is the fix for CVE-2019-12384, must not flag: %#v", got)
	}
	if !hasCVE(got, "CVE-2020-8840") {
		t.Errorf("jackson 2.9.9.2 is still < 2.10.0 (CVE-2020-8840): %#v", got)
	}
	v, ok := extractVersion("guava-31.1-jre.jar")
	if !ok || v.String() != "31.1.0-jre" {
		t.Errorf("extractVersion guava = %v ok=%v", v.String(), ok)
	}
	v, ok = extractVersion("log4j-core-2.14.1.jar")
	if !ok || v.String() != "2.14.1" {
		t.Errorf("extension must not become a qualifier: %v ok=%v", v.String(), ok)
	}
}

func TestEarNesting(t *testing.T) {
	deep := zipBytes(t, map[string][]byte{
		"com/evil/Deep.class": buildMinimalClass(t, "com.evil.Deep", "java.lang.ProcessBuilder", "start", "()Ljava/lang/Process;"),
	})
	war := zipBytes(t, map[string][]byte{
		"WEB-INF/lib/deep.jar":               deep,
		"WEB-INF/classes/com/evil/Web.class": buildMinimalClass(t, "com.evil.Web", "java.lang.String", "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;"),
	})
	outer := writeJar(t, t.TempDir(), "app.ear", map[string][]byte{
		"lib/app.war": war,
	})
	rep, err := Analyze(outer)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if rep.ClassCount != 2 {
		t.Errorf("ClassCount = %d, want 2 (war class + nested jar class)", rep.ClassCount)
	}
	found := false
	for _, m := range rep.Findings {
		if m.Category == "COMMAND_EXECUTION" && m.SourceLocation.File == "lib/app.war!/WEB-INF/lib/deep.jar!/com/evil/Deep.class" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing doubly-nested finding; findings: %#v", rep.Findings)
	}
}

func TestDepthTruncation(t *testing.T) {
	// 6 levels of nesting with maxNestedDepth=3: must stop, flag truncated.
	payload := zipBytes(t, map[string][]byte{
		"com/evil/Deep.class": buildMinimalClass(t, "com.evil.Deep", "java.lang.Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;"),
	})
	for i := 0; i < 6; i++ {
		payload = zipBytes(t, map[string][]byte{
			"level.jar": payload,
		})
	}
	outer := writeJar(t, t.TempDir(), "deep.jar", map[string][]byte{
		"level.jar": payload,
	})
	rep, err := Analyze(outer)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !rep.Truncated {
		t.Error("deep nesting must set Truncated")
	}
}

func TestNewCVERules(t *testing.T) {
	cases := []struct {
		file string
		cve  string
	}{
		{"commons-text-1.9.3.jar", "CVE-2022-42889"},
		{"h2-1.4.200.jar", "CVE-2021-42392"},
		{"xstream-1.4.17.jar", "CVE-2021-39139"},
		{"spring-beans-5.3.17.jar", "CVE-2022-22965"},
		{"commons-text-1.10.0.jar", ""},
		{"h2-2.1.210.jar", ""},
	}
	for _, c := range cases {
		got := filterSev(matchVulnDep(c.file))
		if c.cve == "" {
			if len(got) != 0 {
				t.Errorf("%s: fixed version flagged: %#v", c.file, got)
			}
			continue
		}
		if !hasCVE(got, c.cve) {
			t.Errorf("%s: missing %s, got %#v", c.file, c.cve, got)
		}
	}
}

func hasCVE(deps []VulnDep, cve string) bool {
	for _, d := range deps {
		if d.CVE == cve {
			return true
		}
	}
	return false
}

func filterSev(deps []VulnDep) []VulnDep {
	out := deps[:0]
	for _, d := range deps {
		if d.Severity != "info" {
			out = append(out, d)
		}
	}
	return out
}

func TestManifestEntrySectionsIgnored(t *testing.T) {
	outer := writeJar(t, t.TempDir(), "sec.jar", map[string][]byte{
		"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\r\nMain-Class: com.example.Evil\r\n\r\nName: com/example/Evil.class\r\nSHA-256-Digest: QUJD\r\n\r\n"),
	})
	rep, err := Analyze(outer)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if rep.MainClass != "com.example.Evil" {
		t.Errorf("MainClass = %q", rep.MainClass)
	}
	if _, ok := rep.Manifest["Name"]; ok {
		t.Errorf("entry-section Name leaked into manifest attrs: %#v", rep.Manifest)
	}
	for k := range rep.Manifest {
		if strings.Contains(k, "Digest") {
			t.Errorf("entry-section digest leaked into manifest attrs: %#v", rep.Manifest)
		}
	}
}

func TestManifestLongLine(t *testing.T) {
	// A hostile 100 KiB single line must not kill parsing of what follows.
	outer := writeJar(t, t.TempDir(), "long.jar", map[string][]byte{
		"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\r\nLong-Attr: " + strings.Repeat("A", 100<<10) + "\r\nMain-Class: com.example.Evil\r\n"),
	})
	rep, err := Analyze(outer)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if rep.MainClass != "com.example.Evil" {
		t.Errorf("MainClass = %q, long line truncated the manifest", rep.MainClass)
	}
}

func TestUnparseableCounted(t *testing.T) {
	outer := writeJar(t, t.TempDir(), "mixed.jar", map[string][]byte{
		"com/example/Good.class": buildMinimalClass(t, "com.example.Good", "java.lang.String", "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;"),
		"com/example/Bad.class":  []byte("definitely not a class file"),
	})
	rep, err := Analyze(outer)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if rep.ClassCount != 2 {
		t.Errorf("ClassCount = %d, want 2", rep.ClassCount)
	}
	if rep.UnparseableClasses != 1 {
		t.Errorf("UnparseableClasses = %d, want 1", rep.UnparseableClasses)
	}
}

func TestJavaVersion45(t *testing.T) {
	if got := (&ClassFile{Major: 45}).JavaVersion(); got != "Java 1.1" {
		t.Errorf("JavaVersion(45) = %q, want Java 1.1", got)
	}
}
