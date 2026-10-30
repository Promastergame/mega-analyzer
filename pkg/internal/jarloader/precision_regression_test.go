package jarloader

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/crackpoint"
)

func TestClassTailEveryTruncationRejected(t *testing.T) {
	data := buildMinimalClass(t, "demo.Mod", "java.lang.Runtime", "exec", "()V")
	for n := 0; n < len(data); n++ {
		if _, err := ParseClass(data[:n]); err == nil {
			t.Fatalf("accepted truncation at %d/%d", n, len(data))
		}
	}
	if _, err := ParseClass(append(data, 0)); err == nil {
		t.Fatal("accepted trailing garbage")
	}
}

func TestParsedClassWithoutLiteralsDoesNotScanPoolNoise(t *testing.T) {
	data := buildMinimalClass(t, "MD5", "java.lang.String", "valueOf", "()V")
	cf, err := ParseClass(data)
	if err != nil {
		t.Fatal(err)
	}
	if cf.StringConstants == nil || len(secretScanStrings(cf)) != 0 {
		t.Fatal("empty literal pool must not fall back to all UTF8 entries")
	}
	if firstCategory(analyzeClass(cf, "MD5.class"), "CRYPTO_WEAK_HASH") != nil {
		t.Fatal("class name treated as an algorithm literal")
	}
}

func TestModifiedUTF8SupplementaryAndNUL(t *testing.T) {
	if got := decodeModifiedUTF8([]byte{0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80}); got != "😀" {
		t.Fatalf("surrogate pair decoded as %q", got)
	}
	if got := decodeModifiedUTF8([]byte{'a', 0xc0, 0x80, 'b'}); got != "a\x00b" {
		t.Fatalf("modified NUL decoded as %q", got)
	}
}

func TestInvalidConstantPoolLinksRejected(t *testing.T) {
	data := buildMinimalClass(t, "demo.Mod", "java.lang.Runtime", "exec", "()V")
	// this_class is the second uint16 of the final seven-word class body.
	binary.BigEndian.PutUint16(data[len(data)-12:], 1) // UTF8, not Class
	if _, err := ParseClass(data); err == nil {
		t.Fatal("invalid this_class accepted")
	}
	if err := validatePool([]constant{{}, {tag: cpClass, nameIndex: 7}}); err == nil {
		t.Fatal("dangling pool link accepted")
	}
	badLong := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 2, cpLong, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := ParseClass(badLong); err == nil {
		t.Fatal("long without reserved pool slot accepted")
	}
}

func TestCodeAttributeFraming(t *testing.T) {
	pool := []constant{{}, {tag: cpUtf8, utf8: "Code"}}
	valid := []byte{0, 0, 0, 0, 0, 0, 0, 1, 0xb1, 0, 0, 0, 0}
	if err := validateCode(valid, pool); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(valid); i++ {
		if err := validateCode(valid[:i], pool); err == nil {
			t.Fatalf("truncated Code accepted at %d", i)
		}
	}
	if err := validateCode(append(valid, 0), pool); err == nil {
		t.Fatal("trailing Code payload accepted")
	}
}

func TestSinkOwnerMustMatchExactly(t *testing.T) {
	cf := &ClassFile{ThisClass: "demo.Mod", MethodRefs: []MethodRef{{Class: "fake.java.lang.Runtime", Name: "exec"}}}
	if firstCategory(analyzeClass(cf, "Mod.class"), "COMMAND_EXECUTION") != nil {
		t.Fatal("suffix-only class matched JDK sink")
	}
}

func TestJARBudgetRejectsNegativeAndOverflow(t *testing.T) {
	for _, n := range []int64{-1, 1<<63 - 1} {
		b := &archiveBudget{}
		if b.account(1, n) || b.entries != 0 || b.uncompressed != 0 {
			t.Fatalf("invalid budget committed: %+v", b)
		}
	}
	b := &archiveBudget{uncompressed: maxTotalUncompressed - 1}
	if b.account(1, 2) || b.uncompressed != maxTotalUncompressed-1 {
		t.Fatal("addition overflow/limit was not guarded")
	}
}

func TestCorruptNestedJARIsExplicitAndSiblingsContinue(t *testing.T) {
	p := writeJar(t, t.TempDir(), "outer.jar", map[string][]byte{
		"a.jar": []byte("not ZIP"),
		"b.jar": zipBytes(t, map[string][]byte{"Mod.class": buildMinimalClass(t, "demo.Mod", "java.lang.Runtime", "exec", "()V")}),
	})
	r, err := Analyze(p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Complete || len(r.InspectionIssues) == 0 || r.ClassCount != 1 {
		t.Fatalf("silently ignored corrupt nested JAR: %+v", r)
	}
}

func TestDuplicateNestedJARsBothInspected(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, cls := range []string{"First", "Second"} {
		f, err := w.Create("same.jar")
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(zipBytes(t, map[string][]byte{cls + ".class": buildMinimalClass(t, "demo."+cls, "java.lang.Runtime", "exec", "()V")}))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "duplicates.jar")
	if err := os.WriteFile(p, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(p)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range r.Findings {
		seen[f.SourceLocation.File] = true
	}
	if r.Complete || !seen["same.jar!/First.class"] || !seen["same.jar!/Second.class"] {
		t.Fatalf("duplicate archive shadowed: %+v", r)
	}
}

func TestNestedContainerBudgetNotDoubleCharged(t *testing.T) {
	inner := zipBytes(t, map[string][]byte{"readme.txt": []byte("hello")})
	outer := zipBytes(t, map[string][]byte{"inner.jar": inner})
	z, err := zip.NewReader(bytes.NewReader(outer), int64(len(outer)))
	if err != nil {
		t.Fatal(err)
	}
	r := &Report{Complete: true, Manifest: map[string]string{}}
	budget := &archiveBudget{}
	var major uint16
	analyzeZipLevel(z.File, "", 0, crackpoint.NewFinder(), r, budget, &major)
	if budget.uncompressed != int64(len(inner)+5) {
		t.Fatalf("budget=%d want=%d", budget.uncompressed, len(inner)+5)
	}
}

func TestReadJAREntryRejectsOversize(t *testing.T) {
	data := zipBytes(t, map[string][]byte{"a.txt": []byte("12345")})
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readJAREntry(z.File[0], 4); err == nil {
		t.Fatal("prefix accepted as complete entry")
	}
	if b, err := readJAREntry(z.File[0], 5); err != nil || string(b) != "12345" {
		t.Fatalf("exact boundary: %q %v", b, err)
	}
}

func TestMavenGroupIdentity(t *testing.T) {
	if got := matchMavenCoordinates("other.vendor", "log4j-core", "2.14.1", "pom.properties"); len(got) != 0 {
		t.Fatal("unrelated Maven group matched a Log4j CVE")
	}
	if got := matchMavenCoordinates("org.apache.logging.log4j", "log4j-core", "2.14.1", "pom.properties"); !hasCVE(got, "CVE-2021-44228") {
		t.Fatal("exact Maven identity not matched")
	}
	for _, d := range matchMavenCoordinates("", "log4j-core", "2.14.1", "pom.properties") {
		if d.Severity != "info" {
			t.Fatal("missing Maven group treated as confirmed identity")
		}
	}
}

func TestJARSinkEvidenceDoesNotClaimInvocation(t *testing.T) {
	cf := &ClassFile{ThisClass: "demo.Mod", MethodRefs: []MethodRef{{Class: "java.lang.Runtime", Name: "exec"}}}
	m := firstCategory(analyzeClass(cf, "Mod.class"), "COMMAND_EXECUTION")
	if m == nil || strings.Contains(m.Context, "invoked") || m.Metadata["execution_proven"] != "false" {
		t.Fatalf("misleading evidence: %+v", m)
	}
}

func FuzzParseClassNoPanic(f *testing.F) {
	f.Add([]byte("not a class"))
	// Valid class header/pool/body, no methods, no literal constants.
	f.Add([]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 3, 1, 0, 1, 'C', 7, 0, 1, 0, 0x21, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseClass(data)
	})
}

func TestVersionIntegerOverflowIsUnknown(t *testing.T) {
	if _, ok := extractVersion("9999999999999999999999999999999999.1.0"); ok {
		t.Fatal("overflowed version treated as a real numeric version")
	}
}

func TestMethodHandleAndMethodTypeLinks(t *testing.T) {
	for _, pool := range [][]constant{
		{{}, {tag: cpMethodType, descIndex: 9}},
		{{}, {tag: cpMethodHandle, referenceKind: 0, referenceIndex: 1}},
		{{}, {tag: cpMethodHandle, referenceKind: 5, referenceIndex: 2}, {tag: cpUtf8}},
	} {
		if validatePool(pool) == nil {
			t.Fatal("invalid method handle/type accepted")
		}
	}
}

func TestJARTextCRCFailureIsVisible(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, err := w.CreateHeader(&zip.FileHeader{Name: "config.txt", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("unique-crc-marker")); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	data := b.Bytes()
	i := bytes.Index(data, []byte("unique-crc-marker"))
	if i < 0 {
		t.Fatal("fixture marker missing")
	}
	data[i] = 'X'
	p := filepath.Join(t.TempDir(), "crc.jar")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Complete || len(r.InspectionIssues) == 0 {
		t.Fatal("bad CRC silently ignored")
	}
}

func TestJARUnsafePaths(t *testing.T) {
	for _, name := range []string{"../outside.class", `/absolute.class`, `C:\\x.class`, `a/../../x`, "file:stream"} {
		if !unsafeJARPath(name) {
			t.Errorf("unsafe path accepted: %q", name)
		}
	}
	if unsafeJARPath("com/example/Mod.class") {
		t.Fatal("normal path rejected")
	}
}
