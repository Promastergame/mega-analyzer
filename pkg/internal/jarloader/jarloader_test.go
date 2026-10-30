package jarloader

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// firstCategory returns the first match of the given category, or nil.
func firstCategory(ms []types.Match, cat types.Category) *types.Match {
	for i := range ms {
		if ms[i].Category == cat {
			return &ms[i]
		}
	}
	return nil
}

func TestAnalyzeClass_LibraryInternalsDownranked(t *testing.T) {
	app := &ClassFile{ThisClass: "com.example.App", MethodRefs: []MethodRef{{Class: "java.lang.Runtime", Name: "exec"}}}
	lib := &ClassFile{ThisClass: "org.apache.commons.exec.Executor", MethodRefs: []MethodRef{{Class: "java.lang.Runtime", Name: "exec"}}}
	am := firstCategory(analyzeClass(app, "a"), "COMMAND_EXECUTION")
	lm := firstCategory(analyzeClass(lib, "b"), "COMMAND_EXECUTION")
	if am == nil || lm == nil {
		t.Fatal("expected COMMAND_EXECUTION in both app and library class")
	}
	if !(am.Severity > lm.Severity) {
		t.Errorf("library call should be down-ranked below app call: app=%v lib=%v", am.Severity, lm.Severity)
	}
	if am.Severity < types.SeverityHigh {
		t.Errorf("app Runtime.exec should stay high, got %v", am.Severity)
	}
}

func TestAnalyzeClass_XXENotSuppressedByUnprovenHardening(t *testing.T) {
	ref := []MethodRef{{Class: "javax.xml.parsers.DocumentBuilderFactory", Name: "newInstance"}}
	vuln := &ClassFile{ThisClass: "com.example.Xml", MethodRefs: ref}
	hard := &ClassFile{ThisClass: "com.example.Xml", MethodRefs: ref, Strings: []string{"http://apache.org/xml/features/disallow-doctype-decl"}}
	if firstCategory(analyzeClass(vuln, "a"), "XXE") == nil {
		t.Fatal("expected XXE finding for an unhardened parser factory")
	}
	if firstCategory(analyzeClass(hard, "b"), "XXE") == nil {
		t.Error("a string alone cannot prove XML hardening; retain the review finding")
	}
}

func TestAnalyzeClass_CustomTLSIsNotProvenTrustAll(t *testing.T) {
	cf := &ClassFile{ThisClass: "com.example.TrustEverything", Interfaces: []string{"javax.net.ssl.X509TrustManager"}}
	m := firstCategory(analyzeClass(cf, "a"), "INSECURE_TLS_TRUST")
	if m == nil {
		t.Fatal("expected INSECURE_TLS_TRUST for a custom X509TrustManager")
	}
	if m.Severity != types.SeverityLow {
		t.Errorf("interface alone is a low-severity review point, got %v", m.Severity)
	}
}

func TestAnalyzeClass_WeakCipherGatedOnGetInstance(t *testing.T) {
	withCall := &ClassFile{
		ThisClass:  "com.example.Crypto",
		MethodRefs: []MethodRef{{Class: "javax.crypto.Cipher", Name: "getInstance"}},
		Strings:    []string{"AES/ECB/PKCS5Padding"},
	}
	if firstCategory(analyzeClass(withCall, "a"), "CRYPTO_WEAK_CIPHER") == nil {
		t.Fatal("expected CRYPTO_WEAK_CIPHER for AES/ECB with a Cipher.getInstance call")
	}
	// The same transformation string without the Cipher.getInstance call must
	// not fire — the gate keeps the regex from matching unrelated constants.
	noCall := &ClassFile{ThisClass: "com.example.Crypto", Strings: []string{"AES/ECB/PKCS5Padding"}}
	if firstCategory(analyzeClass(noCall, "b"), "CRYPTO_WEAK_CIPHER") != nil {
		t.Error("weak cipher must be gated on a Cipher.getInstance reference")
	}
}

func TestAnalyzeClass_NewSinksDetected(t *testing.T) {
	cases := []struct {
		ref MethodRef
		cat types.Category
	}{
		{MethodRef{Class: "java.beans.XMLDecoder", Name: "readObject"}, "INSECURE_DESERIALIZATION"},
		{MethodRef{Class: "org.yaml.snakeyaml.Yaml", Name: "load"}, "INSECURE_DESERIALIZATION"},
		{MethodRef{Class: "org.springframework.expression.spel.standard.SpelExpressionParser", Name: "parseExpression"}, "EXPRESSION_INJECTION"},
		{MethodRef{Class: "ognl.Ognl", Name: "getValue"}, "EXPRESSION_INJECTION"},
		{MethodRef{Class: "groovy.lang.GroovyShell", Name: "evaluate"}, "DYNAMIC_CODE_LOADING"},
		{MethodRef{Class: "java.lang.System", Name: "load"}, "NATIVE_CODE_LOADING"},
	}
	for _, c := range cases {
		// Owner is app code so library down-ranking does not interfere.
		cf := &ClassFile{ThisClass: "com.example.Sink", MethodRefs: []MethodRef{c.ref}}
		if firstCategory(analyzeClass(cf, "x"), c.cat) == nil {
			t.Errorf("expected %s finding for %s.%s", c.cat, c.ref.Class, c.ref.Name)
		}
	}
}

func TestAnalyzeClass_NoMessageDigestNoise(t *testing.T) {
	// MessageDigest.getInstance alone is no longer a finding (pure noise on every
	// SHA-256 use); only weak-algorithm string constants are flagged.
	cf := &ClassFile{ThisClass: "com.example.Hash", MethodRefs: []MethodRef{{Class: "java.security.MessageDigest", Name: "getInstance"}}}
	if got := analyzeClass(cf, "a"); len(got) != 0 {
		t.Errorf("MessageDigest.getInstance should produce no findings by itself, got %d: %#v", len(got), got)
	}
}

// buildMinimalClass synthesizes a tiny but structurally valid .class file whose
// constant pool contains a single Methodref to the given class/method. This is
// enough to exercise the parser and sink detection without a JDK.
func buildMinimalClass(t *testing.T, thisClass, refClass, refMethod, refDesc string) []byte {
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

	w(uint32(classMagic))
	w(uint16(0))  // minor
	w(uint16(52)) // major = Java 8

	// Constant pool layout (indices):
	// 1: utf8 thisClass name
	// 2: Class -> 1
	// 3: utf8 "java/lang/Object"
	// 4: Class -> 3 (super)
	// 5: utf8 refClass name (internal)
	// 6: Class -> 5
	// 7: utf8 refMethod
	// 8: utf8 refDesc
	// 9: NameAndType -> 7,8
	// 10: Methodref -> 6,9
	w(uint16(11)) // constant_pool_count = entries+1

	utf8(internal(thisClass)) // 1
	w(uint8(cpClass))         // 2
	w(uint16(1))
	utf8("java/lang/Object") // 3
	w(uint8(cpClass))        // 4
	w(uint16(3))
	utf8(internal(refClass)) // 5
	w(uint8(cpClass))        // 6
	w(uint16(5))
	utf8(refMethod)         // 7
	utf8(refDesc)           // 8
	w(uint8(cpNameAndType)) // 9
	w(uint16(7))
	w(uint16(8))
	w(uint8(cpMethodref)) // 10
	w(uint16(6))
	w(uint16(9))

	w(uint16(0x0021)) // access_flags public super
	w(uint16(2))      // this_class -> 2
	w(uint16(4))      // super_class -> 4
	w(uint16(0))      // interfaces_count
	w(uint16(0))      // fields_count
	w(uint16(0))      // methods_count
	w(uint16(0))      // attributes_count

	return b.Bytes()
}

func internal(dotted string) string {
	out := []byte(dotted)
	for i := range out {
		if out[i] == '.' {
			out[i] = '/'
		}
	}
	return string(out)
}

func TestParseClassAndSink(t *testing.T) {
	data := buildMinimalClass(t, "com.example.Evil", "java.lang.Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;")
	cf, err := ParseClass(data)
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	if cf.ThisClass != "com.example.Evil" {
		t.Errorf("ThisClass = %q", cf.ThisClass)
	}
	if cf.JavaVersion() != "Java 8" {
		t.Errorf("JavaVersion = %q", cf.JavaVersion())
	}
	findings := analyzeClass(cf, "com/example/Evil.class")
	if len(findings) == 0 {
		t.Fatal("expected Runtime.exec sink finding")
	}
	if findings[0].Category != "COMMAND_EXECUTION" {
		t.Errorf("category = %q", findings[0].Category)
	}
}

func TestParseClassRejectsNonClass(t *testing.T) {
	if _, err := ParseClass([]byte("not a class")); err == nil {
		t.Fatal("expected error for non-class data")
	}
}

func TestAnalyzeJar(t *testing.T) {
	dir := t.TempDir()
	jarPath := filepath.Join(dir, "app.jar")
	f, err := os.Create(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)

	mf, _ := zw.Create("META-INF/MANIFEST.MF")
	mf.Write([]byte("Manifest-Version: 1.0\r\nMain-Class: com.example.Evil\r\n"))

	cw, _ := zw.Create("com/example/Evil.class")
	cw.Write(buildMinimalClass(t, "com.example.Evil", "java.io.ObjectInputStream", "readObject", "()Ljava/lang/Object;"))

	cfg, _ := zw.Create("BOOT-INF/classes/application.properties")
	cfg.Write([]byte("telegram.bot=123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi\n"))

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	rep, err := Analyze(jarPath)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if rep.MainClass != "com.example.Evil" {
		t.Errorf("MainClass = %q", rep.MainClass)
	}
	if rep.ClassCount != 1 {
		t.Errorf("ClassCount = %d", rep.ClassCount)
	}
	found := false
	for _, m := range rep.Findings {
		if m.Category == "INSECURE_DESERIALIZATION" {
			found = true
		}
	}
	if !found {
		t.Error("expected INSECURE_DESERIALIZATION finding")
	}
	foundTelegram := false
	for _, m := range rep.Findings {
		if m.Pattern == "secret/telegram-bot-token" {
			foundTelegram = true
			break
		}
	}
	if !foundTelegram {
		t.Fatalf("expected telegram bot token finding, got %#v", rep.Findings)
	}
}

func TestMatchVulnDep(t *testing.T) {
	cases := []struct {
		file    string
		wantCVE string
		wantHit bool
	}{
		{"log4j-core-2.14.1.jar", "CVE-2021-44228", true},
		{"log4j-core-2.17.1.jar", "", false},
		{"spring-core-5.3.17.jar", "CVE-2022-22965", true},
		{"spring-core-5.3.20.jar", "", false},
		{"commons-collections-3.2.1.jar", "CVE-2015-7501", true},
		{"guava-31.0.jar", "", false},
	}
	for _, c := range cases {
		got := matchVulnDep(c.file)
		hit := false
		for _, d := range got {
			if d.CVE == c.wantCVE && d.Severity != "info" {
				hit = true
			}
		}
		if hit != c.wantHit {
			t.Errorf("%s: got %+v, wantHit=%v", c.file, got, c.wantHit)
		}
	}
}

func TestBytecodeURLInventory(t *testing.T) {
	cf := &ClassFile{ThisClass: "com.example.Net", StringConstants: []string{
		"https://api.example.com/v1/ping",
		"https://api.example.com/v1/ping", // duplicate literal: one row
		"http://localhost:8080/health",
		"not a url",
		"just words here",
	}}
	var urls []types.Match
	for _, m := range analyzeClass(cf, "Net.class") {
		if m.Category == types.CategoryNetworkEndpoint && m.Severity == types.SeverityInfo {
			urls = append(urls, m)
		}
	}
	if len(urls) != 1 {
		t.Fatalf("want exactly 1 URL inventory row, got %d: %+v", len(urls), urls)
	}
	u := urls[0]
	if u.Metadata["host"] != "api.example.com" || u.Metadata["scheme"] != "https" {
		t.Errorf("bad host metadata: %+v", u.Metadata)
	}
	if u.EvidenceType != "bytecode_string" {
		t.Errorf("EvidenceType = %q, want bytecode_string", u.EvidenceType)
	}
}

func TestSplitBytecodeURL(t *testing.T) {
	h, s, _ := splitBytecodeURL("https://Example.COM:443/a?b=c")
	if h != "example.com" || s != "https" {
		t.Errorf("got %q %q", h, s)
	}
	if h, _, _ := splitBytecodeURL("https://127.0.0.1/x"); h != "" {
		t.Errorf("loopback must be skipped, got %q", h)
	}
	if h, _, _ := splitBytecodeURL("ftp://example.com/x"); h != "" {
		t.Errorf("non-http scheme must be skipped, got %q", h)
	}
}

func TestDemoteLibraryCrackPoint(t *testing.T) {
	mk := func(class string, conf float64) types.CrackPoint {
		return types.CrackPoint{ClassName: class, Confidence: conf, Suggestion: "check"}
	}
	lib := demoteLibraryCrackPoint(mk("com.google.gson.internal.UnsafeAllocator", 0.90))
	if lib.Confidence >= 0.85 {
		t.Errorf("library crackpoint not demoted below HIGH: %v", lib.Confidence)
	}
	if lib.Suggestion == "check" {
		t.Error("library crackpoint must carry the internals note")
	}
	app := demoteLibraryCrackPoint(mk("meteordevelopment.meteorclient.Main", 0.90))
	if app.Confidence != 0.90 || app.Suggestion != "check" {
		t.Errorf("app crackpoint must be untouched: %+v", app)
	}
	for _, cls := range []string{"net.raphimc.minecraftauth.X", "net.lenni0451.commons.Y", "javassist.CtClass"} {
		if !isThirdPartyLibrary(cls) {
			t.Errorf("isThirdPartyLibrary(%q) = false, want true", cls)
		}
	}
}
