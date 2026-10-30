package jarloader

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/crackpoint"
	"mega-analyzer/pkg/internal/secrets"
	"mega-analyzer/pkg/internal/types"
)

// maxClassBytes caps a single decompressed .class entry to guard against zip
// bombs while still covering essentially all real-world classes.
const maxClassBytes = 32 << 20    // 32 MiB
const maxTextEntryBytes = 2 << 20 // 2 MiB

// dangerousSink describes a method reference that indicates a high-risk
// capability when present in a class's constant pool.
type dangerousSink struct {
	classSuffix string // exact dotted owner; historical field name
	method      string // method name; empty matches any
	category    types.Category
	severity    types.Severity
	confidence  float64 // base confidence before context adjustment
	reason      string
}

// sinks is the catalogue of dangerous Java APIs we flag. These are the top
// real-world RCE / injection / deserialization sources in JVM applications.
// The confidence reflects how strongly the bare presence of the call implies a
// vulnerability: deliberate RCE/deser sinks are high; ubiquitous reflection is
// low so it ranks below real issues instead of burying them.
var sinks = []dangerousSink{
	// ── Deserialization (RCE gadget sinks) ──────────────────────────────────
	{"java.io.ObjectInputStream", "readObject", "INSECURE_DESERIALIZATION", types.SeverityHigh, 0.6, "native Java deserialization (readObject) is a classic RCE gadget sink"},
	{"java.io.ObjectInputStream", "readUnshared", "INSECURE_DESERIALIZATION", types.SeverityHigh, 0.6, "native Java deserialization (readUnshared)"},
	{"java.beans.XMLDecoder", "readObject", "INSECURE_DESERIALIZATION", types.SeverityHigh, 0.7, "XMLDecoder.readObject deserializes arbitrary objects — direct RCE on attacker-controlled XML"},
	{"org.yaml.snakeyaml.Yaml", "load", "INSECURE_DESERIALIZATION", types.SeverityHigh, 0.55, "SnakeYAML Yaml.load with the default constructor instantiates arbitrary types (RCE)"},
	{"com.thoughtworks.xstream.XStream", "fromXML", "INSECURE_DESERIALIZATION", types.SeverityHigh, 0.55, "XStream.fromXML deserializes arbitrary types unless a strict allowlist is configured"},

	// ── OS command execution ────────────────────────────────────────────────
	{"java.lang.Runtime", "exec", "COMMAND_EXECUTION", types.SeverityHigh, 0.6, "Runtime.exec executes OS commands"},
	{"java.lang.ProcessBuilder", "start", "COMMAND_EXECUTION", types.SeverityHigh, 0.6, "ProcessBuilder.start executes OS commands"},

	// ── Dynamic code / class loading ────────────────────────────────────────
	{"java.lang.reflect.Method", "invoke", "DYNAMIC_CODE_LOADING", types.SeverityMedium, 0.3, "reflective method invocation (very common; risky only with attacker-controlled targets)"},
	{"java.lang.Class", "forName", "DYNAMIC_CODE_LOADING", types.SeverityMedium, 0.3, "reflective class loading via Class.forName"},
	{"java.lang.ClassLoader", "defineClass", "DYNAMIC_CODE_LOADING", types.SeverityHigh, 0.55, "runtime class definition via ClassLoader.defineClass"},
	{"java.net.URLClassLoader", "", "DYNAMIC_CODE_LOADING", types.SeverityHigh, 0.5, "URLClassLoader can load and execute code from a (possibly remote) URL"},
	{"javax.script.ScriptEngine", "eval", "DYNAMIC_CODE_LOADING", types.SeverityHigh, 0.6, "script engine eval executes arbitrary script"},
	{"javax.script.ScriptEngineManager", "getEngineByName", "DYNAMIC_CODE_LOADING", types.SeverityMedium, 0.4, "obtains a scripting engine — eval of untrusted script is RCE"},
	{"groovy.lang.GroovyShell", "evaluate", "DYNAMIC_CODE_LOADING", types.SeverityHigh, 0.6, "GroovyShell.evaluate executes arbitrary Groovy (RCE)"},
	{"groovy.lang.GroovyClassLoader", "parseClass", "DYNAMIC_CODE_LOADING", types.SeverityHigh, 0.6, "GroovyClassLoader.parseClass compiles and loads arbitrary Groovy (RCE)"},

	// ── Injection (JNDI / expression languages / SQL) ───────────────────────
	{"javax.naming.InitialContext", "lookup", "JNDI_INJECTION", types.SeverityHigh, 0.6, "JNDI lookup (Log4Shell-style injection sink)"},
	{"javax.naming.Context", "lookup", "JNDI_INJECTION", types.SeverityHigh, 0.6, "JNDI lookup (Log4Shell-style injection sink)"},
	{"org.springframework.expression.spel.standard.SpelExpressionParser", "parseExpression", "EXPRESSION_INJECTION", types.SeverityHigh, 0.5, "Spring SpEL parseExpression on untrusted input is RCE (CVE-2022-22963 class)"},
	{"ognl.Ognl", "getValue", "EXPRESSION_INJECTION", types.SeverityHigh, 0.5, "OGNL getValue on untrusted input is RCE (Struts-style)"},
	{"ognl.Ognl", "setValue", "EXPRESSION_INJECTION", types.SeverityHigh, 0.5, "OGNL setValue on untrusted input is RCE (Struts-style)"},
	{"java.sql.Statement", "executeQuery", "SQL_INJECTION", types.SeverityMedium, 0.35, "raw SQL Statement (potential SQL injection if concatenated)"},
	{"java.sql.Statement", "execute", "SQL_INJECTION", types.SeverityMedium, 0.35, "raw SQL Statement (potential SQL injection if concatenated)"},
	{"java.sql.Statement", "executeUpdate", "SQL_INJECTION", types.SeverityMedium, 0.35, "raw SQL Statement (potential SQL injection if concatenated)"},

	// ── XXE (XML parser factories; suppressed when the class also hardens) ───
	{"javax.xml.parsers.DocumentBuilderFactory", "newInstance", "XXE", types.SeverityMedium, 0.4, "DocumentBuilderFactory — verify external entities/DTDs are disabled (XXE)"},
	{"javax.xml.parsers.SAXParserFactory", "newInstance", "XXE", types.SeverityMedium, 0.4, "SAXParserFactory — verify external entities/DTDs are disabled (XXE)"},
	{"javax.xml.stream.XMLInputFactory", "newInstance", "XXE", types.SeverityMedium, 0.4, "XMLInputFactory — verify IS_SUPPORTING_EXTERNAL_ENTITIES is false (XXE)"},
	{"javax.xml.stream.XMLInputFactory", "newFactory", "XXE", types.SeverityMedium, 0.4, "XMLInputFactory — verify IS_SUPPORTING_EXTERNAL_ENTITIES is false (XXE)"},
	{"javax.xml.transform.TransformerFactory", "newInstance", "XXE", types.SeverityMedium, 0.4, "TransformerFactory — verify ACCESS_EXTERNAL_DTD/STYLESHEET are restricted (XXE/SSRF)"},
	{"org.dom4j.io.SAXReader", "read", "XXE", types.SeverityMedium, 0.4, "dom4j SAXReader — disable DOCTYPE/external entities (XXE)"},

	// Modern runtime class definition APIs (still capabilities, not a verdict).
	{"java.lang.invoke.MethodHandles$Lookup", "defineClass", "DYNAMIC_CODE_LOADING", types.SeverityHigh, 0.55, "Lookup.defineClass defines runtime bytecode"},
	{"java.lang.invoke.MethodHandles$Lookup", "defineHiddenClass", "DYNAMIC_CODE_LOADING", types.SeverityHigh, 0.55, "Lookup.defineHiddenClass defines hidden runtime bytecode"},
	{"java.lang.Runtime", "load", "NATIVE_CODE_LOADING", types.SeverityMedium, 0.45, "Runtime.load loads a native library"},
	{"java.lang.Runtime", "loadLibrary", "NATIVE_CODE_LOADING", types.SeverityLow, 0.25, "Runtime.loadLibrary loads a native library"},

	// ── Native library loading ──────────────────────────────────────────────
	{"java.lang.System", "load", "NATIVE_CODE_LOADING", types.SeverityMedium, 0.45, "System.load loads a native library from an absolute path"},
	{"java.lang.System", "loadLibrary", "NATIVE_CODE_LOADING", types.SeverityLow, 0.25, "System.loadLibrary loads a native library (common; risky if the path/name is attacker-controlled)"},
}

// xxeCategory is the category used for XML-parser-factory sinks; findings of
// this category are suppressed when the same class also references XML
// hardening features.
const xxeCategory types.Category = "XXE"

// weakHashAlgo flags weak digests by string constant, including the
// composite JCA names (MD5withRSA, SHA1withRSA, HmacMD5, HmacSHA1) that
// select weak signature/MAC algorithms.
var weakHashAlgo = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])(MD5|MD2|SHA-?1|HmacMD5|HmacSHA-?1|MD5withRSA|MD2withRSA|SHA1withRSA|SHA1withDSA|SHA1withECDSA)(?:[^A-Za-z0-9]|$)`)

// algoTokenShape requires the whole constant to look like one algorithm
// token so the weak-hash pattern cannot match prose or descriptors.
var algoTokenShape = regexp.MustCompile(`^[A-Za-z0-9/_-]{1,32}$`)

// weakCipherTransform matches Cipher transformation strings that select a
// broken algorithm or the ECB mode. It is only consulted for classes that also
// reference Cipher.getInstance, keeping it from matching unrelated words.
var weakCipherTransform = regexp.MustCompile(`(?i)(?:^|[^A-Za-z])(DES|DESede|RC2|RC4|ARCFOUR|Blowfish)(?:/|$|[^A-Za-z])|/ECB/|/ECB$`)

// xmlHardeningTokens are review context only. Presence of a token does not
// establish its boolean value, target parser instance, or runtime execution.
var xmlHardeningTokens = []string{
	"http://apache.org/xml/features/disallow-doctype-decl",
	"http://xml.org/sax/features/external-general-entities",
	"http://xml.org/sax/features/external-parameter-entities",
	"http://apache.org/xml/features/nonvalidating/load-external-dtd",
	"http://javax.xml.XMLConstants/feature/secure-processing",
	"FEATURE_SECURE_PROCESSING",
	"ACCESS_EXTERNAL_DTD",
	"ACCESS_EXTERNAL_SCHEMA",
	"ACCESS_EXTERNAL_STYLESHEET",
	"setExpandEntityReferences",
	"XMLConstants",
}

// tlsTrustInterfaces identify custom certificate validation to review.
// Implementing these interfaces alone does not establish insecure behavior.
var tlsTrustInterfaces = map[string]string{
	"javax.net.ssl.X509TrustManager": "custom X509TrustManager — verify it actually validates the chain (empty checkServerTrusted = trust-all)",
	"javax.net.ssl.TrustManager":     "custom TrustManager — verify it actually validates certificates",
	"javax.net.ssl.HostnameVerifier": "custom HostnameVerifier — verify it does not unconditionally return true (accepts any hostname)",
}

// thirdPartyPrefixes are dotted package prefixes of widely-bundled libraries
// and the JDK. A dangerous sink whose *owning* class lives here is usually the
// library implementing or wrapping the API, not the application's own risky
// call — so we keep the finding but lower its priority to cut the fat/uber-jar
// noise that otherwise drowns real application findings.
var thirdPartyPrefixes = []string{
	"java.", "javax.", "jakarta.", "sun.", "jdk.", "com.sun.",
	"kotlin.", "kotlinx.", "scala.", "groovy.", "clojure.",
	"org.jetbrains.", "org.intellij.", "org.codehaus.",
	"org.apache.", "org.springframework.", "org.hibernate.", "org.eclipse.",
	"org.slf4j.", "ch.qos.logback.",
	"com.fasterxml.", "com.google.", "com.squareup.", "okhttp3.", "okio.", "retrofit2.",
	"io.netty.", "io.reactivex.", "reactor.", "org.reactivestreams.",
	"org.bouncycastle.", "org.json.", "com.thoughtworks.xstream.", "org.yaml.snakeyaml.",
	"org.objectweb.asm.", "net.bytebuddy.", "org.dom4j.", "org.jdom.",
	"net.raphimc.", "net.lenni0451.", "javassist.",
	"androidx.", "android.support.", "com.android.", "android.",
	"org.junit.", "junit.", "org.mockito.", "org.testng.", "org.assertj.", "org.hamcrest.",
}

// isThirdPartyLibrary reports whether dotted lives in a bundled-library/JDK
// namespace (see thirdPartyPrefixes).
func isThirdPartyLibrary(dotted string) bool {
	for _, p := range thirdPartyPrefixes {
		if strings.HasPrefix(dotted, p) {
			return true
		}
	}
	return false
}

// demoteSeverity lowers a severity by one notch, never below Low. Used to
// down-rank sinks found inside library internals.
func demoteSeverity(s types.Severity) types.Severity {
	switch s {
	case types.SeverityCritical:
		return types.SeverityHigh
	case types.SeverityHigh:
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}

// classHasXMLHardening reports whether any XML-hardening token appears in the
// class's string constants.
func classHasXMLHardening(strs []string) bool {
	for _, s := range strs {
		for _, tok := range xmlHardeningTokens {
			if strings.Contains(s, tok) {
				return true
			}
		}
	}
	return false
}

// Report is the result of analyzing a single JAR/WAR/EAR archive.
type InspectionIssue struct {
	Entry  string `json:"entry"`
	Reason string `json:"reason"`
}

// Report preserves partial findings and explicitly exposes inspection gaps.
type Report struct {
	InstructionCount int                `json:"instruction_count"`
	InvocationCount  int                `json:"invocation_count"`
	MethodCount      int                `json:"method_count"`
	Complete         bool               `json:"complete"`
	InspectionIssues []InspectionIssue  `json:"inspection_issues,omitempty"`
	Target           string             `json:"target"`
	MainClass        string             `json:"main_class,omitempty"`
	ClassCount       int                `json:"class_count"`
	JavaVersion      string             `json:"java_version,omitempty"`
	NestedJars       []string           `json:"nested_jars,omitempty"`
	Findings         []types.Match      `json:"findings,omitempty"`
	VulnDeps         []VulnDep          `json:"vuln_deps,omitempty"`
	Manifest         map[string]string  `json:"manifest,omitempty"`
	CrackPoints      []types.CrackPoint `json:"crack_points,omitempty"`
	// Mods lists Java mod-loader descriptors (Fabric/Quilt/Forge) found in
	// the archive. Bedrock packs never carry these; see javamod.go.
	Mods           []JavaMod `json:"mods,omitempty"`
	Truncated      bool      `json:"truncated,omitempty"`
	TruncateReason string    `json:"truncate_reason,omitempty"`
	// UnparseableClasses counts .class entries the parser rejected
	// (truncated, encrypted, or non-class bytes under a .class name).
	// They contribute to ClassCount but yield no findings: a blind spot
	// worth knowing about instead of silent zeros.
	UnparseableClasses int `json:"unparseable_classes,omitempty"`
	// pomSeen tracks artifactIds observed in pom.properties entries for
	// corroborating filename-based dependency guesses. Not serialized.
	pomSeen map[string]bool
	// Obfuscation accumulators (see obfdetect.go). Not serialized; drained
	// into a single rollup finding by emitObfuscationFinding.
	obfShortNames int
	obfEncStrings int
	obfMarkers    map[string]bool
	obfExamples   []string
}

// Bounds for nested-archive extraction (zip-bomb defense). Per-entry caps
// (maxClassBytes/maxTextEntryBytes) already exist; these bound the whole
// analysis: depth, total entry count and total uncompressed bytes across
// every nesting level.
const (
	maxNestedDepth       = 3
	maxArchiveEntries    = 100000
	maxTotalUncompressed = 2 << 30
	maxNestedArchiveSize = 512 << 20
)

// archiveBudget tracks global extraction limits across nested archives.
type archiveBudget struct {
	entries      int
	uncompressed int64
	truncated    string
}

func (b *archiveBudget) account(entries int, uncompressed int64) bool {
	// Compare before adding; int64 conversion of hostile ZIP64 sizes can be negative.
	if entries < 0 || entries > maxArchiveEntries-b.entries {
		b.truncated = fmt.Sprintf("entry count exceeded %d", maxArchiveEntries)
		return false
	}
	if uncompressed < 0 || uncompressed > maxTotalUncompressed-b.uncompressed {
		b.truncated = fmt.Sprintf("uncompressed size exceeded %d bytes", int64(maxTotalUncompressed))
		return false
	}
	b.entries += entries
	b.uncompressed += uncompressed
	return true
}

// Analyze opens the archive at path and runs static analysis over its
// classes, descending into nested .jar/.war/.ear archives (Spring Boot
// fat-jars, WAR WEB-INF/lib) with bounded depth and size.
func Analyze(path string) (*Report, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	rep := &Report{Target: path, Manifest: map[string]string{}, Complete: true}
	finder := crackpoint.NewFinder()
	budget := &archiveBudget{}
	var maxMajor uint16
	analyzeZipLevel(zr.File, "", 0, finder, rep, budget, &maxMajor)
	if maxMajor > 0 {
		rep.JavaVersion = (&ClassFile{Major: maxMajor}).JavaVersion()
	}
	if budget.truncated != "" {
		rep.Truncated = true
		rep.Complete = false
		rep.TruncateReason = budget.truncated
	}
	// Archive-level obfuscation rollup from the per-class signals above.
	if m := emitObfuscationFinding(rep); m != nil {
		rep.Findings = append(rep.Findings, *m)
	}
	// Stealer/RAT combo escalation across distinct theft behaviors.
	if m := emitRatCombo(rep); m != nil {
		rep.Findings = append(rep.Findings, *m)
	}
	demoteUncorroboratedDeps(rep)
	dedupeVulnDeps(rep)
	return rep, nil
}

// demoteUncorroboratedDeps separates filename guesses from identified
// components: a filename-only match for an artifact never seen in any
// pom.properties keeps its CVE but drops one severity notch with an
// explicit note. Maven-coordinate matches are unaffected.
func demoteUncorroboratedDeps(rep *Report) {
	for i := range rep.VulnDeps {
		d := &rep.VulnDeps[i]
		if d.Evidence != "filename" || d.Severity == "info" {
			continue
		}
		if rep.pomSeen[strings.ToLower(d.Library)] {
			continue
		}
		d.Severity = demoteDepSeverity(d.Severity)
		d.Summary += " (filename match only — confirm artifact identity)"
	}
}

func demoteDepSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "high"
	case "high":
		return "medium"
	case "medium":
		return "low"
	default:
		return s
	}
}

// analyzeZipLevel processes one archive level: manifest (outer level only),
// text entries (secrets + Maven coordinates), classes (parallel), then nested
// archives (recursive). prefix is prepended to finding locations as
// "outer.jar!/inner.jar" chains; depth counts nesting below the outer file.
func analyzeZipLevel(files []*zip.File, prefix string, depth int, finder *crackpoint.Finder, rep *Report, budget *archiveBudget, maxMajor *uint16) {
	loc := func(name string) string {
		if prefix == "" {
			return name
		}
		return prefix + "!/" + name
	}

	var classes []*zip.File
	var nested []*zip.File
	seen := map[string]bool{}
	for _, f := range files {
		if !budget.account(1, int64(f.UncompressedSize64)) {
			break // Still analyze entries already admitted into the budget.
		}
		name := f.Name
		if f.FileInfo().IsDir() {
			continue
		}
		if !f.Mode().IsRegular() {
			rep.issue(loc(name), "non-regular ZIP entry was not read")
			continue
		}
		if unsafeJARPath(name) {
			rep.issue(loc(name), "unsafe ZIP path")
			continue
		}
		if seen[name] {
			rep.issue(loc(name), "duplicate ZIP name; all occurrences are inspected")
		}
		seen[name] = true
		if loader, isMod := DetectModDescriptor(innerJarName(name)); isJARTextEntry(name) || isMod {
			limit := int64(maxTextEntryBytes)
			if isMavenPomProperties(name) {
				limit = 64 << 10
			}
			data, err := readJAREntry(f, limit)
			if err != nil {
				rep.issue(loc(name), err.Error())
				continue
			}
			if depth == 0 && strings.EqualFold(name, "META-INF/MANIFEST.MF") {
				parseManifestData(data, rep)
			}
			if isMod {
				mods, issues := ParseModMetadata(loader, loc(name), data)
				rep.Mods = append(rep.Mods, mods...)
				for _, issue := range issues {
					rep.issue(loc(name), issue)
				}
			}
			if isMostlyText(data) {
				rep.Findings = append(rep.Findings, withLocation(providerFindingsToMatches(secrets.DetectProviders(string(data), loc(name)), loc(name), "JAR text resource"), loc, name)...)
			}
			if isMavenPomProperties(name) {
				group, artifact, version := parseMavenCoords(data)
				if artifact != "" {
					if rep.pomSeen == nil {
						rep.pomSeen = map[string]bool{}
					}
					rep.pomSeen[strings.ToLower(artifact)] = true
				}
				rep.VulnDeps = append(rep.VulnDeps, matchMavenCoordinates(group, artifact, version, loc(name))...)
			}
			continue
		}
		switch {
		case strings.HasSuffix(strings.ToLower(name), ".class"):
			rep.ClassCount++
			classes = append(classes, f)
		case isNestedArchive(name):
			rep.NestedJars = append(rep.NestedJars, loc(name))
			rep.VulnDeps = append(rep.VulnDeps, matchVulnDep(name)...)
			nested = append(nested, f)
		}
	}
	// Vulnerable-dependency detection also runs on the archive's own name.
	if depth == 0 {
		rep.VulnDeps = append(rep.VulnDeps, matchVulnDep(rep.Target)...)
	}

	analyzeClassesParallel(classes, loc, finder, rep, maxMajor)

	if depth >= maxNestedDepth {
		if len(nested) > 0 && budget.truncated == "" {
			budget.truncated = fmt.Sprintf("nesting depth exceeded %d", maxNestedDepth)
		}
		return
	}
	if budget.truncated != "" {
		return
	}
	sort.SliceStable(nested, func(i, j int) bool { return nested[i].Name < nested[j].Name })
	for _, entry := range nested {
		descendNestedEntry(entry, loc(entry.Name), depth+1, finder, rep, budget, maxMajor)
		if budget.truncated != "" {
			return
		}
	}
}

// withLocation rewrites finding locations to the prefixed nested path.
func withLocation(matches []types.Match, loc func(string) string, name string) []types.Match {
	if prefix := loc(name); prefix != name {
		for i := range matches {
			if matches[i].SourceLocation.File == name {
				matches[i].SourceLocation.File = prefix
			}
		}
	}
	return matches
}

func isNestedArchive(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".war") || strings.HasSuffix(lower, ".ear")
}

// innerJarName strips nested "!/" prefixes to the archive-relative path.
func innerJarName(name string) string {
	if i := strings.LastIndex(name, "!/"); i >= 0 {
		return name[i+2:]
	}
	return name
}

// isMavenPomProperties reports META-INF/maven/<group>/<artifact>/pom.properties
// at any nesting level (the "!/" prefixes of nested entries are skipped).
func isMavenPomProperties(name string) bool {
	inner := innerJarName(name)
	lower := strings.ToLower(inner)
	return strings.HasPrefix(lower, "meta-inf/maven/") && strings.HasSuffix(lower, "pom.properties")
}

func descendNestedEntry(entry *zip.File, prefixed string, depth int, finder *crackpoint.Finder, rep *Report, budget *archiveBudget, maxMajor *uint16) {
	data, err := readJAREntry(entry, maxNestedArchiveSize)
	if err != nil {
		rep.issue(prefixed, err.Error())
		return
	}
	// The compressed container bytes were already charged by the parent;
	// the child entries are charged on traversal, never twice here.
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil && err != zip.ErrInsecurePath {
		rep.issue(prefixed, "invalid nested ZIP: "+err.Error())
		return
	}
	if zr == nil {
		rep.issue(prefixed, "missing nested ZIP directory")
		return
	}
	analyzeZipLevel(zr.File, prefixed, depth, finder, rep, budget, maxMajor)
}

// classResult is one analyzed class, indexed for deterministic merging.
type classResult struct {
	idx               int
	entry             string
	skipped           bool // class bytes unreadable: counted, not analyzed
	issue             string
	findings          []types.Match
	cracks            []types.CrackPoint
	obf               classObf
	obfClass          string
	major             uint16
	instructions      int
	methods           int
	calls             int
	bytecodeTruncated bool
}

// analyzeClassesParallel parses and analyzes classes with a worker pool.
// zip.File.Open is safe for concurrent use; results merge sorted by entry
// name so output is deterministic regardless of worker scheduling.
func analyzeClassesParallel(classes []*zip.File, loc func(string) string, finder *crackpoint.Finder, rep *Report, maxMajor *uint16) {
	if len(classes) == 0 {
		return
	}
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	if workers > 8 {
		workers = 8
	}
	if workers > len(classes) {
		workers = len(classes)
	}
	jobs := make(chan int, len(classes))
	results := make(chan classResult, len(classes))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				f := classes[idx]
				name := f.Name
				cf, err := parseClassEntryWithError(f)
				entry := loc(name)
				if err != nil {
					results <- classResult{idx: idx, entry: entry, skipped: true, issue: err.Error()}
					continue
				}
				results <- classResult{
					idx:          idx,
					entry:        entry,
					findings:     analyzeClass(cf, entry),
					cracks:       detectCrackPoints(finder, cf, entry),
					obf:          obfSignals(cf),
					obfClass:     cf.ThisClass,
					major:        cf.Major,
					instructions: cf.InstructionCount, methods: len(cf.Methods), calls: len(cf.CallSites), bytecodeTruncated: cf.BytecodeTruncated,
				}
			}
		}()
	}
	for i := range classes {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(results)

	ordered := make([]classResult, 0, len(classes))
	for r := range results {
		ordered = append(ordered, r)
	}
	sortClassResults(ordered)
	for _, r := range ordered {
		if r.skipped {
			rep.UnparseableClasses++
			rep.issue(r.entry, r.issue)
			continue
		}
		if r.major > *maxMajor {
			*maxMajor = r.major
		}
		rep.InstructionCount += r.instructions
		rep.MethodCount += r.methods
		rep.InvocationCount += r.calls
		if r.bytecodeTruncated {
			rep.issue(r.entry, "call-site retention limit exceeded; bytecode was decoded but evidence is partial")
		}
		rep.Findings = append(rep.Findings, r.findings...)
		for _, c := range r.cracks {
			rep.CrackPoints = append(rep.CrackPoints, demoteLibraryCrackPoint(c))
		}
		mergeObf(rep, r.obfClass, r.obf)
	}
}

// demoteLibraryCrackPoint halves confidence for gates found in bundled
// third-party namespaces: a "license" hit inside Gson is token-expiry
// plumbing, a "premium" hit in an HTTP client is proxy handling — not app
// licensing. The finding stays visible, just no longer loud.
func demoteLibraryCrackPoint(cp types.CrackPoint) types.CrackPoint {
	if !isThirdPartyLibrary(cp.ClassName) {
		return cp
	}
	cp.Confidence *= 0.5
	cp.Suggestion += " [third-party library internals — confirm the gate belongs to first-party code]"
	return cp
}

// netSinkClasses are method-owner types whose references mean the class can
// plausibly move bytes over the network. Used only for static correlation
// ("same class talks HTTP and mentions this URL"), never as flow proof.
var netSinkClasses = map[string]bool{
	"java.net.HttpURLConnection":              true,
	"java.net.http.HttpClient":                true,
	"okhttp3.OkHttpClient":                    true,
	"okhttp3.Call":                            true,
	"java.net.Socket":                         true,
	"javax.net.ssl.SSLSocket":                 true,
	"org.apache.http.client.HttpClient":       true,
	"org.apache.http.impl.client.HttpClients": true,
	"java.net.URL":                            true,
	"java.net.http.HttpRequest":               true,
}

// classNetSink returns the first network-sink method reference in the class,
// or "" when the class references no known sink. Pool order keeps it
// deterministic.
func classNetSink(cf *ClassFile) string {
	if cf == nil {
		return ""
	}
	for _, r := range cf.MethodRefs {
		if netSinkClasses[r.Class] {
			return r.FullName()
		}
	}
	return ""
}

// splitBytecodeURL extracts scheme/host/path from a constant-pool string.
// Only http(s) counts; loopback and unparsable values yield empty host.
func splitBytecodeURL(s string) (host, scheme, path string) {
	t := strings.TrimSpace(s)
	lower := strings.ToLower(t)
	rest := ""
	switch {
	case strings.HasPrefix(lower, "http://"):
		scheme, rest = "http", t[len("http://"):]
	case strings.HasPrefix(lower, "https://"):
		scheme, rest = "https", t[len("https://"):]
	default:
		return "", "", ""
	}
	if i := strings.IndexAny(rest, " \t\r\n\"'<>"); i >= 0 {
		rest = rest[:i]
	}
	u, err := url.Parse(scheme + "://" + rest)
	if err != nil {
		return "", "", ""
	}
	host = strings.ToLower(u.Hostname())
	switch host {
	case "", "localhost", "127.0.0.1", "0.0.0.0", "::1":
		return "", "", ""
	}
	return host, scheme, u.EscapedPath()
}

func sortClassResults(rs []classResult) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].entry == rs[j].entry {
			return rs[i].idx < rs[j].idx
		}
		return rs[i].entry < rs[j].entry
	})
}

func isJARTextEntry(name string) bool {
	lower := strings.ToLower(name)
	if strings.EqualFold(lower, "meta-inf/manifest.mf") {
		return true
	}
	// Only extension groups: named files like application.properties or
	// pom.properties are already covered by their extensions.
	for _, suffix := range []string{
		".properties", ".yml", ".yaml", ".json", ".xml", ".txt", ".env", ".conf", ".config", ".ini",
	} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func scanTextEntrySecrets(f *zip.File, entry string) []types.Match {
	data, err := readJAREntry(f, maxTextEntryBytes)
	if err != nil || !isMostlyText(data) {
		return nil
	}
	return providerFindingsToMatches(secrets.DetectProviders(string(data), entry), entry, "JAR text resource")
}

func isMostlyText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	bad := 0
	for _, b := range data {
		if b == 0 {
			return false
		}
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			bad++
		}
	}
	return bad*100/len(data) < 5
}

func parseClassEntry(f *zip.File) *ClassFile {
	cf, _ := parseClassEntryWithError(f)
	return cf
}

func parseClassEntryWithError(f *zip.File) (*ClassFile, error) {
	data, err := readJAREntry(f, maxClassBytes)
	if err != nil {
		return nil, err
	}
	return ParseClass(data)
}

func parseManifest(f *zip.File, rep *Report) {
	data, err := readJAREntry(f, maxTextEntryBytes)
	if err != nil {
		rep.issue(f.Name, err.Error())
		return
	}
	parseManifestData(data, rep)
}

func parseManifestData(data []byte, rep *Report) {
	if rep.Manifest == nil {
		rep.Manifest = map[string]string{}
	}
	// Main attributes end at the first blank line: per-entry sections below
	// it ("Name:" + digests) are not manifest attributes and must not land
	// in rep.Manifest. The buffer is raised past bufio's 64 KiB default so
	// one hostile long line cannot silently truncate the whole manifest.
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	key := ""
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			break
		}
		// JAR continuation: a line starting with a single space appends
		// to the previous value (headers wrap at 72 bytes). Without
		// unfolding, long Main-Class/Class-Path values get truncated.
		if strings.HasPrefix(line, " ") && key != "" {
			rep.Manifest[key] += line[1:]
			if strings.EqualFold(key, "Main-Class") {
				rep.MainClass += line[1:]
			}
			continue
		}
		if i := strings.Index(line, ":"); i > 0 {
			key = strings.TrimSpace(line[:i])
			val := strings.TrimSpace(line[i+1:])
			rep.Manifest[key] = val
			if strings.EqualFold(key, "Main-Class") {
				rep.MainClass = val
			}
		} else {
			key = ""
		}
	}
	if err := sc.Err(); err != nil {
		rep.issue("META-INF/MANIFEST.MF", "manifest line parsing failed: "+err.Error())
	}
}

// analyzeClass turns dangerous method references and risky string constants in
// one class into findings. Context — whether the owning class is library
// internals, and whether it also hardens its XML parsing — is used to keep the
// signal sharp instead of flooding fat jars with library noise.
func analyzeClass(cf *ClassFile, entry string) []types.Match {
	var out []types.Match
	inLib := isThirdPartyLibrary(cf.ThisClass)
	xmlHardeningMentioned := classHasXMLHardening(secretScanStrings(cf))
	refsCipherGetInstance := false

	for _, ref := range cf.MethodRefs {
		if ref.Class == "javax.crypto.Cipher" && ref.Name == "getInstance" {
			refsCipherGetInstance = true
		}
		for _, s := range sinks {
			if ref.Class != s.classSuffix {
				continue
			}
			if s.method != "" && ref.Name != s.method {
				continue
			}
			sev := s.severity
			conf := s.confidence
			reason := s.reason
			if s.category == xxeCategory && xmlHardeningMentioned {
				reason += "; XML hardening text is present, but the boolean value and parser instance are not verified"
			}
			if inLib {
				// The call lives in a bundled library, not the app's own code:
				// keep it visible but down-rank so real app findings rise above.
				sev = demoteSeverity(sev)
				conf *= 0.55
				reason = "[library internals] " + reason
			}
			out = append(out, types.Match{
				Categorized:       types.Categorized{Category: s.category},
				Text:              ref.FullName(),
				Pattern:           ref.FullName(),
				Context:           "constant-pool reference in " + cf.ThisClass,
				Metadata:          map[string]string{"evidence_kind": "constant_pool_reference", "execution_proven": "false", "target_descriptor": ref.Descriptor},
				ClassName:         cf.ThisClass,
				Severity:          sev,
				IsCritical:        sev >= types.SeverityHigh,
				Confidence:        fmt.Sprintf("%.2f", conf),
				ReasonForSeverity: reason,
				SourceLocation:    types.SourceLocation{File: entry},
			})
		}
	}

	// A custom trust interface is a review point, not evidence of trust-all TLS.
	for _, iface := range cf.Interfaces {
		if reason, ok := tlsTrustInterfaces[iface]; ok {
			sev := types.SeverityLow
			conf := 0.25
			if inLib {
				sev = types.SeverityLow
				conf = 0.15
				reason = "[library internals] " + reason
			}
			out = append(out, types.Match{
				Categorized:       types.Categorized{Category: "INSECURE_TLS_TRUST"},
				Text:              iface,
				Pattern:           "implements " + iface,
				Context:           cf.ThisClass + " implements " + iface,
				ClassName:         cf.ThisClass,
				Severity:          sev,
				IsCritical:        sev >= types.SeverityHigh,
				Confidence:        fmt.Sprintf("%.2f", conf),
				ReasonForSeverity: reason,
				SourceLocation:    types.SourceLocation{File: entry},
			})
		}
	}

	// Weak cipher: a Cipher.getInstance call combined with a transformation
	// string that selects a broken algorithm or ECB mode. Gating on the call
	// keeps the algorithm-name regex from matching unrelated words.
	// Arguments proven to flow into a getInstance call are reported
	// precisely below with their call site instead.
	preciseArgs := preciseCryptoArguments(cf)
	preciseValues := map[string]bool{}
	for _, pa := range preciseArgs {
		preciseValues[pa.value] = true
	}
	if refsCipherGetInstance {
		for _, str := range secretScanStrings(cf) {
			if preciseValues[str] {
				continue // reported precisely below with its call site
			}
			if len(str) > 64 || !weakCipherTransform.MatchString(str) {
				continue
			}
			sev := types.SeverityMedium
			if inLib {
				sev = types.SeverityLow
			}
			out = append(out, types.Match{
				Categorized:       types.Categorized{Category: "CRYPTO_WEAK_CIPHER"},
				Text:              str,
				Pattern:           str,
				Context:           "Cipher.getInstance reference and algorithm literal co-occur in " + cf.ThisClass,
				ClassName:         cf.ThisClass,
				Severity:          sev,
				Confidence:        "0.50",
				ReasonForSeverity: "weak/ECB cipher transformation — use AES/GCM or AES/CBC with authenticated padding",
				SourceLocation:    types.SourceLocation{File: entry},
			})
			break // one weak-cipher finding per class is enough
		}
	}

	// Provider-aware secret scanner over genuine string literals
	// (cpString), backed by the offline credential classifier (llmkeys)
	// for bare high-entropy/family tokens the regex providers miss. The
	// classifier only runs when no provider rule already matched the
	// string, so secrets are never double-reported. Descriptors and
	// attribute names are deliberately excluded: real keys are literals.
	for _, str := range secretScanStrings(cf) {
		pf := secrets.DetectProviders(str, cf.ThisClass)
		out = append(out, providerFindingsToMatches(pf, entry, "JAR class constant pool string in "+cf.ThisClass)...)
		if len(pf) == 0 {
			if m, ok := classifyStringSecret(str, cf.ThisClass, entry); ok {
				out = append(out, m)
			}
		}
	}

	// Weak hash algorithm string constants (e.g. MessageDigest.getInstance("MD5")).
	// Values proven to flow into a getInstance call are reported precisely
	// below with their call site instead.
	for _, str := range secretScanStrings(cf) {
		if preciseValues[str] {
			continue
		}
		if weakHashAlgo.MatchString(str) && algoTokenShape.MatchString(str) {
			out = append(out, types.Match{
				Categorized:       types.Categorized{Category: "CRYPTO_WEAK_HASH"},
				Text:              str,
				Pattern:           str,
				Context:           "weak hash algorithm string in " + cf.ThisClass,
				ClassName:         cf.ThisClass,
				Severity:          types.SeverityMedium,
				Confidence:        "0.50",
				ReasonForSeverity: "weak hash algorithm referenced",
				SourceLocation:    types.SourceLocation{File: entry},
			})
		}
	}
	// Bytecode URL inventory: the text-resource endpoint scan never sees
	// classes, so URLs living only in constant pools would stay invisible
	// (modrinth/discord contact links aside, this is where C2, update and
	// telemetry hosts hide). INFO inventory: string presence, not proven
	// traffic. One row per distinct URL per class; provider-matched strings
	// already have their own finding above. Telegram links get peer
	// classification (user/bot/invite/bot-api); when the same class also
	// references a network sink the row says so — static correlation, not
	// a proven flow.
	sink := classNetSink(cf)
	seenURL := map[string]bool{}
	for _, str := range secretScanStrings(cf) {
		host, scheme, upath := splitBytecodeURL(str)
		if host == "" {
			continue
		}
		key := scheme + "://" + host + upath
		if seenURL[key] {
			continue
		}
		seenURL[key] = true
		if len(secrets.DetectProviders(str, cf.ThisClass)) > 0 {
			continue
		}
		if trackerHosts[host] {
			continue // dedicated ip-tracker finding below, no duplicate row
		}
		reason := "URL embedded in class bytecode (inventory — the endpoint scan covers text resources only)"
		context := "URL string in bytecode constant pool of " + cf.ThisClass
		meta := map[string]string{"scheme": scheme, "host": host, "path": upath}
		if tg, isTG := ParseTelegramLink(str); isTG {
			meta["tg_kind"] = tg.Kind
			meta["tg_target"] = tg.Target
			reason = "Telegram link in bytecode: " + tg.Kind + " — " + tg.Target + " (" + tg.Detail + ")"
			context = "Telegram link (" + tg.Kind + ") in constant pool of " + cf.ThisClass
			if tg.Kind == TGBotAPI {
				reason += ". Taint from a source to this call is NOT proven"
			}
		}
		if sink != "" {
			context += "; same class references network sink " + sink
			meta["net_sink"] = sink
		}
		out = append(out, types.Match{
			Categorized:       types.Categorized{Category: types.CategoryNetworkEndpoint},
			Text:              types.TruncateString(str, 200),
			Pattern:           key,
			Context:           context,
			ClassName:         cf.ThisClass,
			Severity:          types.SeverityInfo,
			Confidence:        "medium",
			EvidenceType:      "bytecode_string",
			ReasonForSeverity: reason,
			SourceLocation:    types.SourceLocation{File: entry},
			Metadata:          meta,
		})
	}
	out = append(out, emitPreciseCrypto(cf, entry, preciseArgs)...)
	// RAT / stealer / tracker indicators: victim data locations, dangerous
	// platform APIs and tracker hosts. Grounded on real stealer builds where
	// these co-occur (Discord/browser/wallet theft plus keylogging).
	out = append(out, emitRatFindings(ratSignals(cf), cf.ThisClass, entry)...)
	out = enrichInvocationEvidence(cf, out)
	for i := range out {
		if out[i].SourceLocation.File == "" {
			out[i].SourceLocation.File = entry
		}
	}
	return out
}

// preciseArg is a constant string proven to flow into argument 0 of a
// tracked Cipher/MessageDigest.getInstance call on an analyzed path.
type preciseArg struct {
	value    string
	caller   string // name+descriptor of the enclosing method
	offset   int    // bytecode offset of the invoke
	cipher   bool   // Cipher.getInstance (false: MessageDigest.getInstance)
	callDesc string // target descriptor for evidence
}

// preciseCryptoArguments resolves constant arguments of tracked getInstance
// calls. Only methods whose code was retained (small, with a tracked call)
// are analyzed; everything else keeps the co-occurrence findings.
func preciseCryptoArguments(cf *ClassFile) []preciseArg {
	if !cf.BytecodeParsed || len(cf.pool) == 0 {
		return nil
	}
	var out []preciseArg
	for i := range cf.Methods {
		m := &cf.Methods[i]
		if len(m.Code) == 0 {
			continue
		}
		for pc, val := range resolvePreciseArgs(m.Code, m.MaxLocals, cf.pool) {
			for _, c := range cf.CallSites {
				if c.Offset != pc || c.Caller != m.Name || c.CallerDescriptor != m.Descriptor {
					continue
				}
				key := c.Target.Class + "." + c.Target.Name
				if preciseArgTargets[key] {
					out = append(out, preciseArg{
						value: val, caller: m.Name + m.Descriptor,
						offset: pc, cipher: strings.HasPrefix(key, "javax.crypto."),
						callDesc: c.Target.Descriptor,
					})
				}
			}
		}
	}
	return out
}

// emitPreciseCrypto turns proven constant arguments into findings when the
// value is actually weak. Strong or unknown values yield nothing: absence
// of a precise finding is not a clean bill of health.
func emitPreciseCrypto(cf *ClassFile, entry string, preciseArgs []preciseArg) []types.Match {
	var out []types.Match
	inLib := isThirdPartyLibrary(cf.ThisClass)
	for _, pa := range preciseArgs {
		var cat types.Category
		if pa.cipher {
			if !weakCipherTransform.MatchString(pa.value) || len(pa.value) > 64 {
				continue
			}
			cat = "CRYPTO_WEAK_CIPHER"
		} else {
			if !weakHashAlgo.MatchString(pa.value) || !algoTokenShape.MatchString(pa.value) {
				continue
			}
			cat = "CRYPTO_WEAK_HASH"
		}
		sev := types.SeverityMedium
		if inLib {
			sev = types.SeverityLow
		}
		kind := "MessageDigest.getInstance"
		if pa.cipher {
			kind = "Cipher.getInstance"
		}
		out = append(out, types.Match{
			Categorized:       types.Categorized{Category: cat},
			Text:              pa.value,
			Pattern:           pa.value,
			Context:           fmt.Sprintf("%s(%q) resolved to a constant argument at bytecode offset %d in %s.%s along the analyzed path", kind, pa.value, pa.offset, cf.ThisClass, pa.caller),
			ClassName:         cf.ThisClass,
			MethodName:        pa.caller,
			Severity:          sev,
			IsCritical:        sev >= types.SeverityHigh,
			Confidence:        "0.95",
			ReasonForSeverity: "weak algorithm proven to reach the crypto call as a constant",
			EvidenceType:      "dataflow_argument",
			SourceLocation:    types.SourceLocation{File: entry, Method: pa.caller},
			Metadata: map[string]string{
				"evidence_kind": "dataflow_argument", "execution_proven": "false",
				"reachability_proven": "false", "bytecode_offset": fmt.Sprint(pa.offset),
				"caller_descriptor": pa.caller, "target_descriptor": pa.callDesc,
			},
			RequiredNextEvidence: "Establish entrypoint reachability and attacker-controlled arguments.",
		})
	}
	return out
}

// secretScanStrings returns the strings secret detection runs on: genuine
// literals when the class was resolved through the pool, falling back to
// the broad pool dump for hand-built ClassFile values (tests) that carry
// no literal resolution.
func secretScanStrings(cf *ClassFile) []string {
	if cf.StringConstants != nil {
		return cf.StringConstants
	}
	return cf.Strings
}

func providerFindingsToMatches(findings []secrets.ProviderFinding, entry string, contextPrefix string) []types.Match {
	out := make([]types.Match, 0, len(findings))
	for _, sf := range findings {
		sev := jarSeverityFromProvider(sf.Severity)
		out = append(out, types.Match{
			SourceLocation:    types.SourceLocation{File: entry, Line: sf.Line},
			Categorized:       types.Categorized{Category: types.CategoryAPIKey},
			Text:              sf.MaskedValue,
			Pattern:           sf.RuleID,
			Context:           contextPrefix + ": " + sf.Context,
			Severity:          sev,
			IsCritical:        sev >= types.SeverityHigh,
			Confidence:        fmt.Sprintf("%.2f", sf.Confidence),
			ReasonForSeverity: sf.Name + " detected in Java archive. " + sf.Remediation,
			Metadata: map[string]string{
				"provider": sf.Provider,
				"masked":   sf.MaskedValue,
				"rule_id":  sf.RuleID,
			},
		})
	}
	return out
}

func jarSeverityFromProvider(sev string) types.Severity {
	switch strings.ToLower(sev) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}
