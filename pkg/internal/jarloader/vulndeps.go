package jarloader

import (
	"regexp"
	"strconv"
	"strings"
)

// VulnDep is a known-vulnerable library detected from a jar filename.
type VulnDep struct {
	Library  string `json:"library"`
	Version  string `json:"version"`
	CVE      string `json:"cve"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	// Evidence records how the component was identified: "filename" (a
	// filename guess) or "maven-coordinates" (pom.properties identity).
	Evidence string `json:"evidence,omitempty"`
}

// vulnRule matches a library by name and a vulnerable version range.
type vulnRule struct {
	name    string // matched against the jar filename (token) or pom artifactId (exact)
	cve     string
	sever   string
	summary string
	// vulnerable reports whether the parsed version is affected.
	vulnerable func(v semver) bool
}

// rules covers the highest-impact, most common JVM library CVEs.
var rules = []vulnRule{
	{
		name: "log4j-core", cve: "CVE-2021-44228", sever: "critical",
		summary:    "Log4Shell: JNDI lookup RCE in Log4j 2.x < 2.15.0",
		vulnerable: func(v semver) bool { return v.major == 2 && v.lt(2, 15, 0, 0) },
	},
	{
		name: "log4j-core", cve: "CVE-2021-45046", sever: "high",
		summary:    "Log4j 2.x 2.15.0 incomplete fix (< 2.16.0)",
		vulnerable: func(v semver) bool { return v.major == 2 && v.ge(2, 15, 0, 0) && v.lt(2, 16, 0, 0) },
	},
	{
		name: "spring-core", cve: "CVE-2022-22965", sever: "critical",
		summary: "Spring4Shell: data binding RCE in spring-core < 5.3.18 / 5.2.20",
		vulnerable: func(v semver) bool {
			return v.lt(5, 2, 20, 0) || (v.major == 5 && v.minor == 3 && v.patch < 18)
		},
	},
	{
		name: "spring-beans", cve: "CVE-2022-22965", sever: "critical",
		summary: "Spring4Shell: data binding RCE in spring-beans < 5.3.18 / 5.2.20",
		vulnerable: func(v semver) bool {
			return v.lt(5, 2, 20, 0) || (v.major == 5 && v.minor == 3 && v.patch < 18)
		},
	},
	{
		name: "jackson-databind", cve: "CVE-2019-12384", sever: "high",
		summary:    "jackson-databind polymorphic deserialization gadget (< 2.9.9.2)",
		vulnerable: func(v semver) bool { return v.major == 2 && v.lt(2, 9, 9, 2) },
	},
	{
		name: "jackson-databind", cve: "CVE-2020-8840", sever: "high",
		summary:    "jackson-databind polymorphic deserialization gadget (< 2.10.0)",
		vulnerable: func(v semver) bool { return v.major == 2 && v.lt(2, 10, 0, 0) },
	},
	{
		name: "commons-collections", cve: "CVE-2015-7501", sever: "critical",
		summary:    "Apache Commons Collections InvokerTransformer deserialization RCE (3.x < 3.2.2)",
		vulnerable: func(v semver) bool { return v.major == 3 && v.lt(3, 2, 2, 0) },
	},
	{
		name: "commons-text", cve: "CVE-2022-42889", sever: "critical",
		summary:    "Text4Shell: script/DNS/URL interpolation RCE in commons-text < 1.10.0",
		vulnerable: func(v semver) bool { return v.lt(1, 10, 0, 0) },
	},
	{
		name: "fastjson", cve: "CVE-2022-25845", sever: "high",
		summary:    "fastjson autoType deserialization RCE (< 1.2.83)",
		vulnerable: func(v semver) bool { return v.lt(1, 2, 83, 0) },
	},
	{
		name: "snakeyaml", cve: "CVE-2022-1471", sever: "high",
		summary:    "SnakeYAML constructor deserialization RCE (< 2.0)",
		vulnerable: func(v semver) bool { return v.lt(2, 0, 0, 0) },
	},
	{
		name: "xstream", cve: "CVE-2021-39139", sever: "high",
		summary:    "XStream unmarshalling RCE (< 1.4.18)",
		vulnerable: func(v semver) bool { return v.lt(1, 4, 18, 0) },
	},
	{
		name: "h2", cve: "CVE-2021-42392", sever: "critical",
		summary:    "H2 console JNDI injection RCE (< 2.1.210)",
		vulnerable: func(v semver) bool { return v.lt(2, 1, 210, 0) },
	},
}

// matchVulnDep inspects a path/filename and returns any matching known CVEs.
func matchVulnDep(path string) []VulnDep {
	base := path
	if i := strings.LastIndexAny(base, "/\\!"); i >= 0 {
		base = base[i+1:]
	}
	lower := strings.ToLower(base)

	var out []VulnDep
	for _, r := range rules {
		if !artifactNameMatch(lower, strings.ToLower(r.name)) {
			continue
		}
		v, ok := extractVersion(base)
		out = append(out, evalVulnRule(r, v, ok, "")...)
	}
	return out
}

// matchVulnDepCoords matches rules against Maven coordinates from a
// META-INF/maven/**/pom.properties entry. artifactId matches exactly
// (case-insensitive): shaded/uber jars keep the real artifactId even when
// no log4j-core-*.jar file exists on disk.
func matchVulnDepCoords(artifactID, version, pomPath string) []VulnDep {
	var out []VulnDep
	for _, r := range rules {
		if !strings.EqualFold(strings.TrimSpace(artifactID), r.name) {
			continue
		}
		v, ok := extractVersion(version)
		for _, d := range evalVulnRule(r, v, ok, pomPath) {
			out = append(out, d)
		}
	}
	return out
}

func evalVulnRule(r vulnRule, v semver, ok bool, source string) []VulnDep {
	note := ""
	evidence := "filename"
	if source != "" {
		note = " (from " + source + ")"
		evidence = "maven-coordinates"
	}
	if !ok {
		// Unknown version: report as a lower-confidence advisory rather than
		// silently dropping it.
		return []VulnDep{{
			Library: r.name, Version: "unknown", CVE: r.cve,
			Severity: "info", Summary: r.summary + " (version not parsed; verify manually)" + note,
			Evidence: evidence,
		}}
	}
	if r.vulnerable(v) {
		return []VulnDep{{
			Library: r.name, Version: v.String(), CVE: r.cve,
			Severity: r.sever, Summary: r.summary + note,
			Evidence: evidence,
		}}
	}
	return nil
}

// artifactNameMatch reports whether name occurs in the filename as a whole
// artifact token: the characters around the match must not be alphanumerics,
// so "commons-collections" does not match "commons-collections4" while
// "my-log4j-core-2.14.1.jar" still matches "log4j-core".
func artifactNameMatch(lower, name string) bool {
	for i := 0; i+len(name) <= len(lower); {
		j := strings.Index(lower[i:], name)
		if j < 0 {
			return false
		}
		i += j
		beforeOK := i == 0 || !isASCIINum(lower[i-1])
		afterOK := i+len(name) == len(lower) || !isASCIINum(lower[i+len(name)])
		if beforeOK && afterOK {
			return true
		}
		i++
	}
	return false
}

func isASCIINum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

func dedupeVulnDeps(rep *Report) {
	if len(rep.VulnDeps) < 2 {
		return
	}
	seen := make(map[string]struct{}, len(rep.VulnDeps))
	out := rep.VulnDeps[:0]
	for _, d := range rep.VulnDeps {
		key := d.Library + "|" + d.Version + "|" + d.CVE
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, d)
	}
	rep.VulnDeps = out
}

// semver is a minimal numeric version with an optional 4th component and
// qualifier (e.g. 2.9.9.2, 31.1-jre, 5.3.18-SNAPSHOT).
type semver struct {
	major, minor, patch, micro int
	qualifier                  string
}

func (v semver) String() string {
	s := strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) + "." + strconv.Itoa(v.patch)
	if v.micro != 0 {
		s += "." + strconv.Itoa(v.micro)
	}
	if v.qualifier != "" {
		s += "-" + v.qualifier
	}
	return s
}

func (v semver) lt(ma, mi, pa, mc int) bool {
	if v.major != ma {
		return v.major < ma
	}
	if v.minor != mi {
		return v.minor < mi
	}
	if v.patch != pa {
		return v.patch < pa
	}
	return v.micro < mc
}

func (v semver) ge(ma, mi, pa, mc int) bool { return !v.lt(ma, mi, pa, mc) }

var versionRe = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?`)

// knownQualifiers are version suffixes that carry no range semantics for
// our rules (-SNAPSHOT is treated as its base; a documented limitation).
// Anything else trailing the numbers (like a file extension) is not a
// qualifier, so "2.14.1.jar" parses as plain 2.14.1.
var knownQualifiers = []string{
	"snapshot", "release", "final", "ga", "jre", "android", "jdk",
}

func qualifierOf(remainder string) string {
	remainder = strings.TrimLeft(remainder, "-._")
	for _, q := range knownQualifiers {
		if len(remainder) >= len(q) && strings.EqualFold(remainder[:len(q)], q) {
			if len(remainder) == len(q) || !isASCIINum(remainder[len(q)]) {
				return remainder[:len(q)]
			}
		}
	}
	return ""
}

// extractVersion pulls the first dotted version (up to 4 numeric components
// plus an optional known qualifier) out of a filename or version string.
func extractVersion(s string) (semver, bool) {
	m := versionRe.FindStringSubmatchIndex(s)
	if m == nil {
		return semver{}, false
	}
	valid := true
	atoi := func(lo, hi int) int {
		if lo < 0 || hi < 0 {
			return 0
		}
		n, err := strconv.Atoi(s[lo:hi])
		if err != nil {
			valid = false
		}
		return n
	}
	v := semver{
		major: atoi(m[2], m[3]),
		minor: atoi(m[4], m[5]),
		patch: atoi(m[6], m[7]),
		micro: atoi(m[8], m[9]),
	}
	if !valid {
		return semver{}, false
	}
	v.qualifier = qualifierOf(s[m[1]:])
	return v, true
}

// parseMavenCoords reads groupId/artifactId/version from a pom.properties
// body ("key=value" lines, "#" comments).
func parseMavenCoords(data []byte) (groupID, artifactID, version string) {
	if len(data) > 64<<10 {
		data = data[:64<<10]
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch key {
		case "groupId":
			groupID = val
		case "artifactId":
			artifactID = val
		case "version":
			version = val
		}
	}
	return groupID, artifactID, version
}

// Maven group IDs distinguish unrelated artifacts with the same short name.
// Missing groups remain visible as informational candidates, not confirmed IDs.
func matchMavenCoordinates(group, artifact, version, source string) []VulnDep {
	groups := map[string]string{
		"log4j-core":          "org.apache.logging.log4j",
		"spring-core":         "org.springframework",
		"spring-beans":        "org.springframework",
		"jackson-databind":    "com.fasterxml.jackson.core",
		"commons-collections": "commons-collections",
		"commons-text":        "org.apache.commons",
		"fastjson":            "com.alibaba",
		"snakeyaml":           "org.yaml",
		"xstream":             "com.thoughtworks.xstream",
		"h2":                  "com.h2database",
	}
	artifact = strings.TrimSpace(artifact)
	group = strings.TrimSpace(group)
	expected, known := groups[artifact]
	if !known || version == "" || (group != "" && group != expected) {
		return nil
	}
	out := matchVulnDepCoords(artifact, version, source)
	if group == "" {
		for i := range out {
			out[i].Severity = "info"
			out[i].Summary += " (groupId missing; artifact identity unconfirmed)"
		}
	}
	return out
}
