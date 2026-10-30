package vulnscan

// Registry bridge for the legacy form fuzzers. Historically the form checks
// (XSS, SQLi, LFI, IDOR, HPP, prototype pollution, upload, SSTI, SSRF, race)
// ran on a separate ad-hoc worker path inside Scanner.Scan, bypassing the
// engine's invasiveness gating, topology, telemetry, deduplication and
// correlation. Registering them here unifies both pipelines: every active
// check now flows through Engine.RunActiveChecks.
//
// The implementations stay in their original files; the runners convert the
// AttackSurface back to a legacy Form and lift the emitted Vulnerabilities
// into Findings.

func init() {
	registerFormCheck("WS-FORM-XSS", "Form XSS (context-aware reflection)",
		[]int{79}, []string{"A03:2021"},
		func(s *Scanner, f Form) []Vulnerability { return s.testXSS(f) })

	registerFormCheck("WS-FORM-SQLI", "Form SQL Injection (differential)",
		[]int{89}, []string{"A03:2021"},
		func(s *Scanner, f Form) []Vulnerability { return s.testSQLi(f) })

	registerFormCheck("WS-FORM-LFI", "Form Local File Inclusion",
		[]int{22}, []string{"A01:2021"},
		func(s *Scanner, f Form) []Vulnerability { return s.testLFI(f) })

	registerFormCheck("WS-FORM-IDOR", "Form Insecure Direct Object Reference",
		[]int{639}, []string{"A01:2021"},
		func(s *Scanner, f Form) []Vulnerability { return s.testIDOR(f) })

	registerFormCheck("WS-FORM-HPP", "Form HTTP Parameter Pollution",
		[]int{235}, []string{"A04:2021"},
		func(s *Scanner, f Form) []Vulnerability { return s.testHPP(f) })

	registerFormCheck("WS-FORM-PROTO", "Form Prototype Pollution",
		[]int{1321}, []string{"A03:2021"},
		func(s *Scanner, f Form) []Vulnerability { return s.testPrototypePollution(f) })

	registerFormCheck("WS-FORM-UPLOAD", "Form File Upload",
		[]int{434}, []string{"A04:2021"},
		func(s *Scanner, f Form) []Vulnerability { return s.testFileUpload(f) })

	registerFormCheck("WS-FORM-SSTI", "Form Server-Side Template Injection",
		[]int{1336}, []string{"A03:2021"},
		func(s *Scanner, f Form) []Vulnerability { return s.checkSSTI(f) })

	registerFormCheck("WS-FORM-SSRF", "Form Server-Side Request Forgery",
		[]int{918}, []string{"A10:2021"},
		func(s *Scanner, f Form) []Vulnerability { return s.checkSSRF(f) })

	registerFormCheck("WS-FORM-RACE", "Form Race Condition",
		[]int{362}, []string{"A04:2021"},
		func(s *Scanner, f Form) []Vulnerability { return s.checkRaceCondition(f) })
}

// registerFormCheck wires one legacy form fuzzer into the registry as an
// active, destructive check (all of them inject payloads into the target).
func registerFormCheck(id, name string, cwe []int, owasp []string,
	run func(s *Scanner, f Form) []Vulnerability) {
	RegisterCheck(CheckDescriptor{
		ID:           id,
		Name:         name,
		CWE:          cwe,
		OWASP:        owasp,
		Phase:        PhaseActive,
		Invasiveness: InvDestructive,
		Run: func(s *Scanner, surface *AttackSurface) []Finding {
			if surface == nil {
				return nil
			}
			return FindingsFromVulns(run(s, surface.ToForm()))
		},
	})
}
