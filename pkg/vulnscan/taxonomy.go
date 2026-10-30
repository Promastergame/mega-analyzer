package vulnscan

import (
	"math"
	"strings"
)

// CVSSVector holds the CVSS v3.1 Base metrics needed to compute a base score.
// Values use the standard single-letter abbreviations.
type CVSSVector struct {
	AV string // Attack Vector: N,A,L,P
	AC string // Attack Complexity: L,H
	PR string // Privileges Required: N,L,H
	UI string // User Interaction: N,R
	S  string // Scope: U,C
	C  string // Confidentiality: H,L,N
	I  string // Integrity: H,L,N
	A  string // Availability: H,L,N
}

// String renders the canonical CVSS:3.1 vector string.
func (v CVSSVector) String() string {
	return "CVSS:3.1/AV:" + v.AV + "/AC:" + v.AC + "/PR:" + v.PR + "/UI:" + v.UI +
		"/S:" + v.S + "/C:" + v.C + "/I:" + v.I + "/A:" + v.A
}

// BaseScore computes the CVSS v3.1 Base Score per the official specification.
func (v CVSSVector) BaseScore() float64 {
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[v.AV]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[v.AC]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[v.UI]
	cia := func(x string) float64 {
		return map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}[x]
	}
	scopeChanged := v.S == "C"
	var pr float64
	if scopeChanged {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[v.PR]
	} else {
		pr = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[v.PR]
	}

	iss := 1 - ((1 - cia(v.C)) * (1 - cia(v.I)) * (1 - cia(v.A)))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * av * ac * pr * ui

	if impact <= 0 {
		return 0
	}
	var score float64
	if scopeChanged {
		score = math.Min(1.08*(impact+exploitability), 10)
	} else {
		score = math.Min(impact+exploitability, 10)
	}
	return roundupCVSS(score)
}

// roundupCVSS rounds up to one decimal place per the CVSS spec.
func roundupCVSS(x float64) float64 {
	return math.Ceil(x*10) / 10
}

// taxonomyEntry maps a check family to its standards metadata.
type taxonomyEntry struct {
	CWE    []int
	OWASP  []string
	Vector CVSSVector
}

// taxonomyCatalog is keyed by finding-ID prefix. Longest matching prefix wins.
var taxonomyCatalog = map[string]taxonomyEntry{
	"WS-XSS":    {CWE: []int{79}, OWASP: []string{"A03:2021"}, Vector: CVSSVector{"N", "L", "N", "R", "C", "L", "L", "N"}},
	"WS-SQLI":   {CWE: []int{89}, OWASP: []string{"A03:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "U", "H", "H", "H"}},
	"WS-CMDI":   {CWE: []int{78}, OWASP: []string{"A03:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "C", "H", "H", "H"}},
	"WS-LFI":    {CWE: []int{22, 98}, OWASP: []string{"A01:2021", "A03:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "U", "H", "N", "N"}},
	"WS-SSRF":   {CWE: []int{918}, OWASP: []string{"A10:2021"}, Vector: CVSSVector{"N", "L", "L", "N", "C", "H", "L", "N"}},
	"WS-SSTI":   {CWE: []int{1336, 94}, OWASP: []string{"A03:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "C", "H", "H", "H"}},
	"WS-IDOR":   {CWE: []int{639}, OWASP: []string{"A01:2021"}, Vector: CVSSVector{"N", "L", "L", "N", "U", "H", "N", "N"}},
	"WS-JWT":    {CWE: []int{347}, OWASP: []string{"A02:2021", "A07:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "U", "H", "H", "N"}},
	"WS-CSRF":   {CWE: []int{352}, OWASP: []string{"A01:2021"}, Vector: CVSSVector{"N", "L", "N", "R", "U", "N", "H", "N"}},
	"WS-CORS":   {CWE: []int{942}, OWASP: []string{"A05:2021"}, Vector: CVSSVector{"N", "L", "N", "R", "U", "H", "L", "N"}},
	"WS-REDIR":  {CWE: []int{601}, OWASP: []string{"A01:2021"}, Vector: CVSSVector{"N", "L", "N", "R", "U", "L", "L", "N"}},
	"WS-HDR":    {CWE: []int{693}, OWASP: []string{"A05:2021"}, Vector: CVSSVector{"N", "L", "N", "R", "U", "L", "N", "N"}},
	"WS-COOK":   {CWE: []int{614, 1004}, OWASP: []string{"A05:2021"}, Vector: CVSSVector{"N", "H", "N", "R", "U", "L", "N", "N"}},
	"WS-HOST":   {CWE: []int{644}, OWASP: []string{"A05:2021"}, Vector: CVSSVector{"N", "H", "N", "N", "U", "L", "L", "N"}},
	"WS-CACHE":  {CWE: []int{525}, OWASP: []string{"A05:2021"}, Vector: CVSSVector{"N", "H", "N", "N", "U", "L", "L", "N"}},
	"WS-HPP":    {CWE: []int{235}, OWASP: []string{"A03:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "U", "L", "L", "N"}},
	"WS-PROTO":  {CWE: []int{1321}, OWASP: []string{"A08:2021"}, Vector: CVSSVector{"N", "H", "N", "N", "U", "L", "L", "L"}},
	"WS-RACE":   {CWE: []int{362}, OWASP: []string{"A04:2021"}, Vector: CVSSVector{"N", "H", "L", "N", "U", "L", "H", "N"}},
	"WS-UPLOAD": {CWE: []int{434}, OWASP: []string{"A04:2021", "A05:2021"}, Vector: CVSSVector{"N", "L", "L", "N", "C", "H", "H", "H"}},
	"WS-GQL":    {CWE: []int{16, 200}, OWASP: []string{"A05:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "U", "L", "N", "N"}},
	"WS-API":    {CWE: []int{200}, OWASP: []string{"A05:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "U", "L", "N", "N"}},
	"WS-SENS":   {CWE: []int{200, 538}, OWASP: []string{"A05:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "U", "H", "N", "N"}},
	"WS-SECRET": {CWE: []int{798, 200}, OWASP: []string{"A07:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "U", "H", "N", "N"}},
	"WS-DESYNC": {CWE: []int{444}, OWASP: []string{"A03:2021"}, Vector: CVSSVector{"N", "H", "N", "N", "C", "H", "H", "L"}},
	"WS-OAST":   {CWE: []int{918, 78}, OWASP: []string{"A10:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "C", "H", "H", "H"}},
	"WS-CHAIN":  {CWE: []int{}, OWASP: []string{}, Vector: CVSSVector{"N", "L", "N", "N", "C", "H", "H", "H"}},

	"API-BOLA":     {CWE: []int{639}, OWASP: []string{"A01:2021"}, Vector: CVSSVector{"N", "L", "L", "N", "U", "H", "N", "N"}},
	"API-DESER":    {CWE: []int{502}, OWASP: []string{"A08:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "C", "H", "H", "H"}},
	"WS-LDAP":      {CWE: []int{90}, OWASP: []string{"A03:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "U", "H", "H", "H"}},
	"WS-XPATH":     {CWE: []int{643}, OWASP: []string{"A03:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "U", "H", "N", "N"}},
	"WS-NOSQL":     {CWE: []int{943}, OWASP: []string{"A03:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "U", "H", "H", "H"}},
	"WS-MASSA":     {CWE: []int{915}, OWASP: []string{"A08:2021"}, Vector: CVSSVector{"N", "L", "L", "N", "U", "H", "H", "N"}},
	"WS-OAUTH-001": {CWE: []int{757}, OWASP: []string{"A07:2021"}, Vector: CVSSVector{"N", "H", "N", "N", "U", "H", "L", "N"}},
	"WS-OAUTH-002": {CWE: []int{601}, OWASP: []string{"A01:2021"}, Vector: CVSSVector{"N", "L", "N", "R", "U", "L", "L", "N"}},
	"WS-SUPPLY":    {CWE: []int{829}, OWASP: []string{"A08:2021"}, Vector: CVSSVector{"N", "L", "N", "R", "U", "H", "L", "N"}},
	"WS-CSPT":      {CWE: []int{22}, OWASP: []string{"A01:2021"}, Vector: CVSSVector{"N", "L", "N", "R", "U", "H", "N", "N"}},
	"WS-CSWSH":     {CWE: []int{1385, 352}, OWASP: []string{"A01:2021"}, Vector: CVSSVector{"N", "L", "N", "R", "U", "H", "H", "N"}},
	"WS-TIMING":    {CWE: []int{208}, OWASP: []string{"A04:2021"}, Vector: CVSSVector{"N", "H", "N", "N", "U", "L", "N", "N"}},
	"WS-REDOS":     {CWE: []int{1333}, OWASP: []string{"A04:2021"}, Vector: CVSSVector{"N", "L", "N", "N", "U", "N", "N", "H"}},
}

// lookupTaxonomy returns the taxonomy entry for a finding ID via longest-prefix match.
func lookupTaxonomy(id string) (taxonomyEntry, bool) {
	bestKey := ""
	for key := range taxonomyCatalog {
		if strings.HasPrefix(id, key) && len(key) > len(bestKey) {
			bestKey = key
		}
	}
	if bestKey == "" {
		return taxonomyEntry{}, false
	}
	return taxonomyCatalog[bestKey], true
}

// EnrichWithTaxonomy fills CWE / OWASP / CVSS on a finding based on its ID.
// The CVSS vector is severity-adjusted so INFO/LOW findings don't inherit a
// scary base score from their family's worst case.
func EnrichWithTaxonomy(f *Finding) {
	entry, ok := lookupTaxonomy(f.ID)
	if !ok {
		return
	}
	if len(f.CWE) == 0 {
		f.CWE = entry.CWE
	}
	if len(f.OWASP) == 0 {
		f.OWASP = entry.OWASP
	}
	if f.CVSSVector == "" {
		vec := adjustVectorForSeverity(entry.Vector, f.Severity)
		f.CVSSVector = vec.String()
		f.CVSS = vec.BaseScore()
	}
}

// adjustVectorForSeverity nudges the impact metrics to line up with the
// finding's declared severity, so a LOW-severity header issue doesn't report
// as CVSS 7+ just because its family can be severe.
func adjustVectorForSeverity(v CVSSVector, sev Severity) CVSSVector {
	switch sev {
	case SeverityInfo:
		v.C, v.I, v.A, v.S = "N", "N", "N", "U"
		v.C = "L"
	case SeverityLow:
		if v.C == "H" {
			v.C = "L"
		}
		if v.I == "H" {
			v.I = "L"
		}
		if v.A == "H" {
			v.A = "L"
		}
		v.S = "U"
	}
	return v
}
