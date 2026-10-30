package media

// Indicator-of-Compromise (IOC) extraction & threat enrichment.
//
// This is a next-level capability layered on top of the existing detection
// pipeline. Where the detector/fusion layers tell you *that* a file hides
// something (a high-entropy region, a trailing ZIP, a polyglot), the IOC
// engine tells you *what* the hidden thing actually is in actionable,
// report-ready terms:
//
//   - Embedded executables      (ELF / Windows PE / Mach-O / DEX / Java)
//   - Command-and-control URLs   (http/https/ftp)
//   - IPv4 addresses
//   - Tor .onion addresses
//   - Crypto-wallet addresses    (BTC / ETH / XMR) — a strong ransomware tell
//   - Shell / download cradles   (PowerShell -enc, certutil, WebClient, etc.)
//   - Email addresses
//
// Critically, it also DECODES base64 blobs found inside the file and scans
// the decoded bytes recursively, surfacing payloads that would otherwise be
// invisible to a surface-level string scan. Any IOC that decoded out of a
// base64 blob is tagged Source == "base64-decoded".
//
// The engine derives an aggregate IOC risk that ForensicEngine folds into the
// unified RiskScore using the same probabilistic-complement model as the rest
// of the scorer, so a discovered PowerShell downloader or embedded PE
// meaningfully raises the file's risk.

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"sort"
	"strings"
)

// IOCType classifies an indicator of compromise.
type IOCType string

const (
	IOCTypeURL          IOCType = "url"
	IOCTypeIPv4         IOCType = "ipv4"
	IOCTypeEmail        IOCType = "email"
	IOCTypeOnion        IOCType = "onion_address"
	IOCTypeCryptoWallet IOCType = "crypto_wallet"
	IOCTypeShellCommand IOCType = "shell_command"
	IOCTypeEmbeddedExec IOCType = "embedded_executable"
	IOCTypeBase64Blob   IOCType = "base64_blob"
)

// IOC is a single actionable indicator of compromise extracted from a file.
type IOC struct {
	Type       IOCType `json:"type"`
	Value      string  `json:"value"`
	Offset     int     `json:"offset"`
	Severity   float64 `json:"severity"`   // 0..1 intrinsic danger of this indicator
	Confidence float64 `json:"confidence"` // 0..1 how sure we are it is real
	Source     string  `json:"source"`     // "raw" or "base64-decoded"
	Context    string  `json:"context"`    // printable snippet around the hit
}

var (
	iocURLRe   = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s"'<>)\]}]{3,}`)
	iocIPv4Re  = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	iocEmailRe = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	iocOnionRe = regexp.MustCompile(`(?i)\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b`)
	iocBTCRe   = regexp.MustCompile(`\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`)
	iocETHRe   = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)
	iocXMRRe   = regexp.MustCompile(`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`)
	iocShellRe = regexp.MustCompile(`(?i)(powershell(\.exe)?\s+[^\n]{0,80}?(-enc\b|-encodedcommand|-nop\b|-w\s+hidden|downloadstring|iex\b|invoke-expression)|certutil\s+-urlcache|bitsadmin\s+/transfer|invoke-webrequest|new-object\s+net\.webclient|/bin/(ba)?sh\s+-c|cmd(\.exe)?\s+/c\b|wget\s+https?://|curl\s+[^\n]{0,40}https?://)`)
	iocB64Re   = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
)

type iocBinSig struct {
	desc  string
	magic []byte
	sev   float64
}

// iocBinarySigs are byte signatures for embedded executable/bytecode formats.
// Any of these appearing inside a media file is highly suspicious regardless
// of offset.
var iocBinarySigs = []iocBinSig{
	{"ELF executable", []byte{0x7F, 'E', 'L', 'F'}, 0.95},
	{"Windows PE executable", []byte("This program cannot be run in DOS mode"), 0.95},
	{"Mach-O executable (LE64)", []byte{0xCF, 0xFA, 0xED, 0xFE}, 0.90},
	{"Mach-O executable (LE32)", []byte{0xCE, 0xFA, 0xED, 0xFE}, 0.90},
	{"Android DEX bytecode", []byte("dex\n"), 0.85},
	{"Java class bytecode", []byte{0xCA, 0xFE, 0xBA, 0xBE}, 0.70},
}

// ExtractIOCs scans a file for indicators of compromise. The regions slice is
// used only to raise confidence for indicators that fall inside an
// already-flagged region; pass nil if unavailable.
func ExtractIOCs(data []byte, regions []Region) []IOC {
	raw := scanForIOCs(data, 0, "raw", regions, 0)
	return finalizeIOCs(raw)
}

func scanForIOCs(data []byte, baseOffset int, source string, regions []Region, depth int) []IOC {
	if len(data) == 0 {
		return nil
	}
	var out []IOC

	baseConf := 0.7
	if source == "base64-decoded" {
		baseConf = 0.8
	}

	add := func(t IOCType, value string, localIdx int, sev float64) {
		if len(value) > 160 {
			value = value[:160]
		}
		absOff := baseOffset + localIdx
		conf := baseConf
		ctxNote := iocPrintableContext(data, localIdx, len(value))
		if iocInRegion(absOff, regions) {
			conf = iocCap(conf + 0.2)
			ctxNote = "[in flagged region] " + ctxNote
		}
		if source == "base64-decoded" {
			// An indicator that had to be un-obfuscated is more suspicious.
			sev = iocCap(sev + 0.15)
		}
		out = append(out, IOC{
			Type:       t,
			Value:      value,
			Offset:     absOff,
			Severity:   sev,
			Confidence: conf,
			Source:     source,
			Context:    ctxNote,
		})
	}

	scan := func(re *regexp.Regexp, t IOCType, sev float64) {
		for _, m := range re.FindAllIndex(data, -1) {
			add(t, string(data[m[0]:m[1]]), m[0], sev)
		}
	}

	scan(iocURLRe, IOCTypeURL, 0.45)
	scan(iocIPv4Re, IOCTypeIPv4, 0.40)
	scan(iocEmailRe, IOCTypeEmail, 0.25)
	scan(iocOnionRe, IOCTypeOnion, 0.75)
	scan(iocShellRe, IOCTypeShellCommand, 0.90)
	scan(iocBTCRe, IOCTypeCryptoWallet, 0.70)
	scan(iocETHRe, IOCTypeCryptoWallet, 0.60)
	scan(iocXMRRe, IOCTypeCryptoWallet, 0.75)

	// Embedded executable/bytecode signatures (binary, not text).
	for _, bs := range iocBinarySigs {
		idx := 0
		for {
			rel := iocIndexFrom(data, bs.magic, idx)
			if rel < 0 {
				break
			}
			add(IOCTypeEmbeddedExec, bs.desc, rel, bs.sev)
			idx = rel + len(bs.magic)
		}
	}

	// Base64-obfuscated payloads: decode and recurse exactly one level so a
	// hidden downloader/URL/executable inside a base64 blob is still found.
	if depth == 0 {
		for _, m := range iocB64Re.FindAllIndex(data, -1) {
			blob := data[m[0]:m[1]]
			if len(blob) > 200000 {
				continue
			}
			dec := iocTryBase64(blob)
			if dec == nil {
				continue
			}
			nested := scanForIOCs(dec, baseOffset+m[0], "base64-decoded", regions, depth+1)
			if len(nested) > 0 {
				// Only flag the blob itself when it actually decoded to
				// something interesting, to avoid noise from benign data.
				preview := string(blob[:iocMin(len(blob), 48)]) + "\u2026"
				add(IOCTypeBase64Blob, preview, m[0], 0.5)
				out = append(out, nested...)
			}
		}
	}

	return out
}

// IOCRiskScore aggregates a slice of IOCs into a single 0..100 risk score
// using the shared probabilistic-complement model. Returns 0 for no IOCs.
func IOCRiskScore(iocs []IOC) float64 {
	if len(iocs) == 0 {
		return 0
	}
	risks := make([]float64, 0, len(iocs))
	for _, i := range iocs {
		risks = append(risks, Clamp(i.Severity*i.Confidence))
	}
	return combineRisks(risks)
}

func finalizeIOCs(iocs []IOC) []IOC {
	best := map[string]IOC{}
	for _, i := range iocs {
		key := string(i.Type) + "|" + i.Value
		if ex, ok := best[key]; ok {
			if i.Severity*i.Confidence > ex.Severity*ex.Confidence {
				best[key] = i
			}
			continue
		}
		best[key] = i
	}
	out := make([]IOC, 0, len(best))
	for _, v := range best {
		out = append(out, v)
	}
	sort.SliceStable(out, func(a, b int) bool {
		sa := out[a].Severity * out[a].Confidence
		sb := out[b].Severity * out[b].Confidence
		if sa != sb {
			return sa > sb
		}
		return out[a].Offset < out[b].Offset
	})
	if len(out) > 250 {
		out = out[:250]
	}
	return out
}

func iocTryBase64(blob []byte) []byte {
	s := string(blob)
	if n := len(s) % 4; n != 0 {
		s = s[:len(s)-n]
	}
	if len(s) < 40 {
		return nil
	}
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
		return dec
	}
	if dec, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return dec
	}
	return nil
}

func iocIndexFrom(data, sub []byte, from int) int {
	if from < 0 || from >= len(data) {
		return -1
	}
	i := bytes.Index(data[from:], sub)
	if i < 0 {
		return -1
	}
	return from + i
}

func iocInRegion(off int, regions []Region) bool {
	for _, r := range regions {
		if off >= r.StartOffset && off <= r.EndOffset {
			return true
		}
	}
	return false
}

func iocPrintableContext(data []byte, idx, length int) string {
	const pad = 24
	start := idx - pad
	if start < 0 {
		start = 0
	}
	end := idx + length + pad
	if end > len(data) {
		end = len(data)
	}
	if start >= end {
		return ""
	}
	b := make([]byte, 0, end-start)
	for _, c := range data[start:end] {
		if c >= 32 && c < 127 {
			b = append(b, c)
		} else {
			b = append(b, '.')
		}
	}
	if len(b) > 120 {
		b = b[:120]
	}
	return string(b)
}

func iocCap(c float64) float64 {
	if c > 0.99 {
		return 0.99
	}
	if c < 0 {
		return 0
	}
	return c
}

func iocMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
