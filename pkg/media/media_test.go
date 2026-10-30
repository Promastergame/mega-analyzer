package media

import (
	"archive/zip"
	"bytes"
	"math"
	"testing"
)

func TestDetectorDEXSafe(t *testing.T) {
	d := NewDetector()
	data := []byte("garbage...dex\n035\x00...more garbage")
	sigs, _ := d.Detect(data)

	foundDEX := false
	for _, s := range sigs {
		if s.Type == SignalMagic && s.Value == string(TypeDEX) {
			foundDEX = true
			if s.Offset != 10 {
				t.Errorf("Expected DEX at offset 10, got %d", s.Offset)
			}
			break
		}
	}
	if !foundDEX {
		t.Errorf("Expected to find DEX magic signal")
	}

	shortData := []byte("dex\n03")
	sigs2, _ := d.Detect(shortData)
	if len(sigs2) != 0 {
		t.Errorf("Expected 0 signals for truncated DEX")
	}
}

func TestDetectorAdaptiveEntropy(t *testing.T) {
	d := NewDetector()

	data := make([]byte, 1024*32)
	for i := range data {
		data[i] = byte(i % 10)
	}

	encrypted := make([]byte, 4096)
	for i := range encrypted {
		encrypted[i] = byte(i % 256)
	}
	copy(data[8192:], encrypted)

	sigs, stats := d.Detect(data)

	if stats.MeanEntropy > 5.0 {
		t.Errorf("Expected low mean entropy, got %f", stats.MeanEntropy)
	}
	if stats.Peaks == 0 {
		t.Errorf("Expected at least one peak for the encrypted chunk")
	}

	foundAnomaly := false
	for _, s := range sigs {
		if s.Type == SignalHighEntropy {
			foundAnomaly = true
			break
		}
	}
	if !foundAnomaly {
		t.Errorf("Expected HighEntropy signal via Z-Score")
	}
}

func TestFusionMathClamping(t *testing.T) {
	f := NewFusionLayer()

	raw := []Signal{
		{Type: SignalPayload, Value: "SQLi", Offset: 0, Length: 10, Confidence: 0.8, Severity: 0.5, Metadata: SignalMetadata{Evidence: "SELECT *"}},
		{Type: SignalPayload, Value: "SQLi", Offset: 5, Length: 10, Confidence: 1.5, Severity: -0.5, Metadata: SignalMetadata{Evidence: "UNION SELECT"}},
	}

	regions := f.Fuse(raw)
	if len(regions) != 1 {
		t.Fatalf("Expected 1 region")
	}

	r := regions[0]
	// First: c=0.8, sev=0.5 -> safeConf = (1-0.8)=0.2, safeSev = (1-0.5)=0.5
	// Second: c clamped to 0.999, sev clamped to 0.0 -> safeConf = 0.2*(1-0.999)=0.0002, safeSev = 0.5*(1-0.0)=0.5
	// Final: FusedConf = 1-0.0002 = 0.9998, FusedSev = 1-0.5 = 0.5
	expectedConf := 1.0 - (1.0-0.8)*(1.0-0.999)
	expectedSev := 0.5

	if math.Abs(r.FusedConfidence-expectedConf) > 0.001 {
		t.Errorf("Expected FusedConfidence %f, got %f", expectedConf, r.FusedConfidence)
	}
	if math.Abs(r.FusedSeverity-expectedSev) > 0.001 {
		t.Errorf("Expected FusedSeverity %f, got %f", expectedSev, r.FusedSeverity)
	}
}

func createApkZip() []byte {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	f1, _ := w.Create("classes.dex")
	f1.Write([]byte("dex\n035\x00dummy"))

	f2, _ := w.Create("AndroidManifest.xml")
	f2.Write([]byte("xml"))

	w.Close()
	return buf.Bytes()
}

func TestEngineDefinitiveIntegration(t *testing.T) {
	zipData := createApkZip()

	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	data := append(pngMagic, []byte("some image data...")...)

	padding := make([]byte, 100)
	data = append(data, padding...)
	data = append(data, zipData...)

	engine := NewForensicEngine()
	res := engine.Analyze(data, "image.png", "image.png")

	if !res.Classification.IsPolyglot {
		t.Errorf("Expected IsPolyglot to be true")
	}
	if res.Classification.PrimaryFormat != TypePNG {
		t.Errorf("Expected PrimaryFormat PNG, got %s", res.Classification.PrimaryFormat)
	}

	foundHiddenApk := false
	for _, hidden := range res.Classification.HiddenFormats {
		if hidden == TypeAPK {
			foundHiddenApk = true
		}
	}
	if !foundHiddenApk {
		t.Errorf("Expected to find hidden APK due to classes.dex")
	}

	if res.RiskScore < 50.0 {
		t.Errorf("Expected RiskScore >= 50.0 for hidden APK, got %f", res.RiskScore)
	}
}
