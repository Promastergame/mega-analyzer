package pipeline

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// 1. DEPTH GUARD
// ═══════════════════════════════════════════════════════════════════════════════

func TestScanContent_DepthGuard(t *testing.T) {
	inner := []byte("-----BEGIN RSA PRIVATE KEY-----\nfakekey")
	l1 := []byte(base64.StdEncoding.EncodeToString(inner))
	l2 := []byte(base64.StdEncoding.EncodeToString(l1))
	l3 := []byte(base64.StdEncoding.EncodeToString(l2))

	result := ScanContent(l3, "nested.txt", types.FileTypeText, SourceKindAsset, 0)
	_ = result
}

func TestScanContent_DepthLimitStops(t *testing.T) {
	data := []byte("DexClassLoader")
	result := ScanContent(data, "f.smali", types.FileTypeSmali, SourceKindSmali, maxDecodeDepth+1)
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings at depth > max, got %d", len(result.Findings))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. ADAPTIVE GAP
// ═══════════════════════════════════════════════════════════════════════════════

func TestAdaptiveGap_ShortFragments(t *testing.T) {
	frags := [][]byte{[]byte("ab"), []byte("cd")}
	gap := adaptiveGap(frags, 1000)
	if gap > 128 {
		t.Errorf("adaptive gap for short fragments = %d, want ≤ 128", gap)
	}
}

func TestContainsFragments_AdaptiveGapRejects(t *testing.T) {
	head := []byte("Runtime")
	gap := bytes.Repeat([]byte("x"), 200)
	tail := []byte("exec")
	data := append(append(head, gap...), tail...)

	frags := [][]byte{head, tail}
	maxGap := adaptiveGap(frags, len(data))

	ok, _ := containsFragments(data, frags, maxGap)
	if ok {
		t.Errorf("fragments 200 bytes apart should be rejected with adaptiveGap=%d", maxGap)
	}
}

func TestContainsFragments_AdaptiveGapAccepts(t *testing.T) {
	data := []byte(`const-string v0, "Runtime.getRuntime().exec"`)
	frags := [][]byte{[]byte("Runtime"), []byte("exec")}
	maxGap := adaptiveGap(frags, len(data))
	ok, _ := containsFragments(data, frags, maxGap)
	if !ok {
		t.Error("close fragments should match with adaptive gap")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. ENTROPY — isLikelyEncoded filters noise
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsLikelyEncoded_TrueForBase64(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xAB, 0xCD}, 64))
	if !isLikelyEncoded([]byte(encoded)) {
		t.Errorf("isLikelyEncoded should return true for valid base64 blob")
	}
}

func TestIsLikelyEncoded_FalseForNormalText(t *testing.T) {
	text := []byte("this is a normal sentence with spaces and punctuation!")
	if isLikelyEncoded(text) {
		t.Error("isLikelyEncoded should return false for normal text with spaces")
	}
}

func TestIsLikelyEncoded_FalseForShortString(t *testing.T) {
	short := []byte("QWxhZGRpbg==")
	if isLikelyEncoded(short) {
		t.Error("isLikelyEncoded should return false for strings < 64 chars")
	}
}

func TestEntropy_NoFalsePositiveOnProtobuf(t *testing.T) {
	data := bytes.Repeat([]byte{0x0a, 0x0b, 0x0c, 0x0d}, 256)
	result := ScanContent(data, "data.bin", types.FileTypeText, SourceKindAsset, 0)
	for _, f := range result.Findings {
		if strings.Contains(f.Pattern, "entropy") {
			t.Errorf("false positive entropy finding: %v", f)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. IP ADDRESS BOOST
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsPublicIPHost(t *testing.T) {
	public := []string{"45.77.12.33", "104.21.0.1", "8.8.8.8"}
	private := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"}

	for _, ip := range public {
		if !isPublicIPHost(ip) {
			t.Errorf("isPublicIPHost(%q) = false, want true", ip)
		}
	}
	for _, ip := range private {
		if isPublicIPHost(ip) {
			t.Errorf("isPublicIPHost(%q) = true, want false", ip)
		}
	}
}

func TestScanContent_PublicIPDoesNotEscalateAddressAlone(t *testing.T) {
	data := []byte("endpoint=http://45.77.12.33/beacon")
	result := ScanContent(data, "config.properties", types.FileTypeText, SourceKindAsset, 0)

	foundHTTP := false
	for _, f := range result.Findings {
		if strings.Contains(f.Pattern, "45.77.12.33") {
			foundHTTP = true
			if f.Severity >= types.SeverityHigh {
				t.Error("numeric address alone escalated the HTTP-reference severity")
			}
		}
	}
	if !foundHTTP {
		t.Error("cleartext HTTP reference was lost")
	}
}

func TestScanContent_PrivateIPNoBoost(t *testing.T) {
	data := []byte("endpoint=http://192.168.1.1/api")
	result := ScanContent(data, "config.properties", types.FileTypeText, SourceKindAsset, 0)

	for _, f := range result.Findings {
		if strings.Contains(f.Pattern, "192.168.1.1") && f.Severity >= types.SeverityHigh {
			t.Error("private IP should not get high-severity boost")
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. PROXIMITY CORRELATION
// ═══════════════════════════════════════════════════════════════════════════════

func TestApplyCorrelation_ProximateBoosts(t *testing.T) {
	findings := []Finding{
		{Category: types.CategoryMalware, Score: 3.0, Offset: 10, Severity: types.SeverityHigh},
		{Category: types.CategoryCredential, Score: 2.0, Offset: 50, Severity: types.SeverityHigh},
	}
	after := applyCorrelation(findings)

	boosted := false
	for _, f := range after {
		if f.Score > 3.0 {
			boosted = true
		}
	}
	if !boosted {
		t.Error("proximate malware+credential findings should be score-boosted")
	}
}

func TestApplyCorrelation_DistantNotBoosted(t *testing.T) {
	findings := []Finding{
		{Category: types.CategoryMalware, Score: 3.0, Offset: 0, Severity: types.SeverityHigh},
		{Category: types.CategoryCredential, Score: 2.0, Offset: int64(proximityWindow) + 1000, Severity: types.SeverityHigh},
	}
	after := applyCorrelation(findings)

	for _, f := range after {
		if f.Score > 3.5 {
			t.Errorf("distant findings should not be correlated, score=%.2f", f.Score)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. HYBRID ZIP DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsDexContainer_FastScanHit_ZipConfirms(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "test_*.apk")
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	fw, _ := zw.Create("classes.dex")
	fw.Write([]byte("dex\n035\x00"))
	zw.Close()
	f.Close()

	if !isDexContainer(f.Name()) {
		t.Error("expected isDexContainer=true for APK with classes.dex")
	}
}

func TestIsDexContainer_NoDexInZip(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "test_*.zip")
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	fw, _ := zw.Create("assets/config.json")
	fw.Write([]byte("{}"))
	zw.Close()
	f.Close()

	if isDexContainer(f.Name()) {
		t.Error("expected isDexContainer=false for ZIP without DEX")
	}
}

func TestQuickScanForDexMarker(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "marker_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	f.Write(bytes.Repeat([]byte{0x00}, 100))
	f.Write([]byte("classes.dex"))
	f.Write(bytes.Repeat([]byte{0x00}, 100))
	f.Close()

	if !quickScanForDexMarker(f.Name()) {
		t.Error("expected quickScanForDexMarker=true when marker is present")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. FILE-LEVEL RISK AGGREGATION
// ═══════════════════════════════════════════════════════════════════════════════

func TestAggregateFileRisk_Flags(t *testing.T) {
	result := ScanResult{
		File: "evil.smali",
		Findings: []Finding{
			{Category: types.CategoryMalware, Pattern: "shell via Runtime.exec", Severity: types.SeverityCritical, Score: 5.0},
			{Category: types.CategoryCredential, Pattern: "RSA private key", Severity: types.SeverityCritical, Score: 4.0},
			{Category: types.CategoryPrivacy, Pattern: "camera permission", Severity: types.SeverityMedium, Score: 2.0},
		},
	}

	risk := AggregateFileRisk(result)

	if risk.WorstSev != types.SeverityCritical {
		t.Errorf("WorstSev = %v, want Critical", risk.WorstSev)
	}
	if !risk.Flags.HasCredentials {
		t.Error("HasCredentials should be true")
	}
	if !risk.Flags.HasPrivacy {
		t.Error("HasPrivacy should be true")
	}
	if risk.FindingCount != 3 {
		t.Errorf("FindingCount = %d, want 3", risk.FindingCount)
	}
	if risk.TotalScore < 1.0 {
		t.Errorf("TotalScore = %.2f, expected > 0", risk.TotalScore)
	}
}

func TestAggregateFileRisk_ScoreCap(t *testing.T) {
	var findings []Finding
	for i := 0; i < 50; i++ {
		findings = append(findings, Finding{
			Category: types.CategoryMalware,
			Score:    5.0,
			Severity: types.SeverityCritical,
		})
	}
	risk := AggregateFileRisk(ScanResult{File: "f.smali", Findings: findings})
	if risk.TotalScore > 100 {
		t.Errorf("TotalScore should be capped at 100, got %.2f", risk.TotalScore)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkScanContent(b *testing.B) {
	data := bytes.Repeat([]byte(
		".method public run()V\n"+
			"    const-string v0, \"DexClassLoader\"\n"+
			"    invoke-static {}, Ljava/lang/Runtime;->getRuntime()\n"+
			"    return-void\n"+
			".end method\n",
	), 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScanContent(data, "Loader.smali", types.FileTypeSmali, SourceKindSmali, 0)
	}
}

func BenchmarkAdaptiveGap(b *testing.B) {
	frags := [][]byte{[]byte("Runtime"), []byte("getRuntime"), []byte("exec")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		adaptiveGap(frags, 65536)
	}
}

func BenchmarkIsPublicIPHost(b *testing.B) {
	hosts := []string{"45.77.12.33", "192.168.1.1", "8.8.8.8", "10.0.0.1"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isPublicIPHost(hosts[i%len(hosts)])
	}
}

func BenchmarkAggregateFileRisk(b *testing.B) {
	findings := make([]Finding, 20)
	for i := range findings {
		findings[i] = Finding{
			Category: types.CategoryMalware,
			Score:    3.0,
			Severity: types.SeverityHigh,
			Pattern:  "DexClassLoader",
		}
	}
	result := ScanResult{File: "bench.smali", Findings: findings}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AggregateFileRisk(result)
	}
}
