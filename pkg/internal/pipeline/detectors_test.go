// pkg/internal/pipeline/detectors_test.go
package pipeline

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// ============================================================================
// Test Helpers (уникальные имена чтобы не конфликтовать)
// ============================================================================

type detectorTestCase struct {
	name         string
	path         string
	content      string
	fileType     types.FileType
	wantCategory types.Category
	wantMatch    bool
}

func runDetectorTest(t *testing.T, detectFn func(*FileDetectContext, *types.FileAnalysis), tc detectorTestCase) {
	t.Helper()

	content := []byte(tc.content)
	ctx := createDetectorCtx(tc.path, content, tc.fileType)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))

	detectFn(ctx, analysis)

	found := hasMatchCategory(analysis.Matches, tc.wantCategory)

	if tc.wantMatch && !found {
		t.Errorf("expected %s detection, got %d matches: %v",
			tc.wantCategory, len(analysis.Matches), getMatchSummary(analysis.Matches))
	}
	if !tc.wantMatch && found {
		t.Errorf("unexpected %s detection in matches: %v",
			tc.wantCategory, getMatchSummary(analysis.Matches))
	}
}

// Уникальное имя — не конфликтует с newTestContext
func createDetectorCtx(path string, content []byte, fileType types.FileType) *FileDetectContext {
	return &FileDetectContext{
		Path:         path,
		Content:      content,
		ContentLower: toLowerBytes(content),
		LineOffsets:  types.NewLineOffsets(content),
		IsAppCode:    true,
		FileType:     fileType,
		Job:          FileJob{RelPath: path},
	}
}

func toLowerBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

func hasMatchCategory(matches []types.Match, cat types.Category) bool {
	for _, m := range matches {
		if m.Category == cat {
			return true
		}
	}
	return false
}

func getMatchSummary(matches []types.Match) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, string(m.Category)+":"+m.Pattern)
	}
	return out
}

// ============================================================================
// Ads Detector Tests
// ============================================================================

func TestAdsDetector(t *testing.T) {
	d := NewAdsDetector()

	tests := []detectorTestCase{
		{
			name: "AdMob SDK",
			path: "smali/Ads.smali",
			content: `
.class public Lcom/app/Ads;
invoke-static {}, Lcom/google/android/gms/ads/AdRequest;->Builder()V
invoke-virtual {v0}, Lcom/google/android/gms/ads/InterstitialAd;->show()V
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryAdNetwork,
			wantMatch:    true,
		},
		{
			name: "Unity Ads",
			path: "smali/UnityAds.smali",
			content: `
invoke-static {}, Lcom/unity3d/ads/UnityAds;->show()V
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryAdNetwork,
			wantMatch:    true,
		},
		{
			name: "No ads - regular code",
			path: "smali/Utils.smali",
			content: `
.class public Lcom/app/Utils;
invoke-virtual {v0}, Ljava/lang/String;->toString()V
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryAdNetwork,
			wantMatch:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDetectorTest(t, d.Detect, tc)
		})
	}
}

// ============================================================================
// Payment Detector Tests
// ============================================================================

func TestPaymentDetector(t *testing.T) {
	d := NewPaymentDetector()

	tests := []detectorTestCase{
		{
			name: "Google BillingClient",
			path: "smali/Purchase.smali",
			content: `
.class public Lcom/app/Purchase;
new-instance v0, Lcom/android/billingclient/api/BillingClient;
invoke-interface {v0}, Lcom/android/billingclient/api/BillingClient;->launchBillingFlow()V
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryBillingClient,
			wantMatch:    true,
		},
		{
			name:         "No payment - regular class",
			path:         "smali/Utils.smali",
			content:      `.class public Lcom/app/Helper;`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryBillingClient,
			wantMatch:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDetectorTest(t, d.Detect, tc)
		})
	}
}

// ============================================================================
// Subscription Detector Tests
// ============================================================================

func TestSubscriptionDetector(t *testing.T) {
	d := NewSubscriptionDetector()

	tests := []detectorTestCase{
		{
			name: "isPremium method",
			path: "smali/Premium.smali",
			content: `
.class public Lcom/app/Premium;
.method public isPremium()Z
    invoke-virtual {p0}, Lcom/android/vending/billing/IInAppBillingService;->getBuyIntent()V
    const/4 v0, 0x0
    return v0
.end method
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategorySubscriptionCheck,
			wantMatch:    true,
		},
		{
			name: "NO false positive - generic isEnabled",
			path: "smali/androidx/appcompat/widget/SwitchCompat.smali",
			content: `
.class public Landroidx/appcompat/widget/SwitchCompat;
.method public foo()V
    invoke-virtual {p0}, Landroid/view/View;->isEnabled()Z
    return-void
.end method
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategorySubscriptionCheck,
			wantMatch:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDetectorTest(t, d.Detect, tc)
		})
	}
}

// ============================================================================
// Analytics Detector Tests
// ============================================================================

func TestAnalyticsDetector(t *testing.T) {
	d := NewAnalyticsDetector()

	tests := []detectorTestCase{
		{
			name: "NO false positive - adjustViewBounds XML",
			path: "res/layout/some.xml",
			content: `
<?xml version="1.0" encoding="utf-8"?>
<ImageView android:adjustViewBounds="true" />
`,
			fileType:     types.FileTypeXML,
			wantCategory: types.CategoryAnalytics,
			wantMatch:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDetectorTest(t, d.Detect, tc)
		})
	}
}

// ============================================================================
// Obfuscation Detector Tests
// ============================================================================

func TestObfuscationDetector(t *testing.T) {
	d := NewObfuscationDetector()

	tests := []detectorTestCase{
		{
			name:         "Qihoo 360 packer",
			path:         "lib/arm64-v8a/libjiagu.so",
			content:      "libjiagu.so\x00some data\x00",
			fileType:     types.FileTypeNative,
			wantCategory: types.CategoryPacker,
			wantMatch:    true,
		},
		{
			name:         "Normal native lib",
			path:         "lib/arm64-v8a/libapp.so",
			content:      "ELF\x00normal library code",
			fileType:     types.FileTypeNative,
			wantCategory: types.CategoryPacker,
			wantMatch:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDetectorTest(t, d.Detect, tc)
		})
	}
}

// ============================================================================
// Crypto Detector Tests
// ============================================================================

func TestCryptoDetector(t *testing.T) {
	d := NewCryptoDetector()

	tests := []detectorTestCase{
		{
			name:         "Coinbase API",
			path:         "smali/Crypto.smali",
			content:      `const-string v0, "https://api.coinbase.com/v2/accounts"`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryCrypto,
			wantMatch:    true,
		},
		{
			name:         "No crypto",
			path:         "smali/Utils.smali",
			content:      `const-string v0, "hello"`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryCrypto,
			wantMatch:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDetectorTest(t, d.Detect, tc)
		})
	}
}

// ============================================================================
// Resource Detector Tests
// ============================================================================

func TestResourceDetector(t *testing.T) {
	d := NewResourceDetector()

	tests := []detectorTestCase{
		{
			name:         "Ad banner layout",
			path:         "res/layout/ad_banner_layout.xml",
			content:      "<LinearLayout/>",
			fileType:     types.FileTypeXML,
			wantCategory: types.CategoryAdResource,
			wantMatch:    true,
		},
		{
			name:         "Normal layout",
			path:         "res/layout/activity_main.xml",
			content:      "<LinearLayout/>",
			fileType:     types.FileTypeXML,
			wantCategory: types.CategoryAdResource,
			wantMatch:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDetectorTest(t, d.Detect, tc)
		})
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestDetectors_EmptyContent(t *testing.T) {
	detectors := []struct {
		name   string
		detect func(*FileDetectContext, *types.FileAnalysis)
	}{
		{"Ads", NewAdsDetector().Detect},
		{"Payment", NewPaymentDetector().Detect},
		{"Subscription", NewSubscriptionDetector().Detect},
		{"Analytics", NewAnalyticsDetector().Detect},
		{"Obfuscation", NewObfuscationDetector().Detect},
		{"Crypto", NewCryptoDetector().Detect},
		{"Resource", NewResourceDetector().Detect},
	}

	for _, d := range detectors {
		t.Run(d.name+"_empty", func(t *testing.T) {
			ctx := createDetectorCtx("test.smali", []byte{}, types.FileTypeSmali)
			analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, 0)
			d.detect(ctx, analysis)
		})
	}
}

func TestVulnSecretDetector_AWSAccessKeyValidation(t *testing.T) {
	d := NewVulnSecretDetector()

	tests := []detectorTestCase{
		{
			name:         "reject localized country text containing akia",
			path:         "assets/flutter_assets/packages/flutter_localized_countries/data/en_ZW.json",
			content:      `{"ZW":"Zimbabue","ak":"Akan","akia":"localized word"}`,
			fileType:     types.FileTypeJSON,
			wantCategory: types.CategoryHardcodedSecret,
			wantMatch:    false,
		},
		{
			name:         "accept full AWS access key id",
			path:         "assets/config.json",
			content:      `{"access_key_id":"AKIA1B2C3D4E5F6G7H8J"}`,
			fileType:     types.FileTypeJSON,
			wantCategory: types.CategoryHardcodedSecret,
			wantMatch:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDetectorTest(t, d.Detect, tc)
		})
	}
}

func TestVulnSecretDetector_FCMServerKeyValidation(t *testing.T) {
	d := NewVulnSecretDetector()
	validKey := "AAAA1234567:" + strings.Repeat("Ab9_-xY", 20)

	tests := []detectorTestCase{
		{
			name:         "reject arbitrary lowercase string starting with aaaa",
			path:         "assets/config.json",
			content:      `{"label":"aaaaaaaa ordinary application text"}`,
			fileType:     types.FileTypeJSON,
			wantCategory: types.CategoryHardcodedSecret,
			wantMatch:    false,
		},
		{
			name:         "reject long lowercase FCM-shaped string",
			path:         "assets/config.json",
			content:      `{"server_key":"aaaa1234567:` + strings.Repeat("A", 120) + `"}`,
			fileType:     types.FileTypeJSON,
			wantCategory: types.CategoryHardcodedSecret,
			wantMatch:    false,
		},
		{
			name:         "reject short FCM-shaped key",
			path:         "assets/config.json",
			content:      `{"server_key":"AAAA1234567:short_token"}`,
			fileType:     types.FileTypeJSON,
			wantCategory: types.CategoryHardcodedSecret,
			wantMatch:    false,
		},
		{
			name:         "reject long key without FCM separator position",
			path:         "assets/config.json",
			content:      `{"server_key":"AAAA12345678` + strings.Repeat("A", 120) + `"}`,
			fileType:     types.FileTypeJSON,
			wantCategory: types.CategoryHardcodedSecret,
			wantMatch:    false,
		},
		{
			name:         "accept valid legacy FCM server key format",
			path:         "assets/config.json",
			content:      `{"server_key":"` + validKey + `"}`,
			fileType:     types.FileTypeJSON,
			wantCategory: types.CategoryHardcodedSecret,
			wantMatch:    true,
		},
		{
			name:         "accept valid key after an invalid aaaa candidate",
			path:         "assets/config.json",
			content:      `{"label":"aaaaaaaa text","server_key":"` + validKey + `"}`,
			fileType:     types.FileTypeJSON,
			wantCategory: types.CategoryHardcodedSecret,
			wantMatch:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDetectorTest(t, d.Detect, tc)
		})
	}
}

func TestVulnNetworkDetector_KnownHTTPReferences(t *testing.T) {
	d := NewVulnNetworkDetector()

	tests := []detectorTestCase{
		{
			name:         "reject Android XML namespace",
			path:         "res/anim/abc_tooltip_enter.xml",
			content:      `<set xmlns:android="http://schemas.android.com/apk/res/android"></set>`,
			fileType:     types.FileTypeXML,
			wantCategory: types.CategoryCleartextTraffic,
			wantMatch:    false,
		},
		{
			name:         "accept real cleartext endpoint",
			path:         "smali/com/app/Api.smali",
			content:      `const-string v0, "http://api.example.com/v1/login"`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryCleartextTraffic,
			wantMatch:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDetectorTest(t, d.Detect, tc)
		})
	}
}

func TestVulnNetworkDetector_MethodLocalTLSSemantics(t *testing.T) {
	d := NewVulnNetworkDetector()
	tests := []detectorTestCase{
		{
			name: "unrelated return true is not hostname verifier",
			path: "smali/com/app/Feature.smali",
			content: `.class public Lcom/app/Feature;
.method public enabled()Z
  .locals 1
  const/4 v0, 0x1
  return v0
.end method`,
			fileType: types.FileTypeSmali, wantCategory: types.CategoryInsecureTLS, wantMatch: false,
		},
		{
			name: "empty checkServerTrusted is vulnerable",
			path: "smali/com/app/TrustAll.smali",
			content: `.class public Lcom/app/TrustAll;
.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
  .locals 0
  return-void
.end method`,
			fileType: types.FileTypeSmali, wantCategory: types.CategoryInsecureTLS, wantMatch: true,
		},
		{
			name: "validating checkServerTrusted is not vulnerable",
			path: "smali/com/app/TrustPinned.smali",
			content: `.class public Lcom/app/TrustPinned;
.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
  .locals 1
  invoke-static {p1}, Lcom/app/Pinning;->validate([Ljava/security/cert/X509Certificate;)V
  return-void
.end method`,
			fileType: types.FileTypeSmali, wantCategory: types.CategoryInsecureTLS, wantMatch: false,
		},
		{
			name: "constant true HostnameVerifier is vulnerable",
			path: "smali/com/app/Verifier.smali",
			content: `.class public Lcom/app/Verifier;
.implements Ljavax/net/ssl/HostnameVerifier;
.method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
  .locals 1
  const/4 v0, 0x1
  return v0
.end method`,
			fileType: types.FileTypeSmali, wantCategory: types.CategoryInsecureTLS, wantMatch: true,
		},
		{
			name: "conditional HostnameVerifier is inconclusive",
			path: "smali/com/app/Verifier.smali",
			content: `.class public Lcom/app/Verifier;
.implements Ljavax/net/ssl/HostnameVerifier;
.method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
  .locals 1
  invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z
  move-result v0
  return v0
.end method`,
			fileType: types.FileTypeSmali, wantCategory: types.CategoryInsecureTLS, wantMatch: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { runDetectorTest(t, d.Detect, tc) })
	}
}

func TestDetectors_LargeContent(t *testing.T) {
	largeContent := strings.Repeat("invoke-virtual {v0}, Ljava/lang/Object;->toString()V\n", 10000)
	ctx := createDetectorCtx("smali/Large.smali", []byte(largeContent), types.FileTypeSmali)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(largeContent)))

	NewAdsDetector().Detect(ctx, analysis)
	NewPaymentDetector().Detect(ctx, analysis)
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkAdsDetector(b *testing.B) {
	d := NewAdsDetector()
	content := []byte(`invoke-static {}, Lcom/google/android/gms/ads/AdRequest;->Builder()V`)
	ctx := createDetectorCtx("smali/Ads.smali", content, types.FileTypeSmali)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
		d.Detect(ctx, analysis)
	}
}

func BenchmarkPaymentDetector(b *testing.B) {
	d := NewPaymentDetector()
	content := []byte(`Lcom/android/billingclient/api/BillingClient;->launchBillingFlow()V`)
	ctx := createDetectorCtx("smali/Pay.smali", content, types.FileTypeSmali)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
		d.Detect(ctx, analysis)
	}
}
