// pkg/internal/pipeline/vuln_crypto_smali_test.go
//
// Tests for the AST-based weak-crypto detector (audit P0-2 / B5).
package pipeline

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/parser"
	"mega-analyzer/pkg/internal/types"
)

// parseCryptoFixture parses smali content and fills method bodies the same
// way Pipeline.processSmali does, mirroring the production wiring.
func parseCryptoFixture(t *testing.T, content string) *types.SmaliClass {
	t.Helper()
	class, err := parser.NewSmaliParser(content).Parse()
	if err != nil {
		t.Fatalf("smali parse failed: %v", err)
	}
	lines := strings.Split(content, "\n")
	for i := range class.Methods {
		m := &class.Methods[i]
		if m.LineStart > 0 && m.LineEnd <= len(lines) {
			m.Body = lines[m.LineStart-1 : m.LineEnd]
		}
	}
	return class
}

func runCryptoAST(t *testing.T, content string) []types.Match {
	t.Helper()
	d := NewVulnCryptoDetector()
	ctx := createDetectorCtx("smali/com/app/Crypto.smali", []byte(content), types.FileTypeSmali)
	ctx.Class = parseCryptoFixture(t, content)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	d.Detect(ctx, analysis)
	return analysis.Matches
}

func cryptoMatches(matches []types.Match) []types.Match {
	out := make([]types.Match, 0, len(matches))
	for _, m := range matches {
		if m.Category == types.CategoryWeakCrypto {
			out = append(out, m)
		}
	}
	return out
}

func TestCryptoAST_DefaultAESIsECB(t *testing.T) {
	matches := cryptoMatches(runCryptoAST(t, `
.class public Lcom/app/Crypto;
.method public encrypt()V
    .locals 2
    const-string v0, "AES"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v1
    return-void
.end method
`))
	if len(matches) == 0 {
		t.Fatal("expected default-AES ECB finding, got none")
	}
	if !matches[0].IsCritical {
		t.Error("expected critical severity for default-ECB AES")
	}
	if matches[0].MethodName != "encrypt" {
		t.Errorf("MethodName = %q, want encrypt", matches[0].MethodName)
	}
	if matches[0].Confidence != "high" {
		t.Errorf("Confidence = %q, want high", matches[0].Confidence)
	}
}

func TestCryptoAST_ExplicitECBAndSafeGCM(t *testing.T) {
	ecb := cryptoMatches(runCryptoAST(t, `
.class public Lcom/app/Crypto;
.method public encrypt()V
    .locals 1
    const-string v0, "AES/ECB/PKCS5Padding"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    return-void
.end method
`))
	if len(ecb) == 0 {
		t.Fatal("expected AES/ECB finding")
	}

	gcm := cryptoMatches(runCryptoAST(t, `
.class public Lcom/app/Crypto;
.method public encrypt()V
    .locals 1
    const-string v0, "AES/GCM/NoPadding"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    return-void
.end method
`))
	if len(gcm) != 0 {
		t.Errorf("AES/GCM must not be flagged, got %d findings", len(gcm))
	}
}

func TestCryptoAST_ZeroIVPayload(t *testing.T) {
	matches := cryptoMatches(runCryptoAST(t, `
.class public Lcom/app/Crypto;
.method public encrypt()V
    .locals 3
    new-instance v0, Ljavax/crypto/spec/IvParameterSpec;
    const/16 v1, 0x10
    new-array v1, v1, [B
    fill-array-data v1, :array_iv
    invoke-direct {v0, v1}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V
    return-void
    :array_iv
    .array-data 1
        0x0t
        0x0t
        0x0t
        0x0t
    .end array-data
.end method
`))
	if len(matches) == 0 {
		t.Fatal("expected static-IV finding")
	}
	if !strings.Contains(matches[0].Context, "all-zero") {
		t.Errorf("expected all-zero IV description, got %q", matches[0].Context)
	}
}

func TestCryptoAST_HardcodedKeyMaterial(t *testing.T) {
	matches := cryptoMatches(runCryptoAST(t, `
.class public Lcom/app/Crypto;
.method public makeKey()Ljavax/crypto/spec/SecretKeySpec;
    .locals 4
    new-instance v0, Ljavax/crypto/spec/SecretKeySpec;
    const-string v1, "supersecretkey16"
    invoke-virtual {v1}, Ljava/lang/String;->getBytes()[B
    move-result-object v2
    const-string v3, "AES"
    invoke-direct {v0, v2, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
    return-object v0
.end method
`))
	if len(matches) == 0 {
		t.Fatal("expected hardcoded-key finding")
	}
	foundKey := false
	for _, m := range matches {
		if strings.Contains(m.Context, "hardcoded key material") {
			foundKey = true
		}
	}
	if !foundKey {
		t.Errorf("expected hardcoded key material finding, got: %v", getMatchSummary(matches))
	}
}

func TestCryptoAST_MD5PasswordEscalation(t *testing.T) {
	plain := cryptoMatches(runCryptoAST(t, `
.class public Lcom/app/Crypto;
.method public checksum([B)[B
    .locals 2
    const-string v0, "MD5"
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v1
    invoke-virtual {v1, p1}, Ljava/security/MessageDigest;->digest([B)[B
    move-result-object v0
    return-object v0
.end method
`))
	if len(plain) == 0 {
		t.Fatal("expected MD5 finding")
	}
	if plain[0].IsCritical {
		t.Error("plain MD5 checksum use should not be critical")
	}

	esc := cryptoMatches(runCryptoAST(t, `
.class public Lcom/app/Crypto;
.method public hashPassword(Ljava/lang/String;)[B
    .locals 2
    const-string v0, "MD5"
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v1
    invoke-virtual {p1}, Ljava/lang/String;->getBytes()[B
    move-result-object v0
    invoke-virtual {v1, v0}, Ljava/security/MessageDigest;->digest([B)[B
    move-result-object v0
    return-object v0
.end method
`))
	if len(esc) == 0 {
		t.Fatal("expected MD5 finding in password context")
	}
	if !esc[0].IsCritical {
		t.Error("MD5 in hashPassword should escalate to critical")
	}
}

func TestCryptoAST_ByteFallbackForCompactStreams(t *testing.T) {
	// smali_compact detector streams have no parseable class: ctx.Class stays
	// nil and the legacy byte patterns must still apply.
	d := NewVulnCryptoDetector()
	content := []byte(`cipher.getinstance("aes") and ivparameterspec(new byte[16])`)
	ctx := createDetectorCtx("smali_compact/crypto_smali", content, types.FileTypeSmali)
	analysis := types.NewFileAnalysis(ctx.Path, ctx.FileType, int64(len(content)))
	d.Detect(ctx, analysis)
	if !hasMatchCategory(analysis.Matches, types.CategoryWeakCrypto) {
		t.Errorf("byte fallback produced no findings: %v", getMatchSummary(analysis.Matches))
	}
}
