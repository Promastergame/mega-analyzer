package sandbox

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureAESKey = "000102030405060708090a0b0c0d0e0f"
const fixtureIV = "101112131415161718191a1b1c1d1e1f"

func TestCryptoCapturedMaterialDecryptsNISTCBCFixture(t *testing.T) {
	// NIST SP 800-38A F.2.1, first block. An independent known-answer fixture
	// verifies byte order, full key length and the pre-operation IV in the report.
	key := "2b7e151628aed2a6abf7158809cf4f3c"
	iv := "000102030405060708090a0b0c0d0e0f"
	a := analyzeCryptoMaterial(&Report{APICalls: []APICall{
		cryptoFixtureCall("BCryptGenerateSymmetricKey", 42, "0x1", "KeyHex", key, "Algorithm", "AES"),
		cryptoFixtureCall("BCryptEncrypt", 42, "0x1", "IVHex", iv, "OutputPresent", "true"),
	}})
	if len(a.Materials) != 2 {
		t.Fatalf("missing captured invocation: %+v", a)
	}
	m := a.Materials[1]
	keyBytes, err := hex.DecodeString(m.KeyHex)
	if err != nil {
		t.Fatal(err)
	}
	ivBytes, err := hex.DecodeString(m.IVHex)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString("7649abac8119b246cee98e9b12e9197d")
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCDecrypter(block, ivBytes).CryptBlocks(data, data)
	if got := hex.EncodeToString(data); got != "6bc1bee22e409f96e93d7e117393172a" {
		t.Fatalf("fixture decryption: %s", got)
	}
}

func cryptoFixtureCall(fn string, pid int, handle string, values ...string) APICall {
	c := APICall{Function: fn, ProcessID: pid, ThreadID: 7, ReturnValue: "0x00000000", Timestamp: time.Unix(1700000000, 0).UTC(), Module: "bcrypt.dll"}
	c.Parameters = []APIParameter{{Name: "hKey", Value: handle}}
	for i := 0; i < len(values); i += 2 {
		c.Parameters = append(c.Parameters, APIParameter{Name: values[i], Value: values[i+1]})
	}
	return c
}

func TestCryptoMaterialCNGCorrelatesInvocations(t *testing.T) {
	create := cryptoFixtureCall("BCryptGenerateSymmetricKey", 42, "0xAA", "KeyHex", strings.ToUpper(fixtureAESKey), "Algorithm", "AES")
	encrypt := cryptoFixtureCall("BCryptEncrypt", 42, "0xaa", "OutputPresent", "true", "IVHex", fixtureIV)
	otherProcess := encrypt
	otherProcess.ProcessID = 43
	failed := encrypt
	failed.ReturnValue = "0xC0000001"
	query := cryptoFixtureCall("BCryptEncrypt", 42, "0xaa", "OutputPresent", "false")
	destroy := cryptoFixtureCall("BCryptDestroyKey", 42, "0xaa")
	got := analyzeCryptoMaterial(&Report{APICalls: []APICall{create, encrypt, encrypt, otherProcess, failed, query, destroy, encrypt}})
	if got.Status != "captured" || got.Rejected != 0 || len(got.Materials) != 2 {
		t.Fatalf("analysis = %+v", got)
	}
	key, use := got.Materials[0], got.Materials[1]
	if key.KeyHex != fixtureAESKey || key.KeyBytes != 16 || key.IVHex != "" || key.Function != create.Function {
		t.Fatalf("key evidence = %+v", key)
	}
	if use.Operation != "encrypt" || use.IVHex != fixtureIV || use.PID != 42 || use.ThreadID != 7 || use.Source != "frida-windows" || use.Observations != 2 || !use.ObservedAt.Equal(encrypt.Timestamp) {
		t.Fatalf("invocation evidence = %+v", use)
	}
}

func TestCryptoMaterialReplacedAndUncapturedHandles(t *testing.T) {
	create := cryptoFixtureCall("BCryptImportKey", 42, "0x1", "KeyHex", fixtureAESKey, "Algorithm", "AES")
	decrypt := cryptoFixtureCall("BCryptDecrypt", 42, "0x1", "OutputPresent", "true")
	uncaptured := cryptoFixtureCall("BCryptImportKey", 42, "0x1")
	got := analyzeCryptoMaterial(&Report{APICalls: []APICall{create, uncaptured, decrypt}})
	if len(got.Materials) != 1 || got.Rejected != 1 {
		t.Fatalf("uncaptured replacement reused old key: %+v", got)
	}
	replacement := cryptoFixtureCall("BCryptImportKey", 42, "0x1", "KeyHex", strings.Repeat("11", 32), "Algorithm", "AES")
	got = analyzeCryptoMaterial(&Report{APICalls: []APICall{create, replacement, decrypt}})
	if len(got.Materials) != 3 || got.Materials[2].KeyHex != strings.Repeat("11", 32) || got.Materials[2].Operation != "decrypt" {
		t.Fatalf("wrong replacement association: %+v", got)
	}
}

func TestCryptoMaterialRejectsInvalidEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, key, iv, alg string
		pid                int
	}{
		{"handle is not key", "0x1234", "", "AES", 42},
		{"odd hex", "123", "", "unknown", 42},
		{"missing", "", "", "AES", 42},
		{"non hex", "zz", "", "unknown", 42},
		{"oversize", strings.Repeat("01", 257), "", "unknown", 42},
		{"bad AES size", "abcd", "", "AES/CBC/PKCS5Padding", 42},
		{"bad iv", fixtureAESKey, "0x12", "AES", 42},
		{"oversize iv", fixtureAESKey, strings.Repeat("01", 33), "AES", 42},
		{"no pid", fixtureAESKey, "", "AES", 0},
		{"oversize label", fixtureAESKey, "", strings.Repeat("a", 129), 42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &CryptoAnalysis{}
			a.add(CryptoMaterial{PID: tc.pid, KeyHex: tc.key, IVHex: tc.iv, Algorithm: tc.alg})
			if len(a.Materials) != 0 || a.Rejected != 1 {
				t.Fatalf("accepted invalid evidence: %+v", a)
			}
		})
	}
	for _, status := range []string{"", "garbage", "0xC0000022", "-1"} {
		call := cryptoFixtureCall("BCryptGenerateSymmetricKey", 42, "0x1", "KeyHex", fixtureAESKey)
		call.ReturnValue = status
		if a := analyzeCryptoMaterial(&Report{APICalls: []APICall{call}}); len(a.Materials) != 0 {
			t.Fatalf("accepted unsuccessful return %q", status)
		}
	}
	for _, handle := range []string{"", "0", "0x0"} {
		call := cryptoFixtureCall("BCryptGenerateSymmetricKey", 42, handle, "KeyHex", fixtureAESKey)
		if a := analyzeCryptoMaterial(&Report{APICalls: []APICall{call}}); len(a.Materials) != 0 {
			t.Fatalf("accepted null handle %q", handle)
		}
	}
}

func TestCryptoMaterialBudgetsAndStatuses(t *testing.T) {
	if got := analyzeCryptoMaterial(&Report{}); got.Status != "not_instrumented" {
		t.Fatal(got)
	}
	if got := analyzeCryptoMaterial(&Report{Frida: &FridaSession{Active: true}}); got.Status != "no_material" {
		t.Fatal(got)
	}
	if got := analyzeCryptoMaterial(&Report{APICalls: []APICall{{Function: "WriteFile"}}}); got.Status != "not_instrumented" {
		t.Fatal(got)
	}
	a := &CryptoAnalysis{}
	for i := 0; i < maxCryptoMaterials+1; i++ {
		a.add(CryptoMaterial{PID: i + 1, KeyHex: fixtureAESKey})
	}
	if len(a.Materials) != maxCryptoMaterials || !a.Truncated || a.Materials[0].Algorithm != "unknown" {
		t.Fatal(a)
	}
	a.add(CryptoMaterial{PID: 1, KeyHex: fixtureAESKey})
	if a.Materials[0].Observations != 2 {
		t.Fatal("duplicates must still count at capacity")
	}
	var calls []APICall
	for i := 0; i < 4097; i++ {
		calls = append(calls, cryptoFixtureCall("BCryptImportKey", 42, fmt.Sprintf("0x%x", i+1), "KeyHex", fixtureAESKey))
	}
	got := analyzeCryptoMaterial(&Report{APICalls: calls})
	if !got.Truncated || len(got.Materials) != maxCryptoMaterials {
		t.Fatal("unbounded handle tracking")
	}
}

func TestFridaSummaryStructuredCryptoAndReportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "frida.log")
	event := fmt.Sprintf(`FRIDA_EVT {"t":1700000000000,"cat":"crypto_key","act":"Cipher.init","pid":42,"algorithm":"AES/CBC/PKCS5Padding","key_hex":%q,"iv_hex":%q,"operation":"decrypt"}`, fixtureAESKey, fixtureIV)
	log := "noise\nFRIDA_EVT broken\nFRIDA_EVT {}\n[device] FRIDA_EVT {\"cat\": \"net\", \"act\": \"connect\"}\n" + event + "\n" + event + "\n"
	if err := os.WriteFile(path, []byte(log), 0600); err != nil {
		t.Fatal(err)
	}
	sess := &FridaSession{Active: true}
	fridaSummarise(path, sess)
	if sess.EventCount != 3 || strings.Join(sess.Categories, ",") != "net,crypto_key" || len(sess.Crypto.Materials) != 1 || sess.Crypto.Materials[0].Observations != 2 {
		t.Fatalf("summary = %+v / %+v", sess, sess.Crypto)
	}
	// Summarising twice replaces, rather than double-counting, the observations.
	fridaSummarise(path, sess)
	rep := &Report{Frida: sess, JSONPath: filepath.Join(dir, "report.json"), MarkdownPath: filepath.Join(dir, "report.md")}
	if err := PersistReport(rep); err != nil {
		t.Fatal(err)
	}
	if rep.CryptoAnalysis.Materials[0].Observations != 2 {
		t.Fatal("double-counted summary")
	}
	data, err := os.ReadFile(rep.JSONPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := PersistReport(&decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.CryptoAnalysis.Materials) != 1 || decoded.CryptoAnalysis.Materials[0].IVHex != fixtureIV {
		t.Fatal("lost material on persisted report reload")
	}
	md, err := os.ReadFile(rep.MarkdownPath)
	if err != nil || !strings.Contains(string(md), fixtureAESKey) || !strings.Contains(string(md), "decryption has not been verified") {
		t.Fatalf("markdown: %s, %v", md, err)
	}
	// Report derivation must not alias the session's mutable slice.
	rep.CryptoAnalysis.Materials[0].KeyHex = "changed"
	if sess.Crypto.Materials[0].KeyHex != fixtureAESKey {
		t.Fatal("report aliases session")
	}
}

func TestFridaSummaryReadFailureAndTruncation(t *testing.T) {
	sess := &FridaSession{}
	fridaSummarise(filepath.Join(t.TempDir(), "missing"), sess)
	if sess.EventCount != 0 {
		t.Fatal(sess)
	}
	path := filepath.Join(t.TempDir(), "oversize.log")
	if err := os.WriteFile(path, []byte("FRIDA_EVT {\"cat\":\"net\"}\n"+strings.Repeat("x", 1024*1024+1)), 0600); err != nil {
		t.Fatal(err)
	}
	fridaSummarise(path, sess)
	if sess.EventCount != 1 || !sess.Crypto.Truncated || len(sess.Warnings) != 1 {
		t.Fatalf("missing partial capture diagnostics: %+v", sess)
	}
}

func TestCryptoMarkdownEscapesSampleLabels(t *testing.T) {
	var b strings.Builder
	writeCryptoAnalysisMarkdown(&b, nil)
	if b.Len() != 0 {
		t.Fatal("nil analysis must be omitted")
	}
	a := &CryptoAnalysis{}
	a.add(CryptoMaterial{PID: 42, KeyHex: fixtureAESKey, Algorithm: "<script>`\n", Operation: "<img src=x>", Source: "&lt;"})
	writeCryptoAnalysisMarkdown(&b, a)
	if strings.Contains(b.String(), "<script>") || strings.Contains(b.String(), "<img") || !strings.Contains(b.String(), "&lt;script&gt;&#96;") || !strings.Contains(b.String(), "&amp;lt;") {
		t.Fatal(b.String())
	}
}
