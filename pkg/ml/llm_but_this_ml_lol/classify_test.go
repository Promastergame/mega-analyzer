package llmkeys

import (
	"strings"
	"testing"
)

// TestDatasetsLoaded makes sure the embedded JSON actually parsed.
func TestDatasetsLoaded(t *testing.T) {
	services, positives, negatives := Stats()
	if services == 0 || positives == 0 || negatives == 0 {
		t.Fatalf("embedded datasets look empty: services=%d positives=%d negatives=%d",
			services, positives, negatives)
	}
}

// TestRealSecrets: values that should be flagged as real credentials.
func TestRealSecrets(t *testing.T) {
	cases := []struct {
		value      string
		wantFamily string
	}{
		{"AKIA1B2C3D4E5F6G7H8J", "aws"},
		{"ghp_AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8", "github"},
		{"sk-ant-Xy12Zw34Vu56Ts78Rq90PoNmLkJiHg", "anthropic"},
		{"glpat-Ab1Cd2Ef3Gh4Ij5Kl6Mn", "gitlab"},
		// No known prefix, but long and random -> still caught by entropy.
		{"Xy7Qw9Zr2Vt4Bn6Mk8Lp0Cd3Fg5Hj1Ab", ""},
		// The user's own example of a "real" key.
		{"awsuiowa098123", ""},
	}
	for _, c := range cases {
		v := Classify(c.value)
		if !v.IsSecret {
			t.Errorf("Classify(%q) = not-secret, want SECRET (reason: %s)", c.value, v.Reason)
		}
		if c.wantFamily != "" && v.Family != c.wantFamily {
			t.Errorf("Classify(%q) family = %q, want %q", c.value, v.Family, c.wantFamily)
		}
	}
}

// TestJunkRejected: the user's "ЭТО МЫ НЕ СЧИТАЕМ" list and friends.
func TestJunkRejected(t *testing.T) {
	junk := []string{
		"123456789",            // just numbers
		"test",                 // test value
		"your_key_here",        // placeholder
		"your_api_key",         // placeholder
		"******",               // mask
		"xxxxxxxxxxxxxxxx",     // all same char
		"0000000000000000",     // all zeros
		"abcdefghijklmnop",     // sequential alphabet
		"1234567890123456",     // sequential-ish digits (handled by variety/seq)
		"changeme",             // placeholder word
		"sk-ant-example-token", // valid prefix but docs example
		"AKIAXXXXXXXXXXXXXXXX", // valid prefix but template body
	}
	for _, j := range junk {
		v := Classify(j)
		if v.IsSecret {
			t.Errorf("Classify(%q) = SECRET, want not-secret (family=%q reason=%s)",
				j, v.Family, v.Reason)
		}
	}
}

// TestClassifyAssignment: full "key = value" lines are judged on the value.
func TestClassifyAssignment(t *testing.T) {
	junkLines := []string{
		"private_key=123456789",
		`private_key = "123456789"`,
		"api_key = test",
		"token: your_key_here",
	}
	for _, line := range junkLines {
		if v := ClassifyAssignment(line); v.IsSecret {
			t.Errorf("ClassifyAssignment(%q) = SECRET, want junk (reason=%s)", line, v.Reason)
		}
	}

	realLines := []string{
		"aws_key = AKIA1B2C3D4E5F6G7H8J",
		`ANTHROPIC_API_KEY="sk-ant-Xy12Zw34Vu56Ts78Rq90PoNmLkJiHg"`,
		"Authorization: Bearer ghp_AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8",
	}
	for _, line := range realLines {
		if v := ClassifyAssignment(line); !v.IsSecret {
			t.Errorf("ClassifyAssignment(%q) = junk, want SECRET (reason=%s)", line, v.Reason)
		}
	}
}

func TestStructuredNonSecretsRejected(t *testing.T) {
	cases := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"f47ac10b-58cc-4372-a567-0e02b2c3d479",
		"507f1f77bcf86cd799439011",
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"commit: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
		"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"$2b$12$KIXg3bKr3PmC7V.1gJzX3uJ5R5K5R5K5R5K5R5K5R5K5R5K5R5K5R",
	}
	for _, c := range cases {
		if v := Classify(c); v.IsSecret {
			t.Errorf("Classify(%q) = SECRET, want structured non-secret (family=%q reason=%s)",
				c, v.Family, v.Reason)
		}
	}
}

// TestAllNegativesRejected sweeps the entire learned junk database: not a
// single one of the 270 examples may be classified as a real secret.
func TestAllNegativesRejected(t *testing.T) {
	for _, n := range Negatives() {
		if v := Classify(n.Value); v.IsSecret {
			t.Errorf("negative %s %q classified as SECRET (family=%q reason=%s)",
				n.ID, n.Value, v.Family, v.Reason)
		}
	}
}

// TestPrivateKeyDetection ensures PEM-formatted private keys are caught.
func TestPrivateKeyDetection(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		// Real base64-encoded keys must have correct prefixes:
		// PKCS#8 unencrypted RSA: MIIEv...
		{"PKCS8 RSA", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDU7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U7Z8U", true},
		// PKCS#1 RSA: MIIEov...
		{"PKCS1 RSA", "MIIEowIBAAKCAQEA0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov0Eov", true},
		// PKCS#8 Encrypted: MIIFDj...
		{"PKCS8 Encrypted", "MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDjFDj", true},
		// OpenSSH: AAAAB3NzaC...
		{"OpenSSH", "AAAAB3NzaC1yc2EAAAADAQABAAABgQDU7Z8NZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaCNZAB3NzaC", true},
		// Multiline PEM blocks
		{"BEGIN/END", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgk...\n-----END PRIVATE KEY-----", true},
		{"BEGIN EC", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIGlVmt...\n-----END EC PRIVATE KEY-----", true},
		// Non-keys
		{"Not a key", "this is just some text with BEGIN and KEY words", false},
		{"Too short", "MIIEv", false}, // base64 prefix but under 100 chars
	}
	for _, c := range cases {
		v := Classify(c.value)
		if v.IsSecret != c.want {
			t.Errorf("TestPrivateKeyDetection(%s) IsSecret=%v, want %v (family=%q reason=%s)",
				c.name, v.IsSecret, c.want, v.Family, v.Reason)
		}
		if c.want && v.Family != "private_key" {
			t.Errorf("TestPrivateKeyDetection(%s) family=%q, want private_key", c.name, v.Family)
		}
	}
}

// TestNonSecretShapes locks the identifier/marker fixes from the Meteor
// cheat-client review: bare PEM markers, camelCase field names and dotted
// config keys must not be secrets, while real keys still fire.
func TestNonSecretShapes(t *testing.T) {
	negatives := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN RSA PUBLIC KEY-----",
		"newRefreshToken",
		"clientTokenValue",
		"meteor.github.authorization",
		"owner;name;branch;accessToken",
	}
	for _, v := range negatives {
		if got := Classify(v); got.IsSecret {
			t.Errorf("Classify(%q) IsSecret=true, want false (family=%q reason=%s)", v, got.Family, got.Reason)
		}
	}
	// Truncated but bodied PEM blocks stay secret (existing contract).
	if got := Classify("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgk...\n-----END PRIVATE KEY-----"); !got.IsSecret {
		t.Errorf("bodied PEM block must stay secret: %+v", got)
	}
	// Twilio SID requires hex body: HTTP header constants must not match.
	if got := Classify("ACCESS_CONTROL_ALLOW_CREDENTIALS"); got.IsSecret {
		t.Errorf("HTTP header constant must not be twilio: %+v", got)
	}
	if got := Classify("AC1234567890abcdef1234567890ABCDEF"); !got.IsSecret || got.Family != "twilio" {
		t.Errorf("hex Twilio SID must stay secret: %+v", got)
	}
}

func TestFamilies(t *testing.T) {
	f := Families()
	if len(f) == 0 {
		t.Error("expected Families() to return a non-empty list of known credential families")
	}
}

func TestClassifyBatch(t *testing.T) {
	inputs := []string{
		"AKIA1B2C3D4E5F6G7H8J",
		"123456789",
	}
	results := ClassifyBatch(inputs)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if !results[0].IsSecret {
		t.Error("expected first input to be classified as secret")
	}
	if results[1].IsSecret {
		t.Error("expected second input to be classified as non-secret")
	}
}

func TestClassifyWithKeyHint(t *testing.T) {
	// "Xy7Qw9Zr2Vt4Bn" has length 14, entropy 3.8. It matches medium-high entropy token, base confidence 0.65.
	borderline := "Xy7Qw9Zr2Vt4Bn"

	// 1. Borderline secret, with key name that is an anti-credential (e.g. "version")
	// confidence drops to 0.65 - 0.15 = 0.50. IsSecret remains true.
	v1 := ClassifyWithKeyHint(borderline, "some_version_string")
	if !v1.IsSecret || v1.Confidence != 0.50 {
		t.Errorf("expected borderline secret to have confidence 0.50, got IsSecret=%v (confidence=%f)", v1.IsSecret, v1.Confidence)
	}

	// 2. Borderline secret, with key name that is a credential hint (e.g. "api_key")
	// confidence boosted by +0.10 to 0.75
	v2 := ClassifyWithKeyHint(borderline, "my_api_key")
	if !v2.IsSecret || v2.Confidence != 0.75 {
		t.Errorf("expected borderline secret confidence to be boosted to 0.75, got IsSecret=%v, confidence=%f", v2.IsSecret, v2.Confidence)
	}

	// 3. Non-secret value, remains non-secret even with credential key name hint
	v3 := ClassifyWithKeyHint("123456789", "token")
	if v3.IsSecret {
		t.Error("expected non-secret value to remain non-secret despite credential key name")
	}
}

func TestClassifyContext(t *testing.T) {
	borderline := "Xy7Qw9Zr2Vt4Bn"

	// Case 1: multiple keywords in surrounding text -> +0.05 boost
	c1 := ClassifyContext(borderline, "", "the database secret key is stored in this variable")
	if c1.StructuralBoost < 0.04 {
		t.Errorf("expected boost for nearby keywords, got %f", c1.StructuralBoost)
	}

	// Case 2: inside quotes -> +0.03 boost
	c2 := ClassifyContext(borderline, "", `let token = "Xy7Qw9Zr2Vt4Bn"`)
	if c2.StructuralBoost < 0.02 {
		t.Errorf("expected boost for quotes, got %f", c2.StructuralBoost)
	}

	// Case 3: documentation or comment penalty -> -0.10 penalty
	c3 := ClassifyContext(borderline, "", `// example token Xy7Qw9Zr2Vt4Bn`)
	if c3.StructuralBoost > -0.09 {
		t.Errorf("expected comment/example penalty, got %f", c3.StructuralBoost)
	}

	// Case 4: test file context penalty -> -0.08 penalty
	c4 := ClassifyContext(borderline, "", `test_filename = Xy7Qw9Zr2Vt4Bn`)
	if c4.StructuralBoost > -0.07 {
		t.Errorf("expected test context penalty, got %f", c4.StructuralBoost)
	}

	// Case 5: demote to non-secret under both anti-credential key and comment penalty
	// Base confidence 0.65 -> key name "version" drops to 0.50 -> comment penalty -0.10 drops to 0.40 -> IsSecret = false
	c5 := ClassifyContext(borderline, "version", `// comment containing Xy7Qw9Zr2Vt4Bn`)
	if c5.IsSecret {
		t.Errorf("expected context to demote borderline secret to non-secret, got IsSecret=%v (confidence=%f)", c5.IsSecret, c5.Confidence)
	}
}

func TestMatchNonSecretStructureAndInternalHelpers(t *testing.T) {
	// Test isLikelyDigest / matchNonSecretStructure
	cases := []struct {
		val  string
		want string // expected reason suffix or empty if not non-secret
	}{
		// sha1/sha256 digest line (using hashes not in the negatives DB)
		{"sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", "digest/fingerprint line, not a secret"},
		{"md5:c3fcd3d76192e4007dfb496cca67e13b", "digest/fingerprint line, not a secret"},
		{"md5-c3fcd3d76192e4007dfb496cca67e13b", "checksum-like string, not a secret"},
		{"sha256:not_a_valid_digest_string", "checksum-like string, not a secret"},
		{"commit:not_hex", ""},
		// UUID (using a uuid not in the negatives DB)
		{"11111111-2222-3333-4444-555555555555", "uuid-like identifier"},
		// Segmented ID
		{"my-custom-segmented-id-with-no-spaces", "structured identifier, not a secret"},
		// Too short segmented ID part
		{"a-b-c-d-e", ""},
		// Segmented ID with non-alphanumeric chars
		{"ab-cd-ef-g#", ""},
	}

	for _, tc := range cases {
		v := Classify(tc.val)
		if tc.want != "" && !strings.Contains(v.Reason, tc.want) {
			t.Errorf("expected Classify(%q) reason to contain %q, got %q", tc.val, tc.want, v.Reason)
		}
		if tc.want == "" && (strings.Contains(v.Reason, "not a secret") || strings.Contains(v.Reason, "identifier")) && v.Reason != "empty value" {
			t.Errorf("expected Classify(%q) to not be structured non-secret, got reason %q", tc.val, v.Reason)
		}
	}
}

func TestTrivialBodyAndPlaceholders(t *testing.T) {
	// Test matchPlaceholder example/sample domination
	v1 := Classify("this_is_a_very_long_token_with_example") // "example" doesn't dominate
	if !v1.IsSecret {
		t.Errorf("expected long token containing 'example' but not dominated by it to be secret, got reason %q", v1.Reason)
	}

	v2 := Classify("short-example") // "example" dominates
	if v2.IsSecret {
		t.Error("expected short token dominated by 'example' to be rejected")
	}

	// Test isTrivialBody
	// twilio family requires 30 chars body
	vTwilioShort := Classify("AC123")
	if vTwilioShort.IsSecret {
		t.Error("expected Twilio token with short body to be rejected as trivial body")
	}

	// a family body containing a placeholder marker
	vPlaceholderBody := Classify("ghp_changeme123")
	if vPlaceholderBody.IsSecret {
		t.Error("expected github token with 'changeme' in body to be rejected as trivial body")
	}
}

func TestIsSequentialStepTest(t *testing.T) {
	// isSequential step test for counting patterns
	// e.g. "acegik" (diff +2) - not a sequential run of diff +1 or -1
	// "1234567890123456" has diffs: 1, 1, 1, 1, 1, 1, 1, 1, -9, 1, 1, 1, 1, 1, 1
	// inc = 14, pairs = 15. inc*4 = 56, pairs*3 = 45. 56 >= 45 -> true.
	if !isSequential("1234567890123456") {
		t.Error("expected 1234567890123456 to be detected as sequential")
	}

	// decreasing step test
	if !isSequential("9876543210987654") {
		t.Error("expected 9876543210987654 to be detected as sequential")
	}
}

func TestClampAndUniqueRatio(t *testing.T) {
	// clamp
	if clamp(0.5, 0.0, 1.0) != 0.5 {
		t.Error("clamp of 0.5 in [0, 1] should be 0.5")
	}
	if clamp(-0.5, 0.0, 1.0) != 0.0 {
		t.Error("clamp of -0.5 in [0, 1] should be 0.0")
	}
	if clamp(1.5, 0.0, 1.0) != 1.0 {
		t.Error("clamp of 1.5 in [0, 1] should be 1.0")
	}

	// uniqueRatio empty
	if uniqueRatio("") != 0 {
		t.Error("uniqueRatio of empty string should be 0")
	}
}

func TestExtreme32Cases(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"AKIAJKLMNOPQRSTUVWXY", false},
		{"ghp_ExAmPlE1234567890123456", false},
		{"sk-changeme1234567890abcdef1234567890...", false},
		{"AKIA123", false},
		{"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9....", true},
		{"AKIAIOSFODNN7EXAMPLE123REAL", true},
		{"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", true},
		{"xoxb-1234567890123-1234567890123-xxxx...", true},
		{"ya29.a0AfH6SMBxxxxxxxxxxxxxxxxxxxxxxx...", true},
		{"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9....", true},
		{"a665a45920422f9d417e4867efdc4fb8a04a1...", false},
		{"550e8400-e29b-41d4-a716-446655440000", false},
		{"VGhpcyBpcyBhIHRlc3Q=", false},
		{"c2stbGl2ZV8xMjM0NTY3ODkwYWJjZGVmZ2hpams=", true},
		{"5d41402abc4b2a76b9719d911017c592", false},
		{"736b2d6c6976655f31323334353637383930", false},
		{"nx-yvir_1234567890nopqrstuvwxyz", false},
		{"sk-live_1234567890αβγδεζηθ", true},
		{"SkLiVe_1234567890AbCdEfGhIjK", true},
		{"sk-ant-api03-1234567890abcdef", true},
		{"hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx...", true},
		{"sk-proj-1234567890abcdef", true},
		{"ODxxxxxxxxxxxxxxxxxxxxxxxxx.xxxxxx.xx...", true},
		{"1234567890:AAE_xxxxxxxxxxxxxxxxxxxxxx...", true},
		{"-----BEGIN PRIVATE KEY----- MIIEvgIBA...", true},
		{"-----BEGIN OPENSSH PRIVATE KEY----- b...", true},
		{"ewogICJhdXRocyI6IHsKICAgICJyZWdpc3Rye...", false},
		{".dockerconfigjson", false},
		{"мой_секретный_ключ_sk...", true},
		{`{"api_key":"sk-live_1234567890abcdef"}`, false},
		{"https://api.com?key=sk-live_1234567890", false},
		{"const API_KEY = 'sk-live_1234567890'", false},
	}

	for i, c := range cases {
		got := Classify(c.val)
		if got.IsSecret != c.want {
			t.Errorf("Case #%d Classify(%q) = %v (conf=%.2f, family=%q, reason=%s), want %v",
				i+1, c.val, got.IsSecret, got.Confidence, got.Family, got.Reason, c.want)
		}
	}
}
