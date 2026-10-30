package sastrules

import (
	"os"
	"path/filepath"
	"testing"
)

// scanSnippet scans a single in-memory java file through the embedded
// engine and returns the set of matched rule IDs.
func scanSnippet(t *testing.T, src string) map[string]bool {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(src), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	eng, err := NewEngineFromEmbedded()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	rep, err := eng.Scan(dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	ids := map[string]bool{}
	for _, m := range rep.Matches {
		ids[m.RuleID] = true
	}
	return ids
}

func TestSecretsRuleSet_Loaded(t *testing.T) {
	rs, err := LoadEmbeddedRuleSets()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	found := false
	for _, r := range rs {
		if r.Name == "secrets_and_crypto_rules" {
			found = true
			if len(r.Rules) < 15 {
				t.Fatalf("expected 15+ secrets rules, got %d", len(r.Rules))
			}
		}
	}
	if !found {
		t.Fatal("secrets_and_crypto_rules bundle not loaded")
	}
}

func TestSecretsRuleSet_AllRulesCompile(t *testing.T) {
	rs, err := LoadEmbeddedRuleSets()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, bundle := range rs {
		if bundle.Name != "secrets_and_crypto_rules" {
			continue
		}
		eng := NewEngineFromRuleSets([]RuleSet{bundle})
		if eng.Stats() != len(bundle.Rules) {
			t.Fatalf("secrets bundle: %d of %d rules compiled — some regexes are not RE2-compatible",
				eng.Stats(), len(bundle.Rules))
		}
	}
}

func TestDetect_AWSAccessKey(t *testing.T) {
	ids := scanSnippet(t, `public class App {
    static final String KEY = "AKIAIOSFODNN7EXAMPLE";
}`)
	if !ids["secret_aws_access_key_id"] {
		t.Fatalf("expected secret_aws_access_key_id, got %v", ids)
	}
}

func TestDetect_GoogleAPIKey(t *testing.T) {
	ids := scanSnippet(t, `String gk = "AIzaSyA1234567890abcdefghijklmnopqrstuv";`)
	if !ids["secret_google_api_key"] {
		t.Fatalf("expected secret_google_api_key, got %v", ids)
	}
}

func TestDetect_PrivateKeyBlock(t *testing.T) {
	ids := scanSnippet(t, `String pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...";`)
	if !ids["secret_private_key_block"] {
		t.Fatalf("expected secret_private_key_block, got %v", ids)
	}
}

func TestDetect_GitHubToken(t *testing.T) {
	ids := scanSnippet(t, `String tok = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";`)
	if !ids["secret_github_token"] {
		t.Fatalf("expected secret_github_token, got %v", ids)
	}
}

func TestDetect_HardcodedPassword(t *testing.T) {
	ids := scanSnippet(t, `props.password = "S3cr3tPr0d!";`)
	if !ids["secret_generic_password_assignment"] {
		t.Fatalf("expected secret_generic_password_assignment, got %v", ids)
	}
}

func TestDetect_HardcodedPassword_PlaceholderIgnored(t *testing.T) {
	ids := scanSnippet(t, `props.password = "changeme";`)
	if ids["secret_generic_password_assignment"] {
		t.Fatal("placeholder password should not fire the hardcoded password rule")
	}
}

func TestDetect_WeakHash(t *testing.T) {
	ids := scanSnippet(t, `MessageDigest md = MessageDigest.getInstance("MD5");`)
	if !ids["crypto_weak_hash_md5_sha1"] {
		t.Fatalf("expected crypto_weak_hash_md5_sha1, got %v", ids)
	}
}

func TestDetect_ECBMode(t *testing.T) {
	ids := scanSnippet(t, `Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");`)
	if !ids["crypto_ecb_mode"] {
		t.Fatalf("expected crypto_ecb_mode, got %v", ids)
	}
}

func TestDetect_HardcodedSecretKeySpec(t *testing.T) {
	ids := scanSnippet(t, `SecretKeySpec sk = new SecretKeySpec("mysecretaeskey12".getBytes(), "AES");`)
	if !ids["crypto_hardcoded_secret_key_spec"] {
		t.Fatalf("expected crypto_hardcoded_secret_key_spec, got %v", ids)
	}
}

func TestDetect_BasicAuthInURL(t *testing.T) {
	ids := scanSnippet(t, `String u = "https://admin:hunter22@api.internal.example.com/v1";`)
	if !ids["secret_basic_auth_in_url"] {
		t.Fatalf("expected secret_basic_auth_in_url, got %v", ids)
	}
}

// TestAllEmbeddedRulesCompile guards against RE2-incompatible regexes
// (lookahead/lookbehind) silently killing rules: before this test was
// added, android_ip_disclosure and android_insecure_random never ran.
func TestAllEmbeddedRulesCompile(t *testing.T) {
	rs, err := LoadEmbeddedRuleSets()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, bundle := range rs {
		eng := NewEngineFromRuleSets([]RuleSet{bundle})
		if eng.Stats() != len(bundle.Rules) {
			t.Errorf("bundle %q: only %d of %d rules compiled — check for lookahead/lookbehind",
				bundle.Name, eng.Stats(), len(bundle.Rules))
		}
	}
}

func TestDetect_IPDisclosure_Revived(t *testing.T) {
	ids := scanSnippet(t, `String host = "192.168.1.100";`)
	if !ids["android_ip_disclosure"] {
		t.Fatalf("expected android_ip_disclosure, got %v", ids)
	}
}

func TestDetect_InsecureRandom_Revived(t *testing.T) {
	ids := scanSnippet(t, `import java.util.Random;
Random r = new Random();`)
	if !ids["android_insecure_random"] {
		t.Fatalf("expected android_insecure_random, got %v", ids)
	}
}

func TestDetect_InsecureRandom_RandomAccessNotFlagged(t *testing.T) {
	ids := scanSnippet(t, `import java.util.RandomAccess; class A implements java.util.RandomAccess {}`)
	if ids["android_insecure_random"] {
		t.Fatal("java.util.RandomAccess must not fire android_insecure_random")
	}
}

func TestDetect_JWTHardcoded(t *testing.T) {
	ids := scanSnippet(t, `String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";`)
	if !ids["secret_jwt_hardcoded"] {
		t.Fatalf("expected secret_jwt_hardcoded, got %v", ids)
	}
}
