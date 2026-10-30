// pkg/internal/matcher/matcher_fuzz_test.go
package matcher

import (
	"strings"
	"testing"
	"unicode/utf8"

	"mega-analyzer/pkg/internal/config"
)

// ============================================================================
// Fuzz Tests
// ============================================================================

func FuzzMatcher(f *testing.F) {
	// Seed corpus — разнообразные входные данные
	seeds := []string{
		// Обычные паттерны
		"password=secret123",
		"const API_KEY = 'sk-xxxx'",
		"invoke-virtual {p0}, Ljavax/crypto/Cipher;->doFinal([B)[B",

		// Unicode edge cases
		"ABCẞDEF",     // ẞ -> ß (длина меняется)
		"İstanbul",    // İ -> i̇ (Turkish)
		"ΣΣΣΣ",        // Greek sigma
		"Überprüfung", // German umlauts
		"日本語テスト",      // Japanese
		"🔐🔑🔒",         // Emojis
		"Ａｐｉ_Ｋｅｙ",     // Fullwidth

		// Boundary cases
		"",
		" ",
		"\n\n\n",
		"\t\r\n",
		"\x00\x00\x00", // Null bytes
		strings.Repeat("a", 100),
		strings.Repeat("a", 10000),
		strings.Repeat("password ", 100), // Repeated matches
		strings.Repeat("\n", 1000),       // Many empty lines

		// Malformed data
		string([]byte{0xFF, 0xFE, 0x00}), // Invalid UTF-8
		"line1\rline2\nline3\r\nline4",   // Mixed line endings

		// Real smali patterns
		`.class public Lcom/test/Test;
.super Ljava/lang/Object;
.method public test()V
    const-string v0, "secret"
    return-void
.end method`,
	}

	for _, s := range seeds {
		f.Add(s)
	}

	cfg := &config.Config{
		MaxMatchesPerFile: 100,
		ContextLines:      2,
		MaxStringLength:   200,
	}

	m, err := NewMatcher(cfg)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, content string) {
		// Should not panic
		matches := m.MatchContent(content, "fuzz.smali")

		// Invariants
		for i, match := range matches {
			// Line number must be positive
			if match.Line <= 0 {
				t.Errorf("match[%d]: invalid line number: %d", i, match.Line)
			}

			// Score must be in valid range
			if match.Score < 0 || match.Score > 10 {
				t.Errorf("match[%d]: score out of bounds: %f", i, match.Score)
			}

			// Category must not be empty
			if match.Category == "" {
				t.Errorf("match[%d]: empty category", i)
			}

			// Pattern must not be empty
			if match.Pattern == "" {
				t.Errorf("match[%d]: empty pattern", i)
			}

			// Text should be valid UTF-8
			if !utf8.ValidString(match.Text) {
				t.Errorf("match[%d]: invalid UTF-8 in Text", i)
			}
		}

		// Match count should not exceed limit
		if len(matches) > cfg.MaxMatchesPerFile {
			t.Errorf("too many matches: %d > %d", len(matches), cfg.MaxMatchesPerFile)
		}
	})
}

func FuzzMatcherWithFilter(f *testing.F) {
	seeds := []string{
		"password",
		"Lcom/google/ads/AdView;",
		"invoke-static {}, Lcom/facebook/;->init()V",
		strings.Repeat("const-string v0, \"test\"\n", 100),
	}

	for _, s := range seeds {
		f.Add(s, true)
		f.Add(s, false)
	}

	cfg := config.DefaultConfig()
	m, err := NewMatcher(cfg)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, content string, isAppCode bool) {
		// Should not panic
		matches := m.MatchContentWithFilter(content, "fuzz.smali", isAppCode)

		// Basic sanity
		for _, match := range matches {
			if match.Line <= 0 {
				t.Errorf("invalid line: %d", match.Line)
			}
		}
	})
}

func FuzzAhoCorasick(f *testing.F) {
	seeds := []string{
		"password secret token",
		"",
		"no matches here",
		strings.Repeat("x", 10000),
		strings.Repeat("password ", 100),
		"passwordpasswordpassword", // Overlapping
		"PassWord SECRET Token",    // Mixed case
		"pass\x00word",             // Null in middle
		"密码password秘密",             // Mixed languages
	}

	for _, s := range seeds {
		f.Add(s)
	}

	keywords := []string{
		"password", "secret", "token", "api_key", "credential",
		"private", "auth", "bearer", "session", "cookie",
	}
	ac := NewAhoCorasick(keywords)

	f.Fuzz(func(t *testing.T, text string) {
		// Should not panic
		results := ac.Search(text)

		// Verify results are valid indices
		for _, idx := range results {
			if idx < 0 || idx >= len(keywords) {
				t.Errorf("invalid keyword index: %d (max: %d)", idx, len(keywords)-1)
			}
		}

		// Results should be sorted (if implementation guarantees this)
		for i := 1; i < len(results); i++ {
			if results[i] < results[i-1] {
				// Not sorted — may be OK depending on implementation
				// t.Logf("results not sorted: %v", results)
			}
		}
	})
}

func FuzzAhoCorasickEmpty(f *testing.F) {
	f.Add("test")
	f.Add("")

	// Empty keyword list
	ac := NewAhoCorasick([]string{})

	f.Fuzz(func(t *testing.T, text string) {
		results := ac.Search(text)
		if len(results) != 0 {
			t.Errorf("expected no results for empty keywords, got %d", len(results))
		}
	})
}
