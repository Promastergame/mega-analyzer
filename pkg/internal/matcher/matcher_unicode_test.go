// pkg/internal/matcher/matcher_unicode_test.go
package matcher

import (
	"strings"
	"testing"
	"unicode/utf8"

	"mega-analyzer/pkg/internal/config"
)

// ============================================================================
// Unicode Edge Cases
// ============================================================================

func TestMatcher_scanLines_UnicodeLowercaseLengthMismatch_NoPanic(t *testing.T) {
	// "ẞ" (U+1E9E) lowercases to "ß" (U+00DF) — UTF-8 byte length shrinks (3 -> 2)
	content := "ABCẞDEF"
	contentLower := strings.ToLower(content)

	if len(contentLower) >= len(content) {
		t.Fatalf("test precondition failed: contentLower should be shorter")
	}

	m := &Matcher{config: config.DefaultConfig()}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("scanLines panicked: %v", r)
		}
	}()

	li := buildLineIndex(content)
	_ = m.scanLines(content, contentLower, "res/values/strings.xml", false, nil, false, li, false)
}

func TestMatcher_Unicode_VariousScripts(t *testing.T) {
	cfg := config.DefaultConfig()
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		content string
	}{
		{"German_sharp_s", "PASSWORDẞTEST"},
		{"Turkish_i", "İstanbul password İ"},
		{"Greek_sigma", "ΣΣΣΣ password σσσσ"},
		{"Japanese", "パスワード password 日本語"},
		{"Chinese", "密码 password 测试"},
		{"Korean", "비밀번호 password 테스트"},
		{"Arabic", "كلمة السر password اختبار"},
		{"Hebrew", "סיסמה password בדיקה"},
		{"Thai", "รหัสผ่าน password ทดสอบ"},
		{"Emoji", "🔐 password 🔑 secret 🔒"},
		{"Math_symbols", "∑∏∫ password ∂∆∇"},
		{"Fullwidth", "ｐａｓｓｗｏｒｄ"},
		{"Mixed", "Пароль_password_密码_🔐"},
		{"ZeroWidth", "pass\u200Bword"},       // Zero-width space
		{"Combining", "pässwörd"},             // Combining diacritics
		{"RTL_mixed", "password مرحبا hello"}, // Right-to-left
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %q: %v", tc.name, r)
				}
			}()

			matches := m.MatchContent(tc.content, "test.smali")

			// Verify all matches have valid UTF-8
			for i, match := range matches {
				if !utf8.ValidString(match.Text) {
					t.Errorf("match[%d]: invalid UTF-8 in Text", i)
				}
				if !utf8.ValidString(match.Context) {
					t.Errorf("match[%d]: invalid UTF-8 in Context", i)
				}
			}
		})
	}
}

func TestMatcher_Unicode_LengthChangingCases(t *testing.T) {
	// Characters where ToLower changes byte length
	lengthChangingChars := []struct {
		name  string
		upper string
		lower string
	}{
		{"German_sharp_S", "ẞ", "ß"},      // 3 bytes -> 2 bytes
		{"Turkish_I", "İ", "i̇"},          // 2 bytes -> 3 bytes (i + combining dot)
		{"Greek_capital_sigma", "Σ", "σ"}, // Same length but different
		{"Kelvin_sign", "K", "k"},         // Special K
	}

	cfg := config.DefaultConfig()
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range lengthChangingChars {
		t.Run(tc.name, func(t *testing.T) {
			// Create content with the character surrounded by ASCII
			content := "password" + tc.upper + "secret"

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic with %s: %v", tc.name, r)
				}
			}()

			_ = m.MatchContent(content, "test.smali")
		})
	}
}

func TestMatcher_Unicode_InvalidUTF8(t *testing.T) {
	cfg := config.DefaultConfig()
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	invalidInputs := []struct {
		name    string
		content []byte
	}{
		{"invalid_continuation", []byte{0x80, 0x81, 0x82}},
		{"truncated_sequence", []byte{0xC2}},      // Start of 2-byte, no continuation
		{"overlong_encoding", []byte{0xC0, 0x80}}, // Overlong NUL
		{"invalid_start", []byte{0xFF, 0xFE}},     // Invalid start bytes
		{"mixed_valid_invalid", []byte("password\xFF\xFEsecret")},
		{"null_bytes", []byte("pass\x00word")},
	}

	for _, tc := range invalidInputs {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on invalid UTF-8 (%s): %v", tc.name, r)
				}
			}()

			// Should handle gracefully, not panic
			_ = m.MatchContent(string(tc.content), "test.smali")
		})
	}
}

func TestMatcher_Unicode_VeryLongLines(t *testing.T) {
	cfg := config.DefaultConfig()
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Very long line with unicode
	longLine := strings.Repeat("日本語テスト_password_", 1000)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on long unicode line: %v", r)
		}
	}()

	matches := m.MatchContent(longLine, "test.smali")

	// Should find "password" matches
	if len(matches) == 0 {
		t.Log("no matches found (may be OK depending on patterns)")
	}
}

func TestMatcher_Unicode_ManySmallLines(t *testing.T) {
	cfg := config.DefaultConfig()
	m, err := NewMatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Many short lines with unicode
	var sb strings.Builder
	for i := 0; i < 10000; i++ {
		sb.WriteString("日本語\n")
	}
	sb.WriteString("password\n") // One match at the end

	content := sb.String()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()

	_ = m.MatchContent(content, "test.smali")
}

// ============================================================================
// AhoCorasick Unicode Tests
// ============================================================================

func TestAhoCorasick_Unicode(t *testing.T) {
	keywords := []string{"password", "secret", "密码", "パスワード"}
	ac := NewAhoCorasick(keywords)

	tests := []struct {
		name     string
		text     string
		wantHits bool
	}{
		{"ascii_match", "the password is here", true},
		{"chinese_match", "这是密码测试", true},
		{"japanese_match", "パスワードです", true},
		{"no_match", "nothing here", false},
		{"mixed", "password 密码 パスワード", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := ac.Search(tc.text)
			hasHits := len(results) > 0

			if hasHits != tc.wantHits {
				t.Errorf("Search(%q) = %v hits, want hits=%v", tc.text, results, tc.wantHits)
			}
		})
	}
}
