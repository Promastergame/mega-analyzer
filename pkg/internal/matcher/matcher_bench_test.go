// pkg/internal/matcher/matcher_bench_test.go
package matcher

import (
	"fmt"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/config"
)

// ============================================================================
// AhoCorasick Benchmarks
// ============================================================================

func BenchmarkAhoCorasick(b *testing.B) {
	keywords := []string{
		"password", "secret", "api_key", "token", "credential",
		"private_key", "auth", "bearer", "session", "cookie",
	}
	ac := NewAhoCorasick(keywords)

	sizes := []int{100, 1000, 10000, 100000}

	for _, size := range sizes {
		text := strings.Repeat("this password contains api_key and secret tokens ", size/50)

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = ac.Search(text)
			}
		})
	}
}

func BenchmarkAhoCorasick_NoMatches(b *testing.B) {
	keywords := []string{"password", "secret", "token"}
	ac := NewAhoCorasick(keywords)

	text := strings.Repeat("nothing interesting here just some random text ", 200)

	b.SetBytes(int64(len(text)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ac.Search(text)
	}
}

func BenchmarkAhoCorasick_ManyKeywords(b *testing.B) {
	// 100 keywords
	keywords := make([]string, 100)
	for i := range keywords {
		keywords[i] = fmt.Sprintf("keyword%d", i)
	}
	ac := NewAhoCorasick(keywords)

	text := strings.Repeat("keyword50 appears here and keyword99 too ", 100)

	b.SetBytes(int64(len(text)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ac.Search(text)
	}
}

// ============================================================================
// Matcher Benchmarks
// ============================================================================

func BenchmarkMatcher_SmallFile(b *testing.B) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)

	content := generateSmaliContent(100) // 100 lines

	b.SetBytes(int64(len(content)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = m.MatchContent(content, "test.smali")
	}
}

func BenchmarkMatcher_MediumFile(b *testing.B) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)

	content := generateSmaliContent(1000) // 1K lines

	b.SetBytes(int64(len(content)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = m.MatchContent(content, "test.smali")
	}
}

func BenchmarkMatcher_LargeFile(b *testing.B) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)

	content := generateSmaliContent(10000) // 10K lines

	b.SetBytes(int64(len(content)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = m.MatchContent(content, "test.smali")
	}
}

func BenchmarkMatcher_WithFilter(b *testing.B) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)

	content := generateSmaliContent(5000)

	b.Run("AppCode_true", func(b *testing.B) {
		b.SetBytes(int64(len(content)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = m.MatchContentWithFilter(content, "test.smali", true)
		}
	})

	b.Run("AppCode_false", func(b *testing.B) {
		b.SetBytes(int64(len(content)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = m.MatchContentWithFilter(content, "test.smali", false)
		}
	})
}

func BenchmarkMatcher_Parallel(b *testing.B) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)

	content := generateSmaliContent(10000)
	contentLower := strings.ToLower(content)

	workers := []int{1, 2, 4, 8}

	for _, w := range workers {
		b.Run(fmt.Sprintf("workers_%d", w), func(b *testing.B) {
			b.SetBytes(int64(len(content)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = m.MatchContentParallel(content, contentLower, "test.smali", true, w)
			}
		})
	}
}

func BenchmarkMatcher_ByFileType(b *testing.B) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)

	files := map[string]string{
		"smali":    generateSmaliContent(1000),
		"xml":      generateXMLContent(1000),
		"manifest": generateManifestContent(),
	}

	for name, content := range files {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(content)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = m.MatchContent(content, "test."+name)
			}
		})
	}
}

func BenchmarkMatcher_HighMatchDensity(b *testing.B) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)

	// Every line has a match
	content := strings.Repeat("const password = \"secret\"\n", 1000)

	b.SetBytes(int64(len(content)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = m.MatchContent(content, "test.smali")
	}
}

func BenchmarkMatcher_NoMatches(b *testing.B) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)

	// No patterns should match
	content := strings.Repeat(".local v0, x:I\nmove v1, v0\n", 1000)

	b.SetBytes(int64(len(content)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = m.MatchContent(content, "test.smali")
	}
}

// ============================================================================
// Comparison Benchmarks
// ============================================================================

func BenchmarkMatcher_Sequential_vs_Parallel(b *testing.B) {
	cfg := config.DefaultConfig()
	m, _ := NewMatcher(cfg)

	content := generateSmaliContent(20000)
	contentLower := strings.ToLower(content)

	b.Run("Sequential", func(b *testing.B) {
		b.SetBytes(int64(len(content)))
		for i := 0; i < b.N; i++ {
			_ = m.MatchContent(content, "test.smali")
		}
	})

	b.Run("Parallel_4", func(b *testing.B) {
		b.SetBytes(int64(len(content)))
		for i := 0; i < b.N; i++ {
			_ = m.MatchContentParallel(content, contentLower, "test.smali", true, 4)
		}
	})
}

// ============================================================================
// Helpers
// ============================================================================

func generateSmaliContent(lines int) string {
	var sb strings.Builder
	sb.Grow(lines * 60)

	sb.WriteString(".class public Lcom/test/Test;\n")
	sb.WriteString(".super Ljava/lang/Object;\n\n")

	for i := 0; i < lines; i++ {
		switch i % 20 {
		case 0:
			sb.WriteString("const-string v0, \"password123\"\n")
		case 1:
			sb.WriteString("invoke-virtual {p0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)V\n")
		case 2:
			sb.WriteString("const-string v1, \"api_key=secret\"\n")
		case 3:
			sb.WriteString("invoke-static {}, Lcom/google/android/gms/ads/AdRequest;->Builder()V\n")
		case 4:
			sb.WriteString("sget-object v0, Lcom/app/Config;->API_TOKEN:Ljava/lang/String;\n")
		default:
			sb.WriteString(fmt.Sprintf("    .local v%d, var%d:I\n", i%16, i))
		}
	}

	sb.WriteString(".end method\n")
	return sb.String()
}

func generateXMLContent(lines int) string {
	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
	sb.WriteString("<resources>\n")

	for i := 0; i < lines; i++ {
		switch i % 10 {
		case 0:
			sb.WriteString(fmt.Sprintf("    <string name=\"api_key_%d\">secret_value</string>\n", i))
		case 1:
			sb.WriteString(fmt.Sprintf("    <string name=\"password_%d\">hidden</string>\n", i))
		default:
			sb.WriteString(fmt.Sprintf("    <string name=\"text_%d\">Normal text</string>\n", i))
		}
	}

	sb.WriteString("</resources>\n")
	return sb.String()
}

func generateManifestContent() string {
	return `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.app">
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
    
    <application android:name=".App">
        <activity android:name=".MainActivity" />
        <service android:name=".MyAccessibilityService"
            android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService" />
            </intent-filter>
        </service>
    </application>
</manifest>`
}
