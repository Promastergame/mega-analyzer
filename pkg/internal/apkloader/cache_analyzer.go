package apkloader

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CacheAnalyzer performs defensive security analysis on Android app cache.
// It scans for unencrypted configs, API keys, tokens, and weak crypto patterns
// without modifying any files.
type CacheAnalyzer struct {
	TargetPkg string
	CacheDir  string
	Findings  []CacheFinding
	Warnings  []string
}

// CacheFinding describes a security-relevant discovery in cache files.
type CacheFinding struct {
	Path        string `json:"path"`
	Type        string `json:"type"`     // "api_key", "token", "unencrypted_save", "weak_crypto", "tracker_config"
	Severity    string `json:"severity"` // "info" | "medium" | "high" | "critical"
	Description string `json:"description"`
	Snippet     string `json:"snippet,omitempty"`
}

// NewCacheAnalyzer creates a defensive cache scanner.
func NewCacheAnalyzer(pkg, cacheDir string) *CacheAnalyzer {
	return &CacheAnalyzer{
		TargetPkg: pkg,
		CacheDir:  cacheDir,
		Findings:  make([]CacheFinding, 0),
		Warnings:  make([]string, 0),
	}
}

// Scan walks the cache directory and analyzes files for security issues.
func (ca *CacheAnalyzer) Scan() error {
	if ca.CacheDir == "" {
		return fmt.Errorf("no cache directory specified")
	}

	info, err := os.Stat(ca.CacheDir)
	if err != nil {
		return fmt.Errorf("cache dir not found: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cache path is not a directory: %s", ca.CacheDir)
	}

	return filepath.Walk(ca.CacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Skip very large files (> 50 MB)
		if info.Size() > 50<<20 {
			return nil
		}

		rel, _ := filepath.Rel(ca.CacheDir, path)
		lower := strings.ToLower(path)

		// Analyze based on file type
		switch {
		case strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".config"):
			ca.analyzeJSONConfig(path, rel, info.Size())
		case strings.HasSuffix(lower, ".xml"):
			ca.analyzeXMLConfig(path, rel, info.Size())
		case strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".sqlite"):
			ca.analyzeDatabase(path, rel)
		case strings.HasSuffix(lower, ".dat") || strings.HasSuffix(lower, ".save") || strings.HasSuffix(lower, ".bin"):
			ca.analyzeRawData(path, rel, info.Size())
		case strings.HasSuffix(lower, ".log") || strings.HasSuffix(lower, ".txt"):
			ca.analyzeLogFile(path, rel, info.Size())
		}

		return nil
	})
}

func (ca *CacheAnalyzer) analyzeJSONConfig(path, rel string, size int64) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return
	}

	// Check for unencrypted save data patterns
	if strings.Contains(string(data), `"coins"`) || strings.Contains(string(data), `"gems"`) ||
		strings.Contains(string(data), `"gold"`) || strings.Contains(string(data), `"money"`) ||
		strings.Contains(string(data), `"score"`) || strings.Contains(string(data), `"level"`) {
		ca.Findings = append(ca.Findings, CacheFinding{
			Path:        rel,
			Type:        "unencrypted_save",
			Severity:    "medium",
			Description: "Potentially unencrypted game save data detected",
			Snippet:     ca.snippet(data, "coins", "gems", "gold", "money"),
		})
	}

	// Check for API keys / tokens
	tokenPatterns := []string{
		"api_key", "apikey", "api-key", "auth_token", "access_token",
		"bearer", "secret", "password", "private_key",
	}
	for _, pat := range tokenPatterns {
		if strings.Contains(string(data), pat) {
			ca.Findings = append(ca.Findings, CacheFinding{
				Path:        rel,
				Type:        "api_key",
				Severity:    "critical",
				Description: fmt.Sprintf("Potential %s found in unencrypted JSON", pat),
				Snippet:     ca.snippet(data, pat),
			})
			break
		}
	}

	// Check for tracker / ad configs
	trackerPatterns := []string{
		"googleads", "admob", "facebook", "appsflyer", "adjust",
		"tapjoy", "chartboost", "ironsource", "unityads",
	}
	for _, pat := range trackerPatterns {
		if strings.Contains(string(data), pat) {
			ca.Findings = append(ca.Findings, CacheFinding{
				Path:        rel,
				Type:        "tracker_config",
				Severity:    "info",
				Description: fmt.Sprintf("Ad/tracker SDK config: %s", pat),
			})
			break
		}
	}
}

func (ca *CacheAnalyzer) analyzeXMLConfig(path, rel string, size int64) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return
	}
	content := string(data)

	// Check for hardcoded URLs / endpoints
	if strings.Contains(content, "http://") || strings.Contains(content, "https://") {
		ca.Findings = append(ca.Findings, CacheFinding{
			Path:        rel,
			Type:        "api_key",
			Severity:    "medium",
			Description: "Hardcoded URL/endpoint in XML config",
			Snippet:     ca.snippet(data, "http"),
		})
	}
}

func (ca *CacheAnalyzer) analyzeDatabase(path, rel string) {
	// SQLite databases often contain sensitive data
	ca.Findings = append(ca.Findings, CacheFinding{
		Path:        rel,
		Type:        "unencrypted_save",
		Severity:    "medium",
		Description: "SQLite database found — may contain unencrypted user data",
	})
}

func (ca *CacheAnalyzer) analyzeRawData(path, rel string, size int64) {
	// Read first 4 KB for magic/header analysis
	buf := make([]byte, 4096)
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	n, _ := f.Read(buf)
	data := buf[:n]

	// Check for weak crypto / plain text in binary files
	printable := 0
	for _, b := range data {
		if b >= 0x20 && b < 0x7F {
			printable++
		}
	}
	if printable > len(data)*3/4 {
		ca.Findings = append(ca.Findings, CacheFinding{
			Path:        rel,
			Type:        "weak_crypto",
			Severity:    "high",
			Description: "Binary data file is mostly printable text — weak or no encryption",
		})
	}

	// Check for embedded JSON in binary
	if strings.Contains(string(data), "{") && strings.Contains(string(data), "}") {
		if strings.Contains(string(data), `"`) {
			ca.Findings = append(ca.Findings, CacheFinding{
				Path:        rel,
				Type:        "weak_crypto",
				Severity:    "high",
				Description: "Embedded JSON detected inside binary data file — possible unencrypted save",
			})
		}
	}
}

func (ca *CacheAnalyzer) analyzeLogFile(path, rel string, size int64) {
	if size > 1<<20 { // Skip logs > 1 MB
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	// Check for leaked tokens / credentials in logs
	if strings.Contains(content, "token") || strings.Contains(content, "secret") ||
		strings.Contains(content, "password") || strings.Contains(content, "api_key") {
		ca.Findings = append(ca.Findings, CacheFinding{
			Path:        rel,
			Type:        "api_key",
			Severity:    "critical",
			Description: "Potential credentials leaked in log file",
			Snippet:     ca.snippet(data, "token", "secret", "password", "api_key"),
		})
	}
}

func (ca *CacheAnalyzer) snippet(data []byte, keywords ...string) string {
	content := string(data)
	for _, kw := range keywords {
		idx := strings.Index(strings.ToLower(content), kw)
		if idx >= 0 {
			start := idx - 30
			if start < 0 {
				start = 0
			}
			end := idx + len(kw) + 30
			if end > len(content) {
				end = len(content)
			}
			return content[start:end]
		}
	}
	return ""
}

// WriteReport saves findings to CACHE_ANALYSIS.json.
func (ca *CacheAnalyzer) WriteReport(outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}
	path := filepath.Join(outputDir, "CACHE_ANALYSIS.json")
	data, err := json.MarshalIndent(struct {
		Package  string         `json:"package"`
		CacheDir string         `json:"cacheDir"`
		Findings []CacheFinding `json:"findings"`
		Warnings []string       `json:"warnings,omitempty"`
	}{
		Package:  ca.TargetPkg,
		CacheDir: ca.CacheDir,
		Findings: ca.Findings,
		Warnings: ca.Warnings,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
