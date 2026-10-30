package vulnscan

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// sensitiveProbe represents a file/path to probe along with detection criteria
type sensitiveProbe struct {
	path       string
	id         string
	name       string
	severity   Severity
	detectFunc func(statusCode int, body string, headers http.Header) (bool, string)
}

var defaultSensitiveProbes = []sensitiveProbe{
	// ── Environment files ────────────────────────────────────────────────────
	{
		path:     "/.env",
		id:       "WS-SENS-001",
		name:     "Exposed .env File",
		severity: SeverityCritical,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && (strings.Contains(body, "APP_") || strings.Contains(body, "DB_") ||
				strings.Contains(body, "SECRET") || strings.Contains(body, "KEY=") ||
				strings.Contains(body, "PASSWORD=") || strings.Contains(body, "TOKEN=")) {
				return true, "Environment variable definitions found in response body"
			}
			return false, ""
		},
	},
	{
		path:     "/.env.local",
		id:       "WS-SENS-001",
		name:     "Exposed .env.local File",
		severity: SeverityCritical,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			return code == 200 && len(body) > 5, "File returned 200 OK with content"
		},
	},
	{
		path:     "/.env.production",
		id:       "WS-SENS-001",
		name:     "Exposed .env.production File",
		severity: SeverityCritical,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			return code == 200 && len(body) > 5, "File returned 200 OK with content"
		},
	},

	// ── Git repository ───────────────────────────────────────────────────────
	{
		path:     "/.git/HEAD",
		id:       "WS-SENS-002",
		name:     "Exposed .git Directory (HEAD)",
		severity: SeverityCritical,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && strings.HasPrefix(strings.TrimSpace(body), "ref:") {
				return true, fmt.Sprintf("Git HEAD: %s", strings.TrimSpace(body))
			}
			return false, ""
		},
	},
	{
		path:     "/.git/config",
		id:       "WS-SENS-002",
		name:     "Exposed .git/config",
		severity: SeverityCritical,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && strings.Contains(body, "[core]") {
				return true, "Git config file exposed — may contain remote URLs and credentials"
			}
			return false, ""
		},
	},

	// ── Admin panels ─────────────────────────────────────────────────────────
	{
		path:     "/admin",
		id:       "WS-SENS-003",
		name:     "Accessible Admin Panel",
		severity: SeverityHigh,
		detectFunc: func(code int, _ string, _ http.Header) (bool, string) {
			return code == 200 || code == 301 || code == 302,
				fmt.Sprintf("Admin path responded with HTTP %d", code)
		},
	},
	{
		path:     "/admin/",
		id:       "WS-SENS-003",
		name:     "Accessible Admin Panel",
		severity: SeverityHigh,
		detectFunc: func(code int, _ string, _ http.Header) (bool, string) {
			return code == 200 || code == 301 || code == 302,
				fmt.Sprintf("Admin path responded with HTTP %d", code)
		},
	},
	{
		path:     "/wp-admin/",
		id:       "WS-SENS-003",
		name:     "WordPress Admin Panel Exposed",
		severity: SeverityHigh,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && strings.Contains(body, "wp-login") {
				return true, "WordPress login page is publicly accessible"
			}
			return false, ""
		},
	},

	// ── Backup / dump files ──────────────────────────────────────────────────
	{
		path:     "/backup.zip",
		id:       "WS-SENS-004",
		name:     "Exposed Backup Archive",
		severity: SeverityCritical,
		detectFunc: func(code int, _ string, headers http.Header) (bool, string) {
			ct := headers.Get("Content-Type")
			return code == 200 && (strings.Contains(ct, "zip") || strings.Contains(ct, "octet-stream")),
				fmt.Sprintf("Archive file accessible — Content-Type: %s", ct)
		},
	},
	{
		path:     "/backup.tar.gz",
		id:       "WS-SENS-004",
		name:     "Exposed Backup Archive (.tar.gz)",
		severity: SeverityCritical,
		detectFunc: func(code int, _ string, headers http.Header) (bool, string) {
			ct := headers.Get("Content-Type")
			return code == 200 && (strings.Contains(ct, "gzip") || strings.Contains(ct, "octet-stream")),
				fmt.Sprintf("Archive file accessible — Content-Type: %s", ct)
		},
	},
	{
		path:     "/dump.sql",
		id:       "WS-SENS-004",
		name:     "Exposed SQL Dump File",
		severity: SeverityCritical,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && (strings.Contains(body, "CREATE TABLE") || strings.Contains(body, "INSERT INTO")) {
				return true, "SQL dump file with schema/data statements found"
			}
			return false, ""
		},
	},
	{
		path:     "/db.sql",
		id:       "WS-SENS-004",
		name:     "Exposed SQL Dump File (db.sql)",
		severity: SeverityCritical,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && (strings.Contains(body, "CREATE TABLE") || strings.Contains(body, "INSERT INTO")) {
				return true, "SQL dump file found"
			}
			return false, ""
		},
	},

	// ── Debug / diagnostic endpoints ─────────────────────────────────────────
	{
		path:     "/phpinfo.php",
		id:       "WS-SENS-005",
		name:     "PHP Info Page Exposed",
		severity: SeverityHigh,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && strings.Contains(body, "PHP Version") {
				return true, "phpinfo() output is publicly accessible — exposes server configuration"
			}
			return false, ""
		},
	},
	{
		path:     "/server-status",
		id:       "WS-SENS-005",
		name:     "Apache Server Status Exposed",
		severity: SeverityMedium,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && strings.Contains(body, "Apache") {
				return true, "Apache mod_status page is publicly accessible"
			}
			return false, ""
		},
	},
	{
		path:     "/server-info",
		id:       "WS-SENS-005",
		name:     "Apache Server Info Exposed",
		severity: SeverityMedium,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && strings.Contains(body, "Apache") {
				return true, "Apache mod_info page is publicly accessible"
			}
			return false, ""
		},
	},

	// ── API / GraphQL ─────────────────────────────────────────────────────────
	{
		path:     "/graphql?query={__schema{types{name}}}",
		id:       "WS-SENS-006",
		name:     "GraphQL Introspection Enabled",
		severity: SeverityMedium,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && strings.Contains(body, "__schema") {
				return true, "GraphQL introspection is enabled — schema is exposed"
			}
			return false, ""
		},
	},

	// ── Spring Boot Actuator ─────────────────────────────────────────────────
	{
		path:     "/actuator",
		id:       "WS-SENS-007",
		name:     "Spring Boot Actuator Exposed",
		severity: SeverityHigh,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && strings.Contains(body, "_links") {
				return true, "Spring Boot Actuator root endpoint is publicly accessible"
			}
			return false, ""
		},
	},
	{
		path:     "/actuator/env",
		id:       "WS-SENS-007",
		name:     "Spring Boot Actuator /env Exposed",
		severity: SeverityCritical,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && (strings.Contains(body, "propertySources") || strings.Contains(body, "systemProperties")) {
				return true, "Actuator /env exposes environment variables and application properties"
			}
			return false, ""
		},
	},
	{
		path:     "/actuator/health",
		id:       "WS-SENS-007",
		name:     "Spring Boot Actuator /health Exposed",
		severity: SeverityLow,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && strings.Contains(body, "status") {
				return true, "Actuator /health endpoint leaks service health information"
			}
			return false, ""
		},
	},

	// ── Miscellaneous ────────────────────────────────────────────────────────
	{
		path:     "/.DS_Store",
		id:       "WS-SENS-008",
		name:     "Exposed .DS_Store File",
		severity: SeverityLow,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			// .DS_Store has a specific binary magic bytes: "Bud1"
			return code == 200 && strings.Contains(body, "Bud1"),
				"macOS .DS_Store file exposed — leaks directory listing"
		},
	},
	{
		path:     "/crossdomain.xml",
		id:       "WS-SENS-009",
		name:     "Permissive crossdomain.xml",
		severity: SeverityMedium,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code == 200 && strings.Contains(body, "allow-access-from") && strings.Contains(body, `domain="*"`) {
				return true, "crossdomain.xml allows access from any domain"
			}
			return false, ""
		},
	},
	{
		path:     "/robots.txt",
		id:       "WS-SENS-010",
		name:     "robots.txt Discloses Sensitive Paths",
		severity: SeverityInfo,
		detectFunc: func(code int, body string, _ http.Header) (bool, string) {
			if code != 200 {
				return false, ""
			}
			var sensitive []string
			for _, line := range strings.Split(body, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToLower(line), "disallow:") {
					path := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "disallow:"))
					if path != "" && path != "/" {
						sensitive = append(sensitive, path)
					}
				}
			}
			if len(sensitive) > 0 {
				return true, fmt.Sprintf("Disallowed paths: %s", strings.Join(sensitive, ", "))
			}
			return false, ""
		},
	},
}

// probeSensitiveFiles probes common sensitive paths on the target.
func (s *Scanner) probeSensitiveFiles() []Vulnerability {
	var list []Vulnerability
	seen := make(map[string]bool) // deduplicate by finding ID + path category

	for _, probe := range defaultSensitiveProbes {
		probeURL := strings.TrimRight(s.Target, "/") + probe.path

		req, err := http.NewRequest("GET", probeURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", s.Config.UserAgent)

		resp, err := s.Client.Do(req)

		if err != nil {
			continue
		}

		// Read limited body to avoid OOM on large responses
		limitedReader := io.LimitReader(resp.Body, 64*1024) // 64 KB limit
		bodyBytes, readErr := io.ReadAll(limitedReader)
		resp.Body.Close()

		if readErr != nil {
			continue
		}

		body := string(bodyBytes)
		triggered, evidence := probe.detectFunc(resp.StatusCode, body, resp.Header)

		if triggered {
			dedupeKey := probe.id + "|" + probe.path
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true

			list = append(list, Vulnerability{
				ID:          probe.id,
				Name:        probe.name,
				Description: fmt.Sprintf("A sensitive file or endpoint at '%s' is publicly accessible and may disclose confidential information.", probe.path),
				Severity:    probe.severity,
				URL:         probeURL,
				Evidence:    evidence,
				Mitigation:  "Restrict access to sensitive paths via server configuration (deny rules, authentication). Remove or relocate backup and debug files from web-accessible directories.",
			})

			s.log("[!] Sensitive file found: %s → %s\n", probeURL, evidence)
		}
	}

	return list
}
