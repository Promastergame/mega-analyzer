package insights

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CarvedVolume represents a carved filesystem block from raw firmware binaries
type CarvedVolume struct {
	Type   string
	Offset int
	Size   int
	Data   []byte
}

func AnalyzeFirmware(target string) (*FirmwareReport, error) {
	files, err := LoadFiles(target, LoadOptions{MaxBytesPerFile: 16 << 20, IncludeBinary: true})
	if err != nil {
		return nil, err
	}
	report := &FirmwareReport{GeneratedAt: time.Now(), Target: target, Kind: classifyFirmwareKind(target), FileCount: len(files)}
	rootHints := map[string]struct{}{}
	for _, f := range files {
		lowerPath := strings.ToLower(filepath.ToSlash(f.Path))
		lowerData := bytes.ToLower(f.Data)
		if isRootFSPath(lowerPath) {
			rootHints[rootHintName(lowerPath)] = struct{}{}
		}
		scanFirmwareServices(report, f, lowerPath, lowerData)
		scanFirmwareWeb(report, f, lowerPath, lowerData)
		scanFirmwareSecrets(report, f, lowerPath, lowerData)
		scanFirmwarePackages(report, f, lowerPath, lowerData)

		// Carve embedded filesystems if it is a raw binary or large binary file
		if classifyFirmwareKind(f.Path) == "raw-binary" || len(f.Data) > 500000 {
			volumes := carveEmbeddedFileSystems(f.Data)
			for _, vol := range volumes {
				rootHints[vol.Type] = struct{}{}

				// Run custom scans on the carved volume data
				lowerVolData := bytes.ToLower(vol.Data)

				// 1. Passwd / root account
				if bytes.Contains(lowerVolData, []byte("root:")) {
					report.Secrets = append(report.Secrets, FirmwareItem{
						Name:     "carved fs root account entry",
						Path:     f.Path,
						Severity: "critical",
						Detail:   fmt.Sprintf("Found root account signature in carved %s volume at offset %d", vol.Type, vol.Offset),
					})
				}

				// 2. Private keys
				if bytes.Contains(lowerVolData, []byte("begin private key")) || bytes.Contains(lowerVolData, []byte("begin rsa private key")) {
					report.Secrets = append(report.Secrets, FirmwareItem{
						Name:     "carved fs private key material",
						Path:     f.Path,
						Severity: "critical",
						Detail:   fmt.Sprintf("Found private key material in carved %s volume at offset %d", vol.Type, vol.Offset),
					})
				}

				// 3. Busybox or common init/binaries
				if bytes.Contains(lowerVolData, []byte("busybox v")) || bytes.Contains(lowerVolData, []byte("/bin/busybox")) {
					report.Packages = append(report.Packages, FirmwareItem{
						Name:     fmt.Sprintf("BusyBox (%s)", vol.Type),
						Path:     f.Path,
						Severity: "medium",
						Detail:   fmt.Sprintf("Found BusyBox signature in carved volume at offset %d", vol.Offset),
					})
				}

				// 4. Default Credentials / configuration service
				credTokens := [][]byte{[]byte("admin:admin"), []byte("admin:password"), []byte("root:root")}
				for _, token := range credTokens {
					if bytes.Contains(lowerVolData, token) {
						report.Services = append(report.Services, FirmwareItem{
							Name:     "default credential risk",
							Path:     f.Path,
							Severity: "critical",
							Detail:   fmt.Sprintf("Found default credential '%s' in carved %s volume at offset %d", string(token), vol.Type, vol.Offset),
						})
					}
				}
			}
		}
	}
	for h := range rootHints {
		report.RootFSHints = append(report.RootFSHints, h)
	}
	sort.Strings(report.RootFSHints)
	report.Score, report.Risk = scoreFirmware(report)
	report.Findings = buildFirmwareFindings(report)
	return report, nil
}

func classifyFirmwareKind(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return "zip-firmware"
	case strings.HasSuffix(lower, ".tar"), strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "tar-firmware"
	case strings.HasSuffix(lower, ".img"):
		return "disk-image"
	case strings.HasSuffix(lower, ".bin"):
		return "raw-binary"
	default:
		return "directory-or-blob"
	}
}

func isRootFSPath(path string) bool {
	return strings.Contains(path, "/etc/passwd") || strings.HasSuffix(path, "etc/passwd") ||
		strings.Contains(path, "/bin/busybox") || strings.Contains(path, "/sbin/init") ||
		strings.Contains(path, "/etc/init.d/") || strings.Contains(path, "/www/") || strings.Contains(path, "/usr/www/")
}

func rootHintName(path string) string {
	switch {
	case strings.Contains(path, "etc/passwd"):
		return "linux /etc/passwd"
	case strings.Contains(path, "busybox"):
		return "busybox userland"
	case strings.Contains(path, "init.d") || strings.Contains(path, "/sbin/init"):
		return "init scripts"
	case strings.Contains(path, "/www/") || strings.Contains(path, "/usr/www/"):
		return "embedded web root"
	default:
		return path
	}
}

func scanFirmwareServices(report *FirmwareReport, f ScannedFile, lowerPath string, lowerData []byte) {
	serviceTokens := []struct{ token, name, severity string }{
		{"telnetd", "telnet daemon", "high"}, {"/usr/sbin/telnet", "telnet service", "high"},
		{"dropbear", "dropbear ssh", "medium"}, {"/usr/sbin/sshd", "ssh service", "medium"},
		{"ftpd", "ftp daemon", "medium"}, {"tftp", "tftp service", "medium"},
		{"upnpd", "upnp daemon", "medium"}, {"dnsmasq", "dnsmasq", "low"},
	}
	for _, t := range serviceTokens {
		idx := bytes.Index(lowerData, []byte(t.token))
		if idx < 0 && !strings.Contains(lowerPath, t.token) {
			continue
		}
		ln := lineNumber(f.Data, idx)
		report.Services = append(report.Services, FirmwareItem{Name: t.name, Path: f.Path, Line: ln, Severity: t.severity, Detail: redactedFirmwareLine(f.Data, ln)})
	}
}

func scanFirmwareWeb(report *FirmwareReport, f ScannedFile, lowerPath string, lowerData []byte) {
	if !(strings.Contains(lowerPath, "/www/") || strings.Contains(lowerPath, "/usr/www/") || strings.Contains(lowerPath, "/htdocs/") || strings.Contains(lowerPath, "/cgi-bin/")) {
		return
	}
	if strings.HasSuffix(lowerPath, ".cgi") || strings.HasSuffix(lowerPath, ".php") || strings.HasSuffix(lowerPath, ".lua") || strings.HasSuffix(lowerPath, ".asp") || bytes.Contains(lowerData, []byte("cgi-bin")) {
		sev := "medium"
		if bytes.Contains(lowerData, []byte("system(")) || bytes.Contains(lowerData, []byte("eval(")) || bytes.Contains(lowerData, []byte("password")) {
			sev = "high"
		}
		report.WebPanels = append(report.WebPanels, FirmwareItem{Name: "embedded web handler", Path: f.Path, Severity: sev, Detail: filepath.Ext(lowerPath)})
	}
}

func scanFirmwareSecrets(report *FirmwareReport, f ScannedFile, lowerPath string, lowerData []byte) {
	if strings.Contains(lowerPath, "id_rsa") || strings.Contains(lowerPath, "dropbear") && strings.Contains(lowerPath, "key") || bytes.Contains(lowerData, []byte("begin private key")) || bytes.Contains(lowerData, []byte("begin rsa private key")) {
		report.Secrets = append(report.Secrets, FirmwareItem{Name: "private key material present", Path: f.Path, Severity: "critical", Detail: "value redacted"})
	}
	if strings.Contains(lowerPath, "etc/passwd") && bytes.Contains(lowerData, []byte("root:")) {
		sev := "medium"
		if bytes.Contains(lowerData, []byte("root:$")) || bytes.Contains(lowerData, []byte("root:!")) || bytes.Contains(lowerData, []byte("root:x:")) {
			sev = "low"
		}
		report.Secrets = append(report.Secrets, FirmwareItem{Name: "passwd root account entry", Path: f.Path, Severity: sev, Detail: "hash/value redacted"})
	}
	secretKinds := detectSecretKinds(f.Data)
	for _, kind := range secretKinds {
		report.Secrets = append(report.Secrets, FirmwareItem{Name: kind, Path: f.Path, Severity: "medium", Detail: "value redacted"})
	}
}

func scanFirmwarePackages(report *FirmwareReport, f ScannedFile, lowerPath string, lowerData []byte) {
	// Image metadata and DEX string pools are not installed-package evidence.
	if !bytes.HasPrefix(f.Data, []byte{0x7f, 'E', 'L', 'F'}) {
		switch strings.ToLower(filepath.Ext(lowerPath)) {
		case ".dex", ".svg", ".png", ".jpg", ".jpeg", ".webp":
			return
		}
	}
	if strings.Contains(lowerPath, "busybox") || bytes.Contains(lowerData, []byte("busybox v")) {
		version := extractBusyBoxVersion(string(f.Data))
		sev := "low"
		if strings.HasPrefix(version, "1.1") || strings.HasPrefix(version, "1.2") || strings.HasPrefix(version, "1.3") {
			sev = "medium"
		}
		report.Packages = append(report.Packages, FirmwareItem{Name: "BusyBox", Path: f.Path, Severity: sev, Detail: version})
	}
	for _, token := range []string{"openssl", "uhttpd", "lighttpd", "boa", "mini_httpd"} {
		if containsFirmwareToken([]byte(filepath.Base(lowerPath)), token) || containsFirmwareToken(lowerData, token) {
			report.Packages = append(report.Packages, FirmwareItem{Name: token, Path: f.Path, Severity: "low"})
		}
	}
}

func containsFirmwareToken(data []byte, token string) bool {
	word := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '+' || c == '/'
	}
	for offset := 0; offset < len(data); {
		rel := bytes.Index(data[offset:], []byte(token))
		if rel < 0 {
			return false
		}
		idx := offset + rel
		end := idx + len(token)
		if (idx == 0 || !word(data[idx-1])) && (end == len(data) || !word(data[end])) {
			return true
		}
		offset = end
	}
	return false
}

func extractBusyBoxVersion(s string) string {
	lower := strings.ToLower(s)
	idx := strings.Index(lower, "busybox v")
	if idx < 0 {
		return "version unknown"
	}
	end := idx + 40
	if end > len(s) {
		end = len(s)
	}
	return strings.TrimSpace(s[idx:end])
}

func redactedFirmwareLine(data []byte, line int) string {
	s := lineAt(data, line)
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "password") || strings.Contains(lower, "passwd") || strings.Contains(lower, "key") || strings.Contains(lower, "secret") {
		return "redacted sensitive line"
	}
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}

func scoreFirmware(report *FirmwareReport) (int, string) {
	score := len(report.RootFSHints) * 5
	for _, s := range report.Services {
		score += firmwareSeverityPoints(s.Severity)
	}
	for _, w := range report.WebPanels {
		score += firmwareSeverityPoints(w.Severity)
	}
	for _, sec := range report.Secrets {
		score += firmwareSeverityPoints(sec.Severity)
	}
	if score > 100 {
		score = 100
	}
	risk := "low"
	if score >= 70 {
		risk = "high"
	} else if score >= 35 {
		risk = "medium"
	}
	return score, risk
}

func firmwareSeverityPoints(sev string) int {
	switch sev {
	case "critical":
		return 30
	case "high":
		return 18
	case "medium":
		return 9
	default:
		return 3
	}
}

func buildFirmwareFindings(report *FirmwareReport) []Finding {
	var out []Finding
	for _, sec := range report.Secrets {
		out = append(out, Finding{Severity: sec.Severity, Category: "firmware", Path: sec.Path, Line: sec.Line, Title: sec.Name, Detail: sec.Detail})
	}
	for _, svc := range report.Services {
		if svc.Severity == "high" || svc.Severity == "critical" {
			out = append(out, Finding{Severity: svc.Severity, Category: "firmware", Path: svc.Path, Line: svc.Line, Title: svc.Name, Detail: svc.Detail})
		}
	}
	return out
}

func carveEmbeddedFileSystems(data []byte) []CarvedVolume {
	var volumes []CarvedVolume

	magics := []struct {
		name  string
		bytes []byte
	}{
		{"SquashFS (hsqs)", []byte{'h', 's', 'q', 's'}},
		{"SquashFS (qshs)", []byte{'q', 's', 'h', 's'}},
		{"SquashFS (shsq)", []byte{'s', 'h', 's', 'q'}},
		{"CramFS (LE)", []byte{0x45, 0x3d, 0xcd, 0x28}},
		{"CramFS (BE)", []byte{0x28, 0xcd, 0x3d, 0x45}},
		{"UBIFS (LE)", []byte{0x31, 0x18, 0x10, 0x06}},
		{"UBIFS (BE)", []byte{0x06, 0x10, 0x18, 0x31}},
	}

	for _, m := range magics {
		offset := 0
		for {
			idx := bytes.Index(data[offset:], m.bytes)
			if idx < 0 {
				break
			}
			absoluteOffset := offset + idx

			carvedLen := len(data) - absoluteOffset
			if carvedLen > 8<<20 { // max 8MB
				carvedLen = 8 << 20
			}

			if carvedLen > 0 {
				volumes = append(volumes, CarvedVolume{
					Type:   m.name,
					Offset: absoluteOffset,
					Size:   carvedLen,
					Data:   data[absoluteOffset : absoluteOffset+carvedLen],
				})
			}

			offset = absoluteOffset + len(m.bytes)
			if offset >= len(data) {
				break
			}
		}
	}

	return volumes
}
