package minecraft

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"path"
	"regexp"
	"strings"
)

var scriptIndicators = []struct {
	id, severity, title string
	pattern             *regexp.Regexp
}{
	{"script-eval", "medium", "Dynamic script evaluation", regexp.MustCompile(`\b(?:eval|Function)\s*\(`)},
	{"shell-command", "high", "Shell command text", regexp.MustCompile(`(?i)\b(?:powershell(?:\.exe)?|cmd\.exe)\s+(?:-|/)`)},
	{"script-process", "high", "Process execution reference", regexp.MustCompile(`\b(?:child_process|execSync|spawnSync)\b`)},
	{"bedrock-http", "info", "Bedrock networking module", regexp.MustCompile(`@minecraft/server-net\b`)},
	{"bedrock-admin", "medium", "Bedrock administration module", regexp.MustCompile(`@minecraft/server-admin\b`)},
	{"credential-reference", "medium", "Launcher credential path reference", regexp.MustCompile(`(?i)(?:launcher_accounts\.json|launcher_msa_credentials\.bin|Login Data)`)},
	{"webhook-reference", "medium", "Discord webhook reference", regexp.MustCompile(`(?i)discord(?:app)?\.com/api/webhooks/`)},
}

func (s *scanner) inspect(name, local string, data []byte, stat *FileStat) {
	base := path.Base(local)
	switch base {
	case "pack.mcmeta":
		s.parsePackMeta(name, data)
	case "manifest.json":
		s.parseManifest(name, data)
	}
	ext := strings.ToLower(path.Ext(local))
	// Detect executable signatures concealed behind asset extensions.
	if len(data) >= 4 && (bytes.HasPrefix(data, []byte{'M', 'Z'}) || bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'})) && ext != ".exe" && ext != ".dll" && ext != ".so" {
		s.add("disguised-executable", "high", "Executable signature in an unexpected file", ext+" file starts with PE/ELF signature (heuristic)", name, "Inspect the payload with the binary analyzer before importing")
	}
	if ext == ".class" {
		// Java bytecode belongs to the JAR analyzer (pkg/internal/jarloader),
		// not to the Bedrock pack scanner.
		s.skip("java-bytecode", name, "Java class files are analyzed by the JAR analyzer, not the Bedrock pack scanner")
		return
	}
	switch ext {
	case ".png", ".jpg", ".jpeg":
		cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			s.skip("invalid-texture", name, err.Error())
			return
		}
		stat.Width, stat.Height = cfg.Width, cfg.Height
		if cfg.Width > 8192 || cfg.Height > 8192 {
			s.add("large-texture", "medium", "Large texture memory footprint", fmt.Sprintf("%dx%d pixels; approximately %.1f MiB RGBA before mipmaps", cfg.Width, cfg.Height, float64(cfg.Width)*float64(cfg.Height)*4/(1<<20)), name, "Reduce texture resolution or document memory requirements")
		}
	case ".exe", ".dll", ".so", ".dylib":
		s.add("native-payload", "medium", "Embedded native executable", ext+" payload", name, "Verify whether the mod needs this platform-specific binary")
	case ".ps1", ".bat", ".cmd", ".sh":
		s.add("shell-script", "medium", "Embedded operating-system script", ext+" script", name, "Review script contents before running any bundled installer")
		s.inspectStrings(name, string(data), true)
	case ".js", ".mjs", ".cjs":
		s.inspectStrings(name, string(data), true)
	case ".mcfunction":
		// Parse command boundaries, not arbitrary chat text containing "run op".
		for _, line := range strings.Split(string(data), "\n") {
			if command := privilegedCommand(line); command != "" {
				s.add("privileged-game-command", "medium", "Privileged game command", command+" command in function", name, "Review effects on players and server administration")
			}
		}
	case ".json", ".mcmeta":
		// JSONC is accepted for Bedrock content. Values are never evaluated.
		if !json.Valid(jsonComments(data)) {
			s.skip("invalid-json", name, "Malformed JSON/JSONC document")
		}
	}

}
func (s *scanner) inspectStrings(name, text string, script bool) {
	for _, rule := range scriptIndicators {
		if !script && (rule.id == "script-eval" || rule.id == "script-process" || strings.HasPrefix(rule.id, "bedrock-")) {
			continue
		}
		if rule.pattern.MatchString(text) {
			s.add(rule.id, rule.severity, rule.title, "Static text indicator; may occur in comments or unused constants", name, "Review surrounding code; the indicator alone does not prove malicious behavior")
		}
	}
}

// Strip comments only outside JSON strings, preserving newlines for errors.
func jsonComments(b []byte) []byte {
	b = bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf})
	out := append([]byte(nil), b...)
	quoted, escape := false, false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if quoted {
			if escape {
				escape = false
			} else if c == '\\' {
				escape = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
			continue
		}
		if c != '/' || i+1 >= len(out) {
			continue
		}
		if out[i+1] == '/' {
			out[i] = ' '
			i++
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		} else if out[i+1] == '*' {
			out[i] = ' '
			out[i+1] = ' '
			i += 2
			closed := false
			for i < len(out) {
				if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
					out[i] = ' '
					out[i+1] = ' '
					i++
					closed = true
					break
				}
				if out[i] != '\n' && out[i] != '\r' {
					out[i] = ' '
				}
				i++
			}
			if !closed {
				return b
			}
		}
	}
	return out
}
