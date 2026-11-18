package pipeline

import (
	"strings"

	"mega-analyzer/pkg/internal/rules"
	"mega-analyzer/pkg/internal/types"
)

// Prove a same-block raw value flowing to a credential preference key.
// A method/field containing "password" plus any putString in the class is
// insufficient. Unknown calls, branches and transformed values lose provenance.
func plaintextCredentialWriteWitness(method *types.SmaliMethod, path, class string) (rules.EvidenceSource, bool) {
	literals := map[string]string{}
	rawValues := map[string]string{}
	pending := ""
	for index, raw := range method.Body {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ".") {
			continue
		}
		if strings.HasPrefix(line, ":") || strings.HasPrefix(line, "if-") || strings.HasPrefix(line, "goto") || strings.Contains(line, "switch ") || strings.HasPrefix(line, "return") || strings.HasPrefix(line, "throw") {
			clear(literals)
			clear(rawValues)
			pending = ""
			continue
		}
		if strings.HasPrefix(line, "invoke-") {
			call, ok := parseCryptoInvoke(line)
			if !ok {
				clear(rawValues)
				pending = ""
				continue
			}
			pending = ""
			regs := call.registers
			switch {
			case call.classDesc == "Landroid/content/SharedPreferences$Editor;" && call.method == "putString" && len(regs) == 3:
				if credentialPreferenceKey(literals[regs[1]]) && rawValues[regs[2]] != "" {
					return rules.EvidenceSource{File: path, Line: method.LineStart + index, Class: class, Method: method.Name, Snippet: rawValues[regs[2]] + "\n" + line}, true
				}
			case (call.classDesc == "Landroid/widget/EditText;" || call.classDesc == "Landroid/widget/TextView;") && call.method == "getText":
				pending = line
			case call.classDesc == "Landroid/content/Intent;" && call.method == "getStringExtra":
				pending = line
			case call.method == "toString" && len(regs) == 1:
				pending = rawValues[regs[0]]
			default:
				for _, reg := range regs {
					delete(rawValues, reg)
				}
			}
			continue
		}
		dest := parseDestRegister(line)
		if dest == "" {
			pending = ""
			continue
		}
		if strings.HasPrefix(line, "move-result-object ") {
			delete(literals, dest)
			rawValues[dest], pending = pending, ""
			continue
		}
		pending = ""
		if strings.HasPrefix(line, "move-object") {
			fields := strings.Fields(strings.ReplaceAll(line, ",", " "))
			if len(fields) >= 3 {
				literals[dest], rawValues[dest] = literals[fields[2]], rawValues[fields[2]]
				continue
			}
		}
		delete(literals, dest)
		delete(rawValues, dest)
		if strings.HasPrefix(line, "const-string") {
			first, last := strings.IndexByte(line, '"'), strings.LastIndexByte(line, '"')
			if last > first && first >= 0 {
				literals[dest] = line[first+1 : last]
				if literals[dest] != "" {
					rawValues[dest] = line
				}
			}
		}
	}
	return rules.EvidenceSource{}, false
}

func credentialPreferenceKey(key string) bool {
	switch strings.ToLower(key) {
	case "password", "passwd", "pwd", "pin", "token", "access_token", "refresh_token", "auth_token", "api_key", "secret":
		return true
	}
	return false
}
