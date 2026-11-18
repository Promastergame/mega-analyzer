package pipeline

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/rules"
	"mega-analyzer/pkg/internal/types"
)

// This is deliberately a bounded same-block proof. Merely declaring storage
// permissions or using Cipher/SecretKeySpec (including config decryption) does
// not establish encryption of file data. Unsupported branches/calls invalidate
// provenance rather than joining unrelated operations into a ransomware claim.
func fileEncryptionWitness(method *types.SmaliMethod, path, class string) (rules.EvidenceSource, bool) {
	ints := make(map[string]int64)
	inputs := make(map[string]string)
	encrypted := make(map[string]string)
	modes := make(map[string]bool)
	initSites := make(map[string]string)
	pending := ""
	resetProvenance := func() {
		clear(ints)
		clear(inputs)
		clear(encrypted)
		clear(modes)
		clear(initSites)
		pending = ""
	}
	for index, raw := range method.Body {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, ":") || strings.HasPrefix(line, "if-") || strings.HasPrefix(line, "goto") || strings.Contains(line, "switch ") || strings.HasPrefix(line, "return") || strings.HasPrefix(line, "throw") {
			resetProvenance()
			continue
		}
		if strings.HasPrefix(line, ".") {
			continue
		}
		lineNumber := method.LineStart + index
		site := fmt.Sprintf("%d: %s", lineNumber, line)
		if strings.HasPrefix(line, "invoke-") {
			pending = ""
			call, ok := parseCryptoInvoke(line)
			if !ok {
				resetProvenance()
				continue
			}
			regs := call.registers
			switch {
			case call.classDesc == "Ljavax/crypto/Cipher;" && call.method == "init" && len(regs) >= 2:
				mode, known := ints[regs[1]]
				modes[regs[0]] = known && mode == 1
				initSites[regs[0]] = site
			case call.classDesc == "Ljava/io/FileInputStream;" && call.method == "read" && len(regs) >= 2 && strings.Contains(call.raw, "read([B"):
				inputs[regs[1]] = site
				delete(encrypted, regs[1])
			case call.classDesc == "Ljavax/crypto/Cipher;" && call.method == "doFinal" && len(regs) >= 2 && strings.Contains(call.raw, "doFinal([B)[B"):
				if modes[regs[0]] && inputs[regs[1]] != "" {
					pending = strings.Join([]string{inputs[regs[1]], initSites[regs[0]], site}, "\n")
				}
			case call.classDesc == "Ljava/io/FileOutputStream;" && call.method == "write" && len(regs) >= 2 && strings.Contains(call.raw, "write([B"):
				if proof := encrypted[regs[1]]; proof != "" {
					return rules.EvidenceSource{File: path, Line: lineNumber, Class: class, Method: method.Name, Snippet: proof + "\n" + site}, true
				}
			default:
				for _, reg := range regs {
					delete(inputs, reg)
					delete(encrypted, reg)
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
			delete(ints, dest)
			delete(inputs, dest)
			delete(modes, dest)
			delete(initSites, dest)
			encrypted[dest], pending = pending, ""
			continue
		}
		pending = ""
		if strings.HasPrefix(line, "move-object") {
			parts := strings.Fields(strings.ReplaceAll(line, ",", " "))
			if len(parts) >= 3 {
				src := parts[2]
				inputs[dest], encrypted[dest], modes[dest], initSites[dest] = inputs[src], encrypted[src], modes[src], initSites[src]
				delete(ints, dest)
				continue
			}
		}
		delete(inputs, dest)
		delete(encrypted, dest)
		delete(modes, dest)
		delete(initSites, dest)
		delete(ints, dest)
		if strings.HasPrefix(line, "const") && !strings.HasPrefix(line, "const-string") && !strings.HasPrefix(line, "const-wide") {
			if value, ok := parseSmaliIntOperand(line); ok {
				ints[dest] = value
			}
		} else if strings.HasPrefix(line, "sget ") && strings.Contains(line, "Ljavax/crypto/Cipher;->ENCRYPT_MODE:I") {
			ints[dest] = 1
		}
	}
	return rules.EvidenceSource{}, false
}
