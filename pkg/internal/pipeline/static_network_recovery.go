package pipeline

import (
	"math/bits"
	"net"
	"net/url"
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/networkrefs"
	"mega-analyzer/pkg/internal/types"
)

type staticByteArray struct {
	method string
	label  string
	data   []byte
}

type staticNetworkValue struct {
	value string
	proof string
}

// recoverStaticNetworkConstants evaluates bounded, recognized byte transforms.
// It never calls sample methods; only validated network constants are admitted.
func recoverStaticNetworkConstants(class *types.SmaliClass) []staticNetworkValue {
	if class == nil {
		return nil
	}
	arrays := staticByteArrays(class)
	if len(arrays) == 0 {
		return nil
	}
	var body strings.Builder
	constants := make(map[uint32]bool)
	for _, method := range class.Methods {
		for _, line := range method.Body {
			body.WriteString(line)
			body.WriteByte('\n')
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "const") {
				continue
			}
			parts := strings.SplitN(line, ",", 2)
			if len(parts) != 2 {
				continue
			}
			literal := strings.Fields(parts[1])
			if len(literal) > 0 {
				if number, err := strconv.ParseInt(strings.TrimSuffix(literal[0], "L"), 0, 64); err == nil {
					constants[uint32(number)] = true
				}
			}
		}
	}
	code := body.String()
	var recovered []staticNetworkValue
	seen := make(map[string]bool)
	add := func(value, proof string) {
		if isStaticNetworkValue(value) && !seen[value] {
			seen[value] = true
			recovered = append(recovered, staticNetworkValue{value: value, proof: proof})
		}
	}
	// Byte-array XOR must also appear in the class's actual instruction stream.
	if strings.Contains(code, "aget-byte") && strings.Contains(code, "xor-int") && strings.Contains(code, "rem-int") {
		for i, payload := range arrays {
			if len(payload.data) < 8 {
				continue
			}
			for j, key := range arrays {
				if i == j || len(key.data) < 2 || len(key.data) > 64 {
					continue
				}
				plain := make([]byte, len(payload.data))
				for offset, value := range payload.data {
					plain[offset] = value ^ key.data[offset%len(key.data)]
				}
				add(string(plain), "repeating XOR of "+payload.method+":"+payload.label+" using "+key.label)
			}
		}
	}
	// This format has a 32-byte binary prefix followed by a newline-separated
	// host pool. All five arithmetic constants and the rotate operation must
	// be present; arbitrary payloads are not tried against a guessed cipher.
	rollingPool := strings.Contains(code, "Ljava/lang/Integer;->rotateLeft(II)I") &&
		strings.Contains(code, "mul-int") && strings.Contains(code, "xor-int")
	for _, required := range []uint32{0x6c2e91b7, 0x19f7e26a, 0xa45d08c3, 0x9e3779b1, 0xd3085b41} {
		rollingPool = rollingPool && constants[required]
	}
	if rollingPool {
		for _, payload := range arrays {
			if len(payload.data) < 48 {
				continue
			}
			plain := make([]byte, len(payload.data))
			a, b := uint32(0x6c2e91b7), uint32(0x19f7e26a)
			for offset, value := range payload.data {
				mixed := uint32(0xa45d08c3)*uint32(offset) + a
				plain[offset] = byte(bits.RotateLeft32(mixed, offset&7)^b) ^ value
				a = a*0x9e3779b1 + 0xd3085b41
				b ^= a >> 11
			}
			hosts := strings.Split(string(plain[32:]), "\n")
			valid := len(hosts) >= 2 && len(hosts) <= 32
			for _, host := range hosts {
				valid = valid && networkrefs.IsRecoveredHostname(host)
			}
			if valid {
				for _, host := range hosts {
					add(host, "ROL32/LCG XOR host pool in "+payload.method+":"+payload.label+"; arithmetic signature matched")
				}
			}
		}
	}
	return recovered
}

func isStaticNetworkValue(value string) bool {
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00 \t\r\n") {
		return false
	}
	if net.ParseIP(value) != nil || networkrefs.IsRecoveredHostname(value) {
		return true
	}
	parsed, err := url.Parse(value)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") &&
		(networkrefs.IsRecoveredHostname(parsed.Hostname()) || net.ParseIP(parsed.Hostname()) != nil)
}

func staticByteArrays(class *types.SmaliClass) []staticByteArray {
	const maxArrays, maxBytes = 32, 64 << 10
	var arrays []staticByteArray
	for _, method := range class.Methods {
		label := ""
		for lineIndex := 0; lineIndex < len(method.Body) && len(arrays) < maxArrays; lineIndex++ {
			line := strings.TrimSpace(method.Body[lineIndex])
			if strings.HasPrefix(line, ":") {
				label = strings.Fields(line)[0]
			}
			if strings.Join(strings.Fields(line), " ") != ".array-data 1" {
				continue
			}
			payload := staticByteArray{method: method.Name, label: label}
			valid, ended := true, false
			for lineIndex++; lineIndex < len(method.Body); lineIndex++ {
				line = strings.TrimSpace(strings.SplitN(method.Body[lineIndex], "#", 2)[0])
				if line == ".end array-data" {
					ended = true
					break
				}
				if line == "" {
					continue
				}
				value, err := strconv.ParseInt(strings.TrimSuffix(line, "t"), 0, 64)
				if err != nil || value < -128 || value > 255 || len(payload.data) >= maxBytes {
					valid = false
				} else {
					payload.data = append(payload.data, byte(value))
				}
			}
			if valid && ended && len(payload.data) > 0 {
				arrays = append(arrays, payload)
			}
		}
	}
	return arrays
}

func (p *Pipeline) recoverStaticClassNetworkValues(analysis *types.FileAnalysis, class *types.SmaliClass) {
	if !p.config.DeobfuscationOptions.EnableStringDec {
		return
	}
	values := recoverStaticNetworkConstants(class)
	if len(values) == 0 {
		return
	}
	if analysis.Deobfuscation == nil {
		analysis.Deobfuscation = &types.DeobfuscationResult{}
	}
	method := types.DeobfMethod{ClassName: class.Name, MethodName: "<static-network-constants>"}
	for _, value := range values {
		analysis.RecoveredStrings = append(analysis.RecoveredStrings, value.value)
		method.RecoveredValues = append(method.RecoveredValues, types.DeobfRecoveredValue{
			Value: value.value, Source: "static_byte_array", Proof: value.proof,
		})
	}
	analysis.RecoveredStrings = dedupeStrings(analysis.RecoveredStrings)
	analysis.Deobfuscation.RecoveredStrings = len(analysis.RecoveredStrings)
	analysis.Deobfuscation.Methods = append(analysis.Deobfuscation.Methods, method)
}
