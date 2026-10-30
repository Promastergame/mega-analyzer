package binzap

import "strings"

// ParseDalvikParams parses the parameter type descriptors from a Dalvik/Smali
// method signature such as "(ILjava/lang/String;Z)V" -> ["I","Ljava/lang/String;","Z"].
// A fully-qualified signature like "Lcom/app/A;->m(Ljava/lang/String;)Z" is also
// accepted. This is a legitimate, dialect-aware helper reused by the taint
// engine and by the (quarantined) legacy fuzzer.
func ParseDalvikParams(sig string) []string { return extractParamTypes(sig) }

// extractParamTypes extracts Dalvik types from a signature like `(ILjava/lang/String;Z)`.
func extractParamTypes(sig string) []string {
	var params []string
	startIdx := strings.Index(sig, "(")
	endIdx := strings.Index(sig, ")")
	if startIdx == -1 || endIdx == -1 || startIdx >= endIdx {
		return params
	}

	rawParams := sig[startIdx+1 : endIdx]
	i := 0
	for i < len(rawParams) {
		switch rawParams[i] {
		case 'L':
			end := strings.Index(rawParams[i:], ";")
			if end == -1 {
				i++
				continue
			}
			params = append(params, rawParams[i:i+end+1])
			i += end + 1
		case '[':
			start := i
			for i < len(rawParams) && rawParams[i] == '[' {
				i++
			}
			if i < len(rawParams) {
				switch rawParams[i] {
				case 'L':
					end := strings.Index(rawParams[i:], ";")
					if end == -1 {
						params = append(params, rawParams[start:i+1])
						i++
					} else {
						params = append(params, rawParams[start:i+end+1])
						i += end + 1
					}
				default:
					params = append(params, rawParams[start:i+1])
					i++
				}
			} else {
				params = append(params, rawParams[start:i])
			}
		default:
			params = append(params, string(rawParams[i]))
			i++
		}
	}
	return params
}
