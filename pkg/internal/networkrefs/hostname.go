package networkrefs

import "strings"

// IsRecoveredHostname accepts common DNS suffixes and RFC-style ASCII labels.
// Package names with invented suffixes remain strings, not network indicators.
func IsRecoveredHostname(value string) bool {
	if len(value) < 4 || len(value) > 253 {
		return false
	}
	parts := strings.Split(strings.ToLower(value), ".")
	if len(parts) < 2 {
		return false
	}
	const commonTLDs = " com org net io gov edu mil int app dev info biz name pro xyz top online site club cloud shop store live me co uk ru su de nl fr us ca au cn jp tv cc ws mobi cfd cyou "
	if !strings.Contains(commonTLDs, " "+parts[len(parts)-1]+" ") {
		return false
	}
	for _, label := range parts {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
