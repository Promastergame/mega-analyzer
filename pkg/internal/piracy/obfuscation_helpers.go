// Package piracy — obfuscation_helpers.go
package piracy

func rot13(s string) string {
	// ROT13 works on ASCII letters only.
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + ((c - 'a' + 13) % 26)
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + ((c - 'A' + 13) % 26)
		}
	}
	return string(b)
}
