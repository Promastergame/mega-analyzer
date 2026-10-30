// Package piracy — obfuscation_types.go
package piracy

// ObfuscationMethod is a classifier for deobfuscation techniques used.
type ObfuscationMethod string

const (
	ObfBase64          ObfuscationMethod = "base64"
	ObfBase64MultiLine ObfuscationMethod = "base64_multiline"
	ObfHex             ObfuscationMethod = "hex"
	ObfURLEncoded      ObfuscationMethod = "urlencoded"
	ObfROT13           ObfuscationMethod = "rot13"
	ObfXOR             ObfuscationMethod = "xor"
	ObfReversed        ObfuscationMethod = "reversed"
	ObfPunycode        ObfuscationMethod = "punycode"
)

type ObfuscatedURL struct {
	Original   string  `json:"original,omitempty"`
	Decoded    string  `json:"decoded,omitempty"`
	Method     string  `json:"method"`
	Domain     string  `json:"domain,omitempty"`
	Confidence float64 `json:"confidence"`
}
