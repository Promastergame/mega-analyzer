package sandbox

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const maxCryptoMaterials = 256
const maxCryptoKeyBytes = 256

// CryptoMaterial is observed key material, not proof that a file can be decrypted.
// IVs belong to the recorded invocation, never to a guessed algorithm or file.
type CryptoMaterial struct {
	Source       string    `json:"source"`
	Function     string    `json:"function"`
	PID          int       `json:"pid"`
	ThreadID     int       `json:"thread_id,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
	Algorithm    string    `json:"algorithm"`
	Operation    string    `json:"operation"`
	KeyHex       string    `json:"key_hex"`
	KeyBytes     int       `json:"key_bytes"`
	IVHex        string    `json:"iv_hex,omitempty"`
	KeyHandle    string    `json:"key_handle,omitempty"`
	Observations int       `json:"observations"`
}

type CryptoAnalysis struct {
	Status    string           `json:"status"`
	Materials []CryptoMaterial `json:"materials"`
	Rejected  int              `json:"rejected"`
	Truncated bool             `json:"truncated"`
}

func canonicalCryptoHex(value string, limit int) (string, bool) {
	if len(value) == 0 || len(value) > limit*2 || len(value)%2 != 0 {
		return "", false
	}
	data, err := hex.DecodeString(value)
	if err != nil {
		return "", false
	}
	return hex.EncodeToString(data), true
}

func (a *CryptoAnalysis) add(m CryptoMaterial) {
	key, ok := canonicalCryptoHex(m.KeyHex, maxCryptoKeyBytes)
	if !ok || m.PID <= 0 || len(m.Algorithm) > 128 {
		a.Rejected++
		return
	}
	m.KeyHex, m.KeyBytes = key, len(key)/2
	if strings.EqualFold(strings.Split(m.Algorithm, "/")[0], "AES") && m.KeyBytes != 16 && m.KeyBytes != 24 && m.KeyBytes != 32 {
		a.Rejected++
		return
	}
	if m.IVHex != "" {
		iv, valid := canonicalCryptoHex(m.IVHex, 32)
		if !valid {
			a.Rejected++
			return
		}
		m.IVHex = iv
	}
	if m.Algorithm == "" {
		m.Algorithm = "unknown"
	}
	for i := range a.Materials {
		p := &a.Materials[i]
		if p.PID == m.PID && p.Source == m.Source && p.Function == m.Function && p.KeyHandle == m.KeyHandle && p.KeyHex == m.KeyHex && p.IVHex == m.IVHex && p.Algorithm == m.Algorithm && p.Operation == m.Operation {
			p.Observations++
			return
		}
	}
	if len(a.Materials) >= maxCryptoMaterials {
		a.Truncated = true
		return
	}
	m.Observations = 1
	a.Materials = append(a.Materials, m)
	a.Status = "captured"
}

func cryptoParameter(call APICall, name string) string {
	for _, p := range call.Parameters {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func analyzeCryptoMaterial(report *Report) *CryptoAnalysis {
	a := &CryptoAnalysis{Status: "not_instrumented", Materials: []CryptoMaterial{}}
	if report.CryptoAnalysis != nil && len(report.APICalls) == 0 {
		*a = *report.CryptoAnalysis
		a.Materials = append([]CryptoMaterial{}, report.CryptoAnalysis.Materials...)
	}
	if report.Frida != nil {
		if report.Frida.Active && a.Status == "not_instrumented" {
			a.Status = "no_material"
		}
		if captured := report.Frida.Crypto; captured != nil {
			*a = *captured
			a.Materials = append([]CryptoMaterial{}, captured.Materials...)
		}
	}
	collector := newCryptoAccumulator(a)
	for _, call := range report.APICalls {
		collector.observe(call)
	}
	return a
}

// Incremental collection is also used by the durable remote journal. Handles
// are process-local and expire on destruction/replacement.
type cryptoAccumulator struct {
	analysis *CryptoAnalysis
	keys     map[string]CryptoMaterial
}

func newCryptoAccumulator(a *CryptoAnalysis) *cryptoAccumulator {
	return &cryptoAccumulator{analysis: a, keys: make(map[string]CryptoMaterial)}
}

func (c *cryptoAccumulator) observe(call APICall) {
	a, keys := c.analysis, c.keys
	if !strings.HasPrefix(call.Function, "BCrypt") {
		return
	}
	if a.Status == "not_instrumented" {
		a.Status = "no_material"
	}
	status, err := strconv.ParseUint(strings.TrimSpace(call.ReturnValue), 0, 32)
	if err != nil || status != 0 || call.ProcessID <= 0 {
		return // CNG NTSTATUS: only an explicit successful return is evidence.
	}
	handle := strings.ToLower(cryptoParameter(call, "hKey"))
	if handle == "" || handle == "0x0" || handle == "0" {
		return
	}
	identity := fmt.Sprintf("%d:%s", call.ProcessID, handle)
	switch call.Function {
	case "BCryptDestroyKey":
		delete(keys, identity)
	case "BCryptGenerateSymmetricKey", "BCryptImportKey":
		delete(keys, identity)
		m := CryptoMaterial{Source: "frida-windows", Function: call.Function,
			PID: call.ProcessID, ThreadID: call.ThreadID, ObservedAt: call.Timestamp,
			Algorithm: cryptoParameter(call, "Algorithm"), Operation: "key_creation",
			KeyHex: cryptoParameter(call, "KeyHex"), KeyHandle: handle}
		before := a.Rejected
		a.add(m)
		if a.Rejected == before {
			if len(keys) >= 4096 {
				a.Truncated = true
				clear(keys)
			}
			keys[identity] = m
		}
	case "BCryptEncrypt", "BCryptDecrypt":
		if m, ok := keys[identity]; ok && cryptoParameter(call, "OutputPresent") == "true" {
			m.Function, m.ObservedAt, m.ThreadID = call.Function, call.Timestamp, call.ThreadID
			m.Operation = strings.ToLower(strings.TrimPrefix(call.Function, "BCrypt"))
			m.IVHex = cryptoParameter(call, "IVHex")
			a.add(m)
		}
	}
}

func writeCryptoAnalysisMarkdown(b *strings.Builder, a *CryptoAnalysis) {
	if a == nil {
		return
	}
	escape := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "`", "&#96;", "\n", " ", "\r", " ").Replace
	fmt.Fprintf(b, "\n## Captured Crypto Material\n\nStatus: %s. Rejected records: %d. Truncated: %t.\n\n", escape(a.Status), a.Rejected, a.Truncated)
	b.WriteString("Observed keys and invocation IVs only; file decryption has not been verified. Hardware-backed keys and custom crypto may be unavailable.\n\n")
	for _, m := range a.Materials {
		// Reports may also be reloaded from disk; treat every string as untrusted.
		fmt.Fprintf(b, "- %s, PID %d, %s / %s; %s; %d bytes; %d observations\n  - Key (hex): `%s`\n", escape(m.Algorithm), m.PID, escape(m.Source), escape(m.Function), escape(m.Operation), m.KeyBytes, m.Observations, escape(m.KeyHex))
		if m.IVHex != "" {
			fmt.Fprintf(b, "  - IV (hex): `%s`\n", escape(m.IVHex))
		}
	}
}
