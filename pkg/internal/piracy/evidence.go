// Package piracy — evidence.go
package piracy

// ═══════════════════════════════════════════════════════════════════════════════
// EVIDENCE — единица доказательства
// ═══════════════════════════════════════════════════════════════════════════════

type Evidence struct {
	Type        SignalType
	Strength    SignalStrength
	Source      string
	Pattern     string
	Location    string
	Confidence  float64
	Weight      float64
	Description string
}

// effectiveScore — единый способ вычислить "силу" улики
func (e Evidence) effectiveScore(strengthWeight float64) float64 {
	return e.Confidence * e.Weight * strengthWeight
}
