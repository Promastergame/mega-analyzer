package s1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func identityHash(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func backendFingerprint(b Backend) string {
	if f, ok := b.(interface{ Fingerprint() string }); ok {
		return f.Fingerprint()
	}
	return ""
}
func (b *EmbedBackend) Fingerprint() string {
	if b.enc.Fingerprint() == "" {
		return ""
	}
	return identityHash([]any{"embed-v3", b.enc.Fingerprint(), b.Scale, b.Bias, FeatureVersion})
}
func (b *NLIBackend) Fingerprint() string    { return b.enc.Fingerprint() }
func (b *CachedBackend) Fingerprint() string { return backendFingerprint(b.backend) }
func (e EnsembleBackend) Fingerprint() string {
	ids := []string{"ensemble-mean-v1"}
	for _, m := range e.Members {
		id := backendFingerprint(m)
		if id == "" {
			return ""
		}
		ids = append(ids, id)
	}
	return identityHash(ids)
}

// ConfigurationFingerprint is independent of file paths, temperatures and cache
// sizes. Changes in weights, retrieval, fusion or routing memory invalidate it.
// Custom backends must implement Fingerprint or set Engine.ModelFingerprint.
func (e *Engine) ConfigurationFingerprint() string {
	model := backendFingerprint(e.Backend)
	if model == "" {
		model = e.ModelFingerprint
	}
	if model == "" {
		return ""
	}
	expertNames := []string{}
	for _, ex := range e.Experts {
		expertNames = append(expertNames, ex.Name())
	}
	skills := []any{}
	if e.Skills != nil {
		e.Skills.mu.RLock()
		defer e.Skills.mu.RUnlock()
		for _, s := range e.Skills.Skills {
			skills = append(skills, []any{s.Name, s.Desc, s.Body, s.Examples})
		}
	}
	return identityHash([]any{"decision-config-v1", Version, FeatureVersion, model, e.AuxiliaryFingerprint, backendFingerprint(e.SkillBackend), e.NoLex, e.LexScale, e.MaxChunkWords, e.MaxChunkTokens, e.MaxChunks, e.MaxPairs, expertNames, skills})
}

func (e *Engine) CalibrationIssue() string {
	actual := e.ConfigurationFingerprint()
	if actual == "" {
		return "model_fingerprint_unavailable"
	}
	if e.Calib.Fingerprint == "" {
		return "legacy_calibration_unbound"
	}
	if e.Calib.Fingerprint != actual {
		return "configuration_mismatch"
	}
	return ""
}

// BindCalibration is for calibration output only, never to bless an old file.
func (e *Engine) BindCalibration(c Calibration) (Calibration, error) {
	c.Fingerprint = e.ConfigurationFingerprint()
	if c.Fingerprint == "" {
		return c, fmt.Errorf("backend has no stable model fingerprint")
	}
	return c, nil
}
