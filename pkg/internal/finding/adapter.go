package finding

import (
	"strings"
)

type LegacyInput struct {
	RuleID         string
	Detector       string
	Kind           Kind
	Category       string
	Title          string
	Description    string
	Severity       string
	Confidence     float64
	EvidenceType   string
	Evidence       string
	ArtifactSHA256 string
	Location       Location
	CWE            []string
	MASVS          []string
}

func FromLegacy(input LegacyInput) Finding {
	ruleID := strings.TrimSpace(input.RuleID)
	if ruleID == "" {
		ruleID = RuleID(input.Category, input.Title)
	}
	confidence := input.Confidence
	if confidence < 0 {
		confidence = 0
	} else if confidence > 1 {
		confidence = 1
	}
	evidence := NewEvidence(input.EvidenceType, input.Description, input.Evidence, input.Location)
	fingerprint := Fingerprint(ruleID, input.Location, input.Evidence)
	return Finding{
		SchemaVersion: 1,
		ID:            fingerprint,
		Fingerprint:   fingerprint,
		RuleID:        ruleID,
		Kind:          input.Kind,
		Category:      input.Category,
		Title:         input.Title,
		Description:   input.Description,
		Severity:      strings.ToLower(input.Severity),
		Confidence:    confidence,
		CWE:           append([]string(nil), input.CWE...),
		MASVS:         append([]string(nil), input.MASVS...),
		Locations:     []Location{input.Location},
		Evidence:      []Evidence{evidence},
		Provenance: []Provenance{{
			Engine:         "mega-analyzer",
			Detector:       input.Detector,
			RuleID:         ruleID,
			SourceArtifact: input.Location.File,
			ArtifactSHA256: input.ArtifactSHA256,
		}},
		Occurrences: 1,
	}
}
