package finding

import (
	"crypto/sha256"
	"encoding/hex"
)

type Evidence struct {
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Snippet     string   `json:"snippet,omitempty"`
	Digest      string   `json:"sha256"`
	Location    Location `json:"location"`
}

func NewEvidence(kind, description, snippet string, location Location) Evidence {
	digest := sha256.Sum256([]byte(snippet))
	return Evidence{
		Type:        kind,
		Description: description,
		Snippet:     snippet,
		Digest:      hex.EncodeToString(digest[:]),
		Location:    location,
	}
}
