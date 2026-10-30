package configs

import _ "embed"

// All detection databases are baked into the binary so the analyzer works as a
// single, fully offline executable — no loose JSON files required on disk.

//go:embed endpoint_config.json
var endpointConfigJSON []byte

//go:embed aetrium_anchors.json
var aetriumAnchorsJSON []byte

//go:embed banking_threats.json
var bankingThreatsJSON []byte

//go:embed custom_keywords.json
var customKeywordsJSON []byte

//go:embed context_downgrades.json
var contextDowngradesJSON []byte

//go:embed malware_combos.json
var malwareCombosJSON []byte

//go:embed permission_rules.json
var permissionRulesJSON []byte

//go:embed piracy_sites.json
var piracySitesJSON []byte

// EndpointConfig returns the embedded endpoint detector configuration.
func EndpointConfig() []byte { return endpointConfigJSON }

// AetriumAnchors returns the embedded HDC vulnerability anchor signatures.
func AetriumAnchors() []byte { return aetriumAnchorsJSON }

// BankingThreats returns the embedded banking-trojan rule set.
func BankingThreats() []byte { return bankingThreatsJSON }

// CustomKeywords returns the embedded custom keyword list.
func CustomKeywords() []byte { return customKeywordsJSON }

// ContextDowngrades returns the embedded default benign-context rule set
// (downgrade-only, never suppressing).
func ContextDowngrades() []byte { return contextDowngradesJSON }

// MalwareCombos returns the embedded malware-combination rule set.
func MalwareCombos() []byte { return malwareCombosJSON }

// PermissionRules returns the embedded Android permission rule set.
func PermissionRules() []byte { return permissionRulesJSON }

// PiracySites returns the embedded piracy-site configuration.
func PiracySites() []byte { return piracySitesJSON }

// files maps a base filename to its embedded bytes, for generic lookups.
var files = map[string][]byte{
	"endpoint_config.json":  endpointConfigJSON,
	"aetrium_anchors.json":  aetriumAnchorsJSON,
	"banking_threats.json":  bankingThreatsJSON,
	"context_downgrades.json": contextDowngradesJSON,
	"custom_keywords.json":  customKeywordsJSON,
	"malware_combos.json":   malwareCombosJSON,
	"permission_rules.json": permissionRulesJSON,
	"piracy_sites.json":     piracySitesJSON,
}

// File returns the embedded config bytes for a base filename (e.g.
// "banking_threats.json") and whether it exists.
func File(name string) ([]byte, bool) {
	b, ok := files[name]
	return b, ok
}
