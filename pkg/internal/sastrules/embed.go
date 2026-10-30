package sastrules

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed mobsf_android_rules.json
var mobsfRulesJSON []byte

//go:embed mobsf_android_apis.json
var mobsfAPIsJSON []byte

//go:embed secrets_crypto_rules.json
var secretsCryptoJSON []byte

//go:embed piracy_dex_rules.json
var piracyDexRulesJSON []byte

//go:embed gov_sso_rules.json
var govSSORulesJSON []byte

// LoadEmbeddedRuleSets returns all built-in MobSF-derived rule sets plus the
// DEX license/piracy taxonomy rules. Result is cached after first call.
func LoadEmbeddedRuleSets() ([]RuleSet, error) {
	if cached != nil {
		return cached, nil
	}
	var rs RuleSet
	if err := json.Unmarshal(mobsfRulesJSON, &rs); err != nil {
		return nil, fmt.Errorf("decode embedded rules: %w", err)
	}
	var apis RuleSet
	if err := json.Unmarshal(mobsfAPIsJSON, &apis); err != nil {
		return nil, fmt.Errorf("decode embedded apis: %w", err)
	}
	var secrets RuleSet
	if err := json.Unmarshal(secretsCryptoJSON, &secrets); err != nil {
		return nil, fmt.Errorf("decode embedded secrets rules: %w", err)
	}
	var piracyDex RuleSet
	if err := json.Unmarshal(piracyDexRulesJSON, &piracyDex); err != nil {
		return nil, fmt.Errorf("decode embedded piracy/dex rules: %w", err)
	}
	var govSSO RuleSet
	if err := json.Unmarshal(govSSORulesJSON, &govSSO); err != nil {
		return nil, fmt.Errorf("decode embedded gov-sso rules: %w", err)
	}
	cached = []RuleSet{rs, apis, secrets, piracyDex, govSSO}
	return cached, nil
}

var cached []RuleSet
