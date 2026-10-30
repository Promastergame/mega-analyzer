package niap

import (
	_ "embed"
	"encoding/json"
)

//go:embed android_niap_rules.json
var niapRulesJSON []byte

func loadEmbeddedRules() ([]Rule, error) {
	var rules []Rule
	if err := json.Unmarshal(niapRulesJSON, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}
