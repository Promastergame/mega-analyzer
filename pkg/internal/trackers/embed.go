package trackers

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed exodus_db.json
var exodusDB []byte

// LoadDB returns the embedded tracker signature database as a slice
// of Tracker records. The result is cached after the first call.
func LoadDB() ([]Tracker, error) {
	if cachedDB != nil {
		return cachedDB, nil
	}
	var ts []Tracker
	if err := json.Unmarshal(exodusDB, &ts); err != nil {
		return nil, fmt.Errorf("decode exodus_db.json: %w", err)
	}
	cachedDB = ts
	return ts, nil
}

var cachedDB []Tracker
