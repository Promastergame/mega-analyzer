package llmkeys

import _ "embed"

// keysDatasetJSON holds the synthetic positive examples, baked into the binary.
//
//go:embed keys_dataset.json
var keysDatasetJSON []byte

// negativesJSON holds the synthetic non-secret examples, baked into the binary.
//
//go:embed negatives.json
var negativesJSON []byte
