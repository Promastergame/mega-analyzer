package ml

import (
	"mega-analyzer/pkg/internal/appconfig"

	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var (
	dynamicMLPatterns []VulnerablePattern
	dynamicMLMutex    sync.RWMutex
	dynamicMLLoadOnce sync.Once
	dynamicMLFilePath = appconfig.Path("configs/dynamic_rules/ml_patterns.json")
)

// LoadDynamicMLPatterns loads patterns from the JSON storage file.
//
// This used to run from an init(), and it created directories and wrote a file
// relative to the process working directory. Importing this package therefore
// had a filesystem side effect in every binary, every test run and every
// `go vet` — which is where the copies of configs/dynamic_rules/ml_patterns.json
// scattered around the tree came from. Loading is now explicit and read-only:
// a missing file is simply an empty rule set, not something to create.
func LoadDynamicMLPatterns() error {
	dynamicMLMutex.Lock()
	defer dynamicMLMutex.Unlock()

	if _, err := os.Stat(dynamicMLFilePath); os.IsNotExist(err) {
		dynamicMLPatterns = []VulnerablePattern{}
		return nil
	}

	data, err := os.ReadFile(dynamicMLFilePath)
	if err != nil {
		return err
	}

	var patterns []VulnerablePattern
	if err := json.Unmarshal(data, &patterns); err != nil {
		return err
	}

	dynamicMLPatterns = patterns
	return nil
}

// SaveDynamicMLPatterns saves patterns to the JSON storage file
func SaveDynamicMLPatterns() error {
	dynamicMLMutex.RLock()
	defer dynamicMLMutex.RUnlock()

	dir := filepath.Dir(dynamicMLFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(dynamicMLPatterns, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(dynamicMLFilePath, data, 0644)
}

// GetDynamicMLPatterns returns all active dynamic patterns, loading them from
// disk on first use.
func GetDynamicMLPatterns() []VulnerablePattern {
	dynamicMLLoadOnce.Do(func() { _ = LoadDynamicMLPatterns() })

	dynamicMLMutex.RLock()
	defer dynamicMLMutex.RUnlock()

	// Return a copy to prevent race conditions
	copied := make([]VulnerablePattern, len(dynamicMLPatterns))
	copy(copied, dynamicMLPatterns)
	return copied
}

// AddDynamicMLPattern adds a new pattern
func AddDynamicMLPattern(pattern VulnerablePattern) error {
	if pattern.ID == "" {
		return fmt.Errorf("pattern ID cannot be empty")
	}

	dynamicMLMutex.Lock()
	// Check if already exists
	for _, p := range dynamicMLPatterns {
		if p.ID == pattern.ID {
			dynamicMLMutex.Unlock()
			return fmt.Errorf("pattern with ID %s already exists", pattern.ID)
		}
	}

	dynamicMLPatterns = append(dynamicMLPatterns, pattern)
	dynamicMLMutex.Unlock()

	return SaveDynamicMLPatterns()
}

// UpdateDynamicMLPattern updates an existing pattern
func UpdateDynamicMLPattern(id string, pattern VulnerablePattern) error {
	dynamicMLMutex.Lock()
	found := false
	for i, p := range dynamicMLPatterns {
		if p.ID == id {
			dynamicMLPatterns[i] = pattern
			found = true
			break
		}
	}
	dynamicMLMutex.Unlock()

	if !found {
		return fmt.Errorf("pattern with ID %s not found", id)
	}

	return SaveDynamicMLPatterns()
}

// DeleteDynamicMLPattern deletes a pattern by ID
func DeleteDynamicMLPattern(id string) error {
	dynamicMLMutex.Lock()
	index := -1
	for i, p := range dynamicMLPatterns {
		if p.ID == id {
			index = i
			break
		}
	}

	if index == -1 {
		dynamicMLMutex.Unlock()
		return fmt.Errorf("pattern with ID %s not found", id)
	}

	dynamicMLPatterns = append(dynamicMLPatterns[:index], dynamicMLPatterns[index+1:]...)
	dynamicMLMutex.Unlock()

	return SaveDynamicMLPatterns()
}
