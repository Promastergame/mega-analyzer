package deobfmetrics

import (
	"errors"
	"fmt"
)

// DeobfState captures a measurable snapshot of a program either before or
// after deobfuscation.
type DeobfState struct {
	// Entropy
	AvgNameEntropy float64 `json:"avg_name_entropy"`
	MaxNameEntropy float64 `json:"max_name_entropy"`

	// Identifiers (mutually exclusive classes; see ClassifyName)
	TotalIdentifiers int `json:"total_identifiers"`
	ReadableNames    int `json:"readable_names"`   // neither obfuscated nor clearly meaningful
	ObfuscatedNames  int `json:"obfuscated_names"` // single char / random-looking
	MeaningfulNames  int `json:"meaningful_names"` // dictionary words or camelCase

	// Control-flow graph
	TotalBlocks       int `json:"total_blocks"`
	DispatcherBlocks  int `json:"dispatcher_blocks"` // switch-based dispatchers (flattening)
	OpaquePredicates  int `json:"opaque_predicates"` // always-true/false conditions
	UnreachableBlocks int `json:"unreachable_blocks"`

	// Strings
	TotalStrings     int `json:"total_strings"`
	EncryptedStrings int `json:"encrypted_strings"` // high-entropy strings still present
	DecryptedStrings int `json:"decrypted_strings"` // formerly-encrypted strings recovered

	// Reflection
	TotalReflection    int `json:"total_reflection"`    // reflective calls present
	ResolvedReflection int `json:"resolved_reflection"` // resolved to direct calls

	// Code volume / complexity
	TotalInstructions int `json:"total_instructions"`
	DeadInstructions  int `json:"dead_instructions"` // unreachable code
	CyclomaticTotal   int `json:"cyclomatic_total"`  // sum of cyclomatic complexity
}

// ErrInvalidState is returned when a DeobfState contains impossible values.
var ErrInvalidState = errors.New("deobfmetrics: invalid state")

// Validate checks internal consistency of a single state snapshot. It reports
// the first violated invariant, wrapped with ErrInvalidState.
func (s DeobfState) Validate() error {
	nonNegative := []struct {
		name string
		val  int
	}{
		{"total_identifiers", s.TotalIdentifiers},
		{"readable_names", s.ReadableNames},
		{"obfuscated_names", s.ObfuscatedNames},
		{"meaningful_names", s.MeaningfulNames},
		{"total_blocks", s.TotalBlocks},
		{"dispatcher_blocks", s.DispatcherBlocks},
		{"opaque_predicates", s.OpaquePredicates},
		{"unreachable_blocks", s.UnreachableBlocks},
		{"total_strings", s.TotalStrings},
		{"encrypted_strings", s.EncryptedStrings},
		{"decrypted_strings", s.DecryptedStrings},
		{"total_reflection", s.TotalReflection},
		{"resolved_reflection", s.ResolvedReflection},
		{"total_instructions", s.TotalInstructions},
		{"dead_instructions", s.DeadInstructions},
		{"cyclomatic_total", s.CyclomaticTotal},
	}
	for _, f := range nonNegative {
		if f.val < 0 {
			return fmt.Errorf("%w: %s is negative (%d)", ErrInvalidState, f.name, f.val)
		}
	}
	if s.AvgNameEntropy < 0 || s.MaxNameEntropy < 0 {
		return fmt.Errorf("%w: entropy cannot be negative", ErrInvalidState)
	}
	if s.ResolvedReflection > s.TotalReflection {
		return fmt.Errorf("%w: resolved_reflection (%d) > total_reflection (%d)",
			ErrInvalidState, s.ResolvedReflection, s.TotalReflection)
	}
	if s.DeadInstructions > s.TotalInstructions {
		return fmt.Errorf("%w: dead_instructions (%d) > total_instructions (%d)",
			ErrInvalidState, s.DeadInstructions, s.TotalInstructions)
	}
	if classified := s.ReadableNames + s.ObfuscatedNames + s.MeaningfulNames; s.TotalIdentifiers > 0 && classified > s.TotalIdentifiers {
		return fmt.Errorf("%w: classified names (%d) exceed total_identifiers (%d)",
			ErrInvalidState, classified, s.TotalIdentifiers)
	}
	if s.TotalStrings > 0 && s.EncryptedStrings+s.DecryptedStrings > s.TotalStrings {
		return fmt.Errorf("%w: encrypted_strings (%d) + decrypted_strings (%d) exceed total_strings (%d)",
			ErrInvalidState, s.EncryptedStrings, s.DecryptedStrings, s.TotalStrings)
	}
	if s.TotalBlocks > 0 && s.DispatcherBlocks > s.TotalBlocks {
		return fmt.Errorf("%w: dispatcher_blocks (%d) exceed total_blocks (%d)",
			ErrInvalidState, s.DispatcherBlocks, s.TotalBlocks)
	}
	return nil
}

// ValidateTransition checks consistency between before and after DeobfState snapshots.
// It reports invariants that must hold across the deobfuscation transition.
func ValidateTransition(before, after DeobfState) error {
	if after.ObfuscatedNames > before.ObfuscatedNames {
		return fmt.Errorf("%w: after.obfuscated_names (%d) > before.obfuscated_names (%d)",
			ErrInvalidState, after.ObfuscatedNames, before.ObfuscatedNames)
	}
	if after.DecryptedStrings > before.EncryptedStrings && before.EncryptedStrings > 0 {
		return fmt.Errorf("%w: after.decrypted_strings (%d) > before.encrypted_strings (%d)",
			ErrInvalidState, after.DecryptedStrings, before.EncryptedStrings)
	}
	return nil
}

// StateInput is the raw data needed to build a DeobfState via ExtractState.
type StateInput struct {
	Identifiers        []string
	Strings            []string
	TotalBlocks        int
	TotalInstructions  int
	DeadInstructions   int
	CyclomaticTotal    int
	DispatcherBlocks   int
	OpaquePredicates   int
	UnreachableBlocks  int
	ReflectionCalls    int
	ResolvedReflection int

	// RecoveredStrings is the count of strings that were encrypted in the
	// baseline and have since been decrypted to readable form. It is set by
	// the caller when extracting the "after" state; for a baseline it is 0.
	RecoveredStrings int
}

// ExtractState builds a DeobfState from raw method/class data. Identifier
// entropy is computed once per name and reused for classification.
func ExtractState(input StateInput) DeobfState {
	state := DeobfState{
		TotalIdentifiers:   len(input.Identifiers),
		TotalBlocks:        input.TotalBlocks,
		TotalStrings:       len(input.Strings),
		TotalReflection:    input.ReflectionCalls,
		TotalInstructions:  input.TotalInstructions,
		DeadInstructions:   input.DeadInstructions,
		CyclomaticTotal:    input.CyclomaticTotal,
		DispatcherBlocks:   input.DispatcherBlocks,
		OpaquePredicates:   input.OpaquePredicates,
		UnreachableBlocks:  input.UnreachableBlocks,
		ResolvedReflection: input.ResolvedReflection,
		DecryptedStrings:   input.RecoveredStrings,
	}

	// Classify identifiers (single entropy computation per name).
	var entropySum float64
	for _, name := range input.Identifiers {
		entropy := ShannonEntropy(name)
		entropySum += entropy
		if entropy > state.MaxNameEntropy {
			state.MaxNameEntropy = entropy
		}

		switch ClassifyName(name, entropy) {
		case ClassObfuscated:
			state.ObfuscatedNames++
		case ClassMeaningful:
			state.MeaningfulNames++
		default:
			state.ReadableNames++
		}
	}
	if n := len(input.Identifiers); n > 0 {
		state.AvgNameEntropy = entropySum / float64(n)
	}

	// Count high-entropy (still encrypted) strings.
	for _, s := range input.Strings {
		if IsHighEntropyString(s) {
			state.EncryptedStrings++
		}
	}

	return state
}
