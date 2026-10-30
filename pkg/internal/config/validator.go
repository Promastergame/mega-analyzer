package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Config Validation CLI
// ═══════════════════════════════════════════════════════════════════════════════

// ValidationResult holds validation results
type ValidationResult struct {
	Valid       bool     `json:"valid"`
	Path        string   `json:"path"`
	Warnings    []string `json:"warnings"`
	Errors      []string `json:"errors"`
	Suggestions []string `json:"suggestions"`
}

// ValidateConfigFile validates a config file and returns detailed results
func ValidateConfigFile(path string) (*ValidationResult, error) {
	result := &ValidationResult{
		Path:        path,
		Valid:       true,
		Warnings:    make([]string, 0),
		Errors:      make([]string, 0),
		Suggestions: make([]string, 0),
	}

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read file: %v", err))
		return result, nil
	}

	// Parse JSON
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid JSON: %v", err))
		return result, nil
	}

	// Validate fields
	result.Warnings = append(result.Warnings, validateWorkers(cfg.Workers)...)
	result.Warnings = append(result.Warnings, validateFileSizes(cfg.MaxFileSize, cfg.MaxFileSizeMB, cfg.MaxResourceSizeMB)...)
	result.Warnings = append(result.Warnings, validateOutputDir(cfg.OutputDir)...)
	result.Warnings = append(result.Warnings, validateLogging(cfg.LogLevel.String(), cfg.LogFile)...)

	// Suggestions
	result.Suggestions = append(result.Suggestions, suggestOptimizations(&cfg)...)

	// Check if any errors
	if len(result.Errors) > 0 {
		result.Valid = false
	}

	return result, nil
}

// validateWorkers checks worker configuration
func validateWorkers(workers int) []string {
	var warnings []string

	if workers <= 0 {
		warnings = append(warnings, fmt.Sprintf("Workers=%d is invalid (should be > 0), will use CPU cores", workers))
	} else if workers > 128 {
		warnings = append(warnings, fmt.Sprintf("Workers=%d is very high (max recommended: 128)", workers))
	}

	return warnings
}

// validateFileSizes checks file size limits
func validateFileSizes(maxFileSize int64, maxFileSizeMB, maxResourceSizeMB int) []string {
	var warnings []string

	if maxFileSize > 0 && maxFileSizeMB > 0 {
		warnings = append(warnings, "Both max_file_size (bytes) and max_file_size_mb are set, MB value will be used")
	}

	if maxFileSizeMB > 1024 {
		warnings = append(warnings, fmt.Sprintf("max_file_size_mb=%d is very large (max: 1024 MB)", maxFileSizeMB))
	}

	if maxResourceSizeMB > 1024 {
		warnings = append(warnings, fmt.Sprintf("max_resource_size_mb=%d is very large (max: 1024 MB)", maxResourceSizeMB))
	}

	return warnings
}

// validateOutputDir checks output directory configuration
func validateOutputDir(outputDir string) []string {
	var warnings []string

	if outputDir == "" {
		warnings = append(warnings, "output_dir is empty, will use 'analysis_output'")
	}

	if strings.ContainsAny(outputDir, `/\:*?"<>|`) {
		warnings = append(warnings, fmt.Sprintf("output_dir '%s' contains invalid characters", outputDir))
	}

	return warnings
}

// validateLogging checks logging configuration
func validateLogging(logLevel string, logFile string) []string {
	var warnings []string

	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}

	if logLevel != "" && !validLevels[strings.ToLower(logLevel)] {
		warnings = append(warnings, fmt.Sprintf("log_level '%s' is invalid (valid: debug, info, warn, error)", logLevel))
	}

	if logFile != "" && !strings.Contains(logFile, ".log") {
		warnings = append(warnings, fmt.Sprintf("log_file '%s' doesn't end with .log", logFile))
	}

	return warnings
}

// suggestOptimizations provides suggestions for better configuration
func suggestOptimizations(cfg *Config) []string {
	var suggestions []string

	if cfg.Workers == 0 {
		suggestions = append(suggestions, "Consider setting workers explicitly for consistent behavior")
	}

	if cfg.MaxFileSizeMB == 0 && cfg.MaxResourceSizeMB == 0 {
		suggestions = append(suggestions, "Consider setting file size limits to prevent memory issues with large APKs")
	}

	if cfg.LogLevel.String() == "DEBUG" {
		suggestions = append(suggestions, "Debug logging will generate large logs, use only for troubleshooting")
	}

	if !cfg.EnableCallGraph && cfg.EnableCorrelations {
		suggestions = append(suggestions, "Correlations without call graph may be less accurate")
	}

	return suggestions
}

// PrintValidationResult prints validation results in a human-readable format
func (r *ValidationResult) Print() {
	fmt.Printf("Config Validation: %s\n", r.Path)
	fmt.Println(strings.Repeat("=", 60))

	if r.Valid {
		fmt.Println("✓ Config is valid")
	} else {
		fmt.Println("✗ Config has errors")
	}

	if len(r.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, err := range r.Errors {
			fmt.Printf("  ✗ %s\n", err)
		}
	}

	if len(r.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, warn := range r.Warnings {
			fmt.Printf("  ⚠ %s\n", warn)
		}
	}

	if len(r.Suggestions) > 0 {
		fmt.Println("\nSuggestions:")
		for _, sugg := range r.Suggestions {
			fmt.Printf("  💡 %s\n", sugg)
		}
	}

	fmt.Println()
}

// PrintJSON prints validation results in JSON format
func (r *ValidationResult) PrintJSON() error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
