package errors

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Error with Hints
// ═══════════════════════════════════════════════════════════════════════════════

// HintError wraps an error with helpful hints
type HintError struct {
	err   error
	hints []string
}

// Error implements the error interface
func (e *HintError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

// Unwrap returns the underlying error
func (e *HintError) Unwrap() error {
	return e.err
}

// Hints returns all hints
func (e *HintError) Hints() []string {
	return e.hints
}

// String returns formatted error with hints
func (e *HintError) String() string {
	if e.err == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(e.err.Error())

	if len(e.hints) > 0 {
		sb.WriteString("\n")
		for i, hint := range e.hints {
			sb.WriteString(fmt.Sprintf("Hint: %s\n", hint))
			if i < len(e.hints)-1 {
				sb.WriteString("      ")
			}
		}
	}

	return sb.String()
}

// WithHint wraps an error with a single hint
func WithHint(err error, hint string) error {
	if err == nil {
		return nil
	}
	return &HintError{
		err:   err,
		hints: []string{hint},
	}
}

// WithHints wraps an error with multiple hints
func WithHints(err error, hints ...string) error {
	if err == nil {
		return nil
	}
	return &HintError{
		err:   err,
		hints: hints,
	}
}

// Common error hints
var (
	// HintDebug suggests running with debug mode
	HintDebug = "Try running with --debug for more details"

	// HintCheckFile suggests checking if file exists
	HintCheckFile = "Check if the file exists and you have read permissions"

	// HintCheckAPK suggests checking if file is valid APK
	HintCheckAPK = "Check if the file is a valid APK (use `file app.apk` or `aapt dump badging app.apk`)"

	// HintCheckDir suggests checking directory
	HintCheckDir = "Check if the directory exists and is readable"

	// HintTryProfile suggests trying a different profile
	HintTryProfile = "Try using a different profile (--profile quick) to reduce resource usage"

	// HintIncreaseMemory suggests increasing memory limits
	HintIncreaseMemory = "Consider increasing --max-file-size or using --profile deep"

	// HintCheckNetwork suggests checking network connectivity
	HintCheckNetwork = "Check your network connection or use --sandbox-allow-net"

	// HintCheckPermissions suggests checking file permissions
	HintCheckPermissions = "Check file/directory permissions (chmod 755 or 644)"

	// HintTryForce suggests using force flag
	HintTryForce = "Try using --force flag to override"

	// HintCheckConfig suggests checking configuration
	HintCheckConfig = "Check your configuration file with --validate-config"
)

// WrapWithHint wraps an error with context and adds common hints
func WrapWithHint(err error, context string) error {
	if err == nil {
		return nil
	}

	// Determine appropriate hint based on error message
	errStr := strings.ToLower(err.Error())
	var hints []string

	if strings.Contains(errStr, "file not found") || strings.Contains(errStr, "no such file") {
		hints = append(hints, HintCheckFile)
	} else if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "access denied") {
		hints = append(hints, HintCheckPermissions)
	} else if strings.Contains(errStr, "apk") || strings.Contains(errStr, "dex") {
		hints = append(hints, HintCheckAPK)
	} else if strings.Contains(errStr, "directory") || strings.Contains(errStr, "folder") {
		hints = append(hints, HintCheckDir)
	} else if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "timed out") {
		hints = append(hints, HintTryProfile)
	} else if strings.Contains(errStr, "memory") || strings.Contains(errStr, "out of memory") {
		hints = append(hints, HintIncreaseMemory)
	} else if strings.Contains(errStr, "network") || strings.Contains(errStr, "connection") {
		hints = append(hints, HintCheckNetwork)
	} else if strings.Contains(errStr, "config") || strings.Contains(errStr, "configuration") {
		hints = append(hints, HintCheckConfig)
	}

	// Add debug hint for all errors
	hints = append(hints, HintDebug)

	return Wrap(err, context, hints...)
}

// Wrap wraps an error with context and optional hints
func Wrap(err error, context string, hints ...string) error {
	if err == nil {
		return nil
	}

	// Combine with existing hints if the error already has them
	if he, ok := err.(*HintError); ok {
		newHints := append([]string{}, hints...)
		newHints = append(newHints, he.hints...)
		return &HintError{
			err:   fmt.Errorf("%s: %w", context, he.err),
			hints: newHints,
		}
	}

	return &HintError{
		err:   fmt.Errorf("%s: %w", context, err),
		hints: hints,
	}
}

// PrintHintError prints error with hints in a formatted way
func PrintHintError(err error) {
	if err == nil {
		return
	}

	// Check if it's a HintError
	if he, ok := err.(*HintError); ok {
		fmt.Printf("Error: %s\n", he.err.Error())
		if len(he.hints) > 0 {
			fmt.Println()
			for i, hint := range he.hints {
				if i == 0 {
					fmt.Printf("Hint: %s\n", hint)
				} else {
					fmt.Printf("      %s\n", hint)
				}
			}
		}
		return
	}

	// Regular error
	fmt.Printf("Error: %v\n", err)
}
