package errors

import (
	"fmt"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Error Wrapping Utilities
// ═══════════════════════════════════════════════════════════════════════════════

// New creates a new error with a message.
// Use this instead of errors.New() for consistency.
func New(message string) error {
	return fmt.Errorf("%s", message)
}

// Newf creates a new error with a formatted message.
func Newf(format string, args ...interface{}) error {
	return fmt.Errorf(format, args...)
}
