package vulnscan

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrorKind classifies a scan error so the engine can decide whether to retry,
// skip, degrade, or abort - replacing the old binary "return err or silently
// continue" handling.
type ErrorKind string

const (
	ErrTransient ErrorKind = "Transient" // network timeout -> retry with backoff
	ErrPermanent ErrorKind = "Permanent" // DNS failure -> skip this target
	ErrFatal     ErrorKind = "Fatal"     // invalid config -> abort scan
	ErrDegraded  ErrorKind = "Degraded"  // chromedp missing -> skip phase, continue
)

// ScanError wraps an underlying error with phase and classification context.
type ScanError struct {
	Phase   ScanPhase
	Kind    ErrorKind
	Surface string
	Wrapped error
}

func (e *ScanError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("[%s/%s] surface=%q: %v", e.Phase, e.Kind, e.Surface, e.Wrapped)
}

func (e *ScanError) Unwrap() error { return e.Wrapped }

// NewScanError builds a classified scan error.
func NewScanError(phase ScanPhase, kind ErrorKind, surface string, err error) *ScanError {
	return &ScanError{Phase: phase, Kind: kind, Surface: surface, Wrapped: err}
}

// ClassifyNetworkError maps a raw transport error to a ScanError kind.
func ClassifyNetworkError(err error) ErrorKind {
	if err == nil {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrTransient
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ErrPermanent
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "eof"):
		return ErrTransient
	case strings.Contains(msg, "no such host") || strings.Contains(msg, "server misbehaving"):
		return ErrPermanent
	case strings.Contains(msg, "connection refused"):
		return ErrPermanent
	default:
		return ErrTransient
	}
}

// Retryable reports whether an error should be retried.
func Retryable(err error) bool {
	var se *ScanError
	if errors.As(err, &se) {
		return se.Kind == ErrTransient
	}
	return ClassifyNetworkError(err) == ErrTransient
}
