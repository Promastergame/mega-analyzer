package vulnscan

import (
	"context"
)

// checkIDCtxKey carries the logical check identity through the HTTP stack so
// the gateway can tag recorded interactions without changing every check
// signature.
type checkIDCtxKey struct{}

// WithCheckID tags ctx so interactions issued with it are attributed to the
// named check in the Ledger.
func WithCheckID(ctx context.Context, checkID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, checkIDCtxKey{}, checkID)
}

func checkIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(checkIDCtxKey{}).(string)
	return id
}

// context returns the run-scoped context for probes issued without an
// explicit ctx (legacy check paths). It never returns nil.
func (s *Scanner) context() context.Context {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.runContext != nil {
		return s.runContext
	}
	return context.Background()
}

// ensureRun binds ctx to this scan run: legacy paths share one cancellation
// source and one Ledger. Safe to call repeatedly; the first context wins
// until stopRun releases it.
func (s *Scanner) ensureRun(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.runContext == nil {
		s.runContext, s.runCancel = context.WithCancelCause(ctx)
	}
	if s.Ledger == nil {
		s.Ledger = NewLedger(10000)
	}
	return s.runContext
}

// stopRun cancels the run-scoped context and detaches it so a reused Scanner
// starts the next run with a fresh cancellation source. Findings, workflows
// and the Ledger survive across runs.
func (s *Scanner) stopRun(err error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.runCancel != nil {
		s.runCancel(err)
	}
	s.runCancel = nil
	s.runContext = nil
}
