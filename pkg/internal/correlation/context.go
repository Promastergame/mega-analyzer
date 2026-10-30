package correlation

import (
	"sort"
	"time"
)

// ProcessContext groups all signals belonging to one runtime process,
// keyed by (PID, name). It is what attack chains usually iterate over,
// since most chains are *per-process* (a downloader chain in PID 1234
// is independent of a downloader chain in PID 5678).
type ProcessContext struct {
	PID         int
	ProcessName string
	Key         string
	FirstSeen   time.Time
	LastSeen    time.Time
	Signals     []*Signal
}

// StaticContext groups all static (audit) signals — they have no PID,
// so they live in their own bucket.
type StaticContext struct {
	Signals []*Signal
}

// ExecutionContext is the full picture passed into chain detectors. It
// contains every per-process bucket plus the static bucket plus a
// cheap by-type index.
type ExecutionContext struct {
	Processes []*ProcessContext
	Static    *StaticContext
	All       []*Signal

	byType    map[string][]*Signal
	byKind    map[SignalKind][]*Signal
	byProcess map[string]*ProcessContext
}

// Group collects signals into an ExecutionContext. The output is
// stable: processes are sorted by FirstSeen, signals within a process
// by Timestamp.
func Group(signals []*Signal) *ExecutionContext {
	ctx := &ExecutionContext{
		Static:    &StaticContext{},
		All:       append([]*Signal(nil), signals...),
		byType:    make(map[string][]*Signal),
		byKind:    make(map[SignalKind][]*Signal),
		byProcess: make(map[string]*ProcessContext),
	}

	for _, sig := range signals {
		if sig == nil {
			continue
		}
		ctx.byType[sig.Type] = append(ctx.byType[sig.Type], sig)
		ctx.byKind[sig.Kind] = append(ctx.byKind[sig.Kind], sig)

		if sig.IsStatic() {
			ctx.Static.Signals = append(ctx.Static.Signals, sig)
			continue
		}

		key := sig.ProcessKey()
		pc, ok := ctx.byProcess[key]
		if !ok {
			pc = &ProcessContext{
				PID:         sig.PID,
				ProcessName: sig.ProcessName,
				Key:         key,
				FirstSeen:   sig.Timestamp,
				LastSeen:    sig.Timestamp,
			}
			ctx.byProcess[key] = pc
		}
		pc.Signals = append(pc.Signals, sig)
		if !sig.Timestamp.IsZero() {
			if pc.FirstSeen.IsZero() || sig.Timestamp.Before(pc.FirstSeen) {
				pc.FirstSeen = sig.Timestamp
			}
			if sig.Timestamp.After(pc.LastSeen) {
				pc.LastSeen = sig.Timestamp
			}
		}
	}

	for _, pc := range ctx.byProcess {
		sort.SliceStable(pc.Signals, func(i, j int) bool {
			a, b := pc.Signals[i], pc.Signals[j]
			if a.Timestamp.Equal(b.Timestamp) {
				return a.Type < b.Type
			}
			return a.Timestamp.Before(b.Timestamp)
		})
		ctx.Processes = append(ctx.Processes, pc)
	}

	sort.SliceStable(ctx.Processes, func(i, j int) bool {
		a, b := ctx.Processes[i], ctx.Processes[j]
		if a.FirstSeen.Equal(b.FirstSeen) {
			return a.PID < b.PID
		}
		// zero timestamps go last
		if a.FirstSeen.IsZero() {
			return false
		}
		if b.FirstSeen.IsZero() {
			return true
		}
		return a.FirstSeen.Before(b.FirstSeen)
	})

	return ctx
}

// SignalsOfType returns all signals (across all processes + static) of
// a given Type. The slice is shared with the context — do not mutate.
func (e *ExecutionContext) SignalsOfType(t string) []*Signal {
	if e == nil {
		return nil
	}
	return e.byType[t]
}

// SignalsOfKind returns all signals of a given Kind.
func (e *ExecutionContext) SignalsOfKind(k SignalKind) []*Signal {
	if e == nil {
		return nil
	}
	return e.byKind[k]
}

// HasType reports whether at least one signal of the given Type exists.
func (e *ExecutionContext) HasType(t string) bool {
	return len(e.SignalsOfType(t)) > 0
}

// HasKind reports whether at least one signal of the given Kind exists.
func (e *ExecutionContext) HasKind(k SignalKind) bool {
	return len(e.SignalsOfKind(k)) > 0
}

// Process returns the per-process bucket for the given key, or nil.
func (e *ExecutionContext) Process(key string) *ProcessContext {
	if e == nil {
		return nil
	}
	return e.byProcess[key]
}

// SignalsOfTypeInProcess returns the subset of SignalsOfType(t) that
// belong to a specific process key. Useful for "did *this* PID do X
// AND Y AND Z" chain checks.
func (e *ExecutionContext) SignalsOfTypeInProcess(key, t string) []*Signal {
	if e == nil {
		return nil
	}
	pc := e.byProcess[key]
	if pc == nil {
		return nil
	}
	out := make([]*Signal, 0, 4)
	for _, s := range pc.Signals {
		if s.Type == t {
			out = append(out, s)
		}
	}
	return out
}

// Filter returns a new slice containing the signals that match pred.
// It never returns nil for an empty result — callers can range over
// it safely.
func Filter(signals []*Signal, pred func(*Signal) bool) []*Signal {
	out := make([]*Signal, 0, len(signals))
	for _, s := range signals {
		if pred(s) {
			out = append(out, s)
		}
	}
	return out
}
