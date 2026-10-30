package apkloader

import (
	"context"
	"sort"
	"strings"
)

// ClassInitializationState is the deterministic state of an app-defined class
// during bounded static reconstruction.
type ClassInitializationState string

const (
	ClassUninitialized ClassInitializationState = "uninitialized"
	ClassInitializing  ClassInitializationState = "initializing"
	ClassInitialized   ClassInitializationState = "initialized"
	ClassUnavailable   ClassInitializationState = "unavailable"
)

// OwnedClassInit is parser-detached class-initialization metadata.
type OwnedClassInit struct {
	ClassName    string
	SuperClass   string
	Initializer  string
	Dependencies []string
}

// OwnedClassInitResolver is immutable and safe for concurrent reads.
type OwnedClassInitResolver struct {
	classes map[string]OwnedClassInit
	ordered []string
}

func NewOwnedClassInitResolver(classes []OwnedClassInit) *OwnedClassInitResolver {
	r := &OwnedClassInitResolver{classes: make(map[string]OwnedClassInit, len(classes))}
	for _, class := range classes {
		if class.ClassName == "" {
			continue
		}
		class.Dependencies = sortedUniqueStrings(class.Dependencies)
		r.classes[class.ClassName] = class
	}
	for name := range r.classes {
		r.ordered = append(r.ordered, name)
	}
	sort.Strings(r.ordered)
	return r
}

func (r *OwnedClassInitResolver) Resolve(className string) (OwnedClassInit, bool) {
	if r == nil {
		return OwnedClassInit{}, false
	}
	class, ok := r.classes[className]
	class.Dependencies = append([]string(nil), class.Dependencies...)
	return class, ok
}

func (r *OwnedClassInitResolver) Classes() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.ordered...)
}

// ClassInitializationOutcome records a bounded initialization decision.
type ClassInitializationOutcome struct {
	ClassName       string                   `json:"class"`
	Initializer     string                   `json:"initializer,omitempty"`
	SuperClass      string                   `json:"superclass,omitempty"`
	Dependencies    []string                 `json:"dependencies,omitempty"`
	State           ClassInitializationState `json:"state"`
	Reason          string                   `json:"reason,omitempty"`
	CommittedFields int                      `json:"committed_fields,omitempty"`
}

// ClassInitializationMetrics summarizes the dependency-aware pass.
type ClassInitializationMetrics struct {
	Attempted       int `json:"attempted,omitempty"`
	Initialized     int `json:"initialized,omitempty"`
	Unavailable     int `json:"unavailable,omitempty"`
	Cycles          int `json:"cycles,omitempty"`
	Rollbacks       int `json:"rollbacks,omitempty"`
	Budgets         int `json:"budgets_exhausted,omitempty"`
	CommittedFields int `json:"committed_fields,omitempty"`
}

// StaticReconstructionResult contains the immutable final snapshot and proof outcomes.
type StaticReconstructionResult struct {
	Resolver *OwnedStaticResolver
	Outcomes []ClassInitializationOutcome
	Metrics  ClassInitializationMetrics
}

// ReconstructStaticFieldsWithClasses initializes only the supplied app-defined
// class closure. Dependencies and superclasses are initialized first; writes
// commit atomically only after a normal return-void.
func ReconstructStaticFieldsWithClasses(ctx context.Context, methods *OwnedMethodResolver, classes *OwnedClassInitResolver, initial *OwnedStaticResolver, config DalvikEmulatorConfig) StaticReconstructionResult {
	if ctx == nil {
		ctx = context.Background()
	}
	values := initial.Values()
	result := StaticReconstructionResult{}
	if methods == nil || classes == nil {
		result.Resolver = NewOwnedStaticResolver(values)
		return result
	}
	config = normalizeDalvikEmulatorConfig(config)
	states := make(map[string]ClassInitializationState)
	outcomes := make(map[string]ClassInitializationOutcome)
	stack := make([]string, 0, config.MaxCallDepth+2)

	var initialize func(string) bool
	initialize = func(className string) bool {
		if err := ctx.Err(); err != nil {
			return false
		}
		switch states[className] {
		case ClassInitialized:
			return true
		case ClassUnavailable:
			return false
		case ClassInitializing:
			result.Metrics.Cycles++
			cycleStart := 0
			for i := range stack {
				if stack[i] == className {
					cycleStart = i
					break
				}
			}
			for _, member := range stack[cycleStart:] {
				states[member] = ClassUnavailable
				outcome := outcomes[member]
				outcome.State = ClassUnavailable
				outcome.Reason = "class initialization cycle"
				outcomes[member] = outcome
			}
			return false
		}
		class, ok := classes.Resolve(className)
		if !ok {
			return true
		}
		result.Metrics.Attempted++
		states[className] = ClassInitializing
		stack = append(stack, className)
		outcome := ClassInitializationOutcome{ClassName: className, Initializer: class.Initializer, SuperClass: class.SuperClass, Dependencies: append([]string(nil), class.Dependencies...), State: ClassInitializing}
		outcomes[className] = outcome

		dependencies := append([]string(nil), class.Dependencies...)
		if class.SuperClass != "" {
			if _, exists := classes.Resolve(class.SuperClass); exists {
				dependencies = append(dependencies, class.SuperClass)
			}
		}
		dependencies = sortedUniqueStrings(dependencies)
		for _, dependency := range dependencies {
			if dependency == className {
				continue
			}
			if _, exists := classes.Resolve(dependency); exists && !initialize(dependency) {
				if states[className] != ClassUnavailable {
					states[className] = ClassUnavailable
					outcome.State = ClassUnavailable
					outcome.Reason = "unavailable class dependency " + dependency
					outcomes[className] = outcome
				}
				stack = stack[:len(stack)-1]
				return false
			}
		}

		if class.Initializer == "" {
			states[className] = ClassInitialized
			outcome.State = ClassInitialized
			outcomes[className] = outcome
			stack = stack[:len(stack)-1]
			result.Metrics.Initialized++
			return true
		}
		method, ok := methods.Resolve(class.Initializer)
		if !ok || len(method.RawInsns) == 0 {
			states[className] = ClassUnavailable
			outcome.State = ClassUnavailable
			outcome.Reason = "owned class initializer unavailable"
			outcomes[className] = outcome
			stack = stack[:len(stack)-1]
			result.Metrics.Unavailable++
			return false
		}

		frame := newClassInitializerExecution(ctx, method, methods, NewOwnedStaticResolver(values), config)
		frame.run()
		if frame.returned && frame.result.Status == DalvikEmulationNoOutput && frame.result.StopReason == "void return" {
			for field, value := range frame.staticTxn {
				values[field] = value
			}
			states[className] = ClassInitialized
			outcome.State = ClassInitialized
			outcome.CommittedFields = len(frame.staticTxn)
			outcomes[className] = outcome
			result.Metrics.Initialized++
			result.Metrics.CommittedFields += len(frame.staticTxn)
			stack = stack[:len(stack)-1]
			return true
		}
		states[className] = ClassUnavailable
		outcome.State = ClassUnavailable
		outcome.Reason = frame.result.StopReason
		outcomes[className] = outcome
		result.Metrics.Unavailable++
		result.Metrics.Rollbacks++
		if frame.result.Status == DalvikEmulationBudgetExhausted {
			result.Metrics.Budgets++
		}
		stack = stack[:len(stack)-1]
		return false
	}

	for _, className := range classes.Classes() {
		initialize(className)
	}
	for _, className := range classes.Classes() {
		if outcome, ok := outcomes[className]; ok {
			result.Outcomes = append(result.Outcomes, outcome)
		}
	}
	result.Resolver = NewOwnedStaticResolver(values)
	return result
}

func newClassInitializerExecution(ctx context.Context, method OwnedDEXMethod, resolver *OwnedMethodResolver, statics *OwnedStaticResolver, config DalvikEmulatorConfig) *dalvikExecution {
	mir := LowerToMIR(method.RawInsns)
	for i := range mir {
		if args := method.InvokeArgs[mir[i].Offset]; len(args) > 0 {
			if n := len(args); n <= len(mir[i].ArgsData) {
				mir[i].ArgsLen = uint8(n)
				copy(mir[i].ArgsData[:], args)
			}
		}
	}
	session := &dalvikEmulationSession{resolver: resolver, statics: statics, active: make(map[string]struct{}), cache: make(map[string]emuValue), eligibility: make(map[string]methodEligibility)}
	frame := &dalvikExecution{
		ctx: ctx, method: method, config: config, mir: mir,
		offsets: make(map[uint32]int, len(mir)), registers: make([]emuValue, int(method.RegistersSize)), visits: make(map[uint32]int),
		result: DalvikEmulationResult{Status: DalvikEmulationNoOutput}, session: session,
		staticTxn: make(map[string]OwnedStaticValue), allowStaticWrites: true,
	}
	for i := range mir {
		frame.offsets[mir[i].Offset] = i
	}
	return frame
}

func classNameFromMemberDescriptor(descriptor string) string {
	if i := strings.Index(descriptor, "->"); i > 0 {
		return descriptor[:i]
	}
	return ""
}

func sortedUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
