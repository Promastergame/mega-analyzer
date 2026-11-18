package dataflow

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/types"
)

type methodData struct {
	Signature       string
	Class           string
	Name            string
	Params          string
	Body            []string
	SourceBody      []string // retained representation, before parameter alias normalization
	SourceAmbiguous bool     // conflicting definitions must not produce a source proof
	Path            string
	LineStart       int
	IsStatic        bool
	IsNative        bool // declared native (JNI): no body, opaque callee
}

// classData is the hierarchy fragment required to resolve app-owned virtual
// and interface calls during backward slicing. All names are DEX descriptors.
type classData struct {
	SuperClass string
	Interfaces []string
}

type Program struct {
	mu      sync.Mutex
	config  Config
	methods map[string]methodData
	classes map[string]classData
	cache   SummaryCache
}

func NewProgram(config Config) *Program {
	defaults := DefaultConfig()
	if config.MaxMethods <= 0 {
		config.MaxMethods = defaults.MaxMethods
	}
	if config.MaxIterations <= 0 {
		config.MaxIterations = defaults.MaxIterations
	}
	if config.MaxFindings <= 0 {
		config.MaxFindings = defaults.MaxFindings
	}
	if config.MaxSliceSteps <= 0 {
		config.MaxSliceSteps = defaults.MaxSliceSteps
	}
	if config.MaxSliceDepth <= 0 {
		config.MaxSliceDepth = defaults.MaxSliceDepth
	}
	if config.MaxSliceStepsPerSink <= 0 {
		config.MaxSliceStepsPerSink = defaults.MaxSliceStepsPerSink
	}
	return &Program{
		config:  config,
		methods: make(map[string]methodData, 1024),
		classes: make(map[string]classData, 256),
	}
}

func (p *Program) SetCache(cache SummaryCache) {
	p.mu.Lock()
	p.cache = cache
	p.mu.Unlock()
}

// SetAppPackage prioritizes the application's own classes when the method
// budget truncates the slice set: app code is sliced before library code,
// so a budget hit costs library coverage first, not visibility into the
// package under review.
func (p *Program) SetAppPackage(pkg string) {
	p.mu.Lock()
	p.config.AppPackage = pkg
	p.mu.Unlock()
}

// SetExportedComponents records the manifest's effectively exported
// components; entry-point taint labels depend on them.
func (p *Program) SetExportedComponents(set map[string]struct{}) {
	p.mu.Lock()
	p.config.ExportedComponents = set
	p.mu.Unlock()
}

// prioritizeSignatures returns signatures ordered app-package first, each
// group alphabetically. A budget truncation then trims libraries, not app code.
func prioritizeSignatures(signatures []string, appPackage string) []string {
	if appPackage == "" {
		return signatures
	}
	prefix := "L" + strings.ReplaceAll(appPackage, ".", "/") + "/"
	appFirst := make([]string, 0, len(signatures))
	rest := make([]string, 0, len(signatures))
	for _, s := range signatures {
		if strings.HasPrefix(s, prefix) {
			appFirst = append(appFirst, s)
		} else {
			rest = append(rest, s)
		}
	}
	return append(appFirst, rest...)
}

func (p *Program) AddClass(path string, class *types.SmaliClass) {
	if class == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	className := normalizeClassDescriptor(class.Name)
	if className == "" {
		return
	}
	interfaces := make([]string, 0, len(class.Interfaces))
	for _, iface := range class.Interfaces {
		if normalized := normalizeClassDescriptor(iface); normalized != "" {
			interfaces = append(interfaces, normalized)
		}
	}
	p.classes[className] = classData{
		SuperClass: normalizeClassDescriptor(class.SuperClass),
		Interfaces: interfaces,
	}
	for i := range class.Methods {
		method := &class.Methods[i]
		native := method.Access.IsNative()
		if len(method.Body) == 0 && !native {
			continue
		}
		data := methodData{
			// The active parser stores class declarations in dot form while
			// invoke-* instructions retain Lpkg/Type; descriptors. Canonicalize
			// here so interprocedural joins use the same key in production.
			Signature: method.FullSignature(className), Class: className,
			Name: method.Name, Params: method.Params, Body: append([]string(nil), method.Body...),
			Path: path, LineStart: method.LineStart, IsStatic: method.Access.IsStatic(),
			IsNative: native,
		}
		data.SourceBody = data.Body
		data.Body = normalizeParameterAliases(data)
		existing, exists := p.methods[data.Signature]
		if exists {
			data.SourceAmbiguous = existing.SourceAmbiguous || !slices.Equal(existing.Body, data.Body) || existing.IsStatic != data.IsStatic || existing.IsNative != data.IsNative
		}
		if !exists || data.Path < existing.Path {
			p.methods[data.Signature] = data
		} else if data.SourceAmbiguous {
			existing.SourceAmbiguous = true
			p.methods[data.Signature] = existing
		}
	}
}

func (p *Program) Analyze(ctx context.Context) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return Result{Findings: []Finding{}, Stats: Stats{LimitReached: true, Cancelled: true}}
	}
	p.mu.Lock()
	methods := make(map[string]methodData, len(p.methods))
	for signature, method := range p.methods {
		methods[signature] = method
	}
	classes := make(map[string]classData, len(p.classes))
	for name, class := range p.classes {
		classes[name] = classData{SuperClass: class.SuperClass, Interfaces: append([]string(nil), class.Interfaces...)}
	}
	cache := p.cache
	p.mu.Unlock()

	result := Result{Findings: make([]Finding, 0, 32)}
	result.Stats.MethodsDiscovered = len(methods)
	signatures := make([]string, 0, len(methods))
	for signature := range methods {
		signatures = append(signatures, signature)
	}
	sort.Strings(signatures)
	signatures = prioritizeSignatures(signatures, p.config.AppPackage)
	if len(signatures) > p.config.MaxMethods {
		result.Stats.MethodsTruncated = len(signatures) - p.config.MaxMethods
		result.Stats.LimitReached = true
		signatures = signatures[:p.config.MaxMethods]
	}
	active := make(map[string]methodData, len(signatures))
	for _, signature := range signatures {
		active[signature] = methods[signature]
	}
	result.Stats.MethodsAnalyzed = len(active)

	// Preserve the content-cache contract for pure leaf summaries. The cache is
	// a prefilter only; evidence is always reconstructed by the backward slice.
	cacheHits, cacheMisses := prepareLeafCache(cache, active, signatures)

	// Sinks define the analysis frontier. Slice only the values they consume,
	// walking backward through register definitions, returns, fields and arrays.
	// This replaces the whole-program forward fixpoint as the production path.
	backward := analyzeBackward(ctx, active, classes, signatures, p.config)
	backward.Stats.CacheHits = cacheHits
	backward.Stats.CacheMisses = cacheMisses
	backward.Stats.MethodsDiscovered = result.Stats.MethodsDiscovered
	backward.Stats.MethodsAnalyzed = result.Stats.MethodsAnalyzed
	backward.Stats.MethodsTruncated = result.Stats.MethodsTruncated
	backward.Stats.LimitReached = backward.Stats.LimitReached || result.Stats.LimitReached
	return backward
}

// normalizeClassDescriptor accepts dot/slash names and pre-normalized DEX
// descriptors. parseInvoke emits DEX descriptors, so method signatures must
// do the same for direct calls to join their definitions.
func normalizeClassDescriptor(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, "L") && strings.HasSuffix(name, ";") {
		name = name[1 : len(name)-1]
	}
	name = strings.ReplaceAll(name, ".", "/")
	return "L" + name + ";"
}

func prepareLeafCache(cache SummaryCache, methods map[string]methodData, signatures []string) (hits, misses int) {
	if cache == nil {
		return 0, 0
	}
	for _, signature := range signatures {
		method := methods[signature]
		if !cacheSafe(method, methods) {
			continue
		}
		if _, ok := cache.Get(signature, method.Body); ok {
			hits++
			continue
		}
		misses++
		// The backward engine does not consume summaries, but keeping a framed
		// cache entry preserves warm-run accounting and future slice prefilters.
		if data, err := json.Marshal(summary{Signature: signature}); err == nil {
			cache.Put(signature, method.Body, data)
		}
	}
	return hits, misses
}

func analyzeMethod(method methodData, summaries map[string]summary, fields map[string]fact) summary {
	result := summary{Signature: method.Signature, FieldWrites: make(map[string]fact)}
	registers := make(map[string]fact, 16)
	// IPC lifecycle callbacks receive attacker-controlled parameters (audit
	// C2): seed them with labels in addition to the abstract parameter bit.
	entryTaints := entryPointTaints(method)
	for register, parameter := range parameterRegisters(method.Params, method.IsStatic) {
		value := fact{Params: uint64(1) << parameter}
		for _, taint := range entryTaints {
			if taint.param != parameter {
				continue
			}
			value.Labels |= taint.labels
			value.Sources = sourceMap(taint.labels, method.Signature+" [IPC entry point]")
			value.Depth += entryPointDepthPenalty
		}
		registers[register] = value
	}
	var pending fact
	hasPending := false
	// Coarse array model (audit C3): one merged fact per array register.
	// Element indexing is not tracked — every aget sees the union of all
	// aput writes. Imprecise but sound for taint purposes.
	arrays := make(map[string]fact, 4)
	for index, raw := range method.Body {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, ".") || strings.HasPrefix(line, ":") {
			continue
		}
		lineNumber := method.LineStart + index
		fieldsList := strings.Fields(strings.ReplaceAll(line, ",", ""))
		if len(fieldsList) >= 2 && strings.HasPrefix(fieldsList[0], "move-result") {
			if hasPending {
				registers[fieldsList[1]] = cloneFact(pending)
			} else {
				delete(registers, fieldsList[1])
			}
			hasPending = false
			continue
		}
		if call, ok := parseInvoke(line); ok {
			args := argumentFacts(call, registers)
			allRegisters := make([]fact, 0, len(call.registers))
			for _, register := range call.registers {
				allRegisters = append(allRegisters, registers[register])
			}
			pending = fact{}
			hasPending = true
			if model, ok := sourceFor(call.signature); ok {
				pending.Labels = model.label
				pending.Sources = sourceMap(model.label, call.signature)
			} else if model, ok := sanitizerFor(call.signature); ok {
				if model.drop {
					// Destructive sanitizer (numeric parse): the value becomes
					// a primitive, no attacker string can survive (audit C4).
					pending = fact{}
				} else {
					for _, arg := range args {
						pending = mergeFacts(pending, arg)
					}
					pending.Sanitized |= model.kind
				}
			} else if callee, ok := summaries[call.signature]; ok {
				pending = substitute(callee.Return, args)
				pending.Depth++
				for field, value := range callee.FieldWrites {
					result.FieldWrites[field] = mergeFacts(result.FieldWrites[field], substitute(value, args))
				}
				for _, flow := range callee.Sinks {
					mapped := flow
					mapped.Fact = substitute(flow.Fact, args)
					mapped.Fact.Depth++
					result.Sinks = appendSink(result.Sinks, mapped)
				}
			} else if isValuePropagator(call.signature) {
				for _, value := range allRegisters {
					pending = mergeFacts(pending, value)
				}
			}

			if isIntentPut(call.signature) && len(call.registers) > 0 {
				receiver := registers[call.registers[0]]
				if len(args) > 0 {
					receiver = mergeFacts(receiver, args[len(args)-1])
				}
				registers[call.registers[0]] = receiver
				pending = receiver
			}
			if strings.Contains(call.signature, "StringBuilder;->append") && len(call.registers) > 0 {
				receiver := registers[call.registers[0]]
				for _, arg := range args {
					receiver = mergeFacts(receiver, arg)
				}
				registers[call.registers[0]] = receiver
				pending = receiver
			}
			// Canonicalization neither authorizes a path nor mutates its receiver.
			// Return-value propagation is handled by the ordinary propagator model.
			// A signature can model several sinks (e.g. sendBroadcast is both
			// data exposure and interception); evaluate every match.
			for _, sink := range sinksFor(call.signature) {
				if (sink.param >= 0 && sink.param < len(args)) || (sink.param == -1 && !call.isStatic) {
					value := fact{}
					if sink.param >= 0 {
						value = args[sink.param]
					} else if len(call.registers) > 0 {
						value = registers[call.registers[0]]
					}
					value.Labels &= sink.labels
					if value.Labels != 0 || value.Params != 0 {
						if sink.sanitizer == SanitizerNone || value.Sanitized&sink.sanitizer == 0 {
							result.Sinks = appendSink(result.Sinks, sinkFlow{
								Sink: call.signature, Category: sink.category, Severity: sink.severity,
								Sanitizer: sink.sanitizer, Fact: value,
								Location: Location{File: method.Path, Line: lineNumber, Method: method.Signature},
							})
						}
					}
				}
			}
			continue
		}
		hasPending = false
		// A caught exception object is not attacker-controlled input by itself.
		// Any attacker data embedded in its message must be established by an
		// explicit source/propagation path, not seeded at move-exception.
		if fieldsList[0] == "move-exception" && len(fieldsList) >= 2 {
			delete(registers, fieldsList[1])
			delete(arrays, fieldsList[1])
			continue
		}
		if len(fieldsList) >= 3 && strings.HasPrefix(fieldsList[0], "move") {
			registers[fieldsList[1]] = cloneFact(registers[fieldsList[2]])
			delete(arrays, fieldsList[1])
			continue
		}
		if len(fieldsList) >= 2 && (strings.HasPrefix(fieldsList[0], "const") || fieldsList[0] == "new-instance" || strings.HasPrefix(fieldsList[0], "new-array")) {
			delete(registers, fieldsList[1])
			delete(arrays, fieldsList[1])
			continue
		}
		if len(fieldsList) >= 3 && strings.HasPrefix(fieldsList[0], "aget") {
			// aget vA, vB, vC → vA := element of array vB.
			value := cloneFact(arrays[fieldsList[2]])
			value.ViaField = true
			registers[fieldsList[1]] = value
			delete(arrays, fieldsList[1])
			continue
		}
		if len(fieldsList) >= 3 && strings.HasPrefix(fieldsList[0], "aput") {
			// aput vA, vB, vC → array vB := merge(element vA).
			arrays[fieldsList[2]] = mergeFacts(arrays[fieldsList[2]], registers[fieldsList[1]])
			continue
		}
		if len(fieldsList) >= 3 && (strings.HasPrefix(fieldsList[0], "iget") || strings.HasPrefix(fieldsList[0], "sget")) {
			field := fieldsList[len(fieldsList)-1]
			value := cloneFact(fields[field])
			value.ViaField = true
			registers[fieldsList[1]] = value
			continue
		}
		if len(fieldsList) >= 3 && (strings.HasPrefix(fieldsList[0], "iput") || strings.HasPrefix(fieldsList[0], "sput")) {
			field := fieldsList[len(fieldsList)-1]
			result.FieldWrites[field] = mergeFacts(result.FieldWrites[field], registers[fieldsList[1]])
			continue
		}
		if len(fieldsList) >= 2 && strings.HasPrefix(fieldsList[0], "return") && fieldsList[0] != "return-void" {
			result.Return = mergeFacts(result.Return, registers[fieldsList[1]])
		}
	}
	if len(result.FieldWrites) == 0 {
		result.FieldWrites = nil
	}
	return result
}

func parameterRegisters(descriptor string, static bool) map[string]int {
	result := make(map[string]int)
	register := 0
	if !static {
		register = 1
	}
	for parameter, width := range parameterWidths(descriptor) {
		if parameter >= 63 {
			break
		}
		for offset := 0; offset < width; offset++ {
			result["p"+strconv.Itoa(register+offset)] = parameter
		}
		register += width
	}
	return result
}

func argumentFacts(call invokeCall, registers map[string]fact) []fact {
	start := 0
	if !call.isStatic {
		start = 1
	}
	widths := parameterWidths(call.params)
	result := make([]fact, 0, len(widths))
	registerIndex := start
	for _, width := range widths {
		if registerIndex >= len(call.registers) {
			result = append(result, fact{})
		} else {
			result = append(result, registers[call.registers[registerIndex]])
		}
		registerIndex += width
	}
	return result
}

func substitute(value fact, args []fact) fact {
	result := cloneFact(value)
	result.Params = 0
	for index := 0; index < 64; index++ {
		if value.Params&(uint64(1)<<index) == 0 {
			continue
		}
		if index < len(args) {
			result = mergeFacts(result, args[index])
		}
	}
	return result
}

func mergeFacts(left, right fact) fact {
	if isEmptyFact(left) {
		return cloneFact(right)
	}
	if isEmptyFact(right) {
		return cloneFact(left)
	}
	result := cloneFact(left)
	result.Labels |= right.Labels
	result.Params |= right.Params
	result.Sanitized &= right.Sanitized
	result.ViaField = left.ViaField || right.ViaField
	if right.Depth < result.Depth {
		result.Depth = right.Depth
	}
	if len(right.Sources) > 0 {
		if result.Sources == nil {
			result.Sources = make(map[Label]string, len(right.Sources))
		}
		for label, source := range right.Sources {
			if current := result.Sources[label]; current == "" || source < current {
				result.Sources[label] = source
			}
		}
	}
	return result
}

func cloneFact(value fact) fact {
	result := value
	if value.Sources != nil {
		result.Sources = make(map[Label]string, len(value.Sources))
		for label, source := range value.Sources {
			result.Sources[label] = source
		}
	}
	return result
}

func isEmptyFact(value fact) bool {
	return value.Labels == 0 && value.Params == 0 && len(value.Sources) == 0
}

func sourceMap(labels Label, source string) map[Label]string {
	result := make(map[Label]string)
	for bit := Label(1); bit <= LabelPII; bit <<= 1 {
		if labels&bit != 0 {
			result[bit] = source
		}
	}
	return result
}

func aggregateFields(summaries map[string]summary) map[string]fact {
	fields := make(map[string]fact)
	for _, item := range summaries {
		for field, value := range item.FieldWrites {
			fields[field] = mergeFacts(fields[field], value)
		}
	}
	return fields
}

func appendSink(flows []sinkFlow, candidate sinkFlow) []sinkFlow {
	for i := range flows {
		current := &flows[i]
		if current.Sink == candidate.Sink && current.Location == candidate.Location && current.Fact.Labels == candidate.Fact.Labels && current.Fact.Params == candidate.Fact.Params {
			current.Fact = mergeFacts(current.Fact, candidate.Fact)
			return flows
		}
	}
	return append(flows, candidate)
}

func cacheSafe(method methodData, methods map[string]methodData) bool {
	for _, line := range method.Body {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "iget") || strings.HasPrefix(trimmed, "sget") || strings.HasPrefix(trimmed, "iput") || strings.HasPrefix(trimmed, "sput") {
			return false
		}
		if call, ok := parseInvoke(trimmed); ok {
			if _, internal := methods[call.signature]; internal {
				return false
			}
		}
	}
	return true
}

func labelName(label Label) string {
	switch label {
	case LabelUserInput:
		return "user_input"
	case LabelIntent:
		return "android_intent"
	case LabelNetwork:
		return "network_response"
	case LabelFile:
		return "file_data"
	case LabelDatabase:
		return "database_data"
	case LabelLocation:
		return "location"
	case LabelCredential:
		return "credential"
	case LabelPII:
		return "pii"
	default:
		return "unknown"
	}
}
