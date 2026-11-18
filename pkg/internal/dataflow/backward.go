package dataflow

import (
	"context"
	"sort"
	"strconv"
	"strings"
)

const maxSliceDepth = 48

type sliceHit struct {
	valueType string // current value upper bound, NOT the type of its taint origin
	source    string
	labels    Label
	steps     []Step
	param     int
	field     bool
	sanitized Sanitizer
	array     *arrayQuery // symbolic projection of an array parameter
}

type sliceState struct {
	incompatibleCasts                                                             int
	methods                                                                       map[string]methodData
	classes                                                                       map[string]classData
	fieldWrites                                                                   map[string][]fieldWrite
	callers                                                                       map[string][]callReference
	visited                                                                       map[string]struct{}
	ctx                                                                           context.Context
	children                                                                      map[string][]string
	descendantCache                                                               map[string][]string
	calleeCache                                                                   map[string][]string
	returnScopes                                                                  map[string]int
	arrayRefs                                                                     map[arrayRefPoint]arrayRefSet
	steps, maxSteps, maxDepth                                                     int
	truncated                                                                     bool
	sinkSteps, maxSinkSteps                                                       int
	sinkTruncated                                                                 bool
	cfgs                                                                          map[string]*methodCFG
	cfgNodes, cfgEdges, cfgIncomplete, cfgQueries, cfgCacheHits, unreachableSinks int
	// exportedComponents holds the dotted names of manifest components with
	// effective export. nil/empty = unknown (legacy behavior); a known
	// non-exported component is labeled as app-internal, not an IPC surface.
	exportedComponents map[string]struct{}
}

type callReference struct {
	caller             string
	index              int
	call               invokeCall
	unresolvedDispatch bool
}

type fieldWrite struct {
	method   string
	line     int
	register string
}

func analyzeBackward(ctx context.Context, active map[string]methodData, classes map[string]classData, signatures []string, config Config) (result Result) {
	result = Result{Findings: make([]Finding, 0, 32)}
	result.Stats.MethodsDiscovered = len(active)
	result.Stats.MethodsAnalyzed = len(active)
	result.Stats.Iterations = 1
	state := &sliceState{methods: active, classes: classes, ctx: ctx, maxSteps: config.MaxSliceSteps, maxDepth: config.MaxSliceDepth, maxSinkSteps: config.MaxSliceStepsPerSink, exportedComponents: config.ExportedComponents}
	if state.maxDepth <= 0 {
		state.maxDepth = maxSliceDepth
	}
	defer func() {
		result.Stats.SliceSteps = state.steps
		result.Stats.SliceLimitReached = state.truncated
		result.Stats.Cancelled = ctx.Err() != nil
		result.Stats.LimitReached = result.Stats.LimitReached || state.truncated || result.Stats.Cancelled
		result.Stats.Findings = len(result.Findings)
		result.Stats.InformationalFlows = len(result.Observations)
		result.Stats.CFGMethods = len(state.cfgs)
		result.Stats.IncompatibleCastFlowsPruned = state.incompatibleCasts
		result.Stats.CFGNodes, result.Stats.CFGEdges = state.cfgNodes, state.cfgEdges
		result.Stats.CFGIncompleteMethods = state.cfgIncomplete
		result.Stats.ReachingDefinitionSteps, result.Stats.ReachingDefinitionCacheHits = state.cfgQueries, state.cfgCacheHits
		result.Stats.UnreachableSinksSkipped = state.unreachableSinks
		result.Stats.LimitReached = result.Stats.LimitReached || state.cfgIncomplete > 0
	}()
	state.buildAuditIndexes(signatures)
	seen := make(map[string]struct{})

	// Two-pass scheduling. Pass 1 collects every sink call site in file order;
	// pass 2 traces them by sensitivity rank. The old single pass walked files
	// top-to-bottom, so one large low-value method could drain the whole-run
	// step budget before later critical sinks were ever traced (the 2026-11-03
	// corpus run hit the slicing ceiling and truncated 108 slices on
	// Приват.apk). Priority order means the untraced remainder is the least
	// sensitive work, not whatever happened to sort last by file name.
	work := collectSinkWork(ctx, signatures, active)
	sort.SliceStable(work, func(i, j int) bool {
		if work[i].rank != work[j].rank {
			return work[i].rank < work[j].rank
		}
		if work[i].signature != work[j].signature {
			return work[i].signature < work[j].signature
		}
		if work[i].index != work[j].index {
			return work[i].index < work[j].index
		}
		return work[i].sink.param < work[j].sink.param
	})
	for _, item := range work {
		if state.stopped() {
			result.Stats.LimitReached = true
			break
		}
		signature, index, call, sink := item.signature, item.index, item.call, item.sink
		method := active[signature]
		if !state.reachableInstruction(signature, index) {
			state.unreachableSinks++
			continue
		}
		register := sinkArgumentRegister(call, sink.param)
		if register == "" {
			continue
		}
		state.visited = make(map[string]struct{})
		state.sinkSteps, state.sinkTruncated = 0, false
		result.Stats.SinksVisited++
		hits := state.traceCallArgument(signature, index-1, call, sink.param, 0)
		if state.sinkTruncated {
			result.Stats.SlicesTruncated++
		}
		result.Stats.Flows += len(hits)
		for _, hit := range hits {
			labels := hit.labels & sink.labels
			if labels == 0 || (sink.sanitizer != SanitizerNone && hit.sanitized&sink.sanitizer != 0) {
				continue
			}
			line := method.LineStart + index
			key := sink.category + "\x00" + hit.source + "\x00" + call.signature + "\x00" + signature + "\x00" + method.Path + "\x00" + strconv.Itoa(line)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			path := append([]Step(nil), hit.steps...)
			path = append(path, Step{Method: signature, Type: "sink", Line: line})
			for i := range path {
				if owner, ok := active[path[i].Method]; ok {
					path[i].File = owner.Path
				}
			}
			confidence := sliceConfidence(path, hit.field)
			informational := sink.category == "log_data_exposure" && labels&(LabelPII|LabelCredential|LabelLocation) == 0
			category, severity := sink.category, sink.severity
			if informational {
				category = "untrusted_log_input"
				severity = "low"
			}
			finding := Finding{
				Source: hit.source, Sink: call.signature, Category: category,
				ExploitChain: exploitChainName(category, labels),
				Label:        labels, Severity: severity, Confidence: confidence,
				Location: Location{File: method.Path, Line: line, Method: signature}, Path: path,
			}
			if informational {
				if len(result.Observations) < config.MaxFindings {
					result.Observations = append(result.Observations, finding)
				} else {
					result.Stats.ObservationsOmitted++
				}
				continue
			}
			result.Findings = append(result.Findings, finding)
			if len(result.Findings) >= config.MaxFindings {
				result.Stats.LimitReached = true
				result.Stats.Findings = len(result.Findings)
				return result
			}
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		left, right := result.Findings[i], result.Findings[j]
		if left.Location.File != right.Location.File {
			return left.Location.File < right.Location.File
		}
		if left.Location.Line != right.Location.Line {
			return left.Location.Line < right.Location.Line
		}
		return left.Sink < right.Sink
	})
	result.Stats.Findings = len(result.Findings)
	return result
}

// sinkWork is one sink call site scheduled for backward tracing.
type sinkWork struct {
	signature string
	index     int
	call      invokeCall
	sink      sinkModel
	rank      int
}

// sinkRank orders the trace queue: severity first (critical → low), and
// logging sinks last — when the run budget runs out mid-corpus, the leftover
// untraced work must be the least sensitive slices. log_data_exposure already
// downgrades to an informational observation when its labels are weak, so its
// full-finding form also waits behind the actionable categories.
func sinkRank(sink sinkModel) int {
	if sink.category == "log_data_exposure" {
		return 4
	}
	switch sink.severity {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	default:
		return 3
	}
}

// collectSinkWork walks methods in file order and records every modeled sink
// argument that a slice could be built for. Pure collection: no slice budget
// is spent here, so cancellation is the only early exit.
func collectSinkWork(ctx context.Context, signatures []string, active map[string]methodData) []sinkWork {
	work := make([]sinkWork, 0, 256)
	for _, signature := range signatures {
		if ctx.Err() != nil {
			return work
		}
		method := active[signature]
		for index, raw := range method.Body {
			call, ok := parseInvoke(raw)
			if !ok {
				continue
			}
			for _, sink := range sinksFor(call.signature) {
				if sinkArgumentRegister(call, sink.param) == "" {
					continue
				}
				work = append(work, sinkWork{
					signature: signature, index: index, call: call,
					sink: sink, rank: sinkRank(sink),
				})
			}
		}
	}
	return work
}

func (s *sliceState) traceRegister(signature string, before int, register string, depth int) []sliceHit {
	if register == "" {
		return nil
	}
	if s.sliceStopped() {
		return nil
	}
	limit := s.maxDepth
	if limit <= 0 {
		limit = maxSliceDepth
	}
	if depth > limit {
		s.truncated = true
		s.sinkTruncated = true
		return nil
	}
	s.steps++
	s.sinkSteps++
	visitKey := signature + "\x00" + strconv.Itoa(before) + "\x00" + register
	if _, ok := s.visited[visitKey]; ok {
		return nil
	}
	s.visited[visitKey] = struct{}{}
	defer delete(s.visited, visitKey)

	method, ok := s.methods[signature]
	if !ok {
		return nil
	}

	if before >= len(method.Body) {
		before = len(method.Body) - 1
	}

	definitions, _ := s.reachingDefinitions(signature, before, register)
	var hits []sliceHit
	for _, index := range definitions.indices {
		if s.sliceStopped() {
			break
		}
		hits = append(hits, s.traceDefinition(signature, method, index, register, depth)...)
	}
	if definitions.entry && !s.sliceStopped() {
		hits = append(hits, s.traceParameter(signature, method, register, depth)...)
	}
	return uniqueSliceHits(hits)
}

func (s *sliceState) traceDefinition(signature string, method methodData, index int, register string, depth int) (resultHits []sliceHit) {
	node := s.cfg(signature).nodes[index]
	if node == nil {
		return nil
	}
	lineNumber := method.LineStart + index
	fields, op := node.fields, node.op
	if node.call != nil && modeledReceiverMutation(*node.call) && node.call.registers[0] == register {
		call := *node.call
		var hits []sliceHit
		// Constructors establish state; append preserves the prior receiver too.
		start := 1
		if strings.Contains(call.signature, ";->append(") {
			start = 0
		}
		for _, arg := range call.registers[start:] {
			hits = append(hits, s.traceRegister(signature, index-1, arg, depth+1)...)
		}
		owner := strings.SplitN(call.signature, "->", 2)[0]
		for i := range hits {
			hits[i].valueType = owner
		}
		return addPropagationStep(uniqueSliceHits(hits), signature, lineNumber)
	}
	switch {
	case strings.HasPrefix(op, "move-result"):
		callIndex, call, found := previousInvoke(method.Body, index-1)
		if !found {
			return nil
		}
		// A value conversion changes the CURRENT type. A Parcelable taint
		// origin can legitimately reach a String via String.valueOf/toString.
		// Declared Object returns deliberately lose precision rather than
		// reusing the input type and pruning a possible flow unsoundly.
		defer func() {
			typ := ""
			if at := strings.LastIndexByte(call.signature, ')'); at >= 0 {
				typ = call.signature[at+1:]
			}
			for i := range resultHits {
				resultHits[i].valueType = typ
			}
		}()
		if source, ok := sourceFor(call.signature); ok {
			if containerReadSource(call.signature) && !call.isStatic && len(call.registers) > 0 {
				hits := s.traceRegister(signature, callIndex-1, call.registers[0], depth+1)
				if len(hits) > 0 {
					return addPropagationStep(hits, signature, method.LineStart+callIndex)
				}
				return []sliceHit{{source: "[unverified container origin] " + call.signature,
					labels: source.label, param: -1,
					steps: []Step{{Method: signature, Type: "source", Line: method.LineStart + callIndex}}}}
			}
			return []sliceHit{{source: call.signature, labels: source.label, param: -1,
				steps: []Step{{Method: signature, Type: "source", Line: method.LineStart + callIndex}}}}
		}
		if sanitizer, ok := sanitizerFor(call.signature); ok {
			if sanitizer.drop {
				return nil
			}
			hits := s.traceCallValues(signature, callIndex-1, call, depth+1)
			for i := range hits {
				hits[i].sanitized |= sanitizer.kind
			}
			return addPropagationStep(hits, signature, lineNumber)
		}
		// JNI bridge first: a native body is opaque (no returns to trace),
		// so resolveCallees must not claim it — taint flows args → result.
		if s.isNativeMethod(call.signature) {
			hits := s.traceCallValues(signature, callIndex-1, call, depth+1)
			return addBridgeStep(hits, signature, lineNumber)
		}
		if callees := s.resolveCallees(call); len(callees) > 0 {
			var hits []sliceHit
			for _, calleeSignature := range callees {
				if s.sliceStopped() {
					break
				}
				hits = append(hits, s.traceReturns(s.methods[calleeSignature], depth+1)...)
			}
			if isDynamicDispatch(call.opcode) && len(callees) > 1 {
				hits = addSliceStep(hits, Step{Method: signature, Type: "unresolved_dispatch", Line: method.LineStart + callIndex})
			}
			return s.bindCalleeParams(signature, callIndex-1, call, hits, depth+1)
		}
		if isValuePropagator(call.signature) || isIntentPut(call.signature) {
			hits := s.traceCallValues(signature, callIndex-1, call, depth+1)
			return addPropagationStep(hits, signature, lineNumber)
		}
		return nil
	case op == "check-cast" && len(fields) >= 3:
		hits := s.traceRegister(signature, index-1, register, depth+1)
		out := hits[:0]
		for _, hit := range hits {
			if definitelyDisjointPlatformTypes(hit.valueType, fields[2]) {
				s.incompatibleCasts++
				continue
			}
			hit.valueType = fields[2]
			out = append(out, hit)
		}
		return addPropagationStep(out, signature, lineNumber)
	case strings.HasPrefix(op, "move") && len(fields) >= 3:
		return addPropagationStep(s.traceRegister(signature, index-1, fields[2], depth+1), signature, lineNumber)
	case strings.HasPrefix(op, "aget") && len(fields) >= 4:
		arrayReg, indexReg := fields[2], fields[3]
		value, known := s.arrayIndex(signature, index-1, indexReg, depth+1, nil)
		hits := s.traceArrayRegister(signature, index-1, arrayReg, arrayQuery{element: true, index: value, known: known}, depth+1)
		return addPropagationStep(hits, signature, lineNumber)
	case strings.HasPrefix(op, "iget") || strings.HasPrefix(op, "sget"):
		field := fields[len(fields)-1]
		var hits []sliceHit
		for _, write := range s.fieldWrites[field] {
			if s.sliceStopped() {
				break
			}
			for _, hit := range s.traceRegister(write.method, write.line-1, write.register, depth+1) {
				hit.field = true
				hits = append(hits, hit)
			}
		}
		return addPropagationStep(hits, signature, lineNumber)
	case strings.HasPrefix(op, "const") || op == "new-instance" || strings.HasPrefix(op, "new-array") || op == "move-exception":
		return nil
	default:
		if (op == "check-cast" || op == "instance-of") && len(fields) >= 2 {
			return s.traceRegister(signature, index-1, register, depth+1)
		}
		if len(fields) >= 3 {
			var hits []sliceHit
			for _, sourceReg := range fields[2:] {
				if isRegister(sourceReg) {
					hits = append(hits, s.traceRegister(signature, index-1, sourceReg, depth+1)...)
				}
			}
			return addPropagationStep(hits, signature, lineNumber)
		}
	}

	return nil
}

func (s *sliceState) traceParameter(signature string, method methodData, register string, depth int) []sliceHit {
	if param, ok := parameterForRegister(method, register); ok {
		for _, seed := range entryPointTaints(method) {
			if seed.param == param {
				return []sliceHit{{source: signature + " " + entryPointLabel(signature, s.exportedComponents), labels: seed.labels, param: -1,
					steps: []Step{{Method: signature, Type: "source", Line: method.LineStart}}, field: true}}
			}
		}
		if s.returnScopes[signature] > 0 {
			return []sliceHit{{param: param}}
		}
		var hits []sliceHit
		for _, ref := range s.callers[signature] {
			if s.sliceStopped() {
				break
			}
			callerRegister := callArgumentRegister(ref.call, param)
			if callerRegister == "" {
				continue
			}
			bound := s.traceCallArgument(ref.caller, ref.index-1, ref.call, param, depth+1)
			stepType := "propagate"
			if ref.unresolvedDispatch {
				stepType = "unresolved_dispatch"
			}
			hits = append(hits, addSliceStep(bound, Step{Method: ref.caller, Type: stepType, Line: s.methods[ref.caller].LineStart + ref.index})...)
		}
		if len(hits) > 0 {
			return hits
		}
		return []sliceHit{{param: param}}
	}

	return nil
}

func (s *sliceState) traceReturns(method methodData, depth int) []sliceHit {
	if s.sliceStopped() {
		return nil
	}
	if s.returnScopes == nil {
		s.returnScopes = make(map[string]int)
	}
	// A return is summarized symbolically, then bound at THIS call site. Do not
	// import taint from every other caller of the same identity/helper method.
	s.returnScopes[method.Signature]++
	defer func() { s.returnScopes[method.Signature]-- }()
	var hits []sliceHit
	for index, raw := range method.Body {
		fields := smaliFields(cleanSmali(raw))
		if len(fields) >= 2 && strings.HasPrefix(fields[0], "return") && fields[0] != "return-void" {
			if !s.reachableInstruction(method.Signature, index) {
				continue
			}
			hits = append(hits, addSliceStep(s.traceRegister(method.Signature, index-1, fields[1], depth+1),
				Step{Method: method.Signature, Type: "return", Line: method.LineStart + index})...)
		}
	}
	return hits
}

func (s *sliceState) bindCalleeParams(caller string, before int, call invokeCall, hits []sliceHit, depth int) []sliceHit {
	var out []sliceHit
	for _, hit := range hits {
		if hit.param < 0 {
			out = append(out, addSliceStep([]sliceHit{hit}, Step{Method: caller, Type: "return", Line: s.methods[caller].LineStart + before + 1})...)
			continue
		}
		register := callArgumentRegister(call, hit.param)
		var bound []sliceHit
		if hit.array != nil {
			bound = s.traceArrayRegister(caller, before, register, *hit.array, depth+1)
		} else {
			bound = s.traceCallArgument(caller, before, call, hit.param, depth+1)
		}
		for _, value := range bound {
			// A helper's transformation belongs to THIS argument at THIS call
			// site. Keep both its sanitizer and its evidence after substitution.
			value.sanitized |= hit.sanitized
			value.field = value.field || hit.field
			path := append([]Step(nil), value.steps...)
			path = append(path, Step{Method: caller, Type: "call", Line: s.methods[caller].LineStart + before + 1})
			path = append(path, hit.steps...)
			value.steps = append(path, Step{Method: caller, Type: "return", Line: s.methods[caller].LineStart + before + 1})
			out = append(out, value)
		}
	}
	return uniqueSliceHits(out)
}

func indexCallers(methods map[string]methodData, resolve func(invokeCall) []string) map[string][]callReference {
	out := make(map[string][]callReference)
	for signature, method := range methods {
		for index, raw := range method.Body {
			if call, ok := parseInvoke(raw); ok {
				callees := resolve(call)
				for _, callee := range callees {
					out[callee] = append(out[callee], callReference{caller: signature, index: index, call: call, unresolvedDispatch: isDynamicDispatch(call.opcode) && len(callees) > 1})
				}
			}
		}
	}
	return out
}

// resolveCallees expands only virtual/interface calls. Direct, static and
// super calls retain their exact target. This is conservative CHA: the
// declared implementation and every app-owned override are considered, while
// the sink/source model remains authoritative for framework APIs.
func (s *sliceState) resolveCallees(call invokeCall) (result []string) {
	if s.stopped() {
		return nil
	}
	if s.calleeCache == nil {
		s.calleeCache = make(map[string][]string)
	}
	key := call.opcode + "\x00" + call.signature
	if cached, ok := s.calleeCache[key]; ok {
		return cached
	}
	defer func() { s.calleeCache[key] = result }()
	if !isDynamicDispatch(call.opcode) {
		if _, exists := s.methods[call.signature]; exists {
			return []string{call.signature}
		}
		return nil
	}
	className, ok := classFromSignature(call.signature)
	if !ok {
		return nil
	}
	result = make([]string, 0, 4)
	seen := make(map[string]struct{}, 4)
	add := func(signature string) {
		if _, exists := s.methods[signature]; !exists {
			return
		}
		if _, duplicate := seen[signature]; duplicate {
			return
		}
		seen[signature] = struct{}{}
		result = append(result, signature)
	}
	add(call.signature)
	for _, descendant := range s.descendants(className) {
		add(descendant + call.signature[len(className):])
	}
	sort.Strings(result)
	return result
}

func isDynamicDispatch(opcode string) bool {
	return strings.HasPrefix(opcode, "invoke-virtual") || strings.HasPrefix(opcode, "invoke-interface")
}

func classFromSignature(signature string) (string, bool) {
	if arrow := strings.Index(signature, "->"); arrow > 0 {
		return signature[:arrow], true
	}
	return "", false
}

func (s *sliceState) descendants(root string) []string {
	if s.descendantCache == nil {
		s.descendantCache = make(map[string][]string)
	}
	if cached, ok := s.descendantCache[root]; ok {
		return cached
	}
	children := s.children
	if children == nil {
		children = make(map[string][]string, len(s.classes))
		for name, class := range s.classes {
			if class.SuperClass != "" {
				children[class.SuperClass] = append(children[class.SuperClass], name)
			}
			for _, iface := range class.Interfaces {
				children[iface] = append(children[iface], name)
			}
		}
	}
	seen := map[string]struct{}{root: {}}
	queue := []string{root}
	var result []string
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, child := range children[current] {
			if _, exists := seen[child]; exists {
				continue
			}
			seen[child] = struct{}{}
			result = append(result, child)
			queue = append(queue, child)
		}
	}
	sort.Strings(result)
	s.descendantCache[root] = result
	return result
}

func indexFieldWrites(methods map[string]methodData) map[string][]fieldWrite {
	out := make(map[string][]fieldWrite)
	for signature, method := range methods {
		for index, raw := range method.Body {
			fields := smaliFields(cleanSmali(raw))
			if len(fields) >= 3 && (strings.HasPrefix(fields[0], "iput") || strings.HasPrefix(fields[0], "sput")) {
				field := fields[len(fields)-1]
				out[field] = append(out[field], fieldWrite{method: signature, line: index, register: fields[1]})
			}
		}
	}
	return out
}

func previousInvoke(body []string, before int) (int, invokeCall, bool) {
	for index := before; index >= 0; index-- {
		line := cleanSmali(body[index])
		if line == "" || strings.HasPrefix(line, ".") || strings.HasPrefix(line, ":") {
			continue
		}
		call, ok := parseInvoke(line)
		return index, call, ok
	}
	return 0, invokeCall{}, false
}

func parameterForRegister(method methodData, register string) (int, bool) {
	if len(register) < 2 || register[0] != 'p' {
		return 0, false
	}
	for candidate, param := range parameterRegisters(method.Params, method.IsStatic) {
		if candidate == register {
			return param, true
		}
	}
	return 0, false
}

func sinkArgumentRegister(call invokeCall, param int) string {
	return callArgumentRegister(call, param)
}

func callArgumentRegister(call invokeCall, param int) string {
	if param == -1 && !call.isStatic && len(call.registers) > 0 {
		return call.registers[0]
	}
	start := 0
	if !call.isStatic {
		start = 1
	}
	widths := parameterWidths(call.params)
	position := start
	for index, width := range widths {
		if index == param && position < len(call.registers) {
			return call.registers[position]
		}
		position += width
	}
	return ""
}

func cleanSmali(raw string) string { return stripSmaliComment(raw) }

var smaliOperandReplacer = strings.NewReplacer(",", " ", "{", " ", "}", " ")

func smaliFields(line string) []string {
	line = smaliOperandReplacer.Replace(line)
	return strings.Fields(line)
}

func isRegister(value string) bool {
	return len(value) > 1 && (value[0] == 'v' || value[0] == 'p') && value[1] >= '0' && value[1] <= '9'
}

func constantBefore(body []string, before int, register string) (string, bool) {
	for index := before; index >= 0; index-- {
		fields := smaliFields(cleanSmali(body[index]))
		if len(fields) >= 3 && fields[1] == register {
			if strings.HasPrefix(fields[0], "const") {
				return fields[2], true
			}
			return "", false
		}
	}
	return "", false
}

func (s *sliceState) isNativeMethod(signature string) bool {
	m, ok := s.methods[signature]
	return ok && m.IsNative
}

func addBridgeStep(hits []sliceHit, method string, line int) []sliceHit {
	return addSliceStep(hits, Step{Method: method, Type: "jni_bridge", Line: line})
}

func addPropagationStep(hits []sliceHit, method string, line int) []sliceHit {
	return addSliceStep(hits, Step{Method: method, Type: "propagate", Line: line})
}

func addSliceStep(hits []sliceHit, step Step) []sliceHit {
	for index := range hits {
		if hits[index].source != "" || hits[index].param >= 0 {
			// Alternative paths may share backing arrays. Never let one path
			// overwrite another path's evidence while appending a step.
			hits[index].steps = append(append([]Step(nil), hits[index].steps...), step)
		}
	}
	return hits
}

func sliceConfidence(path []Step, viaField bool) float64 {
	confidence := 0.99 - float64(len(path)-2)*0.025
	if viaField {
		confidence -= 0.08
	}
	if confidence < 0.55 {
		return 0.55
	}
	return confidence
}

// Deliberately narrow platform theorem, not a package allowlist: String is final
// and does not implement Parcelable. Unknown types/interfaces remain possible.
// Null carries no attacker-chosen filename; conversion methods are handled above.
func definitelyDisjointPlatformTypes(a, b string) bool {
	// JVM arrays implement Cloneable/Serializable, never Parcelable or String.
	// Do not generalize this to arbitrary application interfaces or Object[].
	arrayA, arrayB := strings.HasPrefix(a, "["), strings.HasPrefix(b, "[")
	if arrayA && (b == "Landroid/os/Parcelable;" || b == "Ljava/lang/String;") {
		return true
	}
	if arrayB && (a == "Landroid/os/Parcelable;" || a == "Ljava/lang/String;") {
		return true
	}
	return (a == "Landroid/os/Parcelable;" && b == "Ljava/lang/String;") || (b == "Landroid/os/Parcelable;" && a == "Ljava/lang/String;")
}
