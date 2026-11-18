package dataflow

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/sourceevidence"
)

const (
	sourceMaxMethods      = 4096
	sourceMaxBody         = 4096
	sourceMaxAlternatives = 16
	sourceMaxParts        = 32
)

type sourcePart struct{ kind, text string }
type sourceExpression struct {
	shape string // text, file, builder, array, file_array
	parts []sourcePart
}
type sourceValue []sourceExpression
type sourceFrame struct {
	signature string
	args      map[int]sourceValue
	parent    *sourceFrame
}
type sourceInspector struct {
	state           *sliceState
	report          *sourceevidence.Report
	visiting        map[string]bool
	citations       []sourceevidence.Citation
	cited           map[string]bool
	digests         map[string]string
	proofIncomplete bool
	projection      string // filename suffix or loading-origin dependency
}

// InspectSource checks the actual arguments of native-loading and file-output
// calls. The existing CFG and reaching-definitions engine is shared with taint
// analysis, but this bounded value analysis does not infer a vulnerability.
func (p *Program) InspectSource(ctx context.Context) sourceevidence.Report {
	if ctx == nil {
		ctx = context.Background()
	}
	report := sourceevidence.NewReport()
	p.mu.Lock()
	methods := make(map[string]methodData, len(p.methods))
	for key, method := range p.methods {
		methods[key] = method
	}
	p.mu.Unlock()
	report.MethodsDiscovered = len(methods)
	signatures := make([]string, 0, len(methods))
	for signature := range methods {
		signatures = append(signatures, signature)
	}
	sort.Strings(signatures)
	active := make(map[string]methodData)
	for _, signature := range signatures {
		method := methods[signature]
		if len(active) >= sourceMaxMethods || len(method.Body) > sourceMaxBody || method.IsNative || len(method.Body) == 0 {
			report.MethodsSkipped++
			continue
		}
		active[signature] = method
	}
	if report.MethodsSkipped > 0 {
		report.Status = "partial"
	}
	report.MethodsAnalyzed = len(active)
	s := &sliceState{methods: active, ctx: ctx, maxSteps: 200000, maxSinkSteps: 10000, maxDepth: 24}
	s.callers = make(map[string][]callReference)
	// Only exact direct/static calls are resolved. Virtual dispatch,
	// reflection, native bodies and omitted methods stay unknown.
	for _, signature := range signatures {
		method, exists := active[signature]
		if !exists {
			continue
		}
		for index, raw := range method.Body {
			if index&255 == 0 && ctx.Err() != nil {
				break
			}
			if call, ok := parseInvoke(raw); ok && !isDynamicDispatch(call.opcode) {
				if _, exists := active[call.signature]; exists {
					s.callers[call.signature] = append(s.callers[call.signature], callReference{caller: signature, index: index, call: call})
				}
			}
		}
	}
	in := &sourceInspector{state: s, report: &report, digests: map[string]string{}}
	for _, signature := range signatures {
		method, exists := active[signature]
		if !exists {
			continue
		}
		for index, raw := range method.Body {
			if ctx.Err() != nil || s.stopped() {
				break
			}
			call, ok := parseInvoke(raw)
			if !ok {
				continue
			}
			native := call.signature == "Ljava/lang/System;->load(Ljava/lang/String;)V" ||
				call.signature == "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"
			output := strings.HasPrefix(call.signature, "Ljava/io/FileOutputStream;-><init>(Ljava/io/File;") ||
				strings.HasPrefix(call.signature, "Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;")
			if !native && !output {
				continue
			}
			g := s.cfg(signature)
			s.sinkSteps, s.sinkTruncated = 0, false
			in.visiting, in.cited, in.citations = map[string]bool{}, map[string]bool{}, nil
			in.proofIncomplete = method.SourceAmbiguous || g.incomplete
			in.cite(signature, index)
			if native {
				choice, status, reason := "static_call_path", "supported", ""
				if !g.incomplete && !g.reachable[index] {
					choice, status, reason = "unreachable_call", "unreachable", "unreachable_in_retained_cfg"
				} else if in.proofIncomplete {
					choice, status, reason = "unresolved", "unresolved", "incomplete_or_ambiguous_method"
				}
				if status == "supported" {
					for _, caller := range s.callers[signature] {
						if !s.cfg(caller.caller).incomplete && s.cfg(caller.caller).reachable[caller.index] {
							in.cite(caller.caller, caller.index)
							break
						}
					}
				}
				report.AddCheck(in.check("native_load", signature, index, call.signature, choice, status, reason,
					"В сохранённом CFG есть вызов загрузки библиотеки. Условия ветвей и выполнение во время работы не установлены."))
			}
			kind := "path_origin"
			in.projection = "origin"
			if output {
				kind = "output_name"
				in.projection = "filename"
			}
			if !g.incomplete && !g.reachable[index] {
				report.AddCheck(in.check(kind, signature, index, call.signature, "unresolved", "unresolved", "unreachable_sink",
					"Вызов недостижим в сохранённом CFG."))
				continue
			}
			value := in.value(signature, index-1, callArgumentRegister(call, 0), 0, nil)
			choice, summary := classifySourceValue(value, output)
			status, reason := "supported", ""
			if choice == "unresolved" || in.proofIncomplete || s.sinkTruncated {
				choice, status, reason = "unresolved", "unresolved", "unresolved_value_flow"
				if in.proofIncomplete {
					reason = "incomplete_or_unsupported_source_context"
				}
				if s.sinkTruncated {
					reason = "source_slice_limit"
				}
				summary = "Сохранённый контекст не разрешает эту проверку аргумента; требуется проверить полный путь и оставшиеся условия."
			}
			report.AddCheck(in.check(kind, signature, index, call.signature, choice, status, reason, summary))
		}
	}
	report.SliceSteps = s.steps
	report.Cancelled = ctx.Err() != nil
	report.LimitReached = report.LimitReached || s.truncated || s.sinkTruncated
	if report.Cancelled || report.LimitReached {
		report.Status = "partial"
	}
	sort.Slice(report.Sources, func(i, j int) bool {
		a, b := report.Sources[i], report.Sources[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Method < b.Method
	})
	return report
}

func (in *sourceInspector) check(kind, signature string, index int, sink, choice, status, reason, summary string) sourceevidence.Check {
	method := in.state.methods[signature]
	if len(in.citations) > sourceevidence.MaxCitations {
		status, choice, reason = "unresolved", "unresolved", "citation_limit"
	}
	return sourceevidence.Check{ID: sourceevidence.CheckID(kind, signature, method.Path, method.LineStart+index),
		Kind: kind, Status: status, Choice: choice, Basis: "cfg_reaching_definitions", Scope: "retained_call_sites",
		Summary: summary, Reason: reason, Method: signature, Sink: sink,
		Citations: append([]sourceevidence.Citation(nil), in.citations...)}
}

func (in *sourceInspector) cite(signature string, index int) {
	method := in.state.methods[signature]
	body := method.SourceBody
	if len(body) == 0 {
		body = method.Body
	}
	if index < 0 || index >= len(body) {
		in.proofIncomplete = true
		return
	}
	digest, exists := in.digests[signature]
	if !exists {
		code := strings.Join(body, "\n")
		digest = sourceevidence.Digest(code)
		if !in.report.AddSource(sourceevidence.Source{File: method.Path, Line: method.LineStart, Method: signature,
			Representation: "retained_smali_method", SHA256: digest, Code: code}) {
			in.proofIncomplete = true
			return
		}
		in.digests[signature] = digest
	}
	key := signature + ":" + strconv.Itoa(index)
	if in.cited[key] {
		return
	}
	in.cited[key] = true
	in.citations = append(in.citations, sourceevidence.Citation{File: method.Path, Line: method.LineStart + index,
		Method: signature, Snippet: strings.TrimSpace(body[index]), SHA256: digest})
	if len(in.citations) > sourceevidence.MaxCitations {
		in.proofIncomplete = true
	}
}

func sourceAtom(kind, text string) sourceValue {
	return sourceValue{{shape: "text", parts: []sourcePart{{kind, text}}}}
}
func sourceUnknown() sourceValue { return sourceAtom("unknown", "") }

func (in *sourceInspector) value(signature string, before int, register string, depth int, frame *sourceFrame) sourceValue {
	s := in.state
	if register == "" || depth > s.maxDepth || s.sliceStopped() {
		in.proofIncomplete = true
		return sourceUnknown()
	}
	s.steps++
	s.sinkSteps++
	key := fmt.Sprintf("%s\x00%d\x00%s\x00%p", signature, before, register, frame)
	if in.visiting[key] {
		return sourceUnknown()
	}
	in.visiting[key] = true
	defer delete(in.visiting, key)
	method, exists := s.methods[signature]
	if !exists || method.IsNative || method.SourceAmbiguous || s.cfg(signature).incomplete {
		in.proofIncomplete = true
		return sourceUnknown()
	}
	defs, complete := s.reachingDefinitions(signature, before, register)
	if !complete {
		in.proofIncomplete = true
		return sourceUnknown()
	}
	var out sourceValue
	for _, index := range defs.indices {
		out = joinSourceValues(out, in.definition(signature, index, register, depth+1, frame))
	}
	if defs.entry {
		param, found := parameterForRegister(method, register)
		if !found {
			out = joinSourceValues(out, sourceUnknown())
		} else if bound := sourceFrameFor(frame, signature); bound != nil {
			if value, found := bound.args[param]; found {
				out = joinSourceValues(out, value)
			} else {
				out = joinSourceValues(out, sourceUnknown())
			}
		} else {
			callers := s.callers[signature]
			if len(callers) == 0 || len(callers) > 16 {
				out = joinSourceValues(out, sourceAtom("parameter", register))
			} else {
				incoming := false
				for _, ref := range callers {
					if s.cfg(ref.caller).incomplete {
						out = joinSourceValues(out, sourceUnknown())
						continue
					}
					if !s.cfg(ref.caller).reachable[ref.index] {
						continue
					}
					incoming = true
					in.cite(ref.caller, ref.index)
					out = joinSourceValues(out, in.value(ref.caller, ref.index-1, callArgumentRegister(ref.call, param), depth+1, frame))
				}
				if !incoming {
					out = joinSourceValues(out, sourceAtom("parameter", register))
				}
			}
		}
	}
	if len(out) == 0 {
		return sourceUnknown()
	}
	for _, expression := range out {
		if expression.shape == "builder" || expression.shape == "array" || expression.shape == "file_array" {
			if in.unsupportedObjectMutation(signature, before, register) {
				in.proofIncomplete = true
				return sourceUnknown()
			}
			break
		}
	}
	return out
}

func (in *sourceInspector) definition(signature string, index int, register string, depth int, frame *sourceFrame) sourceValue {
	s := in.state
	node := s.cfg(signature).nodes[index]
	if node == nil {
		return sourceUnknown()
	}
	in.cite(signature, index)
	f, op := node.fields, node.op
	arg := func(reg string) sourceValue { return in.value(signature, index-1, reg, depth+1, frame) }
	if node.call != nil && modeledReceiverMutation(*node.call) {
		call := *node.call
		owner := strings.SplitN(call.signature, "->", 2)[0]
		switch {
		case owner == "Ljava/io/File;" && call.params == "Ljava/lang/String;":
			return reshapeSource(arg(callArgumentRegister(call, 0)), "file")
		case owner == "Ljava/io/File;" && (call.params == "Ljava/lang/String;Ljava/lang/String;" || call.params == "Ljava/io/File;Ljava/lang/String;"):
			if in.projection == "filename" {
				child := arg(callArgumentRegister(call, 1))
				// File(parent, "") inherits its parent's name. Every other
				// nonempty child determines the basename independently.
				if sourceAlwaysEmpty(child) {
					return reshapeSource(arg(callArgumentRegister(call, 0)), "file")
				}
				return reshapeSource(child, "file")
			}
			parent := arg(callArgumentRegister(call, 0))
			if sourceAlwaysUsesDataDir(parent) {
				return reshapeSource(withUnknownSourceSuffix(parent), "file")
			}
			return reshapeSource(concatSource(concatSource(parent, sourceAtom("constant", "/")), arg(callArgumentRegister(call, 1))), "file")
		case (owner == "Ljava/lang/StringBuilder;" || owner == "Ljava/lang/StringBuffer;") && strings.Contains(call.signature, "-><init>("):
			if call.params == "" || call.params == "I" {
				return reshapeSource(sourceAtom("constant", ""), "builder")
			}
			if call.params == "Ljava/lang/String;" || call.params == "Ljava/lang/CharSequence;" {
				return reshapeSource(arg(callArgumentRegister(call, 0)), "builder")
			}
		case (owner == "Ljava/lang/StringBuilder;" || owner == "Ljava/lang/StringBuffer;") &&
			(call.params == "Ljava/lang/String;" || call.params == "Ljava/lang/CharSequence;"):
			if in.projection == "filename" {
				suffix := arg(callArgumentRegister(call, 0))
				if sourceAlwaysResetsBasename(suffix) {
					return reshapeSource(suffix, "builder")
				}
				return reshapeSource(concatSource(arg(register), suffix), "builder")
			}
			prefix := arg(register)
			if sourceAlwaysUsesDataDir(prefix) {
				return reshapeSource(withUnknownSourceSuffix(prefix), "builder")
			}
			return reshapeSource(concatSource(prefix, arg(callArgumentRegister(call, 0))), "builder")
		}
		return sourceUnknown()
	}
	switch {
	case strings.HasPrefix(op, "const-string"):
		raw := cleanSmali(s.methods[signature].Body[index])
		comma := strings.IndexByte(raw, ',')
		if comma < 0 {
			return sourceUnknown()
		}
		text, err := strconv.Unquote(strings.TrimSpace(raw[comma+1:]))
		if err != nil {
			return sourceUnknown()
		}
		return sourceAtom("constant", text)
	case op == "sget-object" && len(f) >= 3 && f[len(f)-1] == "Ljava/io/File;->separator:Ljava/lang/String;":
		return sourceAtom("constant", "/")
	case strings.HasPrefix(op, "iget-object") && len(f) >= 4 && f[len(f)-1] == "Landroid/content/pm/ApplicationInfo;->dataDir:Ljava/lang/String;":
		return sourceAtom("application_data_dir", "ApplicationInfo.dataDir")
	case strings.HasPrefix(op, "move-result"):
		previous := in.previousNode(signature, index)
		if previous == nil {
			return sourceUnknown()
		}
		if previous.call != nil {
			return in.callResult(signature, previous.index, *previous.call, depth+1, frame)
		}
		if strings.HasPrefix(previous.op, "filled-new-array") {
			raw := s.methods[signature].Body[previous.index]
			open, close := strings.IndexByte(raw, '{'), strings.IndexByte(raw, '}')
			if open < 0 || close < open || !strings.Contains(raw[close:], "[Ljava/lang/String;") {
				return sourceUnknown()
			}
			var elements sourceValue
			for _, reg := range parseRegisterList(raw[open+1 : close]) {
				elements = joinSourceValues(elements, in.value(signature, previous.index-1, reg, depth+1, frame))
			}
			in.cite(signature, previous.index)
			return reshapeSource(elements, "array")
		}
		return sourceUnknown()
	case strings.HasPrefix(op, "move") && len(f) >= 3:
		return arg(f[2])
	case op == "check-cast":
		return arg(register)
	case op == "aget-object" && len(f) >= 4:
		value := arg(f[2])
		var elements sourceValue
		for _, expression := range value {
			switch expression.shape {
			case "array":
				expression.shape = "text"
				elements = joinSourceValues(elements, sourceValue{expression})
			case "file_array":
				expression.shape = "file"
				expression.parts = append(append([]sourcePart(nil), expression.parts...), sourcePart{"listed_child", ""})
				elements = joinSourceValues(elements, sourceValue{expression})
			default:
				elements = joinSourceValues(elements, sourceUnknown())
			}
		}
		return elements
	case op == "new-instance":
		return sourceUnknown() // an uninitialised object is not a path
	default:
		return sourceUnknown()
	}
}

func (in *sourceInspector) previousNode(signature string, index int) *cfgInstruction {
	g := in.state.cfg(signature)
	where := sort.SearchInts(g.order, index)
	if where <= 0 || where >= len(g.order) {
		return nil
	}
	previous := g.nodes[g.order[where-1]]
	node := g.nodes[index]
	// move-result must immediately follow its producer on the retained CFG.
	if node == nil || len(node.pred) != 1 || node.pred[0] != previous.index {
		return nil
	}
	return previous
}

func (in *sourceInspector) callResult(signature string, index int, call invokeCall, depth int, frame *sourceFrame) sourceValue {
	in.cite(signature, index)
	argument := func(n int) sourceValue {
		return in.value(signature, index-1, callArgumentRegister(call, n), depth+1, frame)
	}
	receiver := func(before int) sourceValue {
		if len(call.registers) == 0 {
			return sourceUnknown()
		}
		return in.value(signature, before, call.registers[0], depth+1, frame)
	}
	switch call.signature {
	case "Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;":
		return sourceAtom("archive_entry_name", "ZipEntry.getName")
	case "Ljava/io/File;->getPath()Ljava/lang/String;":
		return reshapeSource(receiver(index-1), "text")
	case "Ljava/io/File;->getAbsolutePath()Ljava/lang/String;":
		return absoluteSourcePath(receiver(index - 1))
	case "Ljava/io/File;->listFiles()[Ljava/io/File;":
		return reshapeSource(concatSource(receiver(index-1), sourceAtom("constant", "/")), "file_array")
	case "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;", "Ljava/lang/StringBuffer;->toString()Ljava/lang/String;":
		return reshapeSource(receiver(index-1), "text")
	case "Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;":
		return concatSource(receiver(index-1), argument(0))
	case "Landroid/content/Context;->getFilesDir()Ljava/io/File;", "Landroid/content/Context;->getCacheDir()Ljava/io/File;",
		"Landroid/content/Context;->getCodeCacheDir()Ljava/io/File;", "Landroid/content/Context;->getNoBackupFilesDir()Ljava/io/File;":
		return reshapeSource(sourceAtom("application_data_dir", call.signature), "file")
	}
	if modeledReceiverMutation(call) && strings.Contains(call.signature, "->append(") {
		return in.value(signature, index, call.registers[0], depth+1, frame)
	}
	if isDynamicDispatch(call.opcode) {
		return sourceUnknown()
	}
	callee, exists := in.state.methods[call.signature]
	if !exists || callee.IsNative || callee.SourceAmbiguous || in.state.cfg(call.signature).incomplete {
		return sourceUnknown()
	}
	args := make(map[int]sourceValue)
	for param := range parameterWidths(call.params) {
		args[param] = argument(param)
	}
	nested := &sourceFrame{signature: call.signature, args: args, parent: frame}
	var out sourceValue
	g := in.state.cfg(call.signature)
	for _, id := range g.order {
		node := g.nodes[id]
		if g.reachable[id] && node.op == "return-object" && len(node.fields) >= 2 {
			in.cite(call.signature, id)
			out = joinSourceValues(out, in.value(call.signature, id-1, node.fields[1], depth+1, nested))
		}
	}
	if len(out) == 0 {
		return sourceUnknown()
	}
	return out
}

func joinSourceValues(left, right sourceValue) sourceValue {
	out := append(sourceValue(nil), left...)
	for _, expression := range right {
		duplicate := false
		for _, prior := range out {
			if prior.shape != expression.shape || len(prior.parts) != len(expression.parts) {
				continue
			}
			same := true
			for i := range prior.parts {
				if prior.parts[i] != expression.parts[i] {
					same = false
					break
				}
			}
			if same {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, expression)
		}
	}
	if len(out) > sourceMaxAlternatives {
		return sourceUnknown()
	}
	return out
}

func reshapeSource(value sourceValue, shape string) sourceValue {
	out := make(sourceValue, len(value))
	for i, expression := range value {
		out[i] = sourceExpression{shape: shape, parts: append([]sourcePart(nil), expression.parts...)}
	}
	return out
}

func concatSource(left, right sourceValue) sourceValue {
	var out sourceValue
	if len(left) == 0 || len(right) == 0 {
		return sourceUnknown()
	}
	for _, a := range left {
		for _, b := range right {
			parts := append(append([]sourcePart(nil), a.parts...), b.parts...)
			if len(parts) > sourceMaxParts {
				return sourceUnknown()
			}
			merged := make([]sourcePart, 0, len(parts))
			for _, part := range parts {
				if part.kind == "constant" && part.text == "" {
					continue
				}
				if len(merged) > 0 && part.kind == "constant" && merged[len(merged)-1].kind == "constant" {
					merged[len(merged)-1].text += part.text
				} else {
					merged = append(merged, part)
				}
			}
			if len(merged) == 0 {
				merged = append(merged, sourcePart{"constant", ""})
			}
			out = joinSourceValues(out, sourceValue{{shape: "text", parts: merged}})
			if len(out) == 1 && len(out[0].parts) == 1 && out[0].parts[0].kind == "unknown" {
				return out
			}
		}
	}
	return out
}

func classifySourceValue(value sourceValue, filename bool) (string, string) {
	if len(value) == 0 {
		return "unresolved", "Источник аргумента не установлен."
	}
	choice, literal := "", ""
	for _, expression := range value {
		current := "unresolved"
		if filename {
			// Only the actual output argument is considered. A getName call
			// elsewhere (for entry selection, logging, etc.) is irrelevant.
			if len(expression.parts) > 0 {
				last := expression.parts[len(expression.parts)-1]
				if last.kind == "archive_entry_name" {
					current = "archive_entry_name"
				}
				if last.kind == "constant" {
					name := last.text
					if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
						name = name[slash+1:]
					}
					if name != "" && name != "." && name != ".." {
						// A dynamic prefix without a following separator can
						// change the basename; do not discard it.
						if len(expression.parts) == 1 || strings.Contains(last.text, "/") {
							current = "constant_filename"
							if literal != "" && literal != name {
								return "unresolved", "Имя файла различается между сохранёнными ветвями."
							}
							literal = name
						}
					}
				}
			}
		} else {
			allConstants := len(expression.parts) > 0
			for _, part := range expression.parts {
				allConstants = allConstants && part.kind == "constant"
			}
			if allConstants {
				current = "constant_path"
			}
			if len(expression.parts) > 0 && expression.parts[0].kind == "application_data_dir" {
				// This establishes a retained dependency on dataDir, not
				// containment, canonicalisation, symlink safety or file contents.
				current = "application_data_dir"
			}
			if len(expression.parts) == 1 && expression.parts[0].kind == "parameter" {
				current = "unbound_parameter"
			}
			if len(expression.parts) > 0 && expression.parts[0].kind == "archive_entry_name" {
				current = "archive_entry_name"
			}
		}
		if current == "unresolved" || (choice != "" && choice != current) {
			return "unresolved", "Не все сохранённые пути дают один подтверждённый источник аргумента."
		}
		choice = current
	}
	switch choice {
	case "constant_filename":
		return choice, fmt.Sprintf("Аргумент выходного файла заканчивается постоянным именем %q; имя ZIP-записи не является этим аргументом.", literal)
	case "application_data_dir":
		return choice, "Аргумент загрузки построен с использованием ApplicationInfo.dataDir или каталога Context в сохранённых вызовах. Канонический путь, содержимое файлов и выполнение не проверены."
	case "archive_entry_name":
		return choice, "Аргумент прослеживается до ZipEntry.getName; проверки имени и границ каталога требуют отдельного разбора."
	case "constant_path":
		return choice, "В сохранённом пути аргумент построен из строковых констант."
	case "unbound_parameter":
		return choice, "Аргумент является параметром; подходящий вызывающий код не сохранён."
	default:
		return "unresolved", "Источник аргумента не установлен."
	}
}

func sourceFrameFor(frame *sourceFrame, signature string) *sourceFrame {
	for current := frame; current != nil; current = current.parent {
		if current.signature == signature {
			return current
		}
	}
	return nil
}

func absoluteSourcePath(value sourceValue) sourceValue {
	var out sourceValue
	for _, expression := range value {
		absolute := len(expression.parts) > 0 && (expression.parts[0].kind == "application_data_dir" ||
			(expression.parts[0].kind == "constant" && strings.HasPrefix(expression.parts[0].text, "/")))
		expression.shape = "text"
		if !absolute {
			expression.parts = append([]sourcePart{{"runtime_directory", ""}, {"constant", "/"}}, expression.parts...)
		}
		out = joinSourceValues(out, sourceValue{expression})
	}
	return out
}

func sourceAlwaysEmpty(value sourceValue) bool {
	if len(value) == 0 {
		return false
	}
	for _, expression := range value {
		if len(expression.parts) != 1 || expression.parts[0].kind != "constant" || expression.parts[0].text != "" {
			return false
		}
	}
	return true
}

func sourceAlwaysUsesDataDir(value sourceValue) bool {
	if len(value) == 0 {
		return false
	}
	for _, expression := range value {
		if len(expression.parts) == 0 || expression.parts[0].kind != "application_data_dir" {
			return false
		}
	}
	return true
}

func sourceAlwaysResetsBasename(value sourceValue) bool {
	if len(value) == 0 {
		return false
	}
	for _, expression := range value {
		hasSeparator := false
		for _, part := range expression.parts {
			if part.kind == "constant" && strings.Contains(part.text, "/") {
				hasSeparator = true
				break
			}
		}
		if !hasSeparator {
			return false
		}
	}
	return true
}

func withUnknownSourceSuffix(value sourceValue) sourceValue {
	out := make(sourceValue, len(value))
	for i, expression := range value {
		out[i] = sourceExpression{shape: expression.shape, parts: []sourcePart{expression.parts[0], {"unknown", ""}}}
	}
	return out
}
