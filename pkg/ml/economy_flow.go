package ml

import (
	"sort"
	"strconv"
	"strings"
)

// The resource slice follows registers within a basic block. Unknown writes,
// block entries and control transfers kill facts. References are retained even
// when their resource is unknown so the separate method/field index can resolve
// obfuscated code without retaining every method body in memory.
type economyValue struct {
	Resources []string
	Refs      []EconomyEvidence
	Literal   string
	Storage   string
	Authority string
	Operation string
	Column    bool
	NonAmount bool
	Width     int
}

type economyWrite struct { Reference string; Value economyValue }
type economyMethodSummary struct {
	Method, Operation, ValueType string
	Resources []string
	Result economyValue
	Writes []economyWrite
	Used []EconomyEvidence
}

type economyResolver interface { lookupEconomy(string) economyValue }

// Server-side copies of a balance (network responses, DTOs, sync caches) must
// never be offered a client rewrite: patching them changes nothing on the
// server and only corrupts local display. These owner/class tokens mark a
// value as server-related; the finding stays visible for audit with its
// authority stated instead of receiving a return_max patch.
var economyServerOwnerTokens = []string{
	"response", "responses", "dto", "entity", "entities", "payload", "proto",
	"api", "http", "retrofit", "okhttp", "volley", "grpc", "socket", "network",
	"remote", "server", "backend", "sync", "synchronization", "realtime",
}

func economyServerContext(name string) bool {
	for _, token := range economyTokens(name) {
		for _, marker := range economyServerOwnerTokens {
			if token == marker { return true }
		}
	}
	return false
}

func mergeEconomyValue(a, b economyValue) economyValue {
	a.Resources = append([]string(nil), a.Resources...)
	a.Refs = append([]EconomyEvidence(nil), a.Refs...)
	for _, resource := range b.Resources { a.Resources = appendUniqueString(a.Resources, resource) }
	for _, ref := range b.Refs {
		found := false
		for _, existing := range a.Refs { if existing.Kind == ref.Kind && existing.Reference == ref.Reference { found = true; break } }
		if !found && len(a.Refs) < 24 { a.Refs = append(a.Refs, ref) }
	}
	if a.Storage == "" { a.Storage = b.Storage }
	if b.Authority == "server_related" { a.Authority = b.Authority }
	if a.Operation == "" { a.Operation = b.Operation }
	a.NonAmount = a.NonAmount || b.NonAmount
	return a
}

func economyClassSimpleName(class string) string {
	base := class
	if i := strings.LastIndexAny(base, "/."); i >= 0 { base = base[i+1:] }
	return strings.TrimSuffix(strings.TrimPrefix(base, "L"), ";")
}

func economyMethodReference(mi *MethodInfo) string {
	owner := mi.ClassName
	if owner == "" { owner = mi.ClassPath }
	owner = strings.TrimSuffix(strings.TrimPrefix(owner, "L"), ";")
	return "L" + owner + ";->" + mi.FullSignature
}

func economyRegisters(line string) []string {
	if start := strings.IndexByte(line, '{'); start >= 0 {
		end := strings.IndexByte(line[start:], '}')
		if end < 0 { return nil }
		inside := strings.TrimSpace(line[start+1 : start+end])
		if strings.Contains(inside, "..") {
			parts := strings.Split(inside, "..")
			if len(parts) != 2 { return nil }
			a, b := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			if !isEconomyRegister(a) || !isEconomyRegister(b) || a[0] != b[0] { return nil }
			lo, _ := strconv.Atoi(a[1:]); hi, _ := strconv.Atoi(b[1:])
			if hi < lo || hi-lo > 64 { return nil }
			var out []string
			for n := lo; n <= hi; n++ { out = append(out, string(a[0])+strconv.Itoa(n)) }
			return out
		}
		var out []string
		for _, part := range strings.Split(inside, ",") { reg := strings.TrimSpace(part); if !isEconomyRegister(reg) { if reg == "" && inside == "" { return nil }; return nil }; out = append(out, reg) }
		return out
	}
	_, operands, ok := strings.Cut(line, " ")
	if !ok { _, operands, ok = strings.Cut(line, "\t") }
	if !ok { return nil }
	var out []string
	for _, part := range strings.Split(operands, ",") { reg := strings.TrimSpace(part); if !isEconomyRegister(reg) { break }; out = append(out, reg) }
	return out
}

func isEconomyRegister(reg string) bool {
	if len(reg) < 2 || (reg[0] != 'v' && reg[0] != 'p') { return false }
	for _, c := range reg[1:] { if c < '0' || c > '9' { return false } }
	return true
}

func economyParamBase(mi *MethodInfo) int {
	for _, raw := range mi.RawBody {
		fields := strings.Fields(smaliCodeLine(raw))
		if len(fields) != 2 { continue }
		count, err := strconv.Atoi(fields[1]); if err != nil || count < 0 { continue }
		if fields[0] == ".locals" { return count }
		if fields[0] == ".registers" { return count-countParamRegisters(mi.FullSignature, mi.IsStatic) }
	}
	return -1
}

func analyzeEconomyMethod(mi *MethodInfo, resolver economyResolver) (*EconomyInfo, economyMethodSummary) {
	summary := economyMethodSummary{}
	if mi == nil { return nil, summary }
	summary.Method = strings.Clone(economyMethodReference(mi))
	summary.ValueType = mi.ReturnType
	name := mi.Name
	if name == "" { name = mi.NameLower }
	namedResources := resourcesIn(name)
	namedOperation := economyOperation(name, mi.ReturnType)
	// An obfuscated method name in a resource-named class (Wallet, Shop, ...)
	// is still worth admitting: the class context seeds the resource, but the
	// value stays unresolved until the flow links a named field or key.
	// Display-like names never seed: an animation frame is not an amount even
	// inside a CoinAnimation class.
	if namedOperation != EconomyDisplay {
		className := mi.ClassName
		if className == "" { className = mi.ClassPath }
		if simple := economyClassSimpleName(className); simple != "" {
			for _, resource := range resourcesIn(simple) { namedResources = appendUniqueString(namedResources, resource) }
		}
	}
	if namedOperation == EconomyPrice && len(namedResources) == 0 { namedResources = []string{"currency"} }
	if mi.ReturnType == "Z" && len(namedResources) == 0 && tokenIn(economyTokens(name), "afford", "enough", "sufficient") { namedResources = []string{"currency"}; namedOperation = EconomyAfford }
	values := map[string]economyValue{}
	base := economyParamBase(mi)
	canonical := func(reg string) string { if base >= 0 && strings.HasPrefix(reg, "p") { n, _ := strconv.Atoi(reg[1:]); return "v"+strconv.Itoa(base+n) }; return reg }
	get := func(reg string) economyValue { return values[canonical(reg)] }
	set := func(reg string, value economyValue, width int) {
		reg = canonical(reg)
		// Invalidate overlapping wide pairs, including a write to their high half.
		for key, old := range values {
			if key == reg { delete(values, key); continue }
			if len(key) < 2 || len(reg) < 2 || key[0] != reg[0] { continue }
			n, _ := strconv.Atoi(reg[1:]); k, _ := strconv.Atoi(key[1:])
			if (width == 2 && k == n+1) || (old.Width == 2 && n == k+1) { delete(values, key) }
		}
		value.Width = width
		values[reg] = value
	}
	resolve := func(ref string, value economyValue) economyValue {
		if resolver != nil { value = mergeEconomyValue(value, resolver.lookupEconomy(ref)) }
		return value
	}
	var pending, conditions, displays economyValue
	var state smaliNonCodeState
	entries, numericLayoutKnown := numericBranchEntryLines(mi.RawBody)
	for index, raw := range mi.RawBody {
		line := smaliCodeLine(raw)
		if state.skip(line) { clear(values); pending = economyValue{}; continue }
		if strings.HasPrefix(line, ":") || entries[index] { clear(values); pending = economyValue{} }
		op, executable := insnLine(line)
		if !executable { continue }
		regs := economyRegisters(line)
		lineNo := mi.LineStart + index
		if mi.LineStart == 0 { lineNo = index+1 }
		if !strings.HasPrefix(op, "move-result") { pending = economyValue{} }
		width := 1
		if strings.Contains(op, "wide") || strings.Contains(op, "long") || strings.Contains(op, "double") { width = 2 }
		switch {
		case strings.HasPrefix(op, "const-string") && len(regs) > 0:
			set(regs[0], economyValue{Literal: extractConstString(line)}, 1)
		case strings.HasPrefix(op, "const") && len(regs) > 0:
			set(regs[0], economyValue{}, width)
		case strings.HasPrefix(op, "move-result") && len(regs) > 0:
			set(regs[0], pending, width); pending = economyValue{}
		case strings.HasPrefix(op, "move") && len(regs) > 1:
			set(regs[0], get(regs[1]), width)
		case (strings.HasPrefix(op, "iget") || strings.HasPrefix(op, "sget")) && len(regs) > 0:
			parts := strings.Fields(line); ref := parts[len(parts)-1]
			_, field, ok := strings.Cut(ref, ";->"); if !ok { set(regs[0], economyValue{}, width); continue }
			fieldName, rt, ok := strings.Cut(field, ":"); if !ok { set(regs[0], economyValue{}, width); continue }
			ref = strings.Clone(ref)
			value := economyValue{Refs: []EconomyEvidence{{Kind:"field", Reference:ref, Line:lineNo}}, Storage:"field"}
			if isEconomyNumber(rt) { value.Resources = resourcesIn(fieldName); value.Operation = economyOperation(fieldName, rt); value.NonAmount = economyNonAmountName(fieldName); value = resolve(ref, value) }
			if economyServerContext(strings.Split(ref, ";->")[0]) { value.Authority = "server_related" }
			set(regs[0], value, width)
		case (strings.HasPrefix(op, "iput") || strings.HasPrefix(op, "sput")) && len(regs) > 0:
			parts := strings.Fields(line); ref := parts[len(parts)-1]
			_, field, ok := strings.Cut(ref, ";->"); if !ok { continue }
			fieldName, rt, ok := strings.Cut(field, ":"); if !ok || !isEconomyNumber(rt) { continue }
			value := get(regs[0])
			value = mergeEconomyValue(value, economyValue{Resources:resourcesIn(fieldName), Storage:"field", NonAmount:economyNonAmountName(fieldName)})
			value = resolve(ref, value)
			summary.Writes = append(summary.Writes, economyWrite{strings.Clone(ref), value})
		case strings.HasPrefix(op, "invoke-"):
			end := strings.IndexByte(line, '}'); if end < 0 { continue }
			ref := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line[end+1:]), ","))
			if n := strings.IndexAny(ref, " \t,"); n >= 0 { ref = ref[:n] }
			owner, tail, ok := strings.Cut(ref, ";->"); if !ok { continue }
			method, _, ok := strings.Cut(tail, "("); if !ok { continue }
			close := strings.LastIndexByte(tail, ')'); if close < 0 { continue }
			rt := tail[close+1:]
			lowerOwner, lowerMethod := strings.ToLower(owner), strings.ToLower(method)
			arg := func(n int) economyValue { if n < len(regs) { return get(regs[n]) }; return economyValue{} }
			storage := ""
			if strings.Contains(lowerOwner, "sharedpreferences") { storage = "preferences" }
			if strings.Contains(lowerOwner, "org/json/jsonobject") { storage = "json" }
			if strings.Contains(lowerOwner, "android/os/bundle") { storage = "bundle" }
			if storage != "" && len(regs) >= 2 && arg(1).Literal != "" {
				key := arg(1).Literal
				scope := mi.ClassName
				if len(arg(0).Refs) > 0 { scope = arg(0).Refs[0].Reference }
				keyRef := storage+":"+scope+":"+key
				value := economyValue{Resources:resourcesIn(key), Refs:[]EconomyEvidence{{Kind:storage, Reference:strings.Clone(keyRef), Line:lineNo}}, Storage:storage, Operation:economyOperation(key, rt), NonAmount:economyNonAmountName(key)}
				value = resolve(keyRef, value)
				if strings.HasPrefix(lowerMethod, "put") && len(regs) >= 3 {
					value = mergeEconomyValue(arg(2), value)
					summary.Writes = append(summary.Writes, economyWrite{strings.Clone(keyRef), value})
				} else if strings.HasPrefix(lowerMethod, "get") || strings.HasPrefix(lowerMethod, "opt") { pending = value }
			} else if strings.Contains(lowerOwner, "/cursor") && strings.HasPrefix(lowerMethod, "getcolumnindex") && len(regs) >= 2 && arg(1).Literal != "" {
				key := arg(1).Literal
				pending = economyValue{Resources:resourcesIn(key), Refs:[]EconomyEvidence{{Kind:"sqlite", Reference:strings.Clone(mi.ClassName+":"+regs[0]+":"+key), Line:lineNo}}, Storage:"sqlite", Column:true, NonAmount:economyNonAmountName(key)}
			} else if strings.Contains(lowerOwner, "/cursor") && len(regs) >= 2 && isEconomyNumber(rt) && arg(1).Column {
				pending = arg(1); pending.Column = false
			} else if lowerMethod == "intvalue" || lowerMethod == "longvalue" || lowerMethod == "floatvalue" || lowerMethod == "doublevalue" || lowerMethod == "parseint" || lowerMethod == "parselong" || lowerMethod == "parsefloat" || lowerMethod == "parsedouble" || lowerMethod == "valueof" {
				pending = arg(0)
			} else if lowerMethod == "settext" && len(regs) > 1 {
				displays = mergeEconomyValue(displays, arg(1))
			} else if lowerMethod == "edit" && storage == "preferences" {
				pending = arg(0)
			} else {
				pending = economyValue{Storage:"call", Refs:[]EconomyEvidence{{Kind:"call", Reference:strings.Clone(ref), Line:lineNo}}}
				if isEconomyNumber(rt) && !economyNonAmountName(method) {
					pending.Resources = resourcesIn(method); pending.Operation = economyOperation(method, rt)
					// Only parameterless calls are context independent. Generic
					// getResource(id) calls must not merge different currency IDs.
					if strings.Contains(tail, "()") { pending = resolve(ref, pending) }
				}
				for _, reg := range regs { if get(reg).Authority == "server_related" { pending.Authority = "server_related" } }
				if economyServerContext(owner) || strings.Contains(lowerOwner, "okhttp") || strings.Contains(lowerOwner, "retrofit") || strings.Contains(lowerOwner, "httpurlconnection") || strings.Contains(lowerOwner, "volley") { pending.Authority = "server_related" }
			}
		case (strings.HasPrefix(op, "add-") || strings.HasPrefix(op, "sub-") || strings.HasPrefix(op, "mul-") || strings.HasPrefix(op, "div-")) && len(regs) >= 2:
			start := 1; if strings.Contains(op, "/2addr") { start = 0 }
			value := economyValue{}
			for _, reg := range regs[start:] { value = mergeEconomyValue(value, get(reg)) }
			if strings.HasPrefix(op, "add-") { value.Operation = EconomyReward; if strings.Contains(line, ", -") { value.Operation = EconomySpend } }
			if strings.HasPrefix(op, "sub-") { value.Operation = EconomySpend; if strings.Contains(line, ", -") { value.Operation = EconomyReward } }
			set(regs[0], value, width)
		case strings.HasPrefix(op, "cmp") && len(regs) >= 3:
			value := mergeEconomyValue(get(regs[1]), get(regs[2])); set(regs[0], value, 1)
		case strings.HasPrefix(op, "if-"):
			for _, reg := range regs { conditions = mergeEconomyValue(conditions, get(reg)) }
			clear(values)
		case strings.HasPrefix(op, "return"):
			if op != "return-void" && len(regs) > 0 { summary.Result = mergeEconomyValue(summary.Result, get(regs[0])) }
			clear(values)
		case strings.Contains(op, "-to-") && len(regs) >= 2:
			value := get(regs[1]); if strings.HasSuffix(op, "-long") || strings.HasSuffix(op, "-double") { width = 2 } else { width = 1 }; set(regs[0], value, width)
		case op == "check-cast":
			// A cast does not write a different value.
		case isControlTransfer(op):
			clear(values)
		default:
			if len(regs) > 0 && op != "nop" && !strings.HasPrefix(op, "monitor-") && !strings.HasPrefix(op, "aput") { set(regs[0], economyValue{}, width) }
		}
		if !numericLayoutKnown { clear(values); pending = economyValue{} }
	}
	value := summary.Result
	operation := namedOperation
	if value.Operation == EconomyPrice { operation = EconomyPrice }
	if mi.ReturnType == "V" || len(summary.Writes) > 0 {
		for _, write := range summary.Writes {
			value = mergeEconomyValue(value, write.Value)
			value.Refs = append(value.Refs, EconomyEvidence{Kind:"write", Reference:write.Reference})
			if operation == "" || operation == EconomyBalanceRead || operation == EconomyBalanceWrite {
				operation = EconomyBalanceWrite
				if write.Value.Operation == EconomySpend || write.Value.Operation == EconomyReward { operation = write.Value.Operation }
			}
		}
	}
	if mi.ReturnType == "Z" && len(conditions.Refs) > 0 { value = mergeEconomyValue(value, conditions); if operation == "" { operation = EconomyAfford } }
	if len(displays.Refs) > 0 && !isEconomyNumber(mi.ReturnType) && len(summary.Writes) == 0 { value = mergeEconomyValue(value, displays); operation = EconomyDisplay }
	if namedOperation == EconomyDisplay || value.NonAmount { operation = EconomyDisplay }
	resources := mergeEconomyValue(economyValue{Resources:namedResources}, value).Resources
	if len(resources) > 1 { var specific []string; for _, resource := range resources { if resource != "currency" { specific = append(specific, resource) } }; if len(specific) > 0 { resources = specific } }
	sort.Strings(resources)
	summary.Resources, summary.Operation, summary.Used = resources, operation, value.Refs
	if len(resources) == 0 { return nil, summary }
	info := &EconomyInfo{Resources:resources, Operation:operation, ValueType:mi.ReturnType, Storage:value.Storage, Authority:"unknown", ValueLinked:len(value.Refs)>0, Evidence:append([]EconomyEvidence(nil), value.Refs...)}
	// A price/affordability/validation reading is identified by its operation:
	// getPrice over field "price" carries no resource alias, but the linked
	// value is still the exact number being classified. Only a balance read
	// needs the value itself to carry resource identity.
	info.ValueResolved = len(value.Resources) > 0 ||
		(len(value.Refs) > 0 && (operation == EconomyPrice || operation == EconomyAfford || operation == EconomyValidation))
	if value.Authority != "" { info.Authority = value.Authority }
	if len(namedResources) > 0 { info.Evidence = append(info.Evidence, EconomyEvidence{Kind:"name", Reference:mi.Name}) }
	if economyServerContext(mi.ClassName) || economyServerContext(mi.ClassPath) {
		info.Authority = "server_related"
		info.Evidence = append(info.Evidence, EconomyEvidence{Kind:"class", Reference:economyMethodReference(mi)})
	}
	return info, summary
}

// linkEconomyRelated fills Economy.Related for points that share one storage
// reference (field, preferences key, sqlite column, call). It is the first
// edge set of the resource graph: "diamonds → loaded here → spent there".
// Name/class-only evidence carries no reference and never links. Runs once
// per prediction across all buckets; bounded output, generic hubs skipped.
func linkEconomyRelated(prediction *PatchPrediction) {
	if prediction == nil { return }
	buckets := []*[]PatchPoint{
		&prediction.HighRisk, &prediction.MediumRisk, &prediction.LowRisk,
		&prediction.AuditFindings, &prediction.LibraryFindings, &prediction.MalwareIndicators,
	}
	byRef := map[string][]*PatchPoint{}
	var owners []*PatchPoint
	for _, bucket := range buckets {
		for i := range *bucket {
			point := &(*bucket)[i]
			if point.Economy == nil || len(point.Economy.Resources) == 0 { continue }
			owners = append(owners, point)
			seen := map[string]bool{}
			for _, evidence := range point.Economy.Evidence {
				if evidence.Kind == "name" || evidence.Kind == "class" || evidence.Kind == "write" || evidence.Reference == "" { continue }
				if seen[evidence.Reference] { continue }
				seen[evidence.Reference] = true
				byRef[evidence.Reference] = append(byRef[evidence.Reference], point)
			}
		}
	}
	const maxRelated = 8
	for _, point := range owners {
		if len(point.Economy.Related) > 0 { continue }
		seen := map[string]bool{}
		for _, evidence := range point.Economy.Evidence {
			if evidence.Kind == "name" || evidence.Kind == "class" || evidence.Kind == "write" || evidence.Reference == "" { continue }
			peers := byRef[evidence.Reference]
			if len(peers) < 2 || len(peers) > maxRelated+1 { continue }
			for _, peer := range peers {
				if peer == point { continue }
				name := peer.MethodName
				if name == "" { name = peer.MethodSignature }
				if peer.ClassName != "" && peer.ClassName != point.ClassName { name = peer.ClassName + " " + name }
				key := peer.Economy.Operation + "\x00" + name
				if seen[key] { continue }
				seen[key] = true
				point.Economy.Related = append(point.Economy.Related, EconomyRelation{Method: name, Operation: peer.Economy.Operation, Via: evidence.Kind + ":" + evidence.Reference})
				if len(point.Economy.Related) >= maxRelated { break }
			}
			if len(point.Economy.Related) >= maxRelated { break }
		}
		sort.Slice(point.Economy.Related, func(i, j int) bool {
			if point.Economy.Related[i].Method != point.Economy.Related[j].Method { return point.Economy.Related[i].Method < point.Economy.Related[j].Method }
			return point.Economy.Related[i].Operation < point.Economy.Related[j].Operation
		})
	}
}
