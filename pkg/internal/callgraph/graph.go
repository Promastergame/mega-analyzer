package callgraph

import (
	"sort"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/dexir"
)

type InvokeKind string

const (
	InvokeDirect     InvokeKind = "direct"
	InvokeStatic     InvokeKind = "static"
	InvokeVirtual    InvokeKind = "virtual"
	InvokeInterface  InvokeKind = "interface"
	InvokeReflection InvokeKind = "reflection"
)

type CallSite struct {
	Caller   string
	Callee   string
	Line     int
	Kind     InvokeKind
	Resolved bool
}

type Node struct {
	Method  string
	Class   string
	Name    string
	Callees []string
	Callers []string
}

type Stats struct {
	Nodes             int
	Edges             int
	CHAEdges          int
	ReflectionEdges   int
	InstantiatedTypes int
}

type edge struct {
	CallSite
	cha      bool
	declared bool
}

type Graph struct {
	nodes map[string]*Node
	sites []CallSite
	stats Stats
}

type Builder struct {
	mu        sync.RWMutex
	classes   map[string]*dexir.Class
	fanoutCap int
	applyRTA  bool
}

func NewBuilder() *Builder {
	return &Builder{classes: make(map[string]*dexir.Class), fanoutCap: 50}
}

func (b *Builder) SetFanoutCap(limit int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit > 0 {
		b.fanoutCap = limit
	}
}

func (b *Builder) AddClass(class *dexir.Class) {
	if class == nil || class.Descriptor == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.classes[class.Descriptor] = class
}

// ApplyRTA enables filtering of CHA targets to classes instantiated by new-instance.
func (b *Builder) ApplyRTA() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applyRTA = true
}

func (b *Builder) Build() *Graph {
	b.mu.RLock()
	classes := make([]*dexir.Class, 0, len(b.classes))
	for _, class := range b.classes {
		classes = append(classes, class)
	}
	fanoutCap := b.fanoutCap
	useRTA := b.applyRTA
	b.mu.RUnlock()

	sort.Slice(classes, func(i, j int) bool { return classes[i].Descriptor < classes[j].Descriptor })
	hierarchy := NewClassHierarchy(classes)
	instantiated := collectInstantiated(classes)
	var edges []edge

	for _, class := range classes {
		for _, method := range class.Methods {
			if method == nil {
				continue
			}
			caller := methodRef(class.Descriptor, method)
			edges = append(edges, buildMethodEdges(hierarchy, caller, method, fanoutCap)...)
		}
	}
	if useRTA {
		edges = filterRTA(edges, hierarchy, instantiated)
	}
	return makeGraph(classes, edges, len(instantiated))
}

func collectInstantiated(classes []*dexir.Class) map[string]struct{} {
	out := make(map[string]struct{})
	for _, class := range classes {
		for _, method := range class.Methods {
			for _, ins := range method.Instructions {
				if ins != nil && ins.Op == dexir.OpNewInstance && ins.Type != "" {
					out[ins.Type] = struct{}{}
				}
			}
		}
	}
	return out
}

func buildMethodEdges(h *ClassHierarchy, caller string, method *dexir.Method, fanoutCap int) []edge {
	var edges []edge
	for _, ins := range method.Instructions {
		if ins == nil || !ins.IsInvoke() || ins.Method == nil {
			continue
		}
		kind := invokeKind(ins.Op)
		base := edge{CallSite: CallSite{Caller: caller, Callee: ins.Method.String(), Line: ins.Line, Kind: kind, Resolved: true}, declared: true}
		if kind != InvokeVirtual && kind != InvokeInterface {
			edges = append(edges, base)
			continue
		}

		candidates := []edge{base}
		for _, sub := range h.Subs(ins.Method.Class) {
			defining, ok := h.LookupMethod(sub, ins.Method.Name, ins.Method.Proto)
			if !ok || defining != sub {
				continue
			}
			candidates = append(candidates, edge{
				CallSite: CallSite{Caller: caller, Callee: sub + "->" + ins.Method.Name + ins.Method.Proto, Line: ins.Line, Kind: kind, Resolved: true},
				cha:      true,
			})
		}
		if len(candidates)-1 > fanoutCap {
			base.Resolved = false
			edges = append(edges, base)
		} else {
			edges = append(edges, candidates...)
		}
	}
	return append(edges, reflectionEdges(h, caller, method)...)
}

func invokeKind(op dexir.Opcode) InvokeKind {
	switch op {
	case dexir.OpInvokeStatic, dexir.OpInvokeStaticRange:
		return InvokeStatic
	case dexir.OpInvokeDirect, dexir.OpInvokeDirectRange, dexir.OpInvokeSuper, dexir.OpInvokeSuperRange:
		return InvokeDirect
	case dexir.OpInvokeInterface, dexir.OpInvokeInterfaceRange:
		return InvokeInterface
	default:
		return InvokeVirtual
	}
}

func filterRTA(edges []edge, hierarchy *ClassHierarchy, instantiated map[string]struct{}) []edge {
	out := edges[:0]
	for _, item := range edges {
		if !item.cha || item.declared {
			out = append(out, item)
			continue
		}
		class := classFromMethodRef(item.Callee)
		if !hierarchy.Known(class) {
			out = append(out, item)
			continue
		}
		if _, ok := instantiated[class]; ok {
			out = append(out, item)
		}
	}
	return out
}

func reflectionEdges(h *ClassHierarchy, caller string, method *dexir.Method) []edge {
	stringsByReg := make(map[int32]string)
	classesByReg := make(map[int32]string)
	methodsByReg := make(map[int32]reflectionTarget)
	var pendingClass string
	var pendingMethod *reflectionTarget
	var out []edge

	for _, ins := range method.Instructions {
		if ins == nil {
			continue
		}
		if (ins.Op == dexir.OpConstString || ins.Op == dexir.OpConstStringJumbo) && ins.HasStr {
			stringsByReg[ins.Dst] = ins.Str
			continue
		}
		if ins.Op == dexir.OpMoveResultObject || ins.Op == dexir.OpMoveResult {
			if pendingClass != "" {
				classesByReg[ins.Dst] = pendingClass
				pendingClass = ""
			}
			if pendingMethod != nil {
				methodsByReg[ins.Dst] = *pendingMethod
				pendingMethod = nil
			}
			continue
		}
		if !ins.IsInvoke() || ins.Method == nil {
			pendingClass = ""
			pendingMethod = nil
			continue
		}

		ref := ins.Method
		switch {
		case ref.Class == "Ljava/lang/Class;" && ref.Name == "forName" && len(ins.Srcs) > 0:
			pendingClass = descriptorFromJavaName(stringsByReg[ins.Srcs[0]])
		case ref.Name == "loadClass" && len(ins.Srcs) > 1:
			pendingClass = descriptorFromJavaName(stringsByReg[ins.Srcs[len(ins.Srcs)-1]])
		case ref.Class == "Ljava/lang/Class;" && (ref.Name == "getMethod" || ref.Name == "getDeclaredMethod") && len(ins.Srcs) > 1:
			class := classesByReg[ins.Srcs[0]]
			name := stringsByReg[ins.Srcs[1]]
			if class != "" && name != "" {
				pendingMethod = &reflectionTarget{class: class, name: name}
			}
		case ref.Class == "Ljava/lang/reflect/Method;" && ref.Name == "invoke" && len(ins.Srcs) > 0:
			target, ok := methodsByReg[ins.Srcs[0]]
			if !ok {
				continue
			}
			matches := h.methodsNamed(target.class, target.name)
			if len(matches) > 10 {
				matches = matches[:10]
			}
			for _, match := range matches {
				out = append(out, edge{CallSite: CallSite{
					Caller: caller, Callee: methodRef(target.class, match), Line: ins.Line,
					Kind: InvokeReflection, Resolved: true,
				}})
			}
		}
	}
	return out
}

type reflectionTarget struct{ class, name string }

func descriptorFromJavaName(name string) string {
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, "L") && strings.HasSuffix(name, ";") {
		return name
	}
	return "L" + strings.ReplaceAll(name, ".", "/") + ";"
}

func classFromMethodRef(ref string) string {
	if i := strings.Index(ref, "->"); i >= 0 {
		return ref[:i]
	}
	return ""
}

func makeGraph(classes []*dexir.Class, edges []edge, instantiated int) *Graph {
	g := &Graph{nodes: make(map[string]*Node), stats: Stats{InstantiatedTypes: instantiated}}
	for _, class := range classes {
		for _, method := range class.Methods {
			if method != nil {
				key := methodRef(class.Descriptor, method)
				g.nodes[key] = &Node{Method: key, Class: class.Descriptor, Name: method.Name}
			}
		}
	}
	seen := make(map[string]struct{})
	for _, item := range edges {
		key := item.Caller + "\x00" + item.Callee + "\x00" + string(item.Kind)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		caller := ensureNode(g.nodes, item.Caller)
		callee := ensureNode(g.nodes, item.Callee)
		caller.Callees = append(caller.Callees, item.Callee)
		callee.Callers = append(callee.Callers, item.Caller)
		g.sites = append(g.sites, item.CallSite)
		if item.cha {
			g.stats.CHAEdges++
		}
		if item.Kind == InvokeReflection {
			g.stats.ReflectionEdges++
		}
	}
	for _, node := range g.nodes {
		sort.Strings(node.Callees)
		sort.Strings(node.Callers)
	}
	g.stats.Nodes = len(g.nodes)
	g.stats.Edges = len(g.sites)
	return g
}

func ensureNode(nodes map[string]*Node, ref string) *Node {
	if node := nodes[ref]; node != nil {
		return node
	}
	node := &Node{Method: ref, Class: classFromMethodRef(ref)}
	nodes[ref] = node
	return node
}

func (g *Graph) Callees(method string) []string {
	if g == nil || g.nodes[method] == nil {
		return nil
	}
	return append([]string(nil), g.nodes[method].Callees...)
}

func (g *Graph) Callers(method string) []string {
	if g == nil || g.nodes[method] == nil {
		return nil
	}
	return append([]string(nil), g.nodes[method].Callers...)
}

func (g *Graph) Sites() []CallSite {
	if g == nil {
		return nil
	}
	return append([]CallSite(nil), g.sites...)
}

func (g *Graph) Stats() Stats {
	if g == nil {
		return Stats{}
	}
	return g.stats
}

func (g *Graph) Reachable(from, to string, maxDepth int) ([]string, bool) {
	if g == nil || maxDepth < 0 {
		return nil, false
	}
	type state struct {
		method string
		path   []string
		depth  int
	}
	seen := map[string]struct{}{from: {}}
	queue := []state{{method: from, path: []string{from}}}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.method == to {
			return current.path, true
		}
		if current.depth >= maxDepth {
			continue
		}
		for _, callee := range g.Callees(current.method) {
			if _, ok := seen[callee]; ok {
				continue
			}
			seen[callee] = struct{}{}
			path := append(append([]string(nil), current.path...), callee)
			queue = append(queue, state{method: callee, path: path, depth: current.depth + 1})
		}
	}
	return nil, false
}
