package callgraph

import (
	"sort"

	"mega-analyzer/pkg/internal/dexir"
)

type classInfo struct {
	class   *dexir.Class
	methods map[string]*dexir.Method
}

// ClassHierarchy indexes inheritance and interface implementation facts.
type ClassHierarchy struct {
	classes  map[string]*classInfo
	children map[string]map[string]struct{}
}

func NewClassHierarchy(classes []*dexir.Class) *ClassHierarchy {
	h := &ClassHierarchy{
		classes:  make(map[string]*classInfo, len(classes)),
		children: make(map[string]map[string]struct{}, len(classes)),
	}
	for _, class := range classes {
		h.AddClass(class)
	}
	return h
}

func (h *ClassHierarchy) AddClass(class *dexir.Class) {
	if class == nil || class.Descriptor == "" {
		return
	}
	methods := make(map[string]*dexir.Method, len(class.Methods))
	for _, method := range class.Methods {
		if method != nil {
			methods[methodKey(method.Name, methodProto(method))] = method
		}
	}
	h.classes[class.Descriptor] = &classInfo{class: class, methods: methods}
	for _, parent := range append([]string{class.SuperClass}, class.Interfaces...) {
		if parent == "" {
			continue
		}
		if h.children[parent] == nil {
			h.children[parent] = make(map[string]struct{})
		}
		h.children[parent][class.Descriptor] = struct{}{}
	}
}

func (h *ClassHierarchy) Known(desc string) bool {
	_, ok := h.classes[desc]
	return ok
}

func (h *ClassHierarchy) Supers(desc string) []string {
	seen := map[string]struct{}{desc: {}}
	queue := []string{desc}
	var out []string
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		info := h.classes[current]
		if info == nil {
			continue
		}
		parents := append([]string{info.class.SuperClass}, info.class.Interfaces...)
		for _, parent := range parents {
			if parent == "" {
				continue
			}
			if _, ok := seen[parent]; ok {
				continue
			}
			seen[parent] = struct{}{}
			out = append(out, parent)
			queue = append(queue, parent)
		}
	}
	sort.Strings(out)
	return out
}

func (h *ClassHierarchy) Subs(desc string) []string {
	seen := map[string]struct{}{desc: {}}
	queue := []string{desc}
	var out []string
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for child := range h.children[current] {
			if _, ok := seen[child]; ok {
				continue
			}
			seen[child] = struct{}{}
			out = append(out, child)
			queue = append(queue, child)
		}
	}
	sort.Strings(out)
	return out
}

// LookupMethod resolves a declaration on classDesc or its ancestors.
func (h *ClassHierarchy) LookupMethod(classDesc, name, proto string) (string, bool) {
	seen := make(map[string]struct{})
	queue := []string{classDesc}
	key := methodKey(name, proto)
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, ok := seen[current]; ok {
			continue
		}
		seen[current] = struct{}{}
		info := h.classes[current]
		if info == nil {
			continue
		}
		if _, ok := info.methods[key]; ok {
			return current, true
		}
		if info.class.SuperClass != "" {
			queue = append(queue, info.class.SuperClass)
		}
		queue = append(queue, info.class.Interfaces...)
	}
	return "", false
}

// FindImplementations returns all class descriptors in the hierarchy (classDesc and its subclasses/implementations)
// that define or override the method with the given name and proto signature.
func (h *ClassHierarchy) FindImplementations(classDesc, name, proto string) []string {
	var candidates []string
	targets := append([]string{classDesc}, h.Subs(classDesc)...)
	seen := make(map[string]struct{})
	for _, target := range targets {
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		if defining, ok := h.LookupMethod(target, name, proto); ok && defining == target {
			candidates = append(candidates, target)
		}
	}
	sort.Strings(candidates)
	return candidates
}

func (h *ClassHierarchy) methodsNamed(classDesc, name string) []*dexir.Method {
	info := h.classes[classDesc]
	if info == nil {
		return nil
	}
	var out []*dexir.Method
	for _, method := range info.class.Methods {
		if method != nil && method.Name == name {
			out = append(out, method)
		}
	}
	return out
}

func methodKey(name, proto string) string { return name + proto }

func methodProto(method *dexir.Method) string {
	proto := "("
	for _, param := range method.Params {
		proto += param
	}
	return proto + ")" + method.ReturnType
}

func methodRef(class string, method *dexir.Method) string {
	return class + "->" + method.Name + methodProto(method)
}
