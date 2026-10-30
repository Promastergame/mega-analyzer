package apkloader

import (
	"sort"
	"strings"
)

const accessFlagStatic uint32 = 0x0008

// MethodDescriptor returns the canonical DEX method identity used by owned
// resolvers, invoke references, memoization keys, and execution provenance.
func MethodDescriptor(className, methodName string, parameters []string, returnType string) string {
	var b strings.Builder
	b.Grow(len(className) + len(methodName) + len(returnType) + 4)
	b.WriteString(className)
	b.WriteString("->")
	b.WriteString(methodName)
	b.WriteByte('(')
	for _, parameter := range parameters {
		b.WriteString(parameter)
	}
	b.WriteByte(')')
	b.WriteString(returnType)
	return b.String()
}

func (m Method) Descriptor() string {
	return MethodDescriptor(m.ClassName, m.MethodName, m.Parameters, m.ReturnType)
}

func (m *EncodedMethod) Descriptor() string {
	if m == nil {
		return ""
	}
	return MethodDescriptor(m.ClassName, m.Name, m.Parameters, m.ReturnType)
}

func (m OwnedDEXMethod) Descriptor() string {
	return MethodDescriptor(m.ClassName, m.MethodName, m.Parameters, m.ReturnType)
}

func (m OwnedDEXMethod) IsStatic() bool {
	return m.AccessFlags&accessFlagStatic != 0
}

// OwnedMethodResolver is immutable after construction and safe for concurrent
// reads. It deliberately contains parser-detached methods only.
type OwnedMethodResolver struct {
	methods map[string]OwnedDEXMethod
	ordered []string
}

func NewOwnedMethodResolver(methods []OwnedDEXMethod) *OwnedMethodResolver {
	resolver := &OwnedMethodResolver{methods: make(map[string]OwnedDEXMethod, len(methods))}
	for _, method := range methods {
		descriptor := method.Descriptor()
		if descriptor == "" {
			continue
		}
		if _, exists := resolver.methods[descriptor]; exists {
			continue
		}
		resolver.methods[descriptor] = method
		resolver.ordered = append(resolver.ordered, descriptor)
	}
	sort.Strings(resolver.ordered)
	return resolver
}

func (r *OwnedMethodResolver) Resolve(descriptor string) (OwnedDEXMethod, bool) {
	if r == nil {
		return OwnedDEXMethod{}, false
	}
	method, ok := r.methods[descriptor]
	return method, ok
}

func (r *OwnedMethodResolver) Descriptors() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.ordered...)
}

func (r *OwnedMethodResolver) Len() int {
	if r == nil {
		return 0
	}
	return len(r.methods)
}
