package apkloader

import "sort"

// StaticValueKind is the parser-neutral subset accepted from DEX encoded_value
// and bounded class initialization.
type StaticValueKind uint8

const (
	StaticUnknown StaticValueKind = iota
	StaticIntegral
	StaticNull
	StaticString
	StaticArray
)

// OwnedStaticValue is parser-detached and immutable after resolver construction.
type OwnedStaticValue struct {
	Kind        StaticValueKind
	TypeName    string
	Int64       int64
	String      string
	Elements    []OwnedStaticValue
	Transformed bool
	Operations  []string
}

func FieldDescriptor(className, fieldName, typeName string) string {
	return className + "->" + fieldName + ":" + typeName
}

func (f Field) Descriptor() string {
	return FieldDescriptor(f.ClassName, f.FieldName, f.TypeName)
}

func (f *EncodedField) Descriptor() string {
	if f == nil {
		return ""
	}
	return FieldDescriptor(f.ClassName, f.Name, f.TypeName)
}

// OwnedStaticResolver is immutable after construction and safe for concurrent reads.
type OwnedStaticResolver struct {
	values  map[string]OwnedStaticValue
	ordered []string
}

func NewOwnedStaticResolver(values map[string]OwnedStaticValue) *OwnedStaticResolver {
	resolver := &OwnedStaticResolver{values: make(map[string]OwnedStaticValue, len(values))}
	for descriptor, value := range values {
		resolver.values[descriptor] = cloneOwnedStaticValue(value)
		resolver.ordered = append(resolver.ordered, descriptor)
	}
	sort.Strings(resolver.ordered)
	return resolver
}

func (r *OwnedStaticResolver) Resolve(descriptor string) (OwnedStaticValue, bool) {
	if r == nil {
		return OwnedStaticValue{}, false
	}
	value, ok := r.values[descriptor]
	return cloneOwnedStaticValue(value), ok
}

func (r *OwnedStaticResolver) Descriptors() []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.ordered...)
}

func (r *OwnedStaticResolver) Values() map[string]OwnedStaticValue {
	out := make(map[string]OwnedStaticValue)
	if r == nil {
		return out
	}
	for descriptor, value := range r.values {
		out[descriptor] = cloneOwnedStaticValue(value)
	}
	return out
}

func (r *OwnedStaticResolver) Len() int {
	if r == nil {
		return 0
	}
	return len(r.values)
}

func cloneOwnedStaticValue(value OwnedStaticValue) OwnedStaticValue {
	out := value
	out.Operations = append([]string(nil), value.Operations...)
	out.Elements = make([]OwnedStaticValue, len(value.Elements))
	for i := range value.Elements {
		out.Elements[i] = cloneOwnedStaticValue(value.Elements[i])
	}
	return out
}
