package apkloader

import (
	"reflect"
	"testing"
)

func TestOwnedMethodResolverUsesCanonicalDescriptors(t *testing.T) {
	methods := []OwnedDEXMethod{
		{MethodIdx: 2, ClassName: "Lx/B;", MethodName: "decode", Parameters: []string{"I"}, ReturnType: "Ljava/lang/String;"},
		{MethodIdx: 1, ClassName: "Lx/A;", MethodName: "decode", Parameters: []string{"Ljava/lang/String;"}, ReturnType: "Ljava/lang/String;"},
	}
	resolver := NewOwnedMethodResolver(methods)
	want := []string{
		"Lx/A;->decode(Ljava/lang/String;)Ljava/lang/String;",
		"Lx/B;->decode(I)Ljava/lang/String;",
	}
	if got := resolver.Descriptors(); !reflect.DeepEqual(got, want) {
		t.Fatalf("descriptors = %v, want %v", got, want)
	}
	method, ok := resolver.Resolve(want[1])
	if !ok || method.MethodIdx != 2 {
		t.Fatalf("resolve = %+v, %v", method, ok)
	}
}

func TestMethodDescriptorMatchesOwnedAndReferenceMethods(t *testing.T) {
	parameters := []string{"[B", "I"}
	want := "Lx/D;->decode([BI)Ljava/lang/String;"
	if got := MethodDescriptor("Lx/D;", "decode", parameters, "Ljava/lang/String;"); got != want {
		t.Fatalf("descriptor = %q, want %q", got, want)
	}
	if got := (Method{ClassName: "Lx/D;", MethodName: "decode", Parameters: parameters, ReturnType: "Ljava/lang/String;"}).Descriptor(); got != want {
		t.Fatalf("method descriptor = %q, want %q", got, want)
	}
	if got := (OwnedDEXMethod{ClassName: "Lx/D;", MethodName: "decode", Parameters: parameters, ReturnType: "Ljava/lang/String;"}).Descriptor(); got != want {
		t.Fatalf("owned descriptor = %q, want %q", got, want)
	}
}
