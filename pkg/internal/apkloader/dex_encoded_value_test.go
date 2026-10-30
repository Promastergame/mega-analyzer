package apkloader

import "testing"

func TestDecodeStaticValuesMapsFieldsAndDefaults(t *testing.T) {
	// encoded_array size=2; VALUE_INT(1 byte)=0x7f; VALUE_STRING index=0.
	parser := &DEXParser{data: []byte{2, 0x04, 0x7f, 0x17, 0x00}, strings: []string{"secret"}}
	class := &ClassDef{
		ClassName: "Lx/S;", StaticValuesOff: 0,
		StaticFields: []*EncodedField{
			{FieldIdx: 0, ClassName: "Lx/S;", Name: "n", TypeName: "I"},
			{FieldIdx: 1, ClassName: "Lx/S;", Name: "s", TypeName: "Ljava/lang/String;"},
			{FieldIdx: 2, ClassName: "Lx/S;", Name: "z", TypeName: "Z"},
		},
	}
	// Offset zero means absent by spec, so prefix one padding byte.
	parser.data = append([]byte{0}, parser.data...)
	class.StaticValuesOff = 1
	values, err := parser.decodeStaticValues(class, 4, 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	if got := values["Lx/S;->n:I"]; got.Kind != StaticIntegral || got.Int64 != 0x7f {
		t.Fatalf("int value = %+v", got)
	}
	if got := values["Lx/S;->s:Ljava/lang/String;"]; got.Kind != StaticString || got.String != "secret" {
		t.Fatalf("string value = %+v", got)
	}
	if got := values["Lx/S;->z:Z"]; got.Kind != StaticIntegral || got.Int64 != 0 {
		t.Fatalf("default value = %+v", got)
	}
}

func TestDecodeStaticValuesRejectsMalformedWidth(t *testing.T) {
	parser := &DEXParser{data: []byte{0, 1, 0x84, 1, 2, 3, 4, 5}}
	class := &ClassDef{ClassName: "Lx/S;", StaticValuesOff: 1, StaticFields: []*EncodedField{{ClassName: "Lx/S;", Name: "n", TypeName: "I"}}}
	if _, err := parser.decodeStaticValues(class, 4, 16, 64); err == nil {
		t.Fatal("invalid VALUE_INT width accepted")
	}
}

func TestOwnedStaticResolverDetachesValues(t *testing.T) {
	input := map[string]OwnedStaticValue{"Lx/S;->a:[I": {Kind: StaticArray, Elements: []OwnedStaticValue{{Kind: StaticIntegral, Int64: 7}}}}
	resolver := NewOwnedStaticResolver(input)
	input["Lx/S;->a:[I"].Elements[0].Int64 = 9
	got, ok := resolver.Resolve("Lx/S;->a:[I")
	if !ok || got.Elements[0].Int64 != 7 {
		t.Fatalf("resolver retained mutable input: %+v", got)
	}
	got.Elements[0].Int64 = 11
	again, _ := resolver.Resolve("Lx/S;->a:[I")
	if again.Elements[0].Int64 != 7 {
		t.Fatalf("resolver returned mutable storage: %+v", again)
	}
}
