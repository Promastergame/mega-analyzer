package jarloader

import (
	"bytes"
	"encoding/binary"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func invocationPool() []constant {
	return []constant{{}, {tag: cpUtf8, utf8: "java/lang/Runtime"}, {tag: cpClass, nameIndex: 1}, {tag: cpUtf8, utf8: "exec"}, {tag: cpUtf8, utf8: "()V"}, {tag: cpNameAndType, nameIndex: 3, descIndex: 4}, {tag: cpMethodref, classIndex: 2, ntIndex: 5}}
}

func classWithCode(t *testing.T, code []byte) []byte {
	t.Helper()
	data := buildMinimalClass(t, "demo.App", "java.lang.Runtime", "exec", "()V")
	var b bytes.Buffer
	b.Write(data[:len(data)-14])
	for _, s := range []string{"Code", "run", "()V"} {
		b.WriteByte(cpUtf8)
		binary.Write(&b, binary.BigEndian, uint16(len(s)))
		b.WriteString(s)
	}
	w := func(v any) {
		t.Helper()
		if err := binary.Write(&b, binary.BigEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	w(uint16(0x21))
	w(uint16(2))
	w(uint16(4))
	w(uint16(0))
	w(uint16(0))
	w(uint16(1))
	w(uint16(1))
	w(uint16(12))
	w(uint16(13))
	w(uint16(1))
	w(uint16(11))
	w(uint32(12 + len(code)))
	w(uint16(2))
	w(uint16(1))
	w(uint32(len(code)))
	b.Write(code)
	w(uint16(0))
	w(uint16(0))
	w(uint16(0))
	out := b.Bytes()
	binary.BigEndian.PutUint16(out[8:10], 14)
	return out
}

func TestBytecodeCollectsRealCallCoordinates(t *testing.T) {
	cf, err := ParseClass(classWithCode(t, []byte{0x2a, 0xb6, 0, 10, 0xb1}))
	if err != nil {
		t.Fatal(err)
	}
	if !cf.BytecodeParsed || cf.InstructionCount != 3 || len(cf.CallSites) != 1 || cf.CallSites[0].Offset != 1 || cf.CallSites[0].Caller != "run" {
		t.Fatalf("unexpected bytecode: %+v", cf)
	}
	m := firstCategory(analyzeClass(cf, "App.class"), "COMMAND_EXECUTION")
	if m == nil || m.EvidenceType != "bytecode_invocation" || m.Metadata["bytecode_offset"] != "1" || m.MethodName != "run" || m.Metadata["execution_proven"] != "false" {
		t.Fatalf("missing exact evidence: %+v", m)
	}
}

func TestBytecodeUnusedPoolReferenceRemainsReference(t *testing.T) {
	cf, err := ParseClass(classWithCode(t, []byte{0xb1}))
	if err != nil {
		t.Fatal(err)
	}
	m := firstCategory(analyzeClass(cf, "App.class"), "COMMAND_EXECUTION")
	if m == nil || m.EvidenceType != "constant_pool_reference" || m.MethodName != "" {
		t.Fatalf("unused reference promoted: %+v", m)
	}
}

func TestBytecodeOperandIsNotAnInvocation(t *testing.T) {
	calls, count, _, err := decodeInstructions([]byte{0x11, 0xb6, 0xb8, 0xc4, 0x84, 0, 1, 0xb6, 0xb8, 0xb1}, invocationPool(), 20)
	if err != nil || len(calls) != 0 || count != 3 {
		t.Fatalf("operand decoded as opcode: %v %v %d", err, calls, count)
	}
}

func TestBytecodeRejectsMalformedInstructions(t *testing.T) {
	cases := [][]byte{{0xb6}, {0xb6, 0, 0}, {0xb6, 0, 1}, {0xba, 0, 6, 0, 0}, {0xc4, 0x00}, {0xc4, 0x84, 0}, {0xca}, {0xff}, {0xa7, 0, 1}, {0xa7, 0xff, 0xff}, {0xaa, 0}, {0xab, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}}
	for _, code := range cases {
		if _, _, _, err := decodeInstructions(code, invocationPool(), 20); err == nil {
			t.Errorf("accepted %x", code)
		}
	}
}

func TestBytecodeSwitchAlignmentAndTargets(t *testing.T) {
	code := make([]byte, 21)
	code[0] = 0xaa
	binary.BigEndian.PutUint32(code[4:], 20)
	binary.BigEndian.PutUint32(code[16:], 20)
	code[20] = 0xb1
	calls, count, _, err := decodeInstructions(code, invocationPool(), 20)
	if err != nil || count != 2 || len(calls) != 0 {
		t.Fatalf("valid tableswitch: %v", err)
	}
	code[1] = 1
	if _, _, _, err := decodeInstructions(code, invocationPool(), 20); err == nil {
		t.Fatal("nonzero padding accepted")
	}
	code[1] = 0
	binary.BigEndian.PutUint32(code[16:], 19)
	if _, _, _, err := decodeInstructions(code, invocationPool(), 20); err == nil {
		t.Fatal("switch branch into operand accepted")
	}
}

func TestBytecodeLookupSwitchSortedKeys(t *testing.T) {
	code := make([]byte, 29)
	code[0] = 0xab
	binary.BigEndian.PutUint32(code[4:], 28)
	binary.BigEndian.PutUint32(code[8:], 2)
	binary.BigEndian.PutUint32(code[12:], 1)
	binary.BigEndian.PutUint32(code[16:], 28)
	binary.BigEndian.PutUint32(code[20:], 2)
	binary.BigEndian.PutUint32(code[24:], 28)
	code[28] = 0xb1
	if _, _, _, err := decodeInstructions(code, invocationPool(), 20); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(code[20:], 1)
	if _, _, _, err := decodeInstructions(code, invocationPool(), 20); err == nil {
		t.Fatal("duplicate switch key accepted")
	}
}

func TestBytecodeInvokeInterfaceAndDynamic(t *testing.T) {
	pool := invocationPool()
	pool[6].tag = cpInterfaceMethodref
	calls, _, _, err := decodeInstructions([]byte{0xb9, 0, 6, 1, 0, 0xb1}, pool, 20)
	if err != nil || len(calls) != 1 || calls[0].Opcode != "invokeinterface" {
		t.Fatal(err, calls)
	}
	for _, code := range [][]byte{{0xb9, 0, 6, 0, 0}, {0xb9, 0, 6, 1, 1}} {
		if _, _, _, err := decodeInstructions(code, pool, 20); err == nil {
			t.Fatal("invalid interface operands accepted")
		}
	}
	pool[6] = constant{tag: cpInvokeDynamic, classIndex: 3, ntIndex: 5}
	calls, _, _, err = decodeInstructions([]byte{0xba, 0, 6, 0, 0, 0xb1}, pool, 20)
	if err != nil || len(calls) != 1 || calls[0].BootstrapIndex != 3 || calls[0].Target.Class != "" {
		t.Fatal(err, calls)
	}
}

func TestBytecodeEvidenceRetentionIsBounded(t *testing.T) {
	code := []byte{0xb6, 0, 6, 0xb6, 0, 6, 0xb1}
	calls, count, truncated, err := decodeInstructions(code, invocationPool(), 1)
	if err != nil || len(calls) != 1 || count != 3 || !truncated {
		t.Fatal(err, calls, count, truncated)
	}
}

func TestBytecodeTrivialTLSNeedsExactSignature(t *testing.T) {
	cf := &ClassFile{ThisClass: "demo.Trust", BytecodeParsed: true, Interfaces: []string{"javax.net.ssl.HostnameVerifier"}, Methods: []MethodBody{{Name: "verify", Descriptor: "(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z", Access: 1, TrivialReturn: "true"}}}
	out := trivialTLSFindings(cf)
	if len(out) != 1 || out[0].Severity != types.SeverityHigh || out[0].Metadata["execution_proven"] != "false" {
		t.Fatal(out)
	}
	cf.Methods[0].Access = 9
	if len(trivialTLSFindings(cf)) != 0 {
		t.Fatal("static method is not an override")
	}
	cf.Methods[0].Access = 1
	cf.Methods[0].Descriptor = "()Z"
	if len(trivialTLSFindings(cf)) != 0 {
		t.Fatal("wrong signature accepted")
	}
}

func TestBytecodeEveryClassTruncationRejected(t *testing.T) {
	data := classWithCode(t, []byte{0xb6, 0, 10, 0xb1})
	for i := 0; i < len(data); i++ {
		if _, err := ParseClass(data[:i]); err == nil {
			t.Fatalf("accepted prefix %d", i)
		}
	}
}

func FuzzInstructionBoundaries(f *testing.F) {
	f.Add([]byte{0xb6, 0, 6, 0xb1})
	f.Add([]byte{0xc4, 0x84, 0, 0, 0, 1, 0xb1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			t.Skip()
		}
		_, _, _, _ = decodeInstructions(data, invocationPool(), 64)
	})
}

func TestBytecodeBootstrapResolution(t *testing.T) {
	code := []byte{0xba, 0, 15, 0, 0, 0xb1}
	data := classWithCode(t, code)
	tail := len(buildMinimalClass(t, "demo.App", "java.lang.Runtime", "exec", "()V")) - 14 + 19
	var b bytes.Buffer
	b.Write(data[:tail])
	b.Write([]byte{cpMethodHandle, 6, 0, 10, cpInvokeDynamic, 0, 0, 0, 9})
	name := "BootstrapMethods"
	b.WriteByte(cpUtf8)
	binary.Write(&b, binary.BigEndian, uint16(len(name)))
	b.WriteString(name)
	b.Write(data[tail : len(data)-2])
	b.Write([]byte{0, 1, 0, 16, 0, 0, 0, 6, 0, 1, 0, 14, 0, 0})
	full := b.Bytes()
	binary.BigEndian.PutUint16(full[8:10], 17)
	cf, err := ParseClass(full)
	if err != nil {
		t.Fatal(err)
	}
	if len(cf.CallSites) != 1 || cf.CallSites[0].Bootstrap == nil || cf.CallSites[0].Bootstrap.FullName() != "java.lang.Runtime.exec" {
		t.Fatalf("bootstrap missing: %+v", cf.CallSites)
	}
	// Drop the class attribute; the invokedynamic CP entry must not silently survive.
	missing := append([]byte(nil), full[:len(full)-14]...)
	missing = append(missing, 0, 0)
	if _, err := ParseClass(missing); err == nil {
		t.Fatal("missing bootstrap accepted")
	}
}

func TestBytecodeOverloadsDoNotShareCallEvidence(t *testing.T) {
	a := MethodRef{Class: "java.lang.Runtime", Name: "exec", Descriptor: "(Ljava/lang/String;)Ljava/lang/Process;"}
	b := MethodRef{Class: "java.lang.Runtime", Name: "exec", Descriptor: "([Ljava/lang/String;)Ljava/lang/Process;"}
	cf := &ClassFile{ThisClass: "demo.App", BytecodeParsed: true, MethodRefs: []MethodRef{a, b}, CallSites: []CallSite{{Caller: "run", CallerDescriptor: "()V", Offset: 4, Opcode: "invokevirtual", Target: a}}}
	out := analyzeClass(cf, "App.class")
	if len(out) != 2 || out[0].EvidenceType != "bytecode_invocation" || out[1].EvidenceType != "constant_pool_reference" {
		t.Fatalf("overload evidence leaked: %+v", out)
	}
}

func TestBytecodeModernLookupAndRuntimeSinks(t *testing.T) {
	for _, ref := range []MethodRef{{Class: "java.lang.invoke.MethodHandles$Lookup", Name: "defineHiddenClass"}, {Class: "java.lang.invoke.MethodHandles$Lookup", Name: "defineClass"}, {Class: "java.lang.Runtime", Name: "load"}, {Class: "java.lang.Runtime", Name: "loadLibrary"}} {
		cf := &ClassFile{ThisClass: "demo.App", MethodRefs: []MethodRef{ref}}
		if len(analyzeClass(cf, "App.class")) != 1 {
			t.Fatal("missing modern API", ref)
		}
	}
}
