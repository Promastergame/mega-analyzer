package jarloader

import (
	"encoding/binary"
	"testing"
)

// buildFlowClass assembles a minimal class with one method carrying raw
// bytecode. Pool layout: 1:thisUtf 2:Class1 3:ObjectUtf 4:Class3
// 5:refClass 6:Class5 7:refMethod 8:refDesc 9:NT(7,8) 10:Methodref(6,9)
// 11..: literalUtf, String->literalUtf, "Code", "run", "()V", NT, then Code.
func buildFlowClass(t *testing.T, thisClass, refClass, refMethod, refDesc string, literals []string, code []byte) []byte {
	t.Helper()
	var b []byte
	put := func(v any) {
		var tmp [8]byte
		switch x := v.(type) {
		case uint8:
			b = append(b, byte(x))
		case uint16:
			binary.BigEndian.PutUint16(tmp[:], x)
			b = append(b, tmp[:2]...)
		case uint32:
			binary.BigEndian.PutUint32(tmp[:], x)
			b = append(b, tmp[:4]...)
		case string:
			b = append(b, x...)
		}
	}
	utf := func(s string) {
		put(uint8(cpUtf8))
		put(uint16(len(s)))
		put(s)
	}
	toI := func(dotted string) string {
		out := make([]byte, len(dotted))
		for i := 0; i < len(dotted); i++ {
			if dotted[i] == '.' {
				out[i] = '/'
			} else {
				out[i] = dotted[i]
			}
		}
		return string(out)
	}
	put(uint32(classMagic))
	put(uint16(0))
	put(uint16(52))
	body := func() {}
	_ = body
	// Reserve count position.
	cpStart := len(b)
	put(uint16(0))
	n := 0
	utf(toI(thisClass)) // 1
	n++
	put(uint8(cpClass)) // 2
	put(uint16(1))
	n++
	utf("java/lang/Object") // 3
	n++
	put(uint8(cpClass)) // 4
	put(uint16(3))
	n++
	utf(toI(refClass)) // 5
	n++
	put(uint8(cpClass)) // 6
	put(uint16(5))
	n++
	utf(refMethod) // 7
	n++
	utf(refDesc) // 8
	n++
	put(uint8(cpNameAndType)) // 9
	put(uint16(7))
	put(uint16(8))
	n++
	put(uint8(cpMethodref)) // 10
	put(uint16(6))
	put(uint16(9))
	n++
	litIdx := map[string]uint16{}
	for _, lit := range literals {
		utf(lit)
		litIdx[lit] = uint16(n + 1)
		n++
		put(uint8(cpString))
		put(litIdx[lit])
		n++
	}
	utf("Code") // codeName
	codeName := n + 1
	n++
	utf("run") // methodName
	methodName := n + 1
	n++
	utf("()V") // methodDesc
	methodDesc := n + 1
	n++
	put(uint8(cpNameAndType))
	put(uint16(methodName))
	put(uint16(methodDesc))
	n++
	binary.BigEndian.PutUint16(b[cpStart:], uint16(n+1))
	_ = litIdx
	_ = codeName
	put(uint16(0x0021))
	put(uint16(2))
	put(uint16(4))
	put(uint16(0))
	put(uint16(0))
	put(uint16(1)) // one method
	put(uint16(1)) // public
	put(uint16(methodName))
	put(uint16(methodDesc))
	put(uint16(1)) // one attribute: Code
	put(uint16(codeName))
	// Code attribute: max_stack=2, max_locals=4, code, no handlers, no attrs.
	put(uint32(uint32(12 + len(code))))
	put(uint16(2))
	put(uint16(4))
	put(uint32(uint32(len(code))))
	b = append(b, code...)
	put(uint16(0)) // exception table
	put(uint16(0)) // code attrs
	put(uint16(0)) // class attrs
	return b
}

func TestFlowStraightLine(t *testing.T) {
	// ldc String(MD5); invokestatic #10; return
	code := []byte{0x12, 0x0c, 0xb8, 0x00, 0x0a, 0xb1}
	data := buildFlowClass(t, "com.example.C", "java.security.MessageDigest", "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;", []string{"MD5"}, code)
	cf, err := ParseClass(data)
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	if len(cf.Methods) != 1 || len(cf.Methods[0].Code) == 0 {
		t.Fatalf("code not retained: %+v", cf.Methods)
	}
	got := resolvePreciseArgs(cf.Methods[0].Code, cf.Methods[0].MaxLocals, cf.pool)
	if got[2] != "MD5" {
		t.Errorf("arg at pc=2 = %q, want MD5 (got map %v)", got[2], got)
	}
}

func TestFlowThroughLocal(t *testing.T) {
	// ldc String(DES); astore_1; aload_1; invokestatic #10; return
	code := []byte{0x12, 0x0c, 0x4c, 0x2b, 0xb8, 0x00, 0x0a, 0xb1}
	data := buildFlowClass(t, "com.example.C", "javax.crypto.Cipher", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;", []string{"DES"}, code)
	cf, err := ParseClass(data)
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	got := resolvePreciseArgs(cf.Methods[0].Code, cf.Methods[0].MaxLocals, cf.pool)
	if got[4] != "DES" {
		t.Errorf("arg at pc=4 = %q, want DES (got map %v)", got[4], got)
	}
}

func TestFlowBranchJoinUnknown(t *testing.T) {
	// ldc String(A); ifeq +8; ldc String(B); goto +5; ldc String(C); invokestatic; return
	// Join of B/C at the call: unknown (different constants).
	code := []byte{
		0x12, 0x0c, // 0
		0x99, 0x00, 0x08, // 2: ifeq 10
		0x12, 0x0e, // 5
		0xa7, 0x00, 0x05, // 7: goto 12
		0x12, 0x10, // 10
		0xb8, 0x00, 0x0a, // 12: invokestatic
		0xb1, // 15: return
	}
	data := buildFlowClass(t, "com.example.C", "java.security.MessageDigest", "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;", []string{"A", "B", "C"}, code)
	cf, err := ParseClass(data)
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	got := resolvePreciseArgs(cf.Methods[0].Code, cf.Methods[0].MaxLocals, cf.pool)
	if _, ok := got[12]; ok {
		t.Errorf("joined branches must be unknown, got %q", got[12])
	}
}

func TestFlowSameConstBothBranches(t *testing.T) {
	// Same shape as above but both branches load String(MD5): join keeps it.
	code := []byte{
		0x12, 0x0c, // 0
		0x99, 0x00, 0x08, // 2: ifeq 10
		0x12, 0x0c, // 5
		0xa7, 0x00, 0x05, // 7: goto 12
		0x12, 0x0c, // 10
		0xb8, 0x00, 0x0a, // 12: invokestatic
		0xb1,
	}
	data := buildFlowClass(t, "com.example.C", "java.security.MessageDigest", "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;", []string{"MD5"}, code)
	cf, err := ParseClass(data)
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	got := resolvePreciseArgs(cf.Methods[0].Code, cf.Methods[0].MaxLocals, cf.pool)
	if got[12] != "MD5" {
		t.Errorf("same-const join must stay known, got %v", got)
	}
}

func TestPreciseFindingEndToEnd(t *testing.T) {
	code := []byte{0x12, 0x0c, 0xb8, 0x00, 0x0a, 0xb1}
	data := buildFlowClass(t, "com.example.C", "java.security.MessageDigest", "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;", []string{"MD5"}, code)
	cf, err := ParseClass(data)
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	found := false
	for _, m := range analyzeClass(cf, "C.class") {
		if m.Category == "CRYPTO_WEAK_HASH" && m.Confidence == "0.95" && m.EvidenceType == "dataflow_argument" {
			found = true
			if m.Text != "MD5" {
				t.Errorf("precise text = %q", m.Text)
			}
		}
		if m.Category == "CRYPTO_WEAK_HASH" && m.Confidence == "0.50" {
			t.Errorf("generic co-occurrence must be suppressed when precise: %+v", m)
		}
	}
	if !found {
		t.Fatalf("missing precise CRYPTO_WEAK_HASH; findings: %#v", analyzeClass(cf, "C.class"))
	}
}

func TestPreciseStrongValueSilent(t *testing.T) {
	code := []byte{0x12, 0x0c, 0xb8, 0x00, 0x0a, 0xb1}
	data := buildFlowClass(t, "com.example.C", "javax.crypto.Cipher", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;", []string{"AES/GCM/NoPadding"}, code)
	cf, err := ParseClass(data)
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	for _, m := range analyzeClass(cf, "C.class") {
		if m.Category == "CRYPTO_WEAK_CIPHER" {
			t.Errorf("strong algorithm must not be flagged: %+v", m)
		}
	}
}
