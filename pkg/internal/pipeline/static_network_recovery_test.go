package pipeline

import (
	"fmt"
	"math/bits"
	"slices"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func staticArrayFixture(label string, data []byte) string {
	var body strings.Builder
	fmt.Fprintf(&body, ":%s\n.array-data 1\n", label)
	for _, value := range data {
		fmt.Fprintf(&body, "0x%02xt\n", value)
	}
	body.WriteString(".end array-data\n")
	return body.String()
}

func TestStaticXORNetworkValuesNeedCodeEvidence(t *testing.T) {
	key := []byte{0x51, 0x23, 0xab, 0x09, 0x64}
	want := "198.51.100.42"
	encoded := []byte(want)
	for i := range encoded {
		encoded[i] ^= key[i%len(key)]
	}
	body := staticArrayFixture("key", key) + staticArrayFixture("payload", encoded)
	class := &types.SmaliClass{Name: "Lexample/Config;", Methods: []types.SmaliMethod{{Name: "decode", Body: strings.Split(body, "\n")}}}
	if values := recoverStaticNetworkConstants(class); len(values) != 0 {
		t.Fatal("arrays alone were treated as a decryption algorithm")
	}
	class.Methods[0].Body = append(class.Methods[0].Body, "aget-byte v0, v1, v2", "rem-int v2, v2, v3", "xor-int/2addr v0, v4")
	values := recoverStaticNetworkConstants(class)
	if len(values) != 1 || values[0].value != want || !strings.Contains(values[0].proof, "repeating XOR") {
		t.Fatalf("static XOR recovery = %#v", values)
	}
}

func TestRollingHostPoolRequiresArithmeticSignatureAndWholeValidPool(t *testing.T) {
	want := []string{"controller.example.org", "backup.example.cfd", "spare.example.club"}
	plain := append(make([]byte, 32), []byte(strings.Join(want, "\n"))...)
	encoded := make([]byte, len(plain))
	a, b := uint32(0x6c2e91b7), uint32(0x19f7e26a)
	for i, value := range plain {
		encoded[i] = value ^ byte(bits.RotateLeft32(uint32(0xa45d08c3)*uint32(i)+a, i&7)^b)
		a = a*0x9e3779b1 + 0xd3085b41
		b ^= a >> 11
	}
	code := "const v0, 0x6c2e91b7\nconst v1, 0x19f7e26a\nconst v2, 0xa45d08c3\nconst v3, 0x9e3779b1\nconst v4, 0xd3085b41\nmul-int v0, v0, v1\nxor-int v0, v0, v1\ninvoke-static {v0, v1}, Ljava/lang/Integer;->rotateLeft(II)I\n"
	class := &types.SmaliClass{Name: "Lexample/Pool;", Methods: []types.SmaliMethod{{Name: "pool", Body: strings.Split(code+staticArrayFixture("pool", encoded), "\n")}}}
	values := recoverStaticNetworkConstants(class)
	var got []string
	for _, value := range values {
		got = append(got, value.value)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("host pool = %#v, want %#v", got, want)
	}
	class.Methods[0].Body[0] = "const v0, 0x12345678"
	if values := recoverStaticNetworkConstants(class); len(values) != 0 {
		t.Fatal("host pool accepted without its arithmetic signature")
	}
	class.Methods[0].Body[0] = "const v0, 0x6c2e91b7"
	encoded[len(encoded)-1] ^= 0xff
	class.Methods[0].Body = strings.Split(code+staticArrayFixture("pool", encoded), "\n")
	if values := recoverStaticNetworkConstants(class); len(values) != 0 {
		t.Fatal("partly corrupt pool manufactured a subset of network indicators")
	}
}
