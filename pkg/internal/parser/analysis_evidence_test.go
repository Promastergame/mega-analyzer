package parser

import (
	"reflect"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestSmaliCryptoEvidenceAndControlFlow(t *testing.T) {
	const source = `.class public Lsample/CryptoWorker;
.super Ljava/lang/Object;
.field private key:[B
.field public static endpoint:Ljava/lang/String; = "https://example.invalid"
.method public verifyKey([B)Z
    .registers 8
    :try_start
    const-string v0, "AES/CBC/PKCS5Padding"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v1
    iput-object p1, p0, Lsample/CryptoWorker;->key:[B
    iget-object v2, p0, Lsample/CryptoWorker;->key:[B
    sput-object v0, Lsample/CryptoWorker;->endpoint:Ljava/lang/String;
    sget-object v3, Lsample/CryptoWorker;->endpoint:Ljava/lang/String;
    if-ne v1, v2, :failed
    if-nez v1, :failed
    if-gtz v1, :failed
    if-ltz v1, :failed
    packed-switch v1, :pswitch_data
    sparse-switch v2, :sswitch_data
    :try_end
    const/4 v0, 0x1
    return v0
    :failed
    return v1
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :failed
    .catchall {:try_start .. :try_end} :failed
.end method
`
	p := NewSmaliParser(source)
	class, err := p.Parse()
	if err != nil || len(class.Methods) != 1 {
		t.Fatalf("parse: %+v, %v", class, err)
	}
	m := class.Methods[0]
	if len(p.Lines()) != strings.Count(source, "\n")+1 || len(class.Fields) != 2 || class.Fields[0].TypeKind != "array" || class.Fields[1].Value != `"https://example.invalid"` {
		t.Fatal("lost source/field evidence")
	}
	if len(m.Invokes) != 1 || !strings.Contains(strings.Join(m.Invokes[0].Tags, ","), "crypto") || m.Invokes[0].Class != "javax.crypto.Cipher" {
		t.Fatalf("missing crypto call: %+v", m.Invokes)
	}
	if len(m.FieldAccesses) != 4 {
		t.Fatalf("field accesses: %+v", m.FieldAccesses)
	}
	for i, fa := range m.FieldAccesses {
		if fa.IsStatic != (i >= 2) || fa.IsWrite != (i%2 == 0) || fa.IsRead != (i%2 == 1) || fa.Class != "sample.CryptoWorker" {
			t.Fatalf("field %d: %+v", i, fa)
		}
		if i < 2 && fa.Object != "p0" {
			t.Fatalf("missing object: %+v", fa)
		}
	}
	if len(m.Conditions) != 4 || !reflect.DeepEqual(m.Conditions[0].Operands, []string{"v1", "v2"}) {
		t.Fatalf("conditions: %+v", m.Conditions)
	}
	for _, c := range m.Conditions {
		if !c.Negated || c.Target != ":failed" {
			t.Fatalf("condition: %+v", c)
		}
	}
	if len(m.Switches) != 2 || m.Switches[0].Targets[0] != ":pswitch_data" || m.Switches[1].Type != "sparse-switch" {
		t.Fatalf("switches: %+v", m.Switches)
	}
	if !m.HasTryCatch || len(m.TryCatches) != 2 || m.TryCatches[0].ExceptionType != "java.lang.Exception" || m.TryCatches[1].ExceptionType != "*" {
		t.Fatalf("handlers: %+v", m.TryCatches)
	}
	if m.Metrics.CyclomaticComplexity != 7 || m.Metrics.FieldAccessCount != 4 || m.Metrics.TryCatchCount != 2 || m.SuspicionScore != 5 {
		t.Fatalf("metrics: %+v, score=%d", m.Metrics, m.SuspicionScore)
	}
	if len(p.GetSuspiciousMethods(class, 5)) != 1 || len(p.GetSuspiciousMethods(class, 6)) != 0 {
		t.Fatal("suspicion threshold is not inclusive")
	}
	for _, instruction := range m.Instructions {
		if strings.TrimSpace(p.Lines()[instruction.Line-1]) != instruction.Raw {
			t.Fatalf("wrong evidence location: %+v", instruction)
		}
	}
}

func TestSmaliStringEvidenceFlagsAndEscapes(t *testing.T) {
	for _, tc := range []struct {
		value string
		flags types.StringConstFlags
	}{
		{"", types.StringFlagEmpty},
		{"https://example.invalid/api", types.StringFlagLooksURL | types.StringFlagLooksKey},
		{"com.example.application", types.StringFlagLooksPackage},
		{"MDEyMzQ1Njc4OWFiY2RlZg==", types.StringFlagLooksBase64},
		{"secret_token", types.StringFlagLooksKey},
		{"this ordinary sentence has spaces", 0},
	} {
		s := (&SmaliParser{}).parseConstString(`const-string/jumbo v3, "`+tc.value+`" # comment`, 17)
		if s == nil || s.Flags != tc.flags || s.Line != 17 || s.Register != "v3" || s.Value != tc.value {
			t.Fatalf("%q: %+v", tc.value, s)
		}
	}
	for _, tc := range []struct{ in, want string }{
		{`\r\b\f\0`, "\r\b\f\x00"}, {`\u0041\u0431`, "Aб"}, {`\uZZZZ`, `\uZZZZ`},
		{`\u12`, `\u12`}, {`\q`, `\q`}, {"tail\\", "tail\\"},
	} {
		if got := UnescapeSmaliString(tc.in); got != tc.want {
			t.Fatalf("%q -> %q, want %q", tc.in, got, tc.want)
		}
	}
	p := &SmaliParser{}
	for _, s := range []string{"abc", "abcde", "!!!!"} {
		if p.isBase64Like(s) {
			t.Fatalf("false base64 candidate %q", s)
		}
	}
}

func TestSmaliInstructionCategoriesPreserveOperands(t *testing.T) {
	for _, tc := range []struct {
		opcode   string
		category types.InstructionCategory
	}{
		{"move-object", types.InstrCategoryMove}, {"const/16", types.InstrCategoryConst}, {"goto/16", types.InstrCategoryGoto},
		{"throw", types.InstrCategoryThrow}, {"check-cast", types.InstrCategoryCheckCast}, {"instance-of", types.InstrCategoryInstanceOf},
		{"if-eq", types.InstrCategoryIf}, {"aget-byte", types.InstrCategoryArrayGet}, {"aput-byte", types.InstrCategoryArrayPut},
		{"cmp-long", types.InstrCategoryCompare}, {"xor-int", types.InstrCategoryBinaryOp}, {"int-to-byte", types.InstrCategoryUnaryOp},
		{"new-instance", types.InstrCategoryUnknown},
	} {
		i := (&SmaliParser{}).parseGenericInstruction(tc.opcode+" v0, v1", 8)
		if i == nil || i.Category != tc.category || i.Opcode != tc.opcode || i.Line != 8 || !reflect.DeepEqual(i.Operands, []string{"v0", "v1"}) {
			t.Fatalf("%s: %+v", tc.opcode, i)
		}
	}
}

func TestSmaliMalformedInstructionsDoNotInventEvidence(t *testing.T) {
	p := &SmaliParser{}
	if p.parseInvoke("invoke-static malformed", 1) != nil || p.parseFieldAccess("iget invalid", 1) != nil || p.parseSwitch("packed-switch invalid", 1) != nil || p.parseConstString("const-string invalid", 1) != nil || p.parseCondition("if-eqz", 1) != nil || p.parseReturn("not-a-return", 1) != nil || p.parseGenericInstruction("@@@", 1) != nil {
		t.Fatal("invented evidence from malformed instruction")
	}
	m := &types.SmaliMethod{}
	for _, line := range []string{`.catch Ljava/lang/Exception; {:one} :handler`, `.catchall {:one} :handler`, `.catch invalid`} {
		p.parseCatch(m, line)
	}
	if len(m.TryCatches) != 0 {
		t.Fatal("invented a try range")
	}
	class, err := NewSmaliParser(".class La12;\n.field invalid\n.method public a()V\nreturn-void\n.end method").Parse()
	if err != nil || !class.IsObfuscated || len(class.Fields) != 0 || class.Methods[0].SuspicionScore != 1 {
		t.Fatalf("malformed fields/short method: %+v %v", class, err)
	}
}
