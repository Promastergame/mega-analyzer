package pipeline

import (
	"bytes"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// stringFogEncrypt mirrors StringFogImpl.encrypt for fixtures.
func stringFogEncrypt(data, key []byte) []byte {
	return stringFogXor(data, key)
}

func smaliByteArray(label string, vals []byte) string {
	var b strings.Builder
	b.WriteString("    " + label + "\n")
	b.WriteString("    .array-data 1\n")
	for _, v := range vals {
		b.WriteString("        0x")
		const hexdigits = "0123456789abcdef"
		b.WriteString(string([]byte{hexdigits[v>>4], hexdigits[v&0xf]}))
		b.WriteString("t\n")
	}
	b.WriteString("    .end array-data\n")
	return b.String()
}

func TestStringFogEvaluatorDecodesConstants(t *testing.T) {
	key := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	payload := []byte("https://ethradrone.space/webview")
	enc := stringFogEncrypt(payload, key)

	var smali strings.Builder
	smali.WriteString(".class public Lcom/sync/media/hub/Bison;\n.super Ljava/lang/Object;\n")
	smali.WriteString(".method private dec()Ljava/lang/String;\n")
	smali.WriteString("    .locals 5\n")
	smali.WriteString("    new-array v1, v0, [B\n")
	smali.WriteString(smaliByteArray(":arr_p", enc))
	smali.WriteString("    fill-array-data v1, :arr_p\n")
	smali.WriteString("    new-array v3, v2, [B\n")
	smali.WriteString(smaliByteArray(":arr_k", key))
	smali.WriteString("    fill-array-data v3, :arr_k\n")
	smali.WriteString("    sget-object v4, Lcom/github/megatronking/stringfog/xor/StringFogImpl;->INSTANCE:Lcom/github/megatronking/stringfog/xor/StringFogImpl;\n")
	smali.WriteString("    invoke-virtual {v4, v1, v3}, Lcom/github/megatronking/stringfog/xor/StringFogImpl;->decrypt([B[B)Ljava/lang/String;\n")
	smali.WriteString("    move-result-object v1\n")
	smali.WriteString("    return-object v1\n")
	smali.WriteString(".end method\n")

	content := []byte(smali.String())
	analysis := &types.FileAnalysis{Path: "smali/com/sync/media/hub/Bison.smali", IsAppCode: true, Matches: make([]types.Match, 0)}
	ctx := &FileDetectContext{
		Path:         analysis.Path,
		Content:      content,
		ContentLower: bytes.ToLower(content),
		FileType:     types.FileTypeSmali,
	}

	eval := &stringFogEvaluator{p: NewPipelineForTest()}
	eval.Detect(ctx, analysis)

	found := false
	for _, s := range analysis.RecoveredStrings {
		if s == "https://ethradrone.space/webview" {
			found = true
		}
	}
	if !found {
		t.Fatalf("C2 URL not recovered, got %v", analysis.RecoveredStrings)
	}
	if len(analysis.Matches) != 1 {
		t.Fatalf("expected one inventory match, got %d", len(analysis.Matches))
	}
}

func TestStringFogEvaluatorIgnoresPlainSmali(t *testing.T) {
	content := []byte(".class public Lcom/app/A;\n.super Ljava/lang/Object;\n.method foo()V\n    return-void\n.end method\n")
	analysis := &types.FileAnalysis{Path: "smali/com/app/A.smali", Matches: make([]types.Match, 0)}
	ctx := &FileDetectContext{Path: analysis.Path, Content: content, ContentLower: bytes.ToLower(content), FileType: types.FileTypeSmali}
	eval := &stringFogEvaluator{p: NewPipelineForTest()}
	eval.Detect(ctx, analysis)
	if len(analysis.RecoveredStrings) != 0 || len(analysis.Matches) != 0 {
		t.Fatalf("plain smali produced evidence: %v / %d", analysis.RecoveredStrings, len(analysis.Matches))
	}
}

// NewPipelineForTest builds a minimal Pipeline with the fog registry for
// detector-level unit tests.
func NewPipelineForTest() *Pipeline {
	return &Pipeline{fogKeys: newFogKeyRegistry()}
}
