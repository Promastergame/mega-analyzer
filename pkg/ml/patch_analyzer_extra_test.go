package ml

import (
	"testing"
)

func TestParseInvoke_ExtraEdgeCases(t *testing.T) {
	pa := NewPatchAnalyzer()

	// No arrow -> nil
	if pa.parseInvoke("invoke-virtual {v0}, Lcom/app/Test;") != nil {
		t.Error("Should return nil when no arrow is present")
	}

	// Unknown type
	call := pa.parseInvoke("invoke-custom {v0}, Lcom/app/Test;->run()V")
	if call == nil {
		t.Fatal("Should handle unknown invoke types")
	}
	if call.Type != "unknown" {
		t.Errorf("Expected unknown type, got %s", call.Type)
	}
}

func TestAnalyzeMethodName_ExtraPrefixes(t *testing.T) {
	pa := NewPatchAnalyzer()

	mi := &MethodInfo{Name: "checkLicense", NameLower: "checklicense"}
	pa.analyzeMethodName(mi)
	if !mi.HasCheckPrefix {
		t.Error("Should detect check prefix")
	}
}

func TestIsWorthAnalyzing_AppCodeExtra(t *testing.T) {
	pa := NewPatchAnalyzer()

	// Not application code -> not worth if no security
	mi := &MethodInfo{IsAppCode: false, Name: "normalMethod", NameLower: "normalmethod"}
	if pa.IsWorthAnalyzing(mi) {
		t.Error("Library method without security should not be worth analyzing")
	}
}

func TestSplitLinesPooled(t *testing.T) {
	content := []byte("line1\nline2\r\nline3")
	buf := splitLinesPooled(content)
	defer PutLineBuffer(buf)

	if len(buf.Lines) != 3 {
		t.Errorf("len = %d, want 3", len(buf.Lines))
	}
	if buf.Lines[2] != "line3" {
		t.Errorf("last line = %q", buf.Lines[2])
	}

	empty := splitLinesPooled(nil)
	PutLineBuffer(empty)
}
