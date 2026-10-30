package analyzer

import (
	"testing"
)

// ─── StringClass.String() ─────────────────────────────────────────────────

func TestStringClass_String_PlainText(t *testing.T) {
	s := StringClassPlainText.String()
	if s != "plaintext" {
		t.Errorf("expected 'plaintext', got %q", s)
	}
}

func TestStringClass_String_Identifier(t *testing.T) {
	s := StringClassIdentifier.String()
	if s != "identifier" {
		t.Errorf("expected 'identifier', got %q", s)
	}
}

func TestStringClass_String_Base64(t *testing.T) {
	s := StringClassBase64.String()
	if s != "base64" {
		t.Errorf("expected 'base64', got %q", s)
	}
}

func TestStringClass_String_Hex(t *testing.T) {
	s := StringClassHex.String()
	if s != "hex" {
		t.Errorf("expected 'hex', got %q", s)
	}
}

func TestStringClass_String_Obfuscated(t *testing.T) {
	s := StringClassObfuscated.String()
	if s != "obfuscated" {
		t.Errorf("expected 'obfuscated', got %q", s)
	}
}

func TestStringClass_String_Numeric(t *testing.T) {
	s := StringClassNumeric.String()
	if s != "numeric" {
		t.Errorf("expected 'numeric', got %q", s)
	}
}

func TestStringClass_String_Path(t *testing.T) {
	s := StringClassPath.String()
	if s != "path" {
		t.Errorf("expected 'path', got %q", s)
	}
}

func TestStringClass_String_Unknown(t *testing.T) {
	// Use an invalid StringClass value
	invalidClass := StringClass(999)
	s := invalidClass.String()
	if s != "unknown" {
		t.Errorf("expected 'unknown' for invalid class, got %q", s)
	}
}
