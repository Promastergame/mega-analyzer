package axml

import "fmt"

// Panic containment at the "untrusted file → caller" boundary.
//
// The AXML/ARSC parsers run on attacker-controlled bytes. A bounds bug
// that slips past the fuzz corpus must not crash the whole analyzer: the
// exported entry points below convert any escaping panic into an error
// tagged with the `parser_crash` prefix, which callers surface in the
// report instead of dying. The real fix is still expected upstream — this
// is the safety net the audit report asked for.

// guardPanic runs body and converts a panic into a parser_crash error.
func guardPanic(body func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser_crash: %v", r)
		}
	}()
	body()
	return nil
}

// Decode parses an AXML buffer with panic containment.
func Decode(data []byte) (m *Manifest, err error) {
	if gerr := guardPanic(func() {
		m, err = decodeAXML(data)
	}); gerr != nil {
		m, err = nil, gerr
	}
	return m, err
}

// DecodePlainXML parses a plaintext XML manifest with panic containment.
func DecodePlainXML(data []byte) (m *Manifest, err error) {
	if gerr := guardPanic(func() {
		m, err = decodePlainXML(data)
	}); gerr != nil {
		m, err = nil, gerr
	}
	return m, err
}

// ParseARSC decodes a resources.arsc buffer with panic containment.
func ParseARSC(data []byte) (t *ResourceTable, err error) {
	if gerr := guardPanic(func() {
		t, err = parseARSCInternal(data)
	}); gerr != nil {
		t, err = nil, gerr
	}
	return t, err
}
