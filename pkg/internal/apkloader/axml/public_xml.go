package axml

import (
	"fmt"
	"strings"
)

// GeneratePublicXML renders a public.xml file from the resource table.
// This matches the Apktool format used to preserve resource IDs across
// decode / rebuild cycles. aapt2 link reads res/values/public.xml and
// keeps the declared IDs stable.
//
// Output is a single <resources> root with one <public> child per entry.
// Entries that lack a name or have no values are skipped.
func (t *ResourceTable) GeneratePublicXML() string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	b.WriteString("\n<resources>\n")

	for _, pkg := range t.Packages {
		for _, typ := range pkg.Types {
			for _, entry := range typ.Entries {
				if entry.Name == "" {
					continue
				}
				id := (pkg.ID << 24) | (typ.ID << 16) | (entry.ID & 0xFFFF)
				fmt.Fprintf(&b, "    <public type=\"%s\" name=\"%s\" id=\"0x%08x\" />\n",
					escXML(typ.Name), escXML(entry.Name), id)
			}
		}
	}

	b.WriteString("</resources>\n")
	return b.String()
}

// escXML does minimal XML attribute escaping.
func escXML(s string) string {
	// Fast path: no special chars
	hasSpecial := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '<' || c == '>' || c == '"' || c == '&' || c == '\'' {
			hasSpecial = true
			break
		}
	}
	if !hasSpecial {
		return s
	}

	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '&':
			b.WriteString("&amp;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
