package axml

import (
	"fmt"
	"strconv"
	"strings"
)

// ResolveManifest re-resolves @-references in a parsed Manifest using
// the supplied resource table. Mutates m in place.
//
// Why this is a separate pass:
//
//	AXML decoding happens before we look at resources.arsc — at that
//	point we don't know what `@0x7f130001` points to. Once the table
//	is available, structured fields expose resolved values for analysis.
//	The editable XML retains symbolic references such as @mipmap/icon
//	and @string/app_name, preserving resource types and locale variants
//	when the decoded manifest is rebuilt.
func ResolveManifest(m *Manifest, table *ResourceTable) {
	if m == nil || table == nil {
		return
	}
	resolve := func(s *string) {
		if s == nil || *s == "" {
			return
		}
		if !strings.HasPrefix(*s, "@0x") {
			return
		}
		id, err := strconv.ParseUint((*s)[1:], 0, 32)
		if err != nil {
			return
		}
		if v := table.ResolveDefault(uint32(id)); v != "" {
			*s = v
			return
		}
		if name := table.ResolveName(uint32(id)); name != "" {
			*s = name
		}
	}

	resolve(&m.Application.Label)
	resolve(&m.Application.Icon)
	resolve(&m.Application.Theme)
	resolve(&m.Application.NetworkSecCfg)

	for i := range m.Activities {
		resolveComponentRefs(&m.Activities[i], table)
	}
	for i := range m.Services {
		resolveComponentRefs(&m.Services[i], table)
	}
	for i := range m.Receivers {
		resolveComponentRefs(&m.Receivers[i], table)
	}
	for i := range m.Providers {
		resolveComponentRefs(&m.Providers[i], table)
	}

	// XML is a build input: retain references instead of inlining their values.
	m.XMLBytes = []byte(rewriteXMLReferences(string(m.XMLBytes), table))
}

func resolveComponentRefs(c *Component, table *ResourceTable) {
	resolveString(&c.Permission, table)
	for i := range c.IntentFilts {
		f := &c.IntentFilts[i]
		for j := range f.DataScheme {
			resolveString(&f.DataScheme[j], table)
		}
		for j := range f.DataHost {
			resolveString(&f.DataHost[j], table)
		}
	}
}

func resolveString(s *string, table *ResourceTable) {
	if s == nil || !strings.HasPrefix(*s, "@0x") {
		return
	}
	id, err := strconv.ParseUint((*s)[1:], 0, 32)
	if err != nil {
		return
	}
	if v := table.ResolveDefault(uint32(id)); v != "" {
		*s = v
		return
	}
	if name := table.ResolveName(uint32(id)); name != "" {
		*s = name
	}
}

// rewriteXMLReferences scans rendered XML and rewrites every
// `="@0x...."` occurrence with its symbolic resource name. We do this on the
// final string rather than tracking values per-attribute because the
// XML buffer is the canonical artifact downstream tools consume.
func rewriteXMLReferences(xml string, table *ResourceTable) string {
	const marker = `="@0x`
	if !strings.Contains(xml, marker) {
		return xml
	}
	var b strings.Builder
	b.Grow(len(xml))
	i := 0
	for i < len(xml) {
		idx := strings.Index(xml[i:], marker)
		if idx < 0 {
			b.WriteString(xml[i:])
			break
		}
		b.WriteString(xml[i : i+idx+2]) // include `="`
		i += idx + 2

		// Read up to the closing quote.
		j := strings.IndexByte(xml[i:], '"')
		if j < 0 {
			b.WriteString(xml[i:])
			break
		}
		ref := xml[i : i+j]
		replacement := resolveRefString(ref, table)
		b.WriteString(replacement)
		i += j
	}
	return b.String()
}

func resolveRefString(ref string, table *ResourceTable) string {
	if !strings.HasPrefix(ref, "@0x") {
		return ref
	}
	id, err := strconv.ParseUint(ref[1:], 0, 32)
	if err != nil {
		return ref
	}
	if name := table.ResolveName(uint32(id)); name != "" {
		return escapeXML(name)
	}
	return fmt.Sprintf("@0x%08x", uint32(id))
}
