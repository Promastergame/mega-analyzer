// Package networkrefs distinguishes static metadata from network references.
package networkrefs

import (
	"bytes"
	"strings"
)

// IsXMLMetadataURL excludes namespace identifiers and URLs in XML comments;
// neither is a fetch instruction. Attribute values such as href remain visible.
func IsXMLMetadataURL(content []byte, offset int) bool {
	if IsXMLNamespaceURL(content, offset) {
		return true
	}
	if offset < 0 || offset > len(content) {
		return false
	}
	start := offset - 4096
	if start < 0 {
		start = 0
	}
	before := content[start:offset]
	open := bytes.LastIndex(before, []byte("<!--"))
	return open >= 0 && open > bytes.LastIndex(before, []byte("-->"))
}

// IsXMLNamespaceURL checks the XML attribute containing a URI. The hostname
// alone is insufficient: an image href on the same host can be fetched.
func IsXMLNamespaceURL(content []byte, offset int) bool {
	if offset <= 0 || offset > len(content) {
		return false
	}
	start := offset - 160
	if start < 0 {
		start = 0
	}
	before := bytes.TrimSpace(content[start:offset])
	if len(before) == 0 || (before[len(before)-1] != '"' && before[len(before)-1] != '\'') {
		return false
	}
	before = bytes.TrimSpace(before[:len(before)-1])
	if len(before) == 0 || before[len(before)-1] != '=' {
		return false
	}
	before = bytes.TrimSpace(before[:len(before)-1])
	nameStart := len(before)
	for nameStart > 0 && before[nameStart-1] != ' ' && before[nameStart-1] != '\t' && before[nameStart-1] != '\n' && before[nameStart-1] != '\r' && before[nameStart-1] != '<' {
		nameStart--
	}
	name := strings.ToLower(string(before[nameStart:]))
	return name == "xmlns" || strings.HasPrefix(name, "xmlns:")
}
