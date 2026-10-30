package axml

// namespaceStack tracks XML namespace declarations across the AXML
// chunk stream. Each StartNamespace pushes a (prefix, uri) pair at the
// current depth; matching EndNamespace pops them. Element start/end
// chunks bump and decrement depth so that getPrefix(uri) only sees
// in-scope declarations.
//
// Required for two reasons:
//   - manifest minifiers strip the xmlns:android attribute from the
//     root element; we synthesize one only if the URI is present in
//     the stack but no prefix is left
//   - same URI can be redeclared with different prefix at deeper
//     nesting (rare but legal) and we want the inner one
//
// Storage is a flat int slice rather than a slice of structs to keep
// pushes allocation-free after warmup.
type namespaceStack struct {
	// each level holds 2N entries: prefix0,uri0,prefix1,uri1,...
	// levels are separated by a single sentinel value -1
	data  []int32
	depth int
	// per-level declaration count; index = depth
	count []int32
}

func newNamespaceStack() *namespaceStack {
	return &namespaceStack{
		data:  make([]int32, 0, 64),
		count: make([]int32, 1, 16),
	}
}

func (s *namespaceStack) reset() {
	s.data = s.data[:0]
	s.count = s.count[:1]
	s.count[0] = 0
	s.depth = 0
}

// enterElement is called on RES_XML_START_ELEMENT.
func (s *namespaceStack) enterElement() {
	s.depth++
	s.count = append(s.count, 0)
}

// leaveElement is called on RES_XML_END_ELEMENT. Pops any namespaces
// that were declared at this depth (defensive — well-formed AXML
// matches StartNS/EndNS, but obfuscators often skip end-NS).
func (s *namespaceStack) leaveElement() {
	if s.depth == 0 {
		return
	}
	cur := s.count[s.depth]
	if int(cur)*2 <= len(s.data) {
		s.data = s.data[:int32(len(s.data))-cur*2]
	}
	s.count = s.count[:s.depth]
	s.depth--
}

// pushNamespace records a new (prefix, uri) declaration at the current
// element depth.
func (s *namespaceStack) pushNamespace(prefix, uri uint32) {
	s.data = append(s.data, int32(prefix), int32(uri))
	s.count[s.depth]++
}

// popNamespace removes the most recent declaration. Tolerant of
// underflow: malformed AXML often emits more EndNS than StartNS.
func (s *namespaceStack) popNamespace() {
	if len(s.data) < 2 {
		return
	}
	s.data = s.data[:len(s.data)-2]
	if s.count[s.depth] > 0 {
		s.count[s.depth]--
	}
}

// prefixForURI walks the stack from innermost outward and returns the
// pool index of the prefix that maps to uri, or 0xFFFFFFFF if none.
// 0xFFFFFFFF is the sentinel the rest of the decoder treats as "no
// string available".
func (s *namespaceStack) prefixForURI(uri uint32) uint32 {
	for i := len(s.data) - 2; i >= 0; i -= 2 {
		if uint32(s.data[i+1]) == uri {
			return uint32(s.data[i])
		}
	}
	return 0xFFFFFFFF
}

// activeURIs returns each (prefix, uri) currently in scope, deduped.
// Used to synthesize xmlns:* declarations on the root element when the
// minifier stripped them.
func (s *namespaceStack) activeURIs() [][2]uint32 {
	if len(s.data) == 0 {
		return nil
	}
	out := make([][2]uint32, 0, len(s.data)/2)
	seen := make(map[uint32]struct{}, len(s.data)/2)
	for i := 0; i+1 < len(s.data); i += 2 {
		uri := uint32(s.data[i+1])
		if _, ok := seen[uri]; ok {
			continue
		}
		seen[uri] = struct{}{}
		out = append(out, [2]uint32{uint32(s.data[i]), uri})
	}
	return out
}
