package shared

// EconomyInfo describes a resource and the operation on it. It is discovery
// evidence, not proof that the client is authoritative or that a rewrite works.
type EconomyInfo struct {
	Resources    []string          `json:"resources"`
	Operation    string            `json:"operation"`
	ValueType    string            `json:"value_type,omitempty"`
	Storage      string            `json:"storage,omitempty"`
	Authority    string            `json:"authority"`
	ValueLinked  bool              `json:"value_linked"`
	// ValueResolved is true when the returned value itself carries resource
	// identity (a named field, storage key, column or resource call). A pure
	// class/name match without a resolved value is admitted for audit only:
	// the source is unknown until the resource graph links it.
	ValueResolved bool             `json:"value_resolved,omitempty"`
	Evidence     []EconomyEvidence `json:"evidence,omitempty"`
	Related      []EconomyRelation `json:"related_methods,omitempty"`
}

type EconomyEvidence struct {
	Kind      string `json:"kind"`
	Reference string `json:"reference"`
	Line      int    `json:"line,omitempty"`
}

type EconomyRelation struct {
	Method    string `json:"method"`
	Operation string `json:"operation"`
	Via       string `json:"via"`
}
