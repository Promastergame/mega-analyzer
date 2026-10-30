package axml

// Resource table structures decoded from `resources.arsc`.
//
// ARSC (Android Resource ARSC) is the binary form of compiled
// resources. We parse it to resolve `@0x7f000001`-style references
// emitted by AXML into human-readable values such as `@string/app_name`
// or the literal string "MyApp".
//
// Format reference (public, no code adapted from any third-party tool):
//   - aapt/aapt2 spec describing the chunk layout
//   - Android public docs for resource qualifiers
//
// Coverage:
//   - global value string pool
//   - one or more packages, each with type and key string pools
//   - type-spec chunks (entry-flags table)
//   - type chunks (per-config entries: simple values, compact, sparse,
//     complex bags) — we keep simple values verbatim and summarize
//     bags by their parent reference
//   - library chunks (dynamic references)
//
// Out of scope (intentionally):
//   - rebuilding ARSC (this is a one-way decoder)
//   - applying configuration filters at decode time (consumers do that)

// ResourceTable is the decoded form of resources.arsc.
type ResourceTable struct {
	Packages []ResourcePackage `json:"packages"`
	// GlobalStrings is the value string pool referenced by typed
	// entries through the value-data field. Exposed for callers that
	// want to print a resource by its string-pool index.
	GlobalStrings []string `json:"-"`
}

// ResourcePackage is one <package> in the table. Most APKs have a
// single application package (id=0x7f) plus zero or more shared-library
// packages (id != 0x01 / 0x7f).
type ResourcePackage struct {
	ID      uint32            `json:"id"`
	Name    string            `json:"name"`
	Types   []ResourceType    `json:"types"`
	TypeIDs map[string]uint32 `json:"-"`
	// Library entries, if any (rare outside Maps/Wear apps).
	Libraries []ResourceLibrary `json:"libraries,omitempty"`
}

// ResourceType groups all entries that share the same type ID
// (string, drawable, layout, etc.) across all configurations.
type ResourceType struct {
	ID      uint32          `json:"id"`
	Name    string          `json:"name"`
	Entries []ResourceEntry `json:"entries"`
}

// ResourceEntry is one resource keyed by entry ID. The same entry can
// appear across multiple configs; we flatten configs into a slice of
// ConfigValue keyed by the canonical config string (e.g. "default",
// "ru", "xxhdpi-v26").
type ResourceEntry struct {
	ID     uint32        `json:"id"`
	Name   string        `json:"name"`
	Values []ConfigValue `json:"values"`
	IsBag  bool          `json:"isBag,omitempty"`
}

// ConfigValue holds a single (config, value) pair for an entry.
type ConfigValue struct {
	Config string `json:"config"`
	Value  string `json:"value"`
	// RawType mirrors the on-disk Res_value type tag, useful for
	// downstream classifiers that want to know `string` vs `dimension`
	// without reparsing the rendered text.
	RawType       uint8          `json:"rawType"`
	Parent        string         `json:"parent,omitempty"`
	ComplexValues []ComplexValue `json:"complexValues,omitempty"`
}

// ComplexValue holds a single item in a complex bag (e.g. style item, array element).
type ComplexValue struct {
	NameID  uint32 `json:"nameId"`
	Value   string `json:"value"`
	RawType uint8  `json:"rawType"`
}

// ResourceLibrary is one entry in the package-library table. Used by
// dynamic references (id type 0x07/0x08).
type ResourceLibrary struct {
	PackageID uint32 `json:"packageId"`
	Name      string `json:"name"`
}

// ResolveID returns the resource entry referenced by the encoded ID
// (high byte = pkg, next byte = type, low 16 bits = entry).
// Returns nil when the ID does not map to any entry.
func (t *ResourceTable) ResolveID(id uint32) *ResourceEntry {
	pkgID := (id >> 24) & 0xff
	typeID := (id >> 16) & 0xff
	entryID := id & 0xffff
	for i := range t.Packages {
		if t.Packages[i].ID != pkgID {
			continue
		}
		for j := range t.Packages[i].Types {
			if t.Packages[i].Types[j].ID != typeID {
				continue
			}
			for k := range t.Packages[i].Types[j].Entries {
				if t.Packages[i].Types[j].Entries[k].ID == entryID {
					return &t.Packages[i].Types[j].Entries[k]
				}
			}
		}
	}
	return nil
}

// ResolveDefault returns the entry's value for the default config, or
// the first value if no "default" config exists. Returns "" when the
// entry is unknown or has no values.
func (t *ResourceTable) ResolveDefault(id uint32) string {
	entry := t.ResolveID(id)
	if entry == nil {
		return ""
	}
	for _, v := range entry.Values {
		if v.Config == "default" || v.Config == "" {
			return v.Value
		}
	}
	if len(entry.Values) > 0 {
		return entry.Values[0].Value
	}
	return ""
}

// ResolveName returns the symbolic resource name @type/name for the ID,
// e.g. "@string/app_name". Returns the hex form when unknown.
func (t *ResourceTable) ResolveName(id uint32) string {
	pkgID := (id >> 24) & 0xff
	typeID := (id >> 16) & 0xff
	entryID := id & 0xffff
	for i := range t.Packages {
		if t.Packages[i].ID != pkgID {
			continue
		}
		for j := range t.Packages[i].Types {
			if t.Packages[i].Types[j].ID != typeID {
				continue
			}
			typeName := t.Packages[i].Types[j].Name
			for k := range t.Packages[i].Types[j].Entries {
				if t.Packages[i].Types[j].Entries[k].ID == entryID {
					return "@" + typeName + "/" + t.Packages[i].Types[j].Entries[k].Name
				}
			}
		}
	}
	return ""
}
