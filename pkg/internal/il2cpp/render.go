package il2cpp

import (
	"fmt"
	"strings"
)

// nameResolver renders C#-readable names for metadata and binary structures.
type nameResolver struct {
	m *Metadata
	b *Binary // optional; without it signatures degrade to indices
}

func newNameResolver(m *Metadata, b *Binary) *nameResolver {
	return &nameResolver{m: m, b: b}
}

var primitiveNames = map[byte]string{
	tyVoid: "void", tyBoolean: "bool", tyChar: "char", tyI1: "sbyte",
	tyU1: "byte", tyI2: "short", tyU2: "ushort", tyI4: "int", tyU4: "uint",
	tyI8: "long", tyU8: "ulong", tyR4: "float", tyR8: "double",
	tyString: "string", tyObject: "object", tyI: "IntPtr", tyU: "UIntPtr",
	tyTypedByRef: "TypedReference",
}

// TypeName renders a full C# type name for a binary Il2CppType record.
func (nr *nameResolver) TypeName(t *CType) string {
	if t == nil {
		return "object"
	}
	if t.Byref() {
		return nr.plainTypeName(t) + "&"
	}
	return nr.plainTypeName(t)
}

func (nr *nameResolver) plainTypeName(t *CType) string {
	switch t.Ty() {
	case tyVar, tyMVar:
		idx := int32(t.Data)
		if nr.b == nil {
			return fmt.Sprintf("T%d", idx)
		}
		if idx >= 0 && int(idx) < len(nr.m.GenericParams) {
			return nr.m.Str.Get(nr.m.GenericParams[idx].NameIdx)
		}
		return "T?"
	case tyGenericIn:
		return nr.genericInstName(t)
	case tySzArray:
		return nr.enclosedName(t) + "[]"
	case tyPtr:
		return nr.enclosedName(t) + "*"
	case tyArray:
		if nr.b != nil {
			if shape := nr.b.ArrayShape(t); shape != nil {
				return nr.enclosedName(shape.ElemType) + strings.Repeat(",", int(shape.Rank-1)) + "]"
			}
		}
		return "?[?]"
	case tyByref:
		return nr.enclosedName(t) + "&"
	default:
		if n, ok := primitiveNames[t.Ty()]; ok {
			return n
		}
		if t.isClassKind() {
			if td := nr.typeDefOf(t); td != nil {
				return nr.TypeFullNameGeneric(td)
			}
			return fmt.Sprintf("type#%d", int32(t.Data))
		}
		if t.Ty() == tyFnPtr || t.Ty() == tyInternal {
			return "IntPtr"
		}
		return fmt.Sprintf("ty%#x", t.Ty())
	}
}

// enclosedName renders the element type of a wrapper (pointer/array) record.
func (nr *nameResolver) enclosedName(t *CType) string {
	if nr.b == nil || t.Data == 0 {
		return "?"
	}
	inner := nr.b.recordAt(t.Data)
	if inner == nil {
		return "?"
	}
	return nr.plainTypeName(inner)
}

func (nr *nameResolver) typeDefOf(t *CType) *TypeDefinition {
	if nr.b != nil {
		return nr.b.TypeDefOfCType(t)
	}
	idx := int32(t.Data)
	if idx >= 0 && int(idx) < len(nr.m.TypeDefs) {
		return &nr.m.TypeDefs[idx]
	}
	return nil
}

func (nr *nameResolver) genericInstName(t *CType) string {
	if nr.b == nil {
		return "generic?"
	}
	gc := nr.b.GenericClass(t.Data)
	if gc == nil {
		return "generic?"
	}
	baseRec := nr.b.recordAt(gc.typePtr)
	if baseRec == nil {
		return "generic?"
	}
	td := nr.typeDefOf(baseRec)
	if td == nil {
		return nr.plainTypeName(baseRec) + "<...>"
	}
	base := nr.bareTypeName(td)
	args := nr.b.GenericInstTypes(gc.inst)
	if len(args) == 0 {
		return base + "<>"
	}
	parts := make([]string, 0, len(args))
	for _, a := range args {
		parts = append(parts, nr.TypeName(a))
	}
	return base + "<" + strings.Join(parts, ", ") + ">"
}

// bareTypeName strips the `N arity suffix without adding parameter names.
func (nr *nameResolver) bareTypeName(td *TypeDefinition) string {
	name := nr.m.Str.Get(td.NameIdx)
	if idx := strings.IndexByte(name, '`'); idx > 0 {
		name = name[:idx]
	}
	return name
}

// TypeFullNameGeneric renders namespace.Name<params> for a typedef.
func (nr *nameResolver) TypeFullNameGeneric(td *TypeDefinition) string {
	name := nr.typeDisplayName(td)
	if ns := nr.m.Str.Get(td.NamespaceIdx); ns != "" && td.DeclaringType < 0 {
		return ns + "." + name
	}
	return name
}

// typeDisplayName renders the bare name plus generic parameter placeholders
// (Foo`2 -> Foo<T,U>).
func (nr *nameResolver) typeDisplayName(td *TypeDefinition) string {
	name := nr.m.Str.Get(td.NameIdx)
	if td.GenericCont < 0 || int(td.GenericCont) >= len(nr.m.GenericConts) {
		return name
	}
	gc := &nr.m.GenericConts[td.GenericCont]
	if gc.ParamCount <= 0 {
		return name
	}
	var parts []string
	for i := int64(0); i < int64(gc.ParamCount); i++ {
		pi := gc.ParamStart + i
		if pi >= 0 && pi < int64(len(nr.m.GenericParams)) {
			parts = append(parts, nr.m.Str.Get(nr.m.GenericParams[pi].NameIdx))
		} else {
			parts = append(parts, fmt.Sprintf("T%d", i))
		}
	}
	if idx := strings.IndexByte(name, '`'); idx > 0 {
		name = name[:idx]
	}
	return name + "<" + strings.Join(parts, ", ") + ">"
}

// recordAt reads a scattered Il2CppType record at a virtual address.
func (b *Binary) recordAt(va uint64) *CType {
	raw := b.elf.ReadBytes(va, 12)
	if raw == nil {
		return nil
	}
	t := &CType{Bits: leU32(raw[8:]), b: b}
	if v, ok := b.elf.RelocValue(va); ok {
		t.Data = v
	} else {
		t.Data = leU64(raw)
	}
	return t
}

// Type visibility keywords from ECMA TypeAttributes.
func typeVisibility(td *TypeDefinition) string {
	switch td.Flags & 0x7 {
	case 0:
		return "" // public (typedef default) or notpublic for older
	case 1:
		return "public "
	case 2:
		return "nested public "
	case 3:
		return "nested private "
	case 4:
		return "nested family "
	case 5:
		return "nested assembly "
	case 6:
		return "nested famandassem "
	case 7:
		return "nested famorassem "
	}
	return ""
}

func isInterface(td *TypeDefinition) bool { return td.Flags&0x20 != 0 }
func isAbstract(td *TypeDefinition) bool  { return td.Flags&0x80 != 0 }
func isSealed(td *TypeDefinition) bool    { return td.Flags&0x100 != 0 }

// IsDelegate reports whether the typedef derives from System.MulticastDelegate.
func (nr *nameResolver) IsDelegate(td *TypeDefinition) bool {
	parent := nr.parentTypeDef(td)
	for i := 0; parent != nil && i < 8; i++ {
		n := nr.m.Str.Get(parent.NameIdx)
		if n == "MulticastDelegate" {
			return true
		}
		parent = nr.parentTypeDef(parent)
	}
	return false
}

func (nr *nameResolver) parentTypeDef(td *TypeDefinition) *TypeDefinition {
	if td.Parent < 0 {
		return nil
	}
	if nr.m.Version >= Ver27 {
		if nr.b == nil {
			return nil
		}
		return nr.b.TypeDefOfCType(nr.b.Type(td.Parent))
	}
	idx := td.Parent
	if idx >= 0 && int(idx) < len(nr.m.TypeDefs) {
		return &nr.m.TypeDefs[idx]
	}
	return nil
}

// parentCType returns the raw parent type record (v38+ stores a type index).
func (nr *nameResolver) parentCType(td *TypeDefinition) *CType {
	if nr.b == nil || td.Parent < 0 {
		return nil
	}
	return nr.b.Type(td.Parent)
}

// Method modifiers from MethodAttributes.
func methodModifiers(flags uint16) string {
	var sb strings.Builder
	switch flags & 0x7 {
	case 1:
		sb.WriteString("private ")
	case 4:
		sb.WriteString("family ")
	case 5:
		sb.WriteString("famandassem ")
	case 6:
		if flags&0x40 != 0 {
			sb.WriteString("protected internal ")
		} else {
			sb.WriteString("famorassem ")
		}
	case 7:
		sb.WriteString("public ")
	}
	if flags&0x10 != 0 {
		sb.WriteString("static ")
	}
	if flags&0x400 != 0 && flags&0x40 != 0 {
		sb.WriteString("abstract ")
	} else if flags&0x40 != 0 && flags&0x20 == 0 {
		sb.WriteString("virtual ")
	}
	if flags&0x40 != 0 && flags&0x20 != 0 && flags&0x400 == 0 && flags&0x8 == 0 {
		sb.WriteString("override ")
	}
	return sb.String()
}

// Field modifiers from FieldAttributes stored in the field's Il2CppType.
func fieldModifiers(attrs uint16) string {
	var sb strings.Builder
	switch attrs & 0x7 {
	case 1:
		sb.WriteString("private ")
	case 4:
		sb.WriteString("family ")
	case 6:
		sb.WriteString("internal ")
	case 7:
		sb.WriteString("public ")
	}
	if attrs&0x10 != 0 {
		sb.WriteString("static ")
	}
	if attrs&0x40 != 0 {
		sb.WriteString("const ")
	} else if attrs&0x20 != 0 {
		sb.WriteString("readonly ")
	}
	return sb.String()
}

func fieldIsStatic(attrs uint16) bool  { return attrs&0x10 != 0 }
func fieldIsLiteral(attrs uint16) bool { return attrs&0x40 != 0 }
