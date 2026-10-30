package apkloader

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"
)

func generateSmaliClass(class *ClassDef, parser *DEXParser) string {
	b := generateSmaliClassBytes(class, parser)
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// DisableSmaliHeaders controls headers in the legacy DEX IR helpers.
// DecodeAPK and DecodeDEX use per-call DecodeOptions instead of changing
// this process-wide default.
var DisableSmaliHeaders atomic.Bool

func init() { DisableSmaliHeaders.Store(true) }

func generateSmaliClassBytes(class *ClassDef, parser *DEXParser) []byte {
	return generateSmaliClassBytesWithHeaders(class, parser, !DisableSmaliHeaders.Load())
}

func generateSmaliClassBytesWithHeaders(class *ClassDef, parser *DEXParser, headers bool) []byte {
	var buf bytes.Buffer
	buf.Grow(4096)

	if headers {
		buf.WriteString("# Disassembled from DEX by Mega-Analyzer\n")
		if parser != nil {
			if h := parser.GetDEXHashHex(); h != "" {
				buf.WriteString("# DEX SHA-256: ")
				buf.WriteString(h)
				buf.WriteByte('\n')
			}
		}
		if class.SourceFile != "" {
			buf.WriteString("# Source: ")
			buf.WriteString(class.SourceFile)
			buf.WriteByte('\n')
		}
		buf.WriteByte('\n')
	}

	buf.WriteString(".class ")
	writeAccessFlagsToBuf(&buf, class.AccessFlags)
	buf.WriteString(class.ClassName)
	buf.WriteByte('\n')

	if class.SuperClass != "" {
		buf.WriteString(".super ")
		buf.WriteString(class.SuperClass)
		buf.WriteByte('\n')
	} else {
		buf.WriteString(".super Ljava/lang/Object;\n")
	}

	if class.SourceFile != "" {
		buf.WriteString(".source ")
		buf.WriteString(quoteSmaliString(class.SourceFile))
		buf.WriteByte('\n')
	}

	for _, iface := range class.Interfaces {
		buf.WriteString(".implements ")
		buf.WriteString(iface)
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')

	if ann := formatDEXAnnotations(class.Annotations, ""); ann != "" {
		buf.WriteString(ann)
		buf.WriteByte('\n')
	}

	// Resolve static initializers once per class. Prefer the already-parsed
	// InitialValue (dex_metadata.go); fall back to decoding the encoded_array
	// on demand so synthetic parsers (tests) also round-trip.
	var staticValues map[string]OwnedStaticValue
	if parser != nil && len(class.StaticFields) > 0 {
		if sv, err := parser.decodeStaticValues(class, 8, 65536, 1<<20); err == nil {
			staticValues = sv
		}
	}

	for _, f := range class.StaticFields {
		buf.WriteString(".field ")
		buf.WriteString(fieldAccessFlagsToSmali(f.AccessFlags))
		buf.WriteString(f.Name)
		buf.WriteByte(':')
		buf.WriteString(f.TypeName)
		buf.WriteString(smaliFieldInitializerSuffix(f, staticValues))
		buf.WriteByte('\n')
		if ann := formatDEXAnnotations(f.Annotations, "    "); ann != "" {
			buf.WriteString(ann)
		}
	}
	for _, f := range class.InstanceFields {
		buf.WriteString(".field ")
		buf.WriteString(fieldAccessFlagsToSmali(f.AccessFlags))
		buf.WriteString(f.Name)
		buf.WriteByte(':')
		buf.WriteString(f.TypeName)
		buf.WriteByte('\n')
		if ann := formatDEXAnnotations(f.Annotations, "    "); ann != "" {
			buf.WriteString(ann)
		}
	}
	if len(class.StaticFields) > 0 || len(class.InstanceFields) > 0 {
		buf.WriteByte('\n')
	}

	for _, m := range class.DirectMethods {
		writeSmaliMethodBuf(&buf, m, parser)
	}
	for _, m := range class.VirtualMethods {
		writeSmaliMethodBuf(&buf, m, parser)
	}

	return buf.Bytes()
}

func writeSmaliField(buf *strings.Builder, f *EncodedField) {
	buf.WriteString(".field ")
	buf.WriteString(fieldAccessFlagsToSmali(f.AccessFlags))
	buf.WriteString(f.Name)
	buf.WriteByte(':')
	buf.WriteString(f.TypeName)
	buf.WriteString(smaliFieldInitializerSuffix(f, nil))
	buf.WriteByte('\n')
}

func writeSmaliFieldBuf(buf *bytes.Buffer, f *EncodedField) {
	buf.WriteString(".field ")
	buf.WriteString(fieldAccessFlagsToSmali(f.AccessFlags))
	buf.WriteString(f.Name)
	buf.WriteByte(':')
	buf.WriteString(f.TypeName)
	buf.WriteString(smaliFieldInitializerSuffix(f, nil))
	buf.WriteByte('\n')
}

// smaliFieldInitializerSuffix renders a DEX static-field initializer as a
// smali " = <value>" suffix, or "" when there is nothing to emit.
// staticValues is an optional pre-resolved map from decodeStaticValues; when
// nil the field's own InitialValue (populated by parseClassMetadata) is used.
func smaliFieldInitializerSuffix(f *EncodedField, staticValues map[string]OwnedStaticValue) string {
	if f == nil {
		return ""
	}
	if f.InitialValue != nil {
		if s, ok := smaliDEXValueInitializer(f.TypeName, *f.InitialValue); ok {
			return s
		}
		// Fall through to the legacy map when the new value is not emittable
		// (e.g. arrays live in <clinit>, not in the .field line).
	}
	if staticValues != nil {
		if v, ok := staticValues[f.Descriptor()]; ok {
			if s, ok := smaliOwnedStaticInitializer(f.TypeName, v); ok {
				return s
			}
		}
	}
	return ""
}

func smaliOwnedStaticInitializer(typeName string, v OwnedStaticValue) (string, bool) {
	// Default (implicit zero/null) values carry only dex-static-default.
	// Emitting them would be noise; baksmali omits them as well.
	if isDefaultStaticValue(v) {
		return "", false
	}
	switch v.Kind {
	case StaticIntegral:
		return " = " + smaliIntegralLiteral(typeName, v.Int64), true
	case StaticString:
		return " = " + quoteSmaliString(v.String), true
	case StaticNull:
		return "", false
	default:
		return "", false
	}
}

func isDefaultStaticValue(v OwnedStaticValue) bool {
	for _, op := range v.Operations {
		if op == "dex-static-default" {
			// Explicit values always append dex-encoded-value:<descriptor>.
			for _, op2 := range v.Operations {
				if len(op2) > len("dex-encoded-value:") && op2[:len("dex-encoded-value:")] == "dex-encoded-value:" {
					return false
				}
			}
			return true
		}
	}
	// Values built by parseClassMetadata (DEXValue path) have no Operations;
	// decide by value below in smaliDEXValueInitializer.
	return false
}

func smaliIntegralLiteral(typeName string, i int64) string {
	switch typeName {
	case "Z":
		if i != 0 {
			return "true"
		}
		return "false"
	case "J":
		return strconv.FormatInt(i, 10) + "L"
	case "C":
		// baksmali prints printable chars as 'x'; keep numeric form which
		// both baksmali and smali accept.
		return strconv.FormatInt(i, 10)
	default:
		return strconv.FormatInt(i, 10)
	}
}

func smaliDEXValueInitializer(typeName string, v DEXValue) (string, bool) {
	switch v.Kind {
	case 0, 2, 4: // byte, short, int
		if typeName == "Z" {
			if v.Bits != 0 {
				return " = true", true
			}
			return "", false
		}
		return " = " + smaliIntegralLiteral(typeName, int64(int32(v.Bits))), true
	case 3: // char (zero-extended 16-bit)
		return " = " + strconv.FormatInt(int64(v.Bits&0xffff), 10), true
	case 6: // long
		return " = " + strconv.FormatInt(int64(v.Bits), 10) + "L", true
	case 0x10: // float bits
		f := math.Float32frombits(uint32(v.Bits))
		return " = " + strconv.FormatFloat(float64(f), 'g', -1, 32) + "f", true
	case 0x11: // double bits
		d := math.Float64frombits(v.Bits)
		return " = " + strconv.FormatFloat(d, 'g', -1, 64), true
	case 0x17: // string
		return " = " + quoteSmaliString(v.Text), true
	case 0x1e: // null
		return "", false
	case 0x1f: // boolean
		if typeName == "Z" || typeName == "" {
			if v.Bits != 0 {
				return " = true", true
			}
			// false is the default; omit to match baksmali.
			return "", false
		}
		if v.Bits != 0 {
			return " = true", true
		}
		return "", false
	default:
		return "", false
	}
}

func writeSmaliMethod(buf *strings.Builder, m *EncodedMethod, parser *DEXParser) {
	var b bytes.Buffer
	writeSmaliMethodBuf(&b, m, parser)
	buf.Write(b.Bytes())
}

func writeSmaliMethodBuf(buf *bytes.Buffer, m *EncodedMethod, parser *DEXParser) {
	buf.WriteString(".method ")
	writeAccessFlagsToBuf(buf, m.AccessFlags)
	buf.WriteString(m.Name)
	buf.WriteByte('(')
	for _, param := range m.Parameters {
		buf.WriteString(param)
	}
	buf.WriteByte(')')
	if m.ReturnType != "" {
		buf.WriteString(m.ReturnType)
	} else {
		buf.WriteByte('V')
	}
	buf.WriteByte('\n')
	if ann := formatDEXAnnotations(m.Annotations, "    "); ann != "" {
		buf.WriteString(ann)
	}
	annotationSlot := 0
	if m.AccessFlags&0x0008 == 0 {
		annotationSlot = 1
	}
	for i, typ := range m.Parameters {
		if i < len(m.ParameterAnnotations) && len(m.ParameterAnnotations[i]) > 0 {
			buf.WriteString("    .param p" + strconv.Itoa(annotationSlot) + "\n")
			buf.WriteString(formatDEXAnnotations(m.ParameterAnnotations[i], "        "))
			buf.WriteString("    .end param\n")
		}
		annotationSlot++
		if typ == "J" || typ == "D" {
			annotationSlot++
		}
	}

	code := parser.GetMethodCode(m)
	if code != nil {
		buf.WriteString("    .registers ")
		buf.WriteString(strconv.Itoa(int(code.RegistersSize)))
		buf.WriteByte('\n')

		isStatic := (m.AccessFlags & 0x0008) != 0
		pIdx := 0
		if !isStatic {
			buf.WriteString("    .param p")
			buf.WriteString(strconv.Itoa(pIdx))
			buf.WriteString("    # this: ")
			buf.WriteString(m.ClassName)
			buf.WriteByte('\n')
			pIdx++
		}
		for _, pType := range m.Parameters {
			buf.WriteString("    .param p")
			buf.WriteString(strconv.Itoa(pIdx))
			buf.WriteString("    # ")
			buf.WriteString(pType)
			buf.WriteByte('\n')
			if pType == "J" || pType == "D" {
				pIdx += 2
			} else {
				pIdx++
			}
		}
		buf.WriteByte('\n')

		writeSmaliInsnsBuf(buf, code, parser)
	} else {
		buf.WriteString("    # abstract or native\n")
	}

	buf.WriteString(".end method\n\n")
}

func writeSmaliInsnsBuf(buf *bytes.Buffer, code *CodeItem, parser *DEXParser) {
	if len(code.Insns) == 0 {
		buf.WriteString("    return-void\n")
		return
	}

	labels := make(map[uint32][]string)
	instructions := labelSmaliControlFlow(code, parser, labels)
	for i, t := range code.Tries {
		start := t.StartAddr
		end := t.StartAddr + uint32(t.InsnCount)
		labels[start] = append(labels[start], fmt.Sprintf(":try_start_%d", i))
		labels[end] = append(labels[end], fmt.Sprintf(":try_end_%d", i))
		for _, h := range t.CatchHandlers {
			if h.HasCatchAll {
				labels[h.HandlerAddr] = append(labels[h.HandlerAddr], fmt.Sprintf(":catchall_%d", i))
			} else {
				labels[h.HandlerAddr] = append(labels[h.HandlerAddr], fmt.Sprintf(":catch_%d_%x", i, h.HandlerAddr))
			}
		}
	}

	pos := uint32(0)
	index := 0
	for pos <= uint32(len(code.Insns)) {
		if lbls, ok := labels[pos]; ok {
			for _, l := range lbls {
				buf.WriteString("    ")
				buf.WriteString(l)
				buf.WriteByte('\n')
			}
		}

		if pos == uint32(len(code.Insns)) {
			break
		}

		decoded, size := instructions[index].text, instructions[index].size
		index++
		buf.WriteString("    ")
		buf.WriteString(decoded)
		buf.WriteByte('\n')

		if size == 0 {
			size = 1
		}
		pos += size
	}

	for i, t := range code.Tries {
		for _, h := range t.CatchHandlers {
			if h.HasCatchAll {
				buf.WriteString("    .catchall {:try_start_")
				buf.WriteString(strconv.Itoa(i))
				buf.WriteString(" .. :try_end_")
				buf.WriteString(strconv.Itoa(i))
				buf.WriteString("} :catchall_")
				buf.WriteString(strconv.Itoa(i))
				buf.WriteByte('\n')
			} else {
				buf.WriteString("    .catch ")
				buf.WriteString(h.TypeName)
				buf.WriteString(" {:try_start_")
				buf.WriteString(strconv.Itoa(i))
				buf.WriteString(" .. :try_end_")
				buf.WriteString(strconv.Itoa(i))
				buf.WriteString("} :catch_")
				buf.WriteString(strconv.Itoa(i))
				buf.WriteByte('_')
				buf.WriteString(strconv.FormatUint(uint64(h.HandlerAddr), 16))
				buf.WriteByte('\n')
			}
		}
	}
}

type smaliEmissionInsn struct {
	pos  uint32
	size uint32
	text string
}

// Symbolic targets remain correct when a user inserts code or the assembler
// changes an instruction's width. DEX payload targets are relative to the
// switch instruction, not to the payload block.
func labelSmaliControlFlow(code *CodeItem, parser *DEXParser, labels map[uint32][]string) []smaliEmissionInsn {
	var instructions []smaliEmissionInsn
	starts := map[uint32]bool{}
	indexAt := map[uint32]int{}
	for pos := uint32(0); pos < uint32(len(code.Insns)); {
		text, size := DecodeInsn(code.Insns, pos, code.PayloadOffsets, parser)
		if size == 0 {
			size = 1
		}
		starts[pos] = true
		indexAt[pos] = len(instructions)
		instructions = append(instructions, smaliEmissionInsn{pos: pos, size: size, text: text})
		pos += size
	}
	label := func(target int64) string {
		if target < 0 || !starts[uint32(target)] || target >= int64(len(code.Insns)) {
			return ""
		}
		addr := uint32(target)
		name := fmt.Sprintf(":label_%x", addr)
		if len(labels[addr]) == 0 {
			labels[addr] = []string{name}
		}
		return name
	}
	payloadOwners := map[uint32][]uint32{}
	for i := range instructions {
		in := &instructions[i]
		relative, ok := smaliBranchOffset(code.Insns, in.pos)
		if !ok {
			continue
		}
		target := int64(in.pos) + relative
		name := label(target)
		if name == "" {
			continue
		}
		op := uint8(code.Insns[in.pos])
		if op == 0x2b || op == 0x2c {
			payloadOwners[uint32(target)] = append(payloadOwners[uint32(target)], in.pos)
		}
		// Every branch has its target as the final operand.
		if comma := strings.LastIndex(in.text, ","); comma >= 0 {
			in.text = in.text[:comma+1] + " " + name
		} else if space := strings.IndexByte(in.text, ' '); space >= 0 {
			in.text = in.text[:space+1] + name
		}
	}
	for i := range instructions {
		in := &instructions[i]
		owners := payloadOwners[in.pos]
		if len(owners) == 0 {
			continue
		}
		original := in.text
		var blocks []string
		for _, owner := range owners {
			lines := strings.Split(original, "\n")
			for j := 1; j < len(lines)-1; j++ {
				entry := strings.TrimSpace(lines[j])
				prefix := "        "
				if arrow := strings.Index(entry, "->"); arrow >= 0 {
					prefix += entry[:arrow+2] + " "
					entry = strings.TrimSpace(entry[arrow+2:])
				}
				offset, err := parseSmaliInt(entry)
				if err != nil {
					continue
				}
				if target := label(int64(owner) + offset); target != "" {
					lines[j] = prefix + target
				}
			}
			block := strings.Join(lines, "\n")
			if len(owners) > 1 {
				// A shared DEX payload has different absolute targets for each
				// caller. Give each switch its own symbolic Smali block.
				name := fmt.Sprintf(":payload_%x_%x", in.pos, owner)
				branch := &instructions[indexAt[owner]]
				branch.text = branch.text[:strings.LastIndex(branch.text, ",")+1] + " " + name
				block = name + "\n    " + block
			}
			blocks = append(blocks, block)
		}
		in.text = strings.Join(blocks, "\n    ")
	}
	return instructions
}

func smaliBranchOffset(insns []uint16, pos uint32) (int64, bool) {
	word := insns[pos]
	op := uint8(word)
	if op == 0x26 || op == 0x2b || op == 0x2c {
		if uint64(pos)+3 > uint64(len(insns)) {
			return 0, false
		}
		return int64(int32(uint32(insns[pos+1]) | uint32(insns[pos+2])<<16)), true
	}
	info := opcodeTable[op]
	if uint64(pos)+uint64(info.Size) > uint64(len(insns)) {
		return 0, false
	}
	switch info.Format {
	case Fmt10t:
		return int64(int8(word >> 8)), true
	case Fmt20t, Fmt21t, Fmt22t:
		return int64(int16(insns[pos+1])), true
	case Fmt30t:
		return int64(int32(uint32(insns[pos+1]) | uint32(insns[pos+2])<<16)), true
	}
	return 0, false
}

type smaliFlagInfo struct {
	flag uint32
	name string
}

func fieldAccessFlagsToSmali(flags uint32) string {
	s := accessFlagsToSmali(flags &^ (0x0040 | 0x0080))
	if flags&0x0040 != 0 {
		s += "volatile "
	}
	if flags&0x0080 != 0 {
		s += "transient "
	}
	return s
}

var smaliAccessFlagsTable = [...]smaliFlagInfo{
	{0x0001, "public"},
	{0x0002, "private"},
	{0x0004, "protected"},
	{0x0008, "static"},
	{0x0010, "final"},
	{0x0020, "synchronized"},
	{0x0040, "bridge"},
	{0x0080, "varargs"},
	{0x0100, "native"},
	{0x0200, "interface"},
	{0x0400, "abstract"},
	{0x0800, "strictfp"},
	{0x1000, "synthetic"},
	{0x2000, "annotation"},
	{0x4000, "enum"},
	{0x10000, "constructor"},
}

func writeAccessFlagsToBuf(buf *bytes.Buffer, flags uint32) {
	if flags == 0 {
		return
	}
	for _, fi := range smaliAccessFlagsTable {
		if flags&fi.flag != 0 {
			buf.WriteString(fi.name)
			buf.WriteByte(' ')
		}
	}
}

func accessFlagsToSmali(flags uint32) string {
	if flags == 0 {
		return ""
	}
	var parts []string
	for _, fi := range smaliAccessFlagsTable {
		if flags&fi.flag != 0 {
			parts = append(parts, fi.name)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ") + " "
}
