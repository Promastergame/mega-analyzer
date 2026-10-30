// Package jarloader provides parsing and security analysis of Java archives
// (.jar / .war / .ear) and the .class files they contain. It reuses the same
// finding model as the rest of mega-analyzer so JAR findings flow through the
// existing FP filter, SBOM and reporting pipeline.
package jarloader

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// Java class file magic number.
const classMagic = 0xCAFEBABE

// Constant pool tags (JVMS §4.4).
const (
	cpUtf8               = 1
	cpInteger            = 3
	cpFloat              = 4
	cpLong               = 5
	cpDouble             = 6
	cpClass              = 7
	cpString             = 8
	cpFieldref           = 9
	cpMethodref          = 10
	cpInterfaceMethodref = 11
	cpNameAndType        = 12
	cpMethodHandle       = 15
	cpMethodType         = 16
	cpDynamic            = 17
	cpInvokeDynamic      = 18
	cpModule             = 19
	cpPackage            = 20
)

// ErrNotClassFile is returned when the data does not start with the class magic.
var ErrNotClassFile = errors.New("jarloader: not a Java .class file")

// constant is a decoded constant-pool entry. Only the fields relevant to
// security analysis are retained.
type constant struct {
	tag            uint8
	utf8           string // for cpUtf8
	nameIndex      uint16 // for cpClass, cpNameAndType (name)
	classIndex     uint16 // for ref entries
	ntIndex        uint16 // for ref entries (name_and_type)
	descIndex      uint16 // for cpNameAndType (descriptor)
	stringIndex    uint16 // for cpString
	referenceKind  uint8  // for cpMethodHandle
	referenceIndex uint16 // for cpMethodHandle
}

// MethodRef is a symbolic constant-pool reference, not proof of invocation.
type MethodRef struct {
	Class      string
	Name       string
	Descriptor string
}

// FullName returns Class.Name for display.
func (m MethodRef) FullName() string { return m.Class + "." + m.Name }

// ClassFile is the parsed, analysis-relevant view of a .class file.
type ClassFile struct {
	CallSites         []CallSite
	Methods           []MethodBody
	BytecodeParsed    bool
	BytecodeTruncated bool
	InstructionCount  int
	// pool is retained transiently for argument resolution; it is never
	// serialized and is freed with the ClassFile after analysis.
	pool       []constant
	Major      uint16
	Minor      uint16
	ThisClass  string
	SuperClass string
	Interfaces []string
	// MethodRefs lists every method referenced from the constant pool. This is
	// a cheap, robust over-approximation of "what this class can call" without
	// fully decoding bytecode, and is enough to flag dangerous sinks.
	MethodRefs []MethodRef
	// Strings lists every UTF-8 string constant (used for secret scanning).
	Strings []string
	// StringConstants holds only genuine string literals resolved through
	// cpString entries (ldc operands). Descriptors, attribute names and
	// other pool noise stay out: secret classification runs on these.
	StringConstants []string
}

// JavaVersion returns a human-readable Java SE version derived from the major
// class-file version (e.g. 52 -> "Java 8").
func (c *ClassFile) JavaVersion() string {
	if c.Major < 45 {
		return "unknown"
	}
	if c.Major == 45 {
		return "Java 1.1"
	}
	return fmt.Sprintf("Java %d", c.Major-44)
}

// reader is a minimal big-endian cursor over a byte slice with bounds checks.
type reader struct {
	b   []byte
	pos int
}

func (r *reader) u8() (uint8, error) {
	if r.pos+1 > len(r.b) {
		return 0, errShortRead
	}
	v := r.b[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if r.pos+2 > len(r.b) {
		return 0, errShortRead
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *reader) u32() (uint32, error) {
	if r.pos+4 > len(r.b) {
		return 0, errShortRead
	}
	v := binary.BigEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *reader) skip(n int) error {
	if r.pos+n > len(r.b) {
		return errShortRead
	}
	r.pos += n
	return nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, errShortRead
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

var errShortRead = errors.New("jarloader: unexpected end of class data")

// ParseClass decodes a .class file into a ClassFile. It is defensive: it never
// panics on malformed input and returns a wrapped error instead.
func ParseClass(data []byte) (*ClassFile, error) {
	r := &reader{b: data}

	magic, err := r.u32()
	if err != nil {
		return nil, err
	}
	if magic != classMagic {
		return nil, ErrNotClassFile
	}

	cf := &ClassFile{StringConstants: make([]string, 0)}
	if cf.Minor, err = r.u16(); err != nil {
		return nil, err
	}
	if cf.Major, err = r.u16(); err != nil {
		return nil, err
	}
	if cf.Major < 45 {
		return nil, errors.New("jarloader: unsupported class version below 45")
	}

	cpCount, err := r.u16()
	if err != nil {
		return nil, err
	}

	if cpCount == 0 {
		return nil, errors.New("jarloader: zero constant pool count")
	}

	// Constant pool is 1-indexed; index 0 is unused.
	pool := make([]constant, cpCount)
	for i := 1; i < int(cpCount); i++ {
		tag, err := r.u8()
		if err != nil {
			return nil, err
		}
		c := constant{tag: tag}
		switch tag {
		case cpUtf8:
			n, err := r.u16()
			if err != nil {
				return nil, err
			}
			raw, err := r.bytes(int(n))
			if err != nil {
				return nil, err
			}
			c.utf8 = decodeModifiedUTF8(raw)
		case cpInteger, cpFloat:
			if err := r.skip(4); err != nil {
				return nil, err
			}
		case cpLong, cpDouble:
			if i+1 >= int(cpCount) {
				return nil, errors.New("jarloader: long/double missing reserved pool slot")
			}
			if err := r.skip(8); err != nil {
				return nil, err
			}
			// Long/Double take two pool slots (JVMS §4.4.5).
			pool[i] = c
			i++
			continue
		case cpClass, cpModule, cpPackage:
			if c.nameIndex, err = r.u16(); err != nil {
				return nil, err
			}
		case cpString:
			if c.stringIndex, err = r.u16(); err != nil {
				return nil, err
			}
		case cpFieldref, cpMethodref, cpInterfaceMethodref, cpDynamic, cpInvokeDynamic:
			if c.classIndex, err = r.u16(); err != nil {
				return nil, err
			}
			if c.ntIndex, err = r.u16(); err != nil {
				return nil, err
			}
		case cpNameAndType:
			if c.nameIndex, err = r.u16(); err != nil {
				return nil, err
			}
			if c.descIndex, err = r.u16(); err != nil {
				return nil, err
			}
		case cpMethodHandle:
			if c.referenceKind, err = r.u8(); err != nil {
				return nil, err
			}
			if c.referenceIndex, err = r.u16(); err != nil {
				return nil, err
			}
		case cpMethodType:
			if c.descIndex, err = r.u16(); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("jarloader: unknown constant pool tag %d at index %d", tag, i)
		}
		pool[i] = c
	}

	if err := validatePool(pool); err != nil {
		return nil, err
	}
	cf.pool = pool

	// Helpers to resolve indices into the pool safely.
	utf8At := func(idx uint16) string {
		if int(idx) < len(pool) && pool[idx].tag == cpUtf8 {
			return pool[idx].utf8
		}
		return ""
	}
	classNameAt := func(idx uint16) string {
		if int(idx) < len(pool) && pool[idx].tag == cpClass {
			return normalizeClassName(utf8At(pool[idx].nameIndex))
		}
		return ""
	}

	// access_flags, this_class, super_class
	if err := r.skip(2); err != nil { // access_flags
		return nil, err
	}
	thisIdx, err := r.u16()
	if err != nil {
		return nil, err
	}
	superIdx, err := r.u16()
	if err != nil {
		return nil, err
	}
	cf.ThisClass = classNameAt(thisIdx)
	cf.SuperClass = classNameAt(superIdx)
	if cf.ThisClass == "" || (superIdx != 0 && cf.SuperClass == "") {
		return nil, errors.New("jarloader: invalid this_class/super_class reference")
	}

	// interfaces
	ifCount, err := r.u16()
	if err != nil {
		return nil, err
	}
	for i := 0; i < int(ifCount); i++ {
		idx, err := r.u16()
		if err != nil {
			return nil, err
		}
		if name := classNameAt(idx); name != "" {
			cf.Interfaces = append(cf.Interfaces, name)
		} else {
			return nil, errors.New("jarloader: invalid interface reference")
		}
	}

	// Resolve method references, strings and genuine string literals
	// directly from the pool. The structural tail is checked separately;
	// constant-pool references are not proven call sites.
	stringSeen := map[uint16]bool{}
	for i := 1; i < len(pool); i++ {
		c := pool[i]
		switch c.tag {
		case cpMethodref, cpInterfaceMethodref:
			cls := classNameAt(c.classIndex)
			var name, desc string
			if int(c.ntIndex) < len(pool) && pool[c.ntIndex].tag == cpNameAndType {
				nt := pool[c.ntIndex]
				name = utf8At(nt.nameIndex)
				desc = utf8At(nt.descIndex)
			}
			if cls != "" && name != "" {
				cf.MethodRefs = append(cf.MethodRefs, MethodRef{Class: cls, Name: name, Descriptor: desc})
			}
		case cpUtf8:
			if c.utf8 != "" {
				cf.Strings = append(cf.Strings, c.utf8)
			}
		case cpString:
			// A real string literal: cpString -> cpUtf8. Dedupe by pool
			// index so repeated ldc of one constant counts once.
			if stringSeen[c.stringIndex] {
				continue
			}
			stringSeen[c.stringIndex] = true
			if s := utf8At(c.stringIndex); s != "" {
				cf.StringConstants = append(cf.StringConstants, s)
			}
		}
	}

	tail := *r
	if err := validateClassTail(r, pool); err != nil {
		return nil, err
	}
	if err := collectBytecode(&tail, pool, cf); err != nil {
		return nil, err
	}
	return cf, nil
}

// normalizeClassName converts internal JVM names (java/lang/Runtime) to dotted
// names (java.lang.Runtime).
func normalizeClassName(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			out[i] = '.'
		} else {
			out[i] = s[i]
		}
	}
	return string(out)
}

// decodeModifiedUTF8 handles JVM NUL encoding and UTF-16 surrogate pairs.
// Invalid sequences remain visible rather than being silently discarded.
func decodeModifiedUTF8(b []byte) string {
	ascii := true
	for _, c := range b {
		if c == 0 || c >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return string(b)
	}
	units := make([]uint16, 0, len(b))
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c < 0x80:
			units = append(units, uint16(c))
			i++
		case c&0xe0 == 0xc0 && i+1 < len(b) && b[i+1]&0xc0 == 0x80:
			units = append(units, uint16(c&0x1f)<<6|uint16(b[i+1]&0x3f))
			i += 2
		case c&0xf0 == 0xe0 && i+2 < len(b) && b[i+1]&0xc0 == 0x80 && b[i+2]&0xc0 == 0x80:
			units = append(units, uint16(c&0x0f)<<12|uint16(b[i+1]&0x3f)<<6|uint16(b[i+2]&0x3f))
			i += 3
		default:
			units = append(units, uint16(c))
			i++
		}
	}
	return string(utf16.Decode(units))
}
