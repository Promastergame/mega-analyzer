package jarloader

import "fmt"

// validatePool rejects dangling or wrongly typed links instead of returning a
// plausible-looking partial class. Dynamic bootstrap indices are NOT CP indices.
func validatePool(pool []constant) error {
	is := func(index uint16, tag uint8) bool {
		return index != 0 && int(index) < len(pool) && pool[index].tag == tag
	}
	for i, c := range pool {
		valid := true
		switch c.tag {
		case cpClass, cpModule, cpPackage:
			valid = is(c.nameIndex, cpUtf8)
		case cpString:
			valid = is(c.stringIndex, cpUtf8)
		case cpNameAndType:
			valid = is(c.nameIndex, cpUtf8) && is(c.descIndex, cpUtf8)
		case cpFieldref, cpMethodref, cpInterfaceMethodref:
			valid = is(c.classIndex, cpClass) && is(c.ntIndex, cpNameAndType)
		case cpDynamic, cpInvokeDynamic:
			valid = is(c.ntIndex, cpNameAndType)
		case cpMethodType:
			valid = is(c.descIndex, cpUtf8)
		case cpMethodHandle:
			switch c.referenceKind {
			case 1, 2, 3, 4:
				valid = is(c.referenceIndex, cpFieldref)
			case 5, 8:
				valid = is(c.referenceIndex, cpMethodref)
			case 6, 7:
				valid = is(c.referenceIndex, cpMethodref) || is(c.referenceIndex, cpInterfaceMethodref)
			case 9:
				valid = is(c.referenceIndex, cpInterfaceMethodref)
			default:
				valid = false
			}
		}
		if !valid {
			return fmt.Errorf("jarloader: invalid constant pool reference at index %d", i)
		}
	}
	return nil
}

// Validate member/attribute framing, including Code payload lengths. This is
// NOT a JVM verifier: instructions, stack maps and data flow remain unverified.
func validateClassTail(r *reader, pool []constant) error {
	for kind := 0; kind < 2; kind++ { // fields, then methods
		n, err := r.u16()
		if err != nil {
			return err
		}
		for i := 0; i < int(n); i++ {
			if err := r.skip(2); err != nil { // access_flags
				return err
			}
			for j := 0; j < 2; j++ { // name and descriptor
				idx, err := r.u16()
				if err != nil {
					return err
				}
				if idx == 0 || int(idx) >= len(pool) || pool[idx].tag != cpUtf8 {
					return fmt.Errorf("jarloader: invalid member name/descriptor index %d", idx)
				}
			}
			if err := validateAttributes(r, pool, kind == 1); err != nil {
				return err
			}
		}
	}
	if err := validateAttributes(r, pool, false); err != nil {
		return err
	}
	if r.pos != len(r.b) {
		return fmt.Errorf("jarloader: %d trailing class bytes", len(r.b)-r.pos)
	}
	return nil
}

func validateAttributes(r *reader, pool []constant, allowCode bool) error {
	n, err := r.u16()
	if err != nil {
		return err
	}
	codeSeen := false
	for i := 0; i < int(n); i++ {
		idx, err := r.u16()
		if err != nil {
			return err
		}
		if idx == 0 || int(idx) >= len(pool) || pool[idx].tag != cpUtf8 {
			return fmt.Errorf("jarloader: invalid attribute name index %d", idx)
		}
		size, err := r.u32()
		if err != nil {
			return err
		}
		if uint64(size) > uint64(len(r.b)-r.pos) {
			return errShortRead
		}
		data, err := r.bytes(int(size))
		if err != nil {
			return err
		}
		if pool[idx].utf8 == "Code" {
			if !allowCode || codeSeen {
				return fmt.Errorf("jarloader: misplaced or duplicate Code attribute")
			}
			codeSeen = true
			if err := validateCode(data, pool); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCode(data []byte, pool []constant) error {
	r := &reader{b: data}
	if err := r.skip(4); err != nil { // max_stack, max_locals
		return err
	}
	n, err := r.u32()
	if err != nil {
		return err
	}
	if n == 0 || n >= 65536 {
		return fmt.Errorf("jarloader: invalid Code length %d", n)
	}
	if err := r.skip(int(n)); err != nil {
		return err
	}
	count, err := r.u16()
	if err != nil {
		return err
	}
	for i := 0; i < int(count); i++ {
		var row [4]uint16
		for j := range row {
			row[j], err = r.u16()
			if err != nil {
				return err
			}
		}
		if row[0] >= row[1] || uint32(row[1]) > n || uint32(row[2]) >= n {
			return fmt.Errorf("jarloader: invalid exception handler range")
		}
		if row[3] != 0 && (int(row[3]) >= len(pool) || pool[row[3]].tag != cpClass) {
			return fmt.Errorf("jarloader: invalid exception catch type")
		}
	}
	if err := validateAttributes(r, pool, false); err != nil {
		return err
	}
	if r.pos != len(data) {
		return fmt.Errorf("jarloader: trailing Code attribute bytes")
	}
	return nil
}
