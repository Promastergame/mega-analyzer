package apkloader

import "fmt"

const (
	dexValueByte    = 0x00
	dexValueShort   = 0x02
	dexValueChar    = 0x03
	dexValueInt     = 0x04
	dexValueLong    = 0x06
	dexValueString  = 0x17
	dexValueArray   = 0x1c
	dexValueNull    = 0x1e
	dexValueBoolean = 0x1f
)

type encodedValueLimits struct {
	maxDepth    int
	maxElements int
	maxBytes    int
}

type encodedValueDecoder struct {
	parser   *DEXParser
	limits   encodedValueLimits
	elements int
	bytes    int
}

func (p *DEXParser) decodeStaticValues(class *ClassDef, maxDepth, maxElements, maxBytes int) (map[string]OwnedStaticValue, error) {
	out := make(map[string]OwnedStaticValue)
	if class == nil || len(class.StaticFields) == 0 {
		return out, nil
	}
	for _, field := range class.StaticFields {
		out[field.Descriptor()] = defaultStaticValue(field.TypeName)
	}
	if class.StaticValuesOff == 0 {
		return out, nil
	}
	decoder := &encodedValueDecoder{parser: p, limits: encodedValueLimits{maxDepth: maxDepth, maxElements: maxElements, maxBytes: maxBytes}}
	values, _, err := decoder.decodeArray(class.StaticValuesOff, 0)
	if err != nil {
		return nil, fmt.Errorf("class %s static values: %w", class.ClassName, err)
	}
	if len(values) > len(class.StaticFields) {
		return nil, fmt.Errorf("class %s has %d static values for %d fields", class.ClassName, len(values), len(class.StaticFields))
	}
	for i, value := range values {
		value.TypeName = class.StaticFields[i].TypeName
		value.Operations = append(value.Operations, "dex-encoded-value:"+class.StaticFields[i].Descriptor())
		out[class.StaticFields[i].Descriptor()] = value
	}
	return out, nil
}

func defaultStaticValue(typeName string) OwnedStaticValue {
	if len(typeName) == 1 && typeName != "V" {
		return OwnedStaticValue{Kind: StaticIntegral, TypeName: typeName, Operations: []string{"dex-static-default"}}
	}
	return OwnedStaticValue{Kind: StaticNull, TypeName: typeName, Operations: []string{"dex-static-default"}}
}

func (d *encodedValueDecoder) decodeArray(offset uint32, depth int) ([]OwnedStaticValue, uint32, error) {
	if depth > d.limits.maxDepth {
		return nil, offset, fmt.Errorf("encoded value depth budget exhausted")
	}
	count, n := d.parser.readULEB128At(offset)
	if n == 0 {
		return nil, offset, errBadULEB128
	}
	offset += uint32(n)
	if int(count) > d.limits.maxElements-d.elements {
		return nil, offset, fmt.Errorf("encoded value element budget exhausted")
	}
	d.elements += int(count)
	out := make([]OwnedStaticValue, 0, count)
	for i := uint32(0); i < count; i++ {
		value, next, err := d.decodeValue(offset, depth+1)
		if err != nil {
			return nil, offset, fmt.Errorf("value[%d]: %w", i, err)
		}
		out = append(out, value)
		offset = next
	}
	return out, offset, nil
}

func (d *encodedValueDecoder) decodeValue(offset uint32, depth int) (OwnedStaticValue, uint32, error) {
	if !d.parser.boundsOK(offset, 1) {
		return OwnedStaticValue{}, offset, errOutOfBounds
	}
	header := d.parser.data[offset]
	offset++
	valueType := header & 0x1f
	valueArg := int(header >> 5)
	width := valueArg + 1
	readRaw := func(maxWidth int) (uint64, error) {
		if width > maxWidth || !d.parser.boundsOK(offset, uint32(width)) {
			return 0, fmt.Errorf("invalid encoded value width %d", width)
		}
		if d.bytes+width > d.limits.maxBytes {
			return 0, fmt.Errorf("encoded value byte budget exhausted")
		}
		d.bytes += width
		var raw uint64
		for i := 0; i < width; i++ {
			raw |= uint64(d.parser.data[offset+uint32(i)]) << (8 * i)
		}
		return raw, nil
	}
	signed := func(raw uint64) int64 {
		shift := uint(64 - width*8)
		return int64(raw<<shift) >> shift
	}
	switch valueType {
	case dexValueByte:
		if valueArg != 0 {
			return OwnedStaticValue{}, offset, fmt.Errorf("invalid byte value_arg")
		}
		raw, err := readRaw(1)
		return OwnedStaticValue{Kind: StaticIntegral, Int64: signed(raw)}, offset + uint32(width), err
	case dexValueShort, dexValueInt, dexValueLong:
		maxWidth := map[byte]int{dexValueShort: 2, dexValueInt: 4, dexValueLong: 8}[valueType]
		raw, err := readRaw(maxWidth)
		return OwnedStaticValue{Kind: StaticIntegral, Int64: signed(raw)}, offset + uint32(width), err
	case dexValueChar:
		raw, err := readRaw(2)
		return OwnedStaticValue{Kind: StaticIntegral, Int64: int64(raw)}, offset + uint32(width), err
	case dexValueString:
		raw, err := readRaw(4)
		if err != nil || raw >= uint64(len(d.parser.strings)) {
			if err == nil {
				err = fmt.Errorf("string index out of range")
			}
			return OwnedStaticValue{}, offset, err
		}
		return OwnedStaticValue{Kind: StaticString, String: d.parser.getString(uint32(raw))}, offset + uint32(width), nil
	case dexValueNull:
		if valueArg != 0 {
			return OwnedStaticValue{}, offset, fmt.Errorf("invalid null value_arg")
		}
		return OwnedStaticValue{Kind: StaticNull}, offset, nil
	case dexValueBoolean:
		if valueArg > 1 {
			return OwnedStaticValue{}, offset, fmt.Errorf("invalid boolean value_arg")
		}
		return OwnedStaticValue{Kind: StaticIntegral, TypeName: "Z", Int64: int64(valueArg)}, offset, nil
	case dexValueArray:
		if valueArg != 0 {
			return OwnedStaticValue{}, offset, fmt.Errorf("invalid array value_arg")
		}
		values, next, err := d.decodeArray(offset, depth)
		return OwnedStaticValue{Kind: StaticArray, Elements: values}, next, err
	default:
		return OwnedStaticValue{}, offset, fmt.Errorf("unsupported encoded value type 0x%x", valueType)
	}
}
