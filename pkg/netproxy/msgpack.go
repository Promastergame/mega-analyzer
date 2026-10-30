package netproxy

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
)

const (
	maxMsgPackElements = 100000
	maxInt64Uint       = uint64(1<<63 - 1)
	// maxMsgPackDepth bounds recursion so a deeply-nested payload from an
	// untrusted peer (the MITM periphery decodes attacker-controlled bytes)
	// can't blow the goroutine stack. Real game/app protocol messages nest a
	// handful of levels; 64 is far above any legitimate structure while still
	// terminating a malicious `[[[[...]]]]` long before it exhausts the stack.
	maxMsgPackDepth = 64
)

// SimpleMsgPack provides a minimalistic, zero-dependency MessagePack encoder and decoder.
// It maps MsgPack to standard Go types (map[string]any, []any, string, int64, float64, bool, []byte).

// UnmarshalMsgPack decodes a msgpack byte slice into a generic Go interface{}.
func UnmarshalMsgPack(data []byte) (any, error) {
	val, n, err := parseMsgPackDepth(data, 0)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return val, fmt.Errorf("extra trailing bytes after msgpack payload")
	}
	return val, nil
}

// parseMsgPack decodes one value at the top level (depth 0). It is retained as
// a thin wrapper so existing callers/tests keep working; all recursion goes
// through parseMsgPackDepth so the depth limit is enforced uniformly.
func parseMsgPack(data []byte) (any, int, error) {
	return parseMsgPackDepth(data, 0)
}

func parseMsgPackDepth(data []byte, depth int) (any, int, error) {
	if depth > maxMsgPackDepth {
		return nil, 0, fmt.Errorf("msgpack nesting too deep (> %d)", maxMsgPackDepth)
	}
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("empty data")
	}
	b := data[0]

	// Positive FixInt
	if b <= 0x7f {
		return int64(b), 1, nil
	}
	// Negative FixInt
	if b >= 0xe0 {
		return int64(int8(b)), 1, nil
	}
	// FixStr
	if b >= 0xa0 && b <= 0xbf {
		l := int(b & 0x1f)
		if len(data) < 1+l {
			return nil, 0, fmt.Errorf("truncated fixstr")
		}
		return string(data[1 : 1+l]), 1 + l, nil
	}
	// FixMap
	if b >= 0x80 && b <= 0x8f {
		l := int(b & 0x0f)
		return parseMap(data[1:], l, 1, depth)
	}
	// FixArray
	if b >= 0x90 && b <= 0x9f {
		l := int(b & 0x0f)
		return parseArray(data[1:], l, 1, depth)
	}

	switch b {
	case 0xc0: // nil
		return nil, 1, nil
	case 0xc2: // false
		return false, 1, nil
	case 0xc3: // true
		return true, 1, nil
	case 0xcc: // uint8
		if len(data) < 2 {
			return nil, 0, fmt.Errorf("truncated uint8")
		}
		return int64(data[1]), 2, nil
	case 0xcd: // uint16
		if len(data) < 3 {
			return nil, 0, fmt.Errorf("truncated uint16")
		}
		return int64(binary.BigEndian.Uint16(data[1:])), 3, nil
	case 0xce: // uint32
		if len(data) < 5 {
			return nil, 0, fmt.Errorf("truncated uint32")
		}
		return int64(binary.BigEndian.Uint32(data[1:])), 5, nil
	case 0xcf: // uint64
		if len(data) < 9 {
			return nil, 0, fmt.Errorf("truncated uint64")
		}
		u := binary.BigEndian.Uint64(data[1:])
		if u > maxInt64Uint {
			// Preserve full value instead of silently wrapping to negative.
			return u, 9, nil
		}
		return int64(u), 9, nil
	case 0xd0: // int8
		if len(data) < 2 {
			return nil, 0, fmt.Errorf("truncated int8")
		}
		return int64(int8(data[1])), 2, nil
	case 0xd1: // int16
		if len(data) < 3 {
			return nil, 0, fmt.Errorf("truncated int16")
		}
		return int64(int16(binary.BigEndian.Uint16(data[1:]))), 3, nil
	case 0xd2: // int32
		if len(data) < 5 {
			return nil, 0, fmt.Errorf("truncated int32")
		}
		return int64(int32(binary.BigEndian.Uint32(data[1:]))), 5, nil
	case 0xd3: // int64
		if len(data) < 9 {
			return nil, 0, fmt.Errorf("truncated int64")
		}
		return int64(binary.BigEndian.Uint64(data[1:])), 9, nil
	case 0xca: // float32
		if len(data) < 5 {
			return nil, 0, fmt.Errorf("truncated float32")
		}
		bits := binary.BigEndian.Uint32(data[1:])
		return float64(math.Float32frombits(bits)), 5, nil
	case 0xcb: // float64
		if len(data) < 9 {
			return nil, 0, fmt.Errorf("truncated float64")
		}
		bits := binary.BigEndian.Uint64(data[1:])
		return math.Float64frombits(bits), 9, nil
	case 0xd9: // str8
		if len(data) < 2 {
			return nil, 0, fmt.Errorf("truncated str8")
		}
		l := int(data[1])
		if len(data) < 2+l {
			return nil, 0, fmt.Errorf("truncated str8 data")
		}
		return string(data[2 : 2+l]), 2 + l, nil
	case 0xda: // str16
		if len(data) < 3 {
			return nil, 0, fmt.Errorf("truncated str16")
		}
		l := int(binary.BigEndian.Uint16(data[1:]))
		if len(data) < 3+l {
			return nil, 0, fmt.Errorf("truncated str16 data")
		}
		return string(data[3 : 3+l]), 3 + l, nil
	case 0xdb: // str32
		if len(data) < 5 {
			return nil, 0, fmt.Errorf("truncated str32")
		}
		l := int(binary.BigEndian.Uint32(data[1:]))
		if l < 0 || len(data) < 5+l {
			return nil, 0, fmt.Errorf("truncated str32 data")
		}
		return string(data[5 : 5+l]), 5 + l, nil
	case 0xc4, 0xc5, 0xc6: // bin8, bin16, bin32
		var l int
		var off int
		switch b {
		case 0xc4:
			if len(data) < 2 {
				return nil, 0, fmt.Errorf("truncated bin8")
			}
			l = int(data[1])
			off = 2
		case 0xc5:
			if len(data) < 3 {
				return nil, 0, fmt.Errorf("truncated bin16")
			}
			l = int(binary.BigEndian.Uint16(data[1:]))
			off = 3
		case 0xc6:
			if len(data) < 5 {
				return nil, 0, fmt.Errorf("truncated bin32")
			}
			l = int(binary.BigEndian.Uint32(data[1:]))
			off = 5
		}
		if l < 0 || len(data) < off+l {
			return nil, 0, fmt.Errorf("truncated bin data")
		}
		bin := make([]byte, l)
		copy(bin, data[off:off+l])
		return bin, off + l, nil
	case 0xdc: // array16
		if len(data) < 3 {
			return nil, 0, fmt.Errorf("truncated array16")
		}
		l := int(binary.BigEndian.Uint16(data[1:]))
		return parseArray(data[3:], l, 3, depth)
	case 0xdd: // array32
		if len(data) < 5 {
			return nil, 0, fmt.Errorf("truncated array32")
		}
		l := int(binary.BigEndian.Uint32(data[1:]))
		return parseArray(data[5:], l, 5, depth)
	case 0xde: // map16
		if len(data) < 3 {
			return nil, 0, fmt.Errorf("truncated map16")
		}
		l := int(binary.BigEndian.Uint16(data[1:]))
		return parseMap(data[3:], l, 3, depth)
	case 0xdf: // map32
		if len(data) < 5 {
			return nil, 0, fmt.Errorf("truncated map32")
		}
		l := int(binary.BigEndian.Uint32(data[1:]))
		return parseMap(data[5:], l, 5, depth)
	}
	return nil, 0, fmt.Errorf("unsupported msgpack byte 0x%x", b)
}

func parseMap(data []byte, length int, offset int, depth int) (any, int, error) {
	if length < 0 || length > maxMsgPackElements {
		return nil, 0, fmt.Errorf("msgpack map too large: %d", length)
	}
	// A map of N pairs needs at least 2N bytes (one tag byte per key and per
	// value). Reject a length the remaining buffer cannot possibly satisfy
	// *before* allocating, so a 5-byte map32 header claiming 100000 entries
	// can't force a large allocation. This is the amplification guard.
	if length > 0 && length > len(data)/2 {
		return nil, 0, fmt.Errorf("msgpack map length %d exceeds remaining bytes", length)
	}
	m := make(map[string]any, length)
	for i := 0; i < length; i++ {
		k, n1, err := parseMsgPackDepth(data, depth+1)
		if err != nil {
			return nil, 0, err
		}
		keyStr, ok := k.(string)
		if !ok {
			// fallback: map non-string keys to their string representation
			keyStr = fmt.Sprintf("%v", k)
		}
		data = data[n1:]
		offset += n1

		v, n2, err := parseMsgPackDepth(data, depth+1)
		if err != nil {
			return nil, 0, err
		}
		m[keyStr] = v
		data = data[n2:]
		offset += n2
	}
	return m, offset, nil
}

func parseArray(data []byte, length int, offset int, depth int) (any, int, error) {
	if length < 0 || length > maxMsgPackElements {
		return nil, 0, fmt.Errorf("msgpack array too large: %d", length)
	}
	// Each element needs at least one tag byte, so a length larger than the
	// remaining buffer is impossible — reject before allocating make([]any,
	// length), which is the OOM-amplification vector for array32 headers.
	if length > len(data) {
		return nil, 0, fmt.Errorf("msgpack array length %d exceeds remaining bytes", length)
	}
	arr := make([]any, length)
	for i := 0; i < length; i++ {
		v, n, err := parseMsgPackDepth(data, depth+1)
		if err != nil {
			return nil, 0, err
		}
		arr[i] = v
		data = data[n:]
		offset += n
	}
	return arr, offset, nil
}

// MarshalMsgPack encodes a generic Go interface{} into a msgpack byte slice.
func MarshalMsgPack(v any) ([]byte, error) {
	if v == nil {
		return []byte{0xc0}, nil
	}
	switch val := v.(type) {
	case bool:
		if val {
			return []byte{0xc3}, nil
		}
		return []byte{0xc2}, nil
	case int:
		return encodeInt(int64(val)), nil
	case int64:
		return encodeInt(val), nil
	case uint64:
		return encodeUint64(val), nil
	case float64:
		return encodeFloat64(val), nil
	case string:
		return encodeString(val), nil
	case []byte:
		return encodeBin(val), nil
	case []any:
		return encodeArray(val)
	case map[string]any:
		return encodeMap(val)
	default:
		return nil, fmt.Errorf("unsupported type %T for msgpack encoding", v)
	}
}

func encodeUint64(v uint64) []byte {
	b := make([]byte, 9)
	b[0] = 0xcf
	binary.BigEndian.PutUint64(b[1:], v)
	return b
}

func encodeInt(v int64) []byte {
	if v >= 0 && v <= 127 {
		return []byte{byte(v)}
	}
	if v >= -32 && v <= -1 {
		return []byte{byte(v)}
	}
	if v >= -128 && v <= 127 {
		return []byte{0xd0, byte(v)}
	}
	if v >= -32768 && v <= 32767 {
		b := make([]byte, 3)
		b[0] = 0xd1
		binary.BigEndian.PutUint16(b[1:], uint16(v))
		return b
	}
	if v >= -2147483648 && v <= 2147483647 {
		b := make([]byte, 5)
		b[0] = 0xd2
		binary.BigEndian.PutUint32(b[1:], uint32(v))
		return b
	}
	b := make([]byte, 9)
	b[0] = 0xd3
	binary.BigEndian.PutUint64(b[1:], uint64(v))
	return b
}

func encodeFloat64(v float64) []byte {
	b := make([]byte, 9)
	b[0] = 0xcb
	binary.BigEndian.PutUint64(b[1:], math.Float64bits(v))
	return b
}

func encodeString(v string) []byte {
	l := len(v)
	if l <= 31 {
		b := make([]byte, 1+l)
		b[0] = 0xa0 | byte(l)
		copy(b[1:], v)
		return b
	}
	if l <= 255 {
		b := make([]byte, 2+l)
		b[0] = 0xd9
		b[1] = byte(l)
		copy(b[2:], v)
		return b
	}
	if l <= 65535 {
		b := make([]byte, 3+l)
		b[0] = 0xda
		binary.BigEndian.PutUint16(b[1:], uint16(l))
		copy(b[3:], v)
		return b
	}
	b := make([]byte, 5+l)
	b[0] = 0xdb
	binary.BigEndian.PutUint32(b[1:], uint32(l))
	copy(b[5:], v)
	return b
}

func encodeBin(v []byte) []byte {
	l := len(v)
	if l <= 255 {
		b := make([]byte, 2+l)
		b[0] = 0xc4
		b[1] = byte(l)
		copy(b[2:], v)
		return b
	}
	if l <= 65535 {
		b := make([]byte, 3+l)
		b[0] = 0xc5
		binary.BigEndian.PutUint16(b[1:], uint16(l))
		copy(b[3:], v)
		return b
	}
	b := make([]byte, 5+l)
	b[0] = 0xc6
	binary.BigEndian.PutUint32(b[1:], uint32(l))
	copy(b[5:], v)
	return b
}

func encodeArray(arr []any) ([]byte, error) {
	l := len(arr)
	var out []byte
	if l <= 15 {
		out = append(out, 0x90|byte(l))
	} else if l <= 65535 {
		b := make([]byte, 3)
		b[0] = 0xdc
		binary.BigEndian.PutUint16(b[1:], uint16(l))
		out = append(out, b...)
	} else {
		b := make([]byte, 5)
		b[0] = 0xdd
		binary.BigEndian.PutUint32(b[1:], uint32(l))
		out = append(out, b...)
	}
	for _, v := range arr {
		encoded, err := MarshalMsgPack(v)
		if err != nil {
			return nil, err
		}
		out = append(out, encoded...)
	}
	return out, nil
}

func encodeMap(m map[string]any) ([]byte, error) {
	l := len(m)
	var out []byte
	if l <= 15 {
		out = append(out, 0x80|byte(l))
	} else if l <= 65535 {
		b := make([]byte, 3)
		b[0] = 0xde
		binary.BigEndian.PutUint16(b[1:], uint16(l))
		out = append(out, b...)
	} else {
		b := make([]byte, 5)
		b[0] = 0xdf
		binary.BigEndian.PutUint32(b[1:], uint32(l))
		out = append(out, b...)
	}
	// Go map iteration order is randomised, which would make the encoded bytes
	// non-reproducible — breaking golden tests, replay, and any digest taken
	// over the output. Sort keys so the same map always encodes identically.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ek := encodeString(k)
		out = append(out, ek...)
		ev, err := MarshalMsgPack(m[k])
		if err != nil {
			return nil, err
		}
		out = append(out, ev...)
	}
	return out, nil
}
