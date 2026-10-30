//go:build !amd64

package apkloader

// decodeULEB128Array (Fallback) - последовательное декодирование массива ULEB128.
func decodeULEB128Array(data []byte, count uint32) ([]uint32, int) {
	if count == 0 || len(data) == 0 {
		return nil, 0
	}

	result := make([]uint32, count)
	offset := 0
	dataLen := len(data)

	for i := uint32(0); i < count; i++ {
		var val uint32
		var shift uint
		for {
			if offset >= dataLen {
				return result[:i], offset // Unexpected EOF
			}
			b := data[offset]
			offset++
			val |= uint32(b&0x7F) << shift
			if b&0x80 == 0 {
				break
			}
			shift += 7
			if shift >= 35 {
				return result[:i], offset // Overflows uint32
			}
		}
		result[i] = val
	}

	return result, offset
}
