// Package platformtext decodes subprocess output before it enters UTF-8 JSON.
package platformtext

import (
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

func DecodeConsoleOutput(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var order binary.ByteOrder
	if len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe {
		order = binary.LittleEndian
		data = data[2:]
	} else if len(data) >= 2 && data[0] == 0xfe && data[1] == 0xff {
		order = binary.BigEndian
		data = data[2:]
	}
	if order == nil && len(data) >= 4 && len(data)%2 == 0 {
		even, odd := 0, 0
		for i, b := range data {
			if b == 0 {
				if i%2 == 0 {
					even++
				} else {
					odd++
				}
			}
		}
		if odd > len(data)/4 && even == 0 {
			order = binary.LittleEndian
		} else if even > len(data)/4 && odd == 0 {
			order = binary.BigEndian
		}
	}
	if order != nil {
		words := make([]uint16, 0, (len(data)+1)/2)
		for i := 0; i+1 < len(data); i += 2 {
			words = append(words, order.Uint16(data[i:i+2]))
		}
		if len(data)%2 != 0 {
			words = append(words, 0xfffd)
		}
		return string(utf16.Decode(words))
	}
	if utf8.Valid(data) {
		return string(data)
	}
	return decodeLegacyConsole(data)
}
