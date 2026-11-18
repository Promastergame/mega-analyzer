package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	areaHeader     = 128
	areaMagic      = 0x504f5250
	areaVersion    = 0xfc6ed0ab
	infoNameOffset = 96
	longFlag       = 1 << 16
)

// locateProperty follows Android's property trie. All offsets are relative to
// the area data, while the returned prop_info offset is relative to the file.
func locateProperty(data []byte, key string) (int, error) {
	if len(data) < areaHeader+20 || binary.LittleEndian.Uint32(data[8:]) != areaMagic {
		return 0, errNotFound
	}
	if binary.LittleEndian.Uint32(data[12:]) != areaVersion {
		return 0, fmt.Errorf("unsupported Android property-area version")
	}
	used := int(binary.LittleEndian.Uint32(data[:4]))
	if used < 20 || used > len(data)-areaHeader {
		return 0, fmt.Errorf("invalid property-area length")
	}
	end := areaHeader + used
	word := func(offset int) (uint32, error) {
		if offset < areaHeader || offset+4 > end {
			return 0, fmt.Errorf("property offset out of bounds")
		}
		return binary.LittleEndian.Uint32(data[offset:]), nil
	}
	node := areaHeader // root prop_bt
	for _, part := range strings.Split(key, ".") {
		child, err := word(node + 16)
		if err != nil {
			return 0, err
		}
		seen := map[uint32]bool{}
		found := false
		for child != 0 {
			if seen[child] {
				return 0, fmt.Errorf("cycle in property trie")
			}
			seen[child] = true
			if child > uint32(used-20) || child%4 != 0 {
				return 0, fmt.Errorf("invalid property node")
			}
			node = areaHeader + int(child)
			length, err := word(node)
			if err != nil {
				return 0, err
			}
			if length == 0 || int(length) > end-node-20 {
				return 0, fmt.Errorf("invalid property node name")
			}
			name := string(data[node+20 : node+20+int(length)])
			cmp := len(part) - len(name)
			if cmp == 0 {
				cmp = strings.Compare(part, name)
			}
			if cmp == 0 {
				found = true
				break
			}
			next := node + 8 // left
			if cmp > 0 {
				next = node + 12
			}
			child, err = word(next)
			if err != nil {
				return 0, err
			}
		}
		if !found {
			return 0, errNotFound
		}
	}
	info, err := word(node + 4)
	if err != nil {
		return 0, err
	}
	if info == 0 {
		return 0, errNotFound
	}
	if used < infoNameOffset+len(key)+1 || info%4 != 0 || info > uint32(used-infoNameOffset-len(key)-1) {
		return 0, fmt.Errorf("invalid prop_info offset")
	}
	offset := areaHeader + int(info)
	nameEnd := offset + infoNameOffset + len(key)
	if nameEnd >= end || string(data[offset+infoNameOffset:nameEnd]) != key || data[nameEnd] != 0 {
		return 0, fmt.Errorf("property trie/name mismatch")
	}
	return offset, nil
}
