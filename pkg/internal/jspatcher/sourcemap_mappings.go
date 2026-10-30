package jspatcher

import (
	"fmt"
	"sort"
	"unicode/utf16"
)

// GeneratedPosition identifies a source-map segment in the generated bundle.
// Exact is false when only the preceding segment on the source line is known.
type GeneratedPosition struct {
	Line   int  `json:"line"`
	Column int  `json:"column"`
	Exact  bool `json:"exact"`
}

type sourceMapping struct{ sourceLine, sourceColumn, generatedLine, generatedColumn int }

func decodeSourceMappings(encoded string, sourceCount, baseLine, baseColumn int) (map[int][]sourceMapping, error) {
	result := make(map[int][]sourceMapping)
	// Valid segments preceding a malformed tail are still usable. Sort on every
	// exit because inverse lookups use binary search, including partial maps.
	defer func() {
		for source := range result {
			sort.SliceStable(result[source], func(i, j int) bool {
				a, b := result[source][i], result[source][j]
				if a.sourceLine != b.sourceLine {
					return a.sourceLine < b.sourceLine
				}
				return a.sourceColumn < b.sourceColumn
			})
		}
	}()
	line, column, source, sourceLine, sourceColumn, name := 0, 0, 0, 0, 0, 0
	segments := 0
	for at := 0; at < len(encoded); {
		switch encoded[at] {
		case ';':
			line++
			column = 0
			at++
			continue
		case ',':
			at++
			continue
		}
		var values [5]int
		count := 0
		for at < len(encoded) && encoded[at] != ';' && encoded[at] != ',' {
			if count == len(values) {
				return result, fmt.Errorf("source map segment has too many fields")
			}
			value, next, err := decodeSourceVLQ(encoded, at)
			if err != nil {
				return result, err
			}
			values[count], at = value, next
			count++
		}
		segments++
		if segments > 1_000_000 {
			return result, fmt.Errorf("source map mapping limit reached")
		}
		if count != 1 && count != 4 && count != 5 {
			return result, fmt.Errorf("source map segment has %d fields", count)
		}
		column += values[0]
		if column < 0 || column > 1<<30 {
			return result, fmt.Errorf("invalid generated source map column")
		}
		if count == 1 {
			continue
		}
		source += values[1]
		sourceLine += values[2]
		sourceColumn += values[3]
		if count == 5 {
			name += values[4]
		}
		if source < 0 || source >= sourceCount || sourceLine < 0 || sourceLine > 1<<30 || sourceColumn < 0 || sourceColumn > 1<<30 || name < 0 {
			return result, fmt.Errorf("source map segment refers to an invalid source position")
		}
		generatedColumn := column
		if line == 0 {
			generatedColumn += baseColumn
		}
		result[source] = append(result[source], sourceMapping{sourceLine, sourceColumn, baseLine + line, generatedColumn})
	}
	return result, nil
}

func decodeSourceVLQ(value string, at int) (int, int, error) {
	var decoded uint64
	shift := uint(0)
	for at < len(value) {
		ch := value[at]
		at++
		digit := -1
		switch {
		case ch >= 'A' && ch <= 'Z':
			digit = int(ch - 'A')
		case ch >= 'a' && ch <= 'z':
			digit = int(ch-'a') + 26
		case ch >= '0' && ch <= '9':
			digit = int(ch-'0') + 52
		case ch == '+':
			digit = 62
		case ch == '/':
			digit = 63
		}
		if digit < 0 || shift > 30 {
			return 0, at, fmt.Errorf("invalid or overflowing source map VLQ")
		}
		decoded |= uint64(digit&31) << shift
		if digit&32 == 0 {
			if decoded>>1 > 1<<30 {
				return 0, at, fmt.Errorf("source map VLQ exceeds position limit")
			}
			result := int(decoded >> 1)
			if decoded&1 != 0 {
				result = -result
			}
			return result, at, nil
		}
		shift += 5
	}
	return 0, at, fmt.Errorf("unterminated source map VLQ")
}

func mappedPositions(source mappedSource, line, byteColumn int, sourceLine string) []GeneratedPosition {
	column := 0
	for offset, r := range sourceLine {
		if offset >= byteColumn {
			break
		}
		if utf16.RuneLen(r) == 2 {
			column += 2
		} else {
			column++
		}
	}
	// Find the closest preceding source segment, preserving all generated uses
	// of that source location (a map need not be one-to-one).
	at := sort.Search(len(source.Mappings), func(i int) bool {
		m := source.Mappings[i]
		return m.sourceLine > line || (m.sourceLine == line && m.sourceColumn > column)
	}) - 1
	if at < 0 || source.Mappings[at].sourceLine != line {
		return nil
	}
	matchedColumn := source.Mappings[at].sourceColumn
	var positions []GeneratedPosition
	for at >= 0 && source.Mappings[at].sourceLine == line && source.Mappings[at].sourceColumn == matchedColumn {
		m := source.Mappings[at]
		positions = append(positions, GeneratedPosition{Line: m.generatedLine + 1, Column: m.generatedColumn, Exact: matchedColumn == column})
		at--
	}
	return positions
}
