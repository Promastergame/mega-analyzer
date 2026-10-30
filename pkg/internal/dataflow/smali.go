package dataflow

import (
	"strconv"
	"strings"
)

type invokeCall struct {
	opcode    string
	signature string
	registers []string
	params    string
	isStatic  bool
}

func parseInvoke(line string) (invokeCall, bool) {
	line = stripSmaliComment(line)
	if !strings.HasPrefix(line, "invoke-") {
		return invokeCall{}, false
	}
	space := strings.IndexAny(line, " \t")
	open, close := strings.IndexByte(line, '{'), strings.IndexByte(line, '}')
	arrow := strings.Index(line, "->")
	if space < 0 || open < 0 || close < open || arrow < close {
		return invokeCall{}, false
	}
	classStart := strings.Index(line[close:], "L")
	if classStart < 0 {
		return invokeCall{}, false
	}
	classStart += close
	paren := strings.IndexByte(line[arrow:], '(')
	if paren < 0 {
		return invokeCall{}, false
	}
	paren += arrow
	parenClose := strings.IndexByte(line[paren:], ')')
	if parenClose < 0 {
		return invokeCall{}, false
	}
	parenClose += paren
	registers := parseRegisterList(line[open+1 : close])
	opcode := strings.TrimSpace(line[:space])
	return invokeCall{
		opcode:    opcode,
		signature: strings.TrimSpace(line[classStart:]),
		registers: registers,
		params:    line[paren+1 : parenClose],
		isStatic:  strings.HasPrefix(opcode, "invoke-static"),
	}, true
}

func parseRegisterList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if parts := strings.Split(value, ".."); len(parts) == 2 {
		start, end := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if len(start) >= 2 && len(end) >= 2 && start[0] == end[0] {
			first, err1 := strconv.Atoi(start[1:])
			last, err2 := strconv.Atoi(end[1:])
			// Fmt3rc encodes an unsigned byte register count (up to 255).
			// Bound both the count and register IDs before allocating.
			if err1 == nil && err2 == nil && first >= 0 && last >= first && last <= 65535 && last-first < 255 {
				result := make([]string, 0, last-first+1)
				for i := first; i <= last; i++ {
					result = append(result, string(start[0])+strconv.Itoa(i))
				}
				return result
			}
		}
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if register := strings.TrimSpace(part); register != "" {
			result = append(result, register)
		}
	}
	return result
}

func parameterWidths(descriptor string) []int {
	widths := make([]int, 0, 8)
	for i := 0; i < len(descriptor); {
		start := i
		for i < len(descriptor) && descriptor[i] == '[' {
			i++
		}
		if i >= len(descriptor) {
			break
		}
		if descriptor[i] == 'L' {
			end := strings.IndexByte(descriptor[i:], ';')
			if end < 0 {
				break
			}
			i += end + 1
			widths = append(widths, 1)
			continue
		}
		wide := i == start && (descriptor[i] == 'J' || descriptor[i] == 'D')
		i++
		if wide {
			widths = append(widths, 2)
		} else {
			widths = append(widths, 1)
		}
	}
	return widths
}
