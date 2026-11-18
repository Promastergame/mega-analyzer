package main

import (
	"strings"
	"unicode"
)

// textEdit is shared by the home target field and setting value editors.
type textEdit struct {
	text   string
	cursor int // rune offset
}

func newTextEdit(s string) textEdit {
	return textEdit{text: s, cursor: len([]rune(s))}
}

func (e *textEdit) handleKey(ev keyEvent, intOnly bool) bool {
	buf := []rune(e.text)
	if e.cursor < 0 || e.cursor > len(buf) {
		e.cursor = len(buf)
	}
	insert := func(s string) {
		var rs []rune
		for _, r := range s {
			if unicode.IsControl(r) || (intOnly && (r < '0' || r > '9') && r != '-') {
				continue
			}
			rs = append(rs, r)
		}
		next := append([]rune(nil), buf[:e.cursor]...)
		next = append(next, rs...)
		next = append(next, buf[e.cursor:]...)
		buf = next
		e.cursor += len(rs)
	}
	switch ev.kind {
	case keyLeft:
		if e.cursor > 0 {
			e.cursor--
		}
	case keyRight:
		if e.cursor < len(buf) {
			e.cursor++
		}
	case keyHome:
		e.cursor = 0
	case keyEnd:
		e.cursor = len(buf)
	case keyBackspace:
		if e.cursor > 0 {
			buf = append(buf[:e.cursor-1], buf[e.cursor:]...)
			e.cursor--
		}
	case keyDelete:
		if e.cursor < len(buf) {
			buf = append(buf[:e.cursor], buf[e.cursor+1:]...)
		}
	case keyPaste:
		insert(ev.text)
	case keyChar:
		switch ev.r {
		case 0x01:
			e.cursor = 0 // Ctrl+A
		case 0x05:
			e.cursor = len(buf) // Ctrl+E
		case 0x15:
			buf = nil
			e.cursor = 0 // Ctrl+U
		case 0x17: // Ctrl+W deletes the previous word
			end := e.cursor
			for e.cursor > 0 && unicode.IsSpace(buf[e.cursor-1]) {
				e.cursor--
			}
			for e.cursor > 0 && !unicode.IsSpace(buf[e.cursor-1]) {
				e.cursor--
			}
			buf = append(buf[:e.cursor], buf[end:]...)
		default:
			if unicode.IsControl(ev.r) {
				return false
			}
			insert(string(ev.r))
		}
	default:
		return false
	}
	e.text = string(buf)
	return true
}

// view scrolls horizontally around the cursor without modifying the value.
func (e textEdit) view(width int, th Theme) string {
	if width < 1 {
		return ""
	}
	buf := []rune(e.text)
	pos := e.cursor
	if pos < 0 || pos > len(buf) {
		pos = len(buf)
	}
	start := 0
	for start < pos && visibleLen(string(buf[start:pos]))+1 > width-1 {
		start++
	}
	left := ""
	if start > 0 {
		left = "…"
	}
	before := string(buf[start:pos])
	remaining := width - visibleLen(left+before) - 1
	after := ""
	if remaining > 0 {
		after = truncateVisible(string(buf[pos:]), remaining)
	}
	return th.Muted + left + th.Reset + th.Text + before + th.Reset + th.Primary + th.Bold + "▮" + th.Reset + th.Text + after + th.Reset
}

func cleanTUIPath(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		s = s[1 : len(s)-1]
	}
	// Some shells paste /F:\... for a Windows drive path.
	if len(s) > 3 && s[0] == '/' && s[2] == ':' && (s[3] == '\\' || s[3] == '/') {
		s = s[1:]
	}
	return s
}
