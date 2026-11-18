package main

import (
	"bufio"
	"strings"
)

// decodeKey keeps terminal escape sequences out of editable text. readable is
// used only to distinguish a lone Escape from the start of a key sequence.
func decodeKey(in *bufio.Reader, readable func() bool) (keyEvent, error) {
	r, _, err := in.ReadRune()
	if err != nil {
		return keyEvent{}, err
	}
	switch r {
	case '\r', '\n':
		return keyEvent{kind: keyEnter}, nil
	case '\t':
		return keyEvent{kind: keyTab}, nil
	case '\b', 0x7f:
		return keyEvent{kind: keyBackspace}, nil
	case 0x03:
		return keyEvent{kind: keyInterrupt}, nil
	case 0x1b:
		if in.Buffered() == 0 && !readable() {
			return keyEvent{kind: keyEsc}, nil
		}
		prefix, err := in.ReadByte()
		if err != nil {
			return keyEvent{}, err
		}
		if prefix != '[' && prefix != 'O' {
			_ = in.UnreadByte()
			return keyEvent{kind: keyEsc}, nil
		}
		var seq strings.Builder
		for seq.Len() < 32 {
			if in.Buffered() == 0 && !readable() {
				return keyEvent{kind: keyNone}, nil
			}
			b, err := in.ReadByte()
			if err != nil {
				return keyEvent{}, err
			}
			seq.WriteByte(b)
			if b >= 0x40 && b <= 0x7e {
				break
			}
		}
		s := seq.String()
		if prefix == '[' && s == "200~" {
			// Newlines in a clipboard payload must never submit the form.
			const end = "\x1b[201~"
			var pasted strings.Builder
			pending := ""
			for {
				b, err := in.ReadByte()
				if err != nil {
					return keyEvent{}, err
				}
				pending += string([]byte{b})
				for !strings.HasPrefix(end, pending) {
					pasted.WriteByte(pending[0])
					pending = pending[1:]
				}
				if pending == end {
					return keyEvent{kind: keyPaste, text: pasted.String()}, nil
				}
			}
		}
		keys := map[string]keyKind{
			"A": keyUp, "B": keyDown, "C": keyRight, "D": keyLeft,
			"H": keyHome, "F": keyEnd, "1~": keyHome, "7~": keyHome,
			"4~": keyEnd, "8~": keyEnd, "3~": keyDelete,
			"5~": keyPgUp, "6~": keyPgDn, "Z": keyShiftTab,
			"P": keyF1, "11~": keyF1,
		}
		if kind, ok := keys[s]; ok {
			return keyEvent{kind: kind}, nil
		}
		return keyEvent{kind: keyNone}, nil
	default:
		return keyEvent{kind: keyChar, r: r}, nil
	}
}
