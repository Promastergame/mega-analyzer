package minecraft

import "strings"

// Only a top-level command or the terminal command of modern execute ... run
// is considered. In particular, "say run op Alice" is just chat text.
func privilegedCommand(line string) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "#") {
		return ""
	}
	line = strings.TrimPrefix(line, "/")
	for depth := 0; depth < 32; depth++ {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return ""
		}
		word := strings.TrimPrefix(fields[0], "minecraft:")
		switch word {
		case "op", "deop", "stop", "ban", "ban-ip", "pardon", "pardon-ip", "whitelist":
			return word
		case "execute":
			pos := executeRun(line)
			if pos < 0 {
				return ""
			}
			line = strings.TrimSpace(line[pos:])
		default:
			return ""
		}
	}
	return ""
}

// Locate an unquoted run token outside selectors/NBT. This is a bounded lexer,
// not a complete Minecraft command grammar or execution/reachability analysis.
func executeRun(line string) int {
	var quote byte
	escaped := false
	nesting := 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '[' || c == '{' {
			nesting++
		} else if c == ']' || c == '}' {
			if nesting > 0 {
				nesting--
			}
		}
		space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
		if nesting == 0 && strings.HasPrefix(line[i:], "run") && i > 0 && space(line[i-1]) && (i+3 == len(line) || space(line[i+3])) {
			return i + 3
		}
	}
	return -1
}
