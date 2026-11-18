package experts

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"decisionai/s1"
)

// ToolProperties recognises the effects of simple, explicitly described shell
// calls. It does not infer authorisation, task scope, or runtime safety.
type ToolProperties struct{}

func (ToolProperties) Name() string { return "tool-properties-rule" }

var (
	toolCallLine = regexp.MustCompile(`(?im)^\s*(?:proposed tool call|tool call|предлагаемый вызов|вызов инструмента)\s*:\s*(.+?)\s*$`)
	shellCall    = regexp.MustCompile(`^shell\(\s*("(?:\\.|[^"\\])*"|'[^'\\]*')\s*\)$`)
)

func (ToolProperties) Answer(state any, _ string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	if q.Type != s1.TypeNoul || q.Task != "" {
		return s1.ExpertAnswer{}, false
	}
	negative := false
	switch normalizedQuestion(q.Instr) {
	case "does the call only read data without changing anything", "is this tool call read only", "is the call read only", "вызов только читает данные ничего не изменяя", "этот вызов только читает данные":
	case "does the call change data", "does the call write data", "вызов изменяет данные", "вызов записывает данные":
		negative = true
	default:
		return s1.ExpertAnswer{}, false
	}
	// Arbitrary caller criteria can redefine the question; do not reinterpret them.
	for _, option := range q.Options {
		if strings.TrimSpace(option.Text) != "" {
			return s1.ExpertAnswer{}, false
		}
	}
	call := ""
	if _, value, ok := find(fields(state), "tool_call", "proposed_tool_call"); ok {
		call, _ = value.(string)
	} else if value, ok := state.(string); ok {
		matches := toolCallLine.FindAllStringSubmatch(value, 2)
		if len(matches) == 1 {
			call = matches[0][1]
		} else if len(matches) == 0 {
			call = strings.TrimSpace(value)
		}
	}
	match := shellCall.FindStringSubmatch(strings.TrimSpace(call))
	if match == nil {
		return s1.ExpertAnswer{}, false
	}
	command := match[1][1 : len(match[1])-1]
	if match[1][0] == '"' {
		if err := json.Unmarshal([]byte(match[1]), &command); err != nil {
			return s1.ExpertAnswer{}, false
		}
	}
	words, ok := simpleShellWords(command)
	if !ok {
		return s1.ExpertAnswer{}, false
	}
	readOnly, known := shellReadOnly(words)
	if !known {
		return s1.ExpertAnswer{}, false
	}
	probability := 0.04
	if readOnly != negative {
		probability = 0.96
	}
	detail := "Команда может изменять файлы, состояние репозитория или внешней системы."
	if readOnly {
		detail = "При стандартном исполнении команда только читает данные и выводит результат."
	}
	return s1.ExpertAnswer{Probs: []float64{probability}, Evidence: []string{call, detail}}, true
}

// This deliberately excludes shell composition, substitutions, redirection,
// environment assignments, and unknown wrappers. Quotes only group arguments.
func simpleShellWords(command string) ([]string, bool) {
	if len(command) > 8192 || strings.ContainsAny(command, "$`;&|<>\r\n") {
		return nil, false
	}
	var words []string
	var word strings.Builder
	var quote rune
	active := false
	for _, r := range command {
		if r == '\\' {
			return nil, false
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote, active = r, true
		case ' ', '\t':
			if active {
				words = append(words, word.String())
				word.Reset()
				active = false
			}
		default:
			word.WriteRune(r)
			active = true
		}
	}
	if quote != 0 {
		return nil, false
	}
	if active {
		words = append(words, word.String())
	}
	return words, len(words) > 0 && len(words) <= 64
}

func shellReadOnly(words []string) (bool, bool) {
	switch words[0] {
	case "df", "ls", "pwd", "uname", "stat", "wc", "cat", "head", "tail":
		return true, true
	case "rm", "mv", "cp", "mkdir", "rmdir", "touch", "truncate", "chmod", "chown":
		if len(words) < 2 {
			return false, false
		}
		for _, word := range words[1:] {
			if word == "--help" || word == "--version" {
				return true, true
			}
		}
		return false, true
	case "git":
		if len(words) < 2 {
			return false, false
		}
		switch words[1] {
		case "log":
			for i := 2; i < len(words); i++ {
				if words[i] == "--oneline" {
					continue
				}
				if words[i] == "-n" && i+1 < len(words) {
					if n, err := strconv.Atoi(words[i+1]); err == nil && n >= 0 {
						i++
						continue
					}
				}
				return false, false
			}
			return true, true
		case "add", "commit", "rm", "mv", "reset", "checkout", "switch", "clean", "stash", "apply", "cherry-pick", "rebase", "merge", "pull", "push", "fetch":
			for _, word := range words[2:] {
				if word == "--help" || word == "--dry-run" || word == "-n" {
					return false, false
				}
			}
			return false, true
		}
	}
	return false, false
}
