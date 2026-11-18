package semai

import (
	"regexp"
	"strings"
)

// Option is one answer choice of a multiple-choice question.
type Option struct {
	Label     string   `json:"label"`
	Text      string   `json:"text"`
	Value     *float64 `json:"value,omitempty"`
	IsUnknown bool     `json:"is_unknown_option,omitempty"`
}

var markerRE = regexp.MustCompile(`(^|[\s\[,;])\(?([A-Fa-fА-Еа-е]|[1-9])([).:])`)
var alphabets = []string{"ABCDEF", "АБВГДЕ", "АВСДЕФ"}

func labelIndex(label, alpha string) int {
	l := strings.ToUpper(label)
	for i, r := range []rune(alpha) {
		if string(r) == l {
			return i
		}
	}
	return -1
}

var unknownOptRE = regexp.MustCompile(`(?i)(невозможно|нельзя|не (?:ясно|известно|определ|знаю|хватает|достаточно)|неизвестн|не определ|неопредел|недостаточно|нет (?:правильного|ответа)|unknown|cannot be (?:determined|known)|can't (?:be )?(?:determine|tell)|not enough|insufficient|ambiguous|неоднознач|unc?nown|uncown)`)

// ParseChoices splits "stem + options" text. Explicit options (if given) win over markers found in the text.
func ParseChoices(q string, explicit []string) (stemText string, opts []Option) {
	if len(explicit) >= 2 {
		stemText = strings.TrimSpace(q)
		for i, t := range explicit {
			opts = append(opts, mkOption(string(rune('A'+i)), t))
		}
		return
	}
	ms := markerRE.FindAllStringSubmatchIndex(q, -1)
	type mk struct {
		start, end int
		label      string
		punct      string
	}
	var marks []mk
	for _, m := range ms {
		// m[4:6] label, m[6:8] punct, m[0]+len(group1) start of marker
		start := m[2*1+1] // end of group 1 = start of marker
		label, punct := q[m[4]:m[5]], q[m[6]:m[7]]
		end := m[1]
		if label[0] >= '1' && label[0] <= '9' {
			// digits need ")" or ". " to avoid decimals like 3.5
			if punct == ":" || (punct == "." && !(end < len(q) && (q[end] == ' ' || q[end] == '\n'))) {
				continue
			}
		}
		marks = append(marks, mk{start, end, label, punct})
	}
	for _, alpha := range append([]string{"123456789"}, alphabets...) {
		for s := 0; s < len(marks); s++ {
			idx := func(l string) int {
				if alpha == "123456789" {
					if l[0] >= '1' && l[0] <= '9' {
						return int(l[0] - '1')
					}
					return -1
				}
				return labelIndex(l, alpha)
			}
			if idx(marks[s].label) != 0 {
				continue
			}
			chain := []mk{marks[s]}
			for t := s + 1; t < len(marks); t++ {
				if idx(marks[t].label) == len(chain) {
					chain = append(chain, marks[t])
				}
			}
			if len(chain) < 2 {
				continue
			}
			stemText = strings.TrimSpace(q[:chain[0].start])
			for i, c := range chain {
				to := len(q)
				if i+1 < len(chain) {
					to = chain[i+1].start
				}
				opts = append(opts, mkOption(string(rune('A'+i)), strings.Trim(strings.TrimSpace(q[c.end:to]), ",;")))
			}
			return
		}
	}
	return strings.TrimSpace(q), nil
}

func mkOption(label, text string) Option {
	text = strings.TrimSpace(text)
	o := Option{Label: label, Text: text}
	if unknownOptRE.MatchString(text) {
		o.IsUnknown = true
		return o
	}
	if ns := FindNumbers(tokens(text)); len(ns) == 1 {
		v := ns[0].Val
		o.Value = &v
	}
	return o
}
