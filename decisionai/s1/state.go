package s1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// LinearizeState turns a JSON state into text. A JSON string is used verbatim;
// objects become typed "path: value" lines so structured program state keeps its
// keys and types visible to the model.
func LinearizeState(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("state must be a JSON string or value: %v", err)
	}
	if s, ok := v.(string); ok {
		return s, nil
	}
	var lines []string
	walk(&lines, "", v, 0)
	return strings.Join(lines, "\n"), nil
}

func walk(lines *[]string, path string, v any, depth int) {
	if depth > 12 || len(*lines) > 4000 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			p := k
			if path != "" {
				p = path + "." + k
			}
			walk(lines, p, x[k], depth+1)
		}
	case []any:
		for i, e := range x {
			walk(lines, fmt.Sprintf("%s[%d]", path, i), e, depth+1)
		}
	case string:
		if strings.Contains(x, "\n") {
			*lines = append(*lines, path+":")
			for _, l := range strings.Split(x, "\n") {
				if strings.TrimSpace(l) != "" {
					*lines = append(*lines, "  "+l)
				}
			}
		} else {
			*lines = append(*lines, path+": "+x)
		}
	case bool:
		yn := "нет / false"
		if x {
			yn = "да / true"
		}
		*lines = append(*lines, path+": "+yn)
	case nil:
		*lines = append(*lines, path+": null (нет данных)")
	default:
		*lines = append(*lines, path+": "+fmt.Sprint(x))
	}
}

// Chunk splits state into overlapping windows of roughly maxWords words on sentence
// and line boundaries, so a short-context NLI model sees all of a long state.
// The result is capped at maxChunks (head and tail are kept preferentially).
func Chunk(state string, maxWords, maxChunks int) []string {
	sents := splitSentences(state)
	if len(sents) == 0 {
		return []string{strings.TrimSpace(state)}
	}
	var chunks []string
	var cur []string
	words := 0
	flush := func() {
		if len(cur) > 0 {
			chunks = append(chunks, strings.Join(cur, " "))
		}
	}
	for _, s := range sents {
		w := len(strings.Fields(s))
		if words+w > maxWords && len(cur) > 0 {
			flush()
			// one-sentence overlap keeps cross-sentence facts together
			last := cur[len(cur)-1]
			cur = []string{last}
			words = len(strings.Fields(last))
		}
		cur = append(cur, s)
		words += w
	}
	flush()
	if maxChunks > 0 && len(chunks) > maxChunks {
		head := chunks[:maxChunks/2]
		tail := chunks[len(chunks)-(maxChunks-maxChunks/2):]
		chunks = append(append([]string{}, head...), tail...)
	}
	return chunks
}

func splitSentences(s string) []string {
	var out []string
	var b strings.Builder
	rs := []rune(s)
	for i, r := range rs {
		if r == '\n' {
			if t := strings.TrimSpace(b.String()); t != "" {
				out = append(out, t)
			}
			b.Reset()
			continue
		}
		b.WriteRune(r)
		if (r == '.' || r == '!' || r == '?' || r == ';') && (i+1 == len(rs) || unicode.IsSpace(rs[i+1])) {
			if t := strings.TrimSpace(b.String()); t != "" {
				out = append(out, t)
			}
			b.Reset()
		}
	}
	if t := strings.TrimSpace(b.String()); t != "" {
		out = append(out, t)
	}
	return out
}
