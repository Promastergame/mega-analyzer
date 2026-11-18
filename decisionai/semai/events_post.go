package semai

import (
	"fmt"
	"regexp"
	"strings"
)

// Post operations: «…, делённое на 2», «умноженное на 3» — действие над итоговым числом,
// а не шаг истории. Такой шаг убирается из графа событий и применяется к ответу.

type postOp struct {
	op   string // div | mul
	n    float64
	text string
}

var (
	postWord     = `(раздел\S*|подел\S*|дел[её]н\S*|умнож\S*)`
	postClauseRe = regexp.MustCompile(`^(?:(?:и|а|потом|затем|вс[её]|это|результат|сумма|итог|всё это|все это)\s+)*` + postWord + `\s+на(?:\s|$)`)
	postQRe      = regexp.MustCompile(postWord + `\s+на\s+(\d+(?:[.,]\d+)?)`)
)

func postKind(w string) string {
	if strings.HasPrefix(w, "умнож") {
		return "mul"
	}
	return "div"
}

// takePostOps removes «делённое на N» steps from the story and also reads them from the question.
func takePostOps(clauses []EventClause, question string) ([]EventClause, []postOp) {
	var out []EventClause
	var post []postOp
	for _, c := range clauses {
		t := strings.ToLower(strings.TrimSpace(c.Text))
		if c.HasNum && c.Amount != 0 {
			if m := postClauseRe.FindStringSubmatch(t); m != nil {
				post = append(post, postOp{postKind(m[1]), c.Amount, c.Text})
				continue
			}
		}
		out = append(out, c)
	}
	for _, m := range postQRe.FindAllStringSubmatch(strings.ToLower(question), -1) {
		var n float64
		if _, err := fmt.Sscan(strings.Replace(m[2], ",", ".", 1), &n); err == nil && n != 0 {
			post = append(post, postOp{postKind(m[1]), n, m[0]})
		}
	}
	return out, post
}

// applyPost applies the post operations to the final number and explains each one.
func applyPost(v float64, post []postOp, reason *[]string) float64 {
	for _, p := range post {
		old, sym := v, "÷"
		if p.op == "mul" {
			v *= p.n
			sym = "×"
		} else {
			v /= p.n
		}
		*reason = append(*reason, fmt.Sprintf("«%s» — действие над итогом, а не шаг истории: %s %s %s = %s", p.text, trimNum(old), sym, trimNum(p.n), trimNum(v)))
	}
	return v
}
