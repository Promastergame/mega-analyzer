package semai

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var wordOps = strings.NewReplacer(
	"умноженное на", "*", "умножить на", "*", "помножить на", "*", "умножь на", "*", " multiplied by ", "*", " times ", "*",
	"разделить на", "/", "поделить на", "/", "деленное на", "/", "разделенное на", "/", " divided by ", "/", " over ", "/",
	"в степени", "^", " to the power of ", "^", " plus ", "+", "плюс", "+", " minus ", "-", "минус", "-",
)
var exprRE = regexp.MustCompile(`[\d(][\d\s.,+\-*/^():x×х%]*[\d)]`)
var arithTrigger = map[string]bool{"сколько": true, "будет": true, "равно": true, "чему": true, "посчитай": true, "вычисли": true, "результат": true, "what": true, "calculate": true, "compute": true, "equal": true, "equals": true, "is": true, "how": true, "much": true, "answer": true, "ответ": true, "получится": true, "найди": true, "значение": true, "выражения": true, "выражение": true, "примера": true, "пример": true}

type ap struct {
	toks         []string
	i            int
	implicitHigh bool
	juxt         bool
	err          string
}

func lexExpr(s string) []string {
	var out []string
	rs := []rune(s)
	for i := 0; i < len(rs); {
		r := rs[i]
		switch {
		case r >= '0' && r <= '9' || r == '.':
			j := i
			for j < len(rs) && (rs[j] >= '0' && rs[j] <= '9' || rs[j] == '.') {
				j++
			}
			out = append(out, string(rs[i:j]))
			i = j
		case strings.ContainsRune("+-*/^()", r):
			out = append(out, string(r))
			i++
		default:
			i++
		}
	}
	return out
}

func (p *ap) peek() string {
	if p.i < len(p.toks) {
		return p.toks[p.i]
	}
	return ""
}
func (p *ap) expr() float64 {
	v := p.term()
	for p.peek() == "+" || p.peek() == "-" {
		op := p.toks[p.i]
		p.i++
		r := p.term()
		if op == "+" {
			v += r
		} else {
			v -= r
		}
	}
	return v
}
func (p *ap) startsAtom() bool {
	t := p.peek()
	return t == "(" || (t != "" && (t[0] >= '0' && t[0] <= '9' || t[0] == '.'))
}
func (p *ap) term() float64 {
	v := p.factor()
	for {
		t := p.peek()
		switch {
		case t == "*" || t == "/":
			p.i++
			r := p.factor()
			if t == "*" {
				v *= r
			} else if r == 0 {
				p.err = "деление на ноль"
				return 0
			} else {
				v /= r
			}
		case t == "(" && !p.implicitHigh:
			p.juxt = true
			v *= p.factor()
		default:
			return v
		}
	}
}

// factor handles juxtaposition "2(3+4)" as tighter-than-division when implicitHigh.
func (p *ap) factor() float64 {
	v := p.power()
	for p.implicitHigh && p.peek() == "(" {
		p.juxt = true
		v *= p.power()
	}
	return v
}
func (p *ap) power() float64 {
	b := p.unary()
	if p.peek() == "^" {
		p.i++
		return math.Pow(b, p.power())
	}
	return b
}
func (p *ap) unary() float64 {
	switch p.peek() {
	case "-":
		p.i++
		return -p.unary()
	case "+":
		p.i++
		return p.unary()
	case "(":
		p.i++
		v := p.expr()
		if p.peek() != ")" {
			p.err = "нет закрывающей скобки"
			return 0
		}
		p.i++
		return v
	}
	t := p.peek()
	if t == "" {
		p.err = "неожиданный конец выражения"
		return 0
	}
	v, e := strconv.ParseFloat(t, 64)
	if e != nil {
		p.err = "не число: " + t
		return 0
	}
	p.i++
	return v
}

func evalExpr(toks []string, implicitHigh bool) (v float64, juxt bool, err string) {
	p := &ap{toks: toks, implicitHigh: implicitHigh}
	v = p.expr()
	if p.err == "" && p.i != len(toks) {
		p.err = "лишние символы"
	}
	return v, p.juxt, p.err
}

// solveArithmetic evaluates a plain arithmetic question. When implicit multiplication follows a division
// ("6/2(1+2)") the two accepted conventions disagree, and both are returned as separate readings.
func solveArithmetic(stemText string) *outcome {
	s := " " + normText(stemText) + " "
	s = wordOps.Replace(s)
	s = regexp.MustCompile(`(\d)\s*[xх]\s*(\d)`).ReplaceAllString(s, "$1*$2")
	s = regexp.MustCompile(`(\d):(\d)`).ReplaceAllString(s, "$1/$2")
	s = regexp.MustCompile(`(\d),(\d)`).ReplaceAllString(s, "$1.$2")
	loc := exprRE.FindAllStringIndex(s, -1)
	best := []int(nil)
	for _, l := range loc {
		if best == nil || l[1]-l[0] > best[1]-best[0] {
			best = l
		}
	}
	if best == nil {
		return nil
	}
	expr := s[best[0]:best[1]]
	if !strings.ContainsAny(expr, "+-*/^") {
		return nil
	}
	rest := strings.TrimSpace(s[:best[0]] + " " + s[best[1]:])
	for _, t := range tokens(rest) {
		if isWord(t) && !arithTrigger[t] && !stopWords[t] {
			return nil
		}
	}
	toks := lexExpr(expr)
	nNum := 0
	for _, t := range toks {
		if t[0] >= '0' && t[0] <= '9' || t[0] == '.' {
			nNum++
		}
	}
	if nNum < 2 {
		return nil
	}
	pretty := strings.Join(toks, " ")
	out := &outcome{Solver: "arithmetic", Certainty: 1}
	v1, j1, e1 := evalExpr(toks, true)
	if e1 != "" {
		out.Failure = "Выражение «" + pretty + "» не удалось вычислить: " + e1 + "."
		return out
	}
	v2, _, _ := evalExpr(toks, false)
	if j1 && math.Abs(v1-v2) > 1e-9 {
		out.Readings = []reading{
			{ID: "juxt_high", Title: "Неявное умножение сильнее деления", Detail: fmt.Sprintf("%s = %s (2(1+2) считается одним множителем)", pretty, fmtNum(round9(v1))), W: .5, Val: round9(v1)},
			{ID: "left_to_right", Title: "Строго слева направо", Detail: fmt.Sprintf("%s = %s (умножение и деление равноправны)", pretty, fmtNum(round9(v2))), W: .5, Val: round9(v2)},
		}
		out.Notes = append(out.Notes, "Запись без знака умножения после деления читается по-разному в разных конвенциях.")
		return out
	}
	out.Readings = []reading{{ID: "eval", Title: "Порядок действий", Detail: fmt.Sprintf("%s = %s", pretty, fmtNum(round9(v1))), W: 1, Val: round9(v1)}}
	return out
}
func round9(v float64) float64 { return math.Round(v*1e9) / 1e9 }
