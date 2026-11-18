package experts

// Exact expression engine for the math expert (v1.18): school order of operations,
// fractions, percents, powers, roots, logarithms, factorials, combinatorics,
// comparisons and boolean algebra. Every operation is recorded as a step, so the
// answer can show *how* it was computed: 2 + 2·2 → 2·2 = 4 → 2 + 4 = 6.
//
// Precedence (lowest → highest):
//   → (implication)  |  or   xor   &  and   not
//   comparisons  < > <= >= = !=   (chains: 1 < x < 3)
//   + -      * / mod (and implicit 2x, 2(3+4))
//   unary -  ^ ** (right-assoc)  postfix ! % °   (…)  functions

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type tok struct {
	k   byte // 'n' number, 'i' ident, 'o' operator, '(' ')' ',' , 'x' break
	s   string
	v   float64
	dec int // digits after the decimal point in the literal
}

type node struct {
	op   string // "num" "var" "call" or operator
	v    float64
	name string
	args []*node
	raw  string
}

var mathFuncs = map[string]int{"sqrt": 1, "cbrt": 1, "ln": 1, "lg": 1, "log": -1, "log2": 1, "log10": 1, "abs": 1, "exp": 1,
	"sin": 1, "cos": 1, "tan": 1, "tg": 1, "ctg": 1, "cot": 1, "floor": 1, "ceil": 1, "round": 1, "fact": 1,
	"gcd": 2, "lcm": 2, "comb": 2, "binom": 2, "perm": 2, "min": -1, "max": -1, "pow": 2}

var mathConsts = map[string]float64{"pi": math.Pi, "e": math.E}

func isOperandStart(t tok) bool { return t.k == 'n' || t.k == 'i' || t.k == '(' }

// tokenize splits normalised text into math tokens; anything else becomes a break.
func tokenize(s string) []tok {
	r := []rune(s)
	var out []tok
	var parens []bool // true = function-call parenthesis (commas separate arguments there)
	for i := 0; i < len(r); {
		c := r[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case unicode.IsDigit(c) || c == '.' && i+1 < len(r) && unicode.IsDigit(r[i+1]):
			j := i
			for j < len(r) && unicode.IsDigit(r[j]) {
				j++
			}
			dec := 0
			if j+1 < len(r) && (r[j] == '.' || r[j] == ',' && !(len(parens) > 0 && parens[len(parens)-1])) && unicode.IsDigit(r[j+1]) {
				k := j + 1
				for k < len(r) && unicode.IsDigit(r[k]) {
					k++
				}
				dec = k - j - 1
				j = k
			}
			lit := strings.ReplaceAll(string(r[i:j]), ",", ".")
			v, _ := strconv.ParseFloat(lit, 64)
			out = append(out, tok{k: 'n', s: lit, v: v, dec: dec})
			i = j
		case c < 128 && (unicode.IsLetter(c) || c == '_'):
			j := i
			for j < len(r) && r[j] < 128 && (unicode.IsLetter(r[j]) || unicode.IsDigit(r[j]) || r[j] == '_') {
				j++
			}
			out = append(out, tok{k: 'i', s: string(r[i:j])})
			i = j
		case c == '(' || c == '[':
			fn := len(out) > 0 && out[len(out)-1].k == 'i' && mathFuncs[out[len(out)-1].s] != 0 || len(out) > 0 && out[len(out)-1].k == 'i' && (out[len(out)-1].s == "c" || strings.HasPrefix(out[len(out)-1].s, "log_"))
			parens = append(parens, fn)
			out = append(out, tok{k: '(', s: "("})
			i++
		case c == ')' || c == ']':
			if len(parens) > 0 {
				parens = parens[:len(parens)-1]
			}
			out = append(out, tok{k: ')', s: ")"})
			i++
		case c == ',' || c == ';':
			out = append(out, tok{k: ',', s: ","})
			i++
		default:
			two := ""
			if i+1 < len(r) {
				two = string(r[i : i+2])
			}
			switch two {
			case "<=", ">=", "!=", "==", "**", "&&", "||", "->", "<>":
				if two == "<>" {
					two = "!="
				}
				out = append(out, tok{k: 'o', s: two})
				i += 2
				continue
			}
			if strings.ContainsRune("+-*/^%!<>=&|°", c) {
				out = append(out, tok{k: 'o', s: string(c)})
			} else {
				out = append(out, tok{k: 'x', s: string(c)})
			}
			i++
		}
	}
	return out
}

type parser struct {
	t     []tok
	p     int
	nops  int  // explicit operators and functions seen
	alg   bool // split unknown latin words into single-letter variables (ab → a·b)
	nfunc int
}

func (ps *parser) peek() tok {
	if ps.p < len(ps.t) {
		return ps.t[ps.p]
	}
	return tok{k: 0}
}
func (ps *parser) isOp(s ...string) bool {
	t := ps.peek()
	if t.k != 'o' && t.k != 'i' {
		return false
	}
	for _, x := range s {
		if t.s == x {
			return true
		}
	}
	return false
}

func parseTokens(t []tok, alg bool) (*node, int, error) {
	ps := &parser{t: t, alg: alg}
	n, err := ps.impl()
	if err != nil {
		return nil, 0, err
	}
	if ps.p != len(t) {
		return nil, 0, fmt.Errorf("лишнее после выражения")
	}
	return n, ps.nops, nil
}

func (ps *parser) bin(op string, a, b *node) *node {
	ps.nops++
	return &node{op: op, args: []*node{a, b}}
}

func (ps *parser) impl() (*node, error) {
	a, err := ps.or()
	if err != nil {
		return nil, err
	}
	if ps.isOp("->") {
		ps.p++
		b, err := ps.impl()
		if err != nil {
			return nil, err
		}
		return ps.bin("->", a, b), nil
	}
	return a, nil
}
func (ps *parser) or() (*node, error) {
	a, err := ps.xor()
	for err == nil && ps.isOp("|", "||", "or") {
		ps.p++
		var b *node
		if b, err = ps.xor(); err == nil {
			a = ps.bin("or", a, b)
		}
	}
	return a, err
}
func (ps *parser) xor() (*node, error) {
	a, err := ps.and()
	for err == nil && ps.isOp("xor") {
		ps.p++
		var b *node
		if b, err = ps.and(); err == nil {
			a = ps.bin("xor", a, b)
		}
	}
	return a, err
}
func (ps *parser) and() (*node, error) {
	a, err := ps.not()
	for err == nil && ps.isOp("&", "&&", "and") {
		ps.p++
		var b *node
		if b, err = ps.not(); err == nil {
			a = ps.bin("and", a, b)
		}
	}
	return a, err
}
func (ps *parser) not() (*node, error) {
	if ps.isOp("!", "not") {
		ps.p++
		ps.nops++
		a, err := ps.not()
		if err != nil {
			return nil, err
		}
		return &node{op: "not", args: []*node{a}}, nil
	}
	return ps.cmp()
}

var cmpOps = []string{"<", ">", "<=", ">=", "=", "==", "!="}

func (ps *parser) cmp() (*node, error) {
	a, err := ps.sum()
	if err != nil {
		return nil, err
	}
	var chain *node
	for ps.isOp(cmpOps...) {
		op := ps.peek().s
		if op == "==" {
			op = "="
		}
		ps.p++
		b, err := ps.sum()
		if err != nil {
			return nil, err
		}
		c := ps.bin(op, a, b)
		if chain == nil {
			chain = c
		} else {
			chain = &node{op: "and", args: []*node{chain, c}}
		}
		a = b
	}
	if chain != nil {
		return chain, nil
	}
	return a, nil
}
func (ps *parser) sum() (*node, error) {
	a, err := ps.term()
	for err == nil && ps.isOp("+", "-") {
		op := ps.peek().s
		ps.p++
		var b *node
		if b, err = ps.term(); err == nil {
			a = ps.bin(op, a, b)
		}
	}
	return a, err
}
func (ps *parser) term() (*node, error) {
	a, err := ps.unary()
	for err == nil {
		if ps.isOp("*", "/", "mod") || ps.isOp("%") && ps.p+1 < len(ps.t) && isOperandStart(ps.t[ps.p+1]) {
			op := ps.peek().s
			if op == "%" {
				op = "mod"
			}
			ps.p++
			var b *node
			if b, err = ps.unary(); err == nil {
				a = ps.bin(op, a, b)
			}
			continue
		}
		// implicit multiplication: 2x, 2(3+4), (a+b)(a-b), 2 sqrt 3 — never number·number
		nx := ps.peek()
		prevNum := ps.p > 0 && ps.t[ps.p-1].k == 'n'
		if nx.k == '(' || nx.k == 'i' && !isWordOp(nx.s) || nx.k == 'n' && !prevNum && ps.p > 0 && ps.t[ps.p-1].k == ')' {
			save := ps.p
			b, e2 := ps.unary()
			if e2 != nil {
				ps.p = save
				return a, nil
			}
			a = &node{op: "*", args: []*node{a, b}}
			continue
		}
		break
	}
	return a, err
}

func isWordOp(s string) bool {
	switch s {
	case "and", "or", "xor", "not", "mod":
		return true
	}
	return false
}

func (ps *parser) unary() (*node, error) {
	if ps.isOp("-") {
		ps.p++
		a, err := ps.unary()
		if err != nil {
			return nil, err
		}
		return &node{op: "neg", args: []*node{a}}, nil
	}
	if ps.isOp("+") {
		ps.p++
		return ps.unary()
	}
	return ps.power()
}
func (ps *parser) power() (*node, error) {
	a, err := ps.postfix()
	if err != nil {
		return nil, err
	}
	if ps.isOp("^", "**") {
		ps.p++
		b, err := ps.unary()
		if err != nil {
			return nil, err
		}
		return ps.bin("^", a, b), nil
	}
	return a, nil
}
func (ps *parser) postfix() (*node, error) {
	a, err := ps.primary()
	if err != nil {
		return nil, err
	}
	for {
		switch {
		case ps.isOp("!"):
			ps.p++
			ps.nops++
			a = &node{op: "!", args: []*node{a}}
		case ps.isOp("%") && !(ps.p+1 < len(ps.t) && isOperandStart(ps.t[ps.p+1])):
			ps.p++
			ps.nops++
			a = &node{op: "%", args: []*node{a}}
		case ps.isOp("°"):
			ps.p++
			a = &node{op: "°", args: []*node{a}}
		default:
			return a, nil
		}
	}
}

func (ps *parser) primary() (*node, error) {
	t := ps.peek()
	switch t.k {
	case 'n':
		ps.p++
		return &node{op: "num", v: t.v, raw: t.s}, nil
	case '(':
		ps.p++
		a, err := ps.impl()
		if err != nil {
			return nil, err
		}
		if ps.peek().k != ')' {
			return nil, fmt.Errorf("нет закрывающей скобки")
		}
		ps.p++
		return &node{op: "()", args: []*node{a}}, nil
	case 'i':
		name := t.s
		ps.p++
		base := ""
		if strings.HasPrefix(name, "log_") {
			base, name = name[4:], "log"
		}
		if ar, ok := mathFuncs[name]; ok || name == "c" && ps.peek().k == '(' {
			if name == "c" {
				name, ar = "comb", 2
			}
			ps.nops++
			var args []*node
			if base != "" {
				f, err := strconv.ParseFloat(base, 64)
				if err != nil {
					return nil, fmt.Errorf("основание логарифма")
				}
				args = append(args, &node{op: "num", v: f, raw: base})
			}
			if ps.peek().k == '(' {
				ps.p++
				for {
					a, err := ps.impl()
					if err != nil {
						return nil, err
					}
					args = append(args, a)
					if ps.peek().k == ',' {
						ps.p++
						continue
					}
					break
				}
				if ps.peek().k != ')' {
					return nil, fmt.Errorf("нет закрывающей скобки")
				}
				ps.p++
			} else {
				a, err := ps.power() // sqrt 16, sqrt 2^2 → sqrt(2^2)
				if err != nil {
					return nil, err
				}
				args = append(args, a)
			}
			if ar > 0 && len(args) != ar || name == "log" && len(args) != 2 || len(args) == 0 {
				return nil, fmt.Errorf("%s: неверное число аргументов", name)
			}
			return &node{op: "call", name: name, args: args}, nil
		}
		if _, ok := mathConsts[name]; ok {
			return &node{op: "var", name: name}, nil
		}
		if len(name) == 1 {
			return &node{op: "var", name: name}, nil
		}
		if ps.alg && regexp.MustCompile(`^[a-z]+$`).MatchString(name) && len(name) <= 4 {
			var n *node
			for _, c := range name {
				v := &node{op: "var", name: string(c)}
				if n == nil {
					n = v
				} else {
					n = &node{op: "*", args: []*node{n, v}}
				}
			}
			return n, nil
		}
		return nil, fmt.Errorf("неизвестное слово %s", name)
	}
	return nil, fmt.Errorf("ожидалось число")
}

// ---------- evaluation with steps ----------

type evalCtx struct {
	env   map[string]float64
	steps []string
	trace bool
	err   error
}

func (n *node) vars(out map[string]bool) {
	if n.op == "var" {
		if _, c := mathConsts[n.name]; !c {
			out[n.name] = true
		}
	}
	for _, a := range n.args {
		a.vars(out)
	}
}

func (n *node) isBool() bool {
	switch n.op {
	case "<", ">", "<=", ">=", "=", "!=", "and", "or", "xor", "not", "->":
		return true
	case "()":
		return n.args[0].isBool()
	}
	return false
}

func fact(x float64) float64 {
	if x < 0 || x != math.Trunc(x) || x > 170 {
		return math.NaN()
	}
	r := 1.0
	for i := 2.0; i <= x; i++ {
		r *= i
	}
	return r
}
func comb(n, k float64) float64 {
	if k < 0 || n < 0 || k > n || n != math.Trunc(n) || k != math.Trunc(k) {
		return math.NaN()
	}
	r := 1.0
	for i := 1.0; i <= k; i++ {
		r = r * (n - k + i) / i
	}
	return math.Round(r)
}
func gcd(a, b float64) float64 {
	a, b = math.Abs(a), math.Abs(b)
	for b > 0.5 {
		a, b = b, math.Mod(a, b)
	}
	return a
}
func feq(a, b float64) bool {
	return math.Abs(a-b) <= 1e-9*math.Max(1, math.Max(math.Abs(a), math.Abs(b)))
}
func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (c *evalCtx) step(format string, a ...any) {
	if c.trace && len(c.steps) < 12 {
		c.steps = append(c.steps, fmt.Sprintf(format, a...))
	}
}

func (c *evalCtx) eval(n *node) float64 {
	if c.err != nil {
		return math.NaN()
	}
	switch n.op {
	case "num":
		return n.v
	case "var":
		if v, ok := c.env[n.name]; ok {
			return v
		}
		if v, ok := mathConsts[n.name]; ok {
			return v
		}
		c.err = fmt.Errorf("не задано %s", n.name)
		return math.NaN()
	case "()":
		return c.eval(n.args[0])
	case "neg":
		return -c.eval(n.args[0])
	case "not":
		return b2f(c.eval(n.args[0]) == 0)
	case "!":
		x := c.eval(n.args[0])
		r := fact(x)
		c.step("%s! = %s", fnum(x), fnum(r))
		return r
	case "%":
		return c.eval(n.args[0]) / 100
	case "°":
		return c.eval(n.args[0]) * math.Pi / 180
	case "call":
		var xs []float64
		for _, a := range n.args {
			xs = append(xs, c.eval(a))
		}
		r := callFunc(n.name, xs)
		c.step("%s(%s) = %s", n.name, joinNums(xs), fnum(r))
		return r
	}
	a := c.eval(n.args[0])
	b := c.eval(n.args[1])
	var r float64
	sym := n.op
	switch n.op {
	case "+":
		r = a + b
	case "-":
		r = a - b
	case "*":
		r, sym = a*b, "·"
	case "/":
		if b == 0 {
			c.err = fmt.Errorf("деление на ноль")
			return math.NaN()
		}
		r, sym = a/b, ":"
	case "mod":
		r = math.Mod(a, b)
	case "^":
		r = math.Pow(a, b)
	case "<":
		r = b2f(a < b && !feq(a, b))
	case ">":
		r = b2f(a > b && !feq(a, b))
	case "<=":
		r, sym = b2f(a < b || feq(a, b)), "≤"
	case ">=":
		r, sym = b2f(a > b || feq(a, b)), "≥"
	case "=":
		r = b2f(feq(a, b))
	case "!=":
		r, sym = b2f(!feq(a, b)), "≠"
	case "and":
		r, sym = b2f(a != 0 && b != 0), "и"
	case "or":
		r, sym = b2f(a != 0 || b != 0), "или"
	case "xor":
		r, sym = b2f((a != 0) != (b != 0)), "xor"
	case "->":
		r, sym = b2f(a == 0 || b != 0), "→"
	}
	if n.isBool() {
		c.step("%s %s %s: %s", fnum(a), sym, fnum(b), map[bool]string{true: "верно", false: "неверно"}[r != 0])
	} else {
		c.step("%s %s %s = %s", fnum(a), sym, fnum(b), fnum(r))
	}
	return r
}

func callFunc(name string, x []float64) float64 {
	switch name {
	case "sqrt":
		return math.Sqrt(x[0])
	case "cbrt":
		return math.Cbrt(x[0])
	case "ln":
		return math.Log(x[0])
	case "lg", "log10":
		return math.Log10(x[0])
	case "log2":
		return math.Log2(x[0])
	case "log":
		if x[0] <= 0 || x[0] == 1 || x[1] <= 0 {
			return math.NaN()
		}
		r := math.Log(x[1]) / math.Log(x[0])
		if math.Abs(r-math.Round(r)) < 1e-9 {
			r = math.Round(r)
		}
		return r
	case "abs":
		return math.Abs(x[0])
	case "exp":
		return math.Exp(x[0])
	case "sin":
		return snap(math.Sin(x[0]))
	case "cos":
		return snap(math.Cos(x[0]))
	case "tan", "tg":
		return snap(math.Tan(x[0]))
	case "ctg", "cot":
		return snap(1 / math.Tan(x[0]))
	case "floor":
		return math.Floor(x[0])
	case "ceil":
		return math.Ceil(x[0])
	case "round":
		return math.Round(x[0])
	case "fact":
		return fact(x[0])
	case "gcd":
		return gcd(x[0], x[1])
	case "lcm":
		g := gcd(x[0], x[1])
		if g == 0 {
			return math.NaN()
		}
		return math.Abs(x[0]*x[1]) / g
	case "comb", "binom":
		return comb(x[0], x[1])
	case "perm":
		return fact(x[0]) / fact(x[0]-x[1])
	case "pow":
		return math.Pow(x[0], x[1])
	case "min", "max":
		r := x[0]
		for _, v := range x[1:] {
			if name == "min" && v < r || name == "max" && v > r {
				r = v
			}
		}
		return r
	}
	return math.NaN()
}

func snap(x float64) float64 {
	if r := math.Round(x*1e9) / 1e9; math.Abs(r-x) < 1e-12 {
		return r
	}
	return x
}

func fnum(x float64) string {
	if math.IsNaN(x) {
		return "?"
	}
	if math.Abs(x-math.Round(x)) < 1e-9 && math.Abs(x) < 1e15 {
		return strconv.FormatFloat(math.Round(x), 'f', -1, 64)
	}
	s := strconv.FormatFloat(x, 'g', 6, 64)
	if p, q, ok := ratio(x); ok && q <= 100 {
		return fmt.Sprintf("%s (= %d/%d)", s, p, q)
	}
	return s
}

func ratio(x float64) (int64, int64, bool) {
	for q := int64(2); q <= 1000; q++ {
		p := math.Round(x * float64(q))
		if math.Abs(p/float64(q)-x) < 1e-9 {
			return int64(p), q, true
		}
	}
	return 0, 0, false
}

func joinNums(x []float64) string {
	var s []string
	for _, v := range x {
		s = append(s, fnum(v))
	}
	return strings.Join(s, ", ")
}

// ---------- normalisation of words to symbols ----------

type wrep struct {
	re  *regexp.Regexp
	rep string
}

func wr(pattern, rep string) wrep {
	return wrep{regexp.MustCompile(`(^|[^\p{L}\d_])(?:` + pattern + `)([^\p{L}\d_]|$)`), "${1}" + rep + "${2}"}
}

var (
	symRepl = strings.NewReplacer("×", "*", "·", "*", "∙", "*", "÷", "/", "−", "-", "–", "-", "—", "-", "≤", "<=", "≥", ">=", "≠", "!=",
		"√", " sqrt ", "∛", " cbrt ", "π", "pi", "∧", "&", "∨", "|", "¬", "!", "⊕", " xor ", "→", "->", "⇒", "->", "=>", "->", "²", "^2", "³", "^3", "ё", "е",
		"ⁿ", "^n", "⁄", "/")
	numWords = []wrep{wr("ноль|нуль", "0"), wr("один|одна|одно|одну", "1"), wr("два|две|дважды", "2"), wr("три|трижды", "3"), wr("четыре", "4"),
		wr("пять", "5"), wr("шесть", "6"), wr("семь", "7"), wr("восемь", "8"), wr("девять", "9"), wr("десять", "10"),
		wr("zero", "0"), wr("one", "1"), wr("two|twice", "2"), wr("three|thrice", "3"), wr("four", "4"), wr("five", "5"), wr("six", "6"), wr("ten", "10")}
	logBaseRe = regexp.MustCompile(`логарифм\s+(?:числа\s+)?(\S+?)\s+по\s+основанию\s+(\S+?)(?:[\s,?.!]|$)`)
	logOfRe   = regexp.MustCompile(`log\s*(?:base\s*)?(\d+(?:\.\d+)?)\s+of\s+(\S+?)(?:[\s,?.!]|$)`)
	combRe    = regexp.MustCompile(`(?:число\s+сочетаний|сочетани[йяе]|сочетаний)\s+из\s+(\d+)\s+по\s+(\d+)`)
	factRe    = regexp.MustCompile(`факториал\s+(?:числа\s+)?(\d+)`)
	powRe     = regexp.MustCompile(`(\d+(?:[.,]\d+)?)\s+в\s+(-?\d+(?:[.,]\d+)?)(?:-?(?:й|ой|ей|ей|ую))?\s+степени`)
	pctOfRe   = regexp.MustCompile(`(\d+(?:[.,]\d+)?)\s*(?:%|процент(?:ов|а)?)\s+(?:от|of)\s+`)
	pctRe     = regexp.MustCompile(`(\d+(?:[.,]\d+)?)\s*процент(?:ов|а)?`)
	degRe     = regexp.MustCompile(`(\d+)\s*(?:градус(?:ов|а)?|degrees?)`)

	wordOps = []wrep{
		wr("больше\\s+или\\s+равно|больше\\s+либо\\s+равно|не\\s+меньше,?\\s+чем|не\\s+меньше|не\\s+менее|at\\s+least|greater\\s+than\\s+or\\s+equal\\s+to", ">="),
		wr("меньше\\s+или\\s+равно|меньше\\s+либо\\s+равно|не\\s+больше,?\\s+чем|не\\s+больше|не\\s+более|at\\s+most|less\\s+than\\s+or\\s+equal\\s+to", "<="),
		wr("не\\s+равно|не\\s+равен|не\\s+равна|не\\s+равны|is\\s+not\\s+equal\\s+to|not\\s+equal\\s+to|does\\s+not\\s+equal", "!="),
		wr("больше,?\\s+чем|больше|более|greater\\s+than|more\\s+than|bigger\\s+than|is\\s+greater\\s+than", ">"),
		wr("меньше,?\\s+чем|меньше|менее|less\\s+than|smaller\\s+than|is\\s+less\\s+than", "<"),
		wr("равняется|равно|равен|равна|равны|будет\\s+равно|is\\s+equal\\s+to|equals|equal\\s+to|equal|is", "="),
		wr("квадратный\\s+корень\\s+из|корень\\s+квадратный\\s+из|корень\\s+из|корень|square\\s+root\\s+of|root\\s+of|sqrt\\s+of", " sqrt "),
		wr("кубический\\s+корень\\s+из|корень\\s+третьей\\s+степени\\s+из|cube\\s+root\\s+of", " cbrt "),
		wr("натуральный\\s+логарифм|натуральный\\s+логарифм\\s+от", " ln "),
		wr("десятичный\\s+логарифм|десятичный\\s+логарифм\\s+от", " lg "),
		wr("плюс|прибавить|сложить\\s+с|plus|added\\s+to", " + "),
		wr("минус|отнять|вычесть|minus|take\\s+away", " - "),
		wr("умножить\\s+на|умноженное\\s+на|умножить|помножить\\s+на|times|multiplied\\s+by", " * "),
		wr("разделить\\s+на|делить\\s+на|деленное\\s+на|поделить\\s+на|divided\\s+by|over", " / "),
		wr("в\\s+квадрате|squared", " ^2 "),
		wr("в\\s+кубе|cubed", " ^3 "),
		wr("в\\s+степени|to\\s+the\\s+power\\s+of|to\\s+the\\s+power|power\\s+of", " ^ "),
		wr("по\\s+модулю|mod|modulo|остаток\\s+от\\s+деления\\s+на", " mod "),
		wr("нод", " gcd "), wr("нок", " lcm "), wr("синус", " sin "), wr("косинус", " cos "), wr("тангенс", " tan "), wr("котангенс", " ctg "),
		wr("модуль\\s+числа|модуль", " abs "),
	}
	boolOps = []wrep{
		wr("истина|истинно|правда|true", " 1 "), wr("ложь|ложно|false", " 0 "),
		wr("исключающее\\s+или|xor", " xor "), wr("если\\s+(?:.{1,3})\\s+то", " -> "), wr("влечет|следует|implies", " -> "),
		wr("или|or", " | "), wr("и|and", " & "), wr("не|not", " ! "),
	}
)

func applyW(s string, rs []wrep) string {
	for _, r := range rs {
		for i := 0; i < 2; i++ {
			s = r.re.ReplaceAllString(s, r.rep)
		}
	}
	return s
}

// normMath lowercases and turns spoken math into symbols. boolCtx also maps и/или/не.
func normMath(s string, boolCtx bool) string {
	s = strings.ToLower(s)
	s = symRepl.Replace(s)
	s = regexp.MustCompile(`(\d)\s*:\s*(\d)`).ReplaceAllString(s, "$1 / $2") // 6 : 2 school division
	s = logBaseRe.ReplaceAllString(s, " log($2, $1) ")
	s = logOfRe.ReplaceAllString(s, " log($1, $2) ")
	s = combRe.ReplaceAllString(s, " comb($1, $2) ")
	s = factRe.ReplaceAllString(s, " $1! ")
	s = applyW(s, numWords)
	s = powRe.ReplaceAllString(s, " $1 ^ $2 ")
	s = pctOfRe.ReplaceAllString(s, " $1 % * ")
	s = pctRe.ReplaceAllString(s, " $1 % ")
	s = degRe.ReplaceAllString(s, " $1° ")
	s = applyW(s, wordOps)
	if boolCtx {
		s = applyW(s, boolOps)
	}
	return s
}

// ---------- span search ----------

type mspan struct {
	n      *node
	ops    int
	lo, hi int // token range
	toks   []tok
	text   string
}

// spans finds parseable math expressions in normalised text, best (most operators, longest) first,
// non-overlapping. minOps = 0 also returns bare numbers.
func spans(s string, minOps int, alg bool) []mspan {
	t := tokenize(s)
	var cands []mspan
	for i := 0; i < len(t); i++ {
		if t[i].k == 'x' || t[i].k == ',' || t[i].k == ')' {
			continue
		}
		for j := i + 1; j <= len(t) && j-i <= 60; j++ {
			if t[j-1].k == 'x' {
				break
			}
			n, ops, err := parseTokens(t[i:j], alg)
			if err != nil || ops < minOps {
				continue
			}
			cands = append(cands, mspan{n: n, ops: ops, lo: i, hi: j, toks: t[i:j]})
		}
	}
	sort.SliceStable(cands, func(a, b int) bool {
		if cands[a].ops != cands[b].ops {
			return cands[a].ops > cands[b].ops
		}
		if la, lb := cands[a].hi-cands[a].lo, cands[b].hi-cands[b].lo; la != lb {
			return la > lb
		}
		return cands[a].lo < cands[b].lo
	})
	used := make([]bool, len(t))
	var out []mspan
	for _, c := range cands {
		free := true
		for k := c.lo; k < c.hi; k++ {
			if used[k] {
				free = false
				break
			}
		}
		if !free {
			continue
		}
		for k := c.lo; k < c.hi; k++ {
			used[k] = true
		}
		c.text = tokText(c.toks)
		out = append(out, c)
	}
	return out
}

func tokText(t []tok) string {
	var b strings.Builder
	for i, x := range t {
		if i > 0 && !(x.k == ')' || x.k == ',' || t[i-1].k == '(' || x.s == "!" && t[i-1].k != 'o' || x.s == "%" || x.s == "°") {
			b.WriteByte(' ')
		}
		switch x.s {
		case "*":
			b.WriteString("·")
		case "/":
			b.WriteString(":")
		case "&":
			b.WriteString("и")
		case "|":
			b.WriteString("или")
		default:
			b.WriteString(x.s)
		}
	}
	return b.String()
}

// evalSteps evaluates with a step trace.
func evalSteps(n *node, env map[string]float64) (float64, []string, error) {
	c := &evalCtx{env: env, trace: true}
	v := c.eval(n)
	if c.err == nil && (math.IsNaN(v) || math.IsInf(v, 0)) {
		c.err = fmt.Errorf("значение не определено")
	}
	return v, c.steps, c.err
}

func evalQuiet(n *node, env map[string]float64) (float64, bool) {
	c := &evalCtx{env: env}
	v := c.eval(n)
	return v, c.err == nil && !math.IsNaN(v) && !math.IsInf(v, 0)
}

func freeVars(n *node) []string {
	m := map[string]bool{}
	n.vars(m)
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
