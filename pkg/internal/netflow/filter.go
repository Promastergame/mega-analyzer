package netflow

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Record is the unit a Filter is evaluated against: either a single observed
// payload (from FlowTable.Observe) or a whole flow (from Flow.Record).
type Record struct {
	Protocol  Protocol
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Direction string
	Length    int
	SNI       string
	Payload   []byte
}

// Filter is a compiled display-filter expression. Build one with Compile, then
// test records with Match. The grammar is a familiar Wireshark/BPF-style
// language:
//
//	proto == tls and port == 443
//	ip == 10.0.0.5 and not sni matches "\.ads\."
//	(proto == http1 or proto == http2) and payload contains "password"
//	len > 1400
//	websocket                      # bare protocol name is shorthand for proto == websocket
//
// Fields:  proto, ip[.src|.dst], port[.src|.dst], len, dir, sni, payload
// Ops:     == != > < >= <= contains matches   (matches takes a Go regexp)
// Logic:   and/&&  or/||  not/!  ( )
type Filter struct {
	root node
	src  string
}

// String returns the original filter source.
func (f *Filter) String() string { return f.src }

// Match reports whether the record satisfies the filter.
func (f *Filter) Match(r Record) bool { return f.root.eval(r) }

// Compile parses a display-filter expression. An empty expression compiles to
// a filter that matches everything.
func Compile(expr string) (*Filter, error) {
	toks, err := lex(expr)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	if p.peek().kind == tokEOF {
		return &Filter{root: literalNode(true), src: expr}, nil
	}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("netflow: unexpected trailing token %q", p.peek().text)
	}
	return &Filter{root: root, src: expr}, nil
}

// ─── AST ────────────────────────────────────────────────────────────────────

type node interface{ eval(r Record) bool }

type literalNode bool

func (l literalNode) eval(Record) bool { return bool(l) }

type notNode struct{ inner node }

func (n notNode) eval(r Record) bool { return !n.inner.eval(r) }

type andNode struct{ l, r node }

func (a andNode) eval(r Record) bool { return a.l.eval(r) && a.r.eval(r) }

type orNode struct{ l, r node }

func (o orNode) eval(r Record) bool { return o.l.eval(r) || o.r.eval(r) }

type cmpNode struct {
	field string
	op    string
	value string
	re    *regexp.Regexp // non-nil only for "matches"
}

func (c cmpNode) eval(r Record) bool { return evalCmp(c, r) }

// ─── Lexer ───────────────────────────────────────────────────────────────────

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokString
	tokNumber
	tokOp
	tokLParen
	tokRParen
	tokAnd
	tokOr
	tokNot
	tokContains
	tokMatches
)

type token struct {
	kind tokKind
	text string
}

func lex(s string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{tokLParen, "("})
			i++
		case c == ')':
			toks = append(toks, token{tokRParen, ")"})
			i++
		case c == '&' && i+1 < len(s) && s[i+1] == '&':
			toks = append(toks, token{tokAnd, "&&"})
			i += 2
		case c == '|' && i+1 < len(s) && s[i+1] == '|':
			toks = append(toks, token{tokOr, "||"})
			i += 2
		case c == '=' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, token{tokOp, "=="})
			i += 2
		case c == '!' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, token{tokOp, "!="})
			i += 2
		case c == '>' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, token{tokOp, ">="})
			i += 2
		case c == '<' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, token{tokOp, "<="})
			i += 2
		case c == '>':
			toks = append(toks, token{tokOp, ">"})
			i++
		case c == '<':
			toks = append(toks, token{tokOp, "<"})
			i++
		case c == '!':
			toks = append(toks, token{tokNot, "!"})
			i++
		case c == '"' || c == '\'':
			str, n, err := lexString(s[i:], c)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{tokString, str})
			i += n
		case isIdentByte(c):
			j := i
			for j < len(s) && isIdentByte(s[j]) {
				j++
			}
			word := s[i:j]
			toks = append(toks, classifyWord(word))
			i = j
		default:
			return nil, fmt.Errorf("netflow: unexpected character %q in filter", string(c))
		}
	}
	toks = append(toks, token{tokEOF, ""})
	return toks, nil
}

func lexString(s string, quote byte) (string, int, error) {
	var b strings.Builder
	i := 1
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i += 2
			continue
		}
		if s[i] == quote {
			return b.String(), i + 1, nil
		}
		b.WriteByte(s[i])
		i++
	}
	return "", 0, fmt.Errorf("netflow: unterminated string literal")
}

func classifyWord(word string) token {
	switch strings.ToLower(word) {
	case "and":
		return token{tokAnd, word}
	case "or":
		return token{tokOr, word}
	case "not":
		return token{tokNot, word}
	case "contains":
		return token{tokContains, word}
	case "matches":
		return token{tokMatches, word}
	}
	if isNumber(word) {
		return token{tokNumber, word}
	}
	return token{tokIdent, word}
}

func isIdentByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == ':' || c == '/'
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ─── Parser ──────────────────────────────────────────────────────────────────

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokAnd {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = andNode{left, right}
	}
	return left, nil
}

func (p *parser) parseNot() (node, error) {
	if p.peek().kind == tokNot {
		p.next()
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return notNode{inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (node, error) {
	tok := p.peek()
	if tok.kind == tokLParen {
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("netflow: missing closing ')'")
		}
		p.next()
		return inner, nil
	}
	if tok.kind != tokIdent {
		return nil, fmt.Errorf("netflow: expected a field name, got %q", tok.text)
	}
	return p.parseComparison()
}

var knownFields = map[string]bool{
	"proto": true, "ip": true, "ip.src": true, "ip.dst": true,
	"port": true, "port.src": true, "port.dst": true,
	"len": true, "dir": true, "sni": true, "payload": true,
}

func (p *parser) parseComparison() (node, error) {
	field := p.next().text
	opTok := p.peek()

	// Bare protocol name (e.g. "tls") is shorthand for `proto == <name>`.
	if opTok.kind != tokOp && opTok.kind != tokContains && opTok.kind != tokMatches {
		if !knownFields[strings.ToLower(field)] && isProtocolName(field) {
			return cmpNode{field: "proto", op: "==", value: strings.ToLower(field)}, nil
		}
		return nil, fmt.Errorf("netflow: expected an operator after %q", field)
	}

	fieldKey := strings.ToLower(field)
	if !knownFields[fieldKey] {
		return nil, fmt.Errorf("netflow: unknown field %q", field)
	}

	var op string
	switch opTok.kind {
	case tokOp:
		op = opTok.text
	case tokContains:
		op = "contains"
	case tokMatches:
		op = "matches"
	}
	p.next()

	valTok := p.next()
	if valTok.kind != tokIdent && valTok.kind != tokString && valTok.kind != tokNumber {
		return nil, fmt.Errorf("netflow: expected a value after %q %s", field, op)
	}
	c := cmpNode{field: fieldKey, op: op, value: valTok.text}
	if op == "matches" {
		re, err := regexp.Compile(valTok.text)
		if err != nil {
			return nil, fmt.Errorf("netflow: bad regexp in matches: %w", err)
		}
		c.re = re
	}
	return c, nil
}

func isProtocolName(s string) bool {
	switch Protocol(strings.ToLower(s)) {
	case ProtoHTTP1, ProtoHTTP2, ProtoWebSocket, ProtoTLS, ProtoDNS, ProtoSSH, ProtoUnknown:
		return true
	}
	return false
}

// ─── Evaluation ──────────────────────────────────────────────────────────────

func evalCmp(c cmpNode, r Record) bool {
	switch c.field {
	case "len":
		return numCompare(c.op, int64(r.Length), c.value)
	case "port":
		return numCompare(c.op, int64(r.SrcPort), c.value) || numCompare(c.op, int64(r.DstPort), c.value)
	case "port.src":
		return numCompare(c.op, int64(r.SrcPort), c.value)
	case "port.dst":
		return numCompare(c.op, int64(r.DstPort), c.value)
	case "proto":
		return strCompare(c, string(r.Protocol))
	case "dir":
		return strCompare(c, r.Direction)
	case "sni":
		return strCompare(c, r.SNI)
	case "payload":
		return strCompare(c, string(r.Payload))
	case "ip":
		// Unqualified ip matches either endpoint. For == that means "either
		// side equals"; for != it means "neither side equals".
		if c.op == "!=" {
			return strCompare(c, r.SrcIP) && strCompare(c, r.DstIP)
		}
		return strCompare(c, r.SrcIP) || strCompare(c, r.DstIP)
	case "ip.src":
		return strCompare(c, r.SrcIP)
	case "ip.dst":
		return strCompare(c, r.DstIP)
	}
	return false
}

func numCompare(op string, have int64, rawWant string) bool {
	want, err := strconv.ParseInt(rawWant, 10, 64)
	if err != nil {
		return false
	}
	switch op {
	case "==":
		return have == want
	case "!=":
		return have != want
	case ">":
		return have > want
	case "<":
		return have < want
	case ">=":
		return have >= want
	case "<=":
		return have <= want
	}
	return false
}

func strCompare(c cmpNode, have string) bool {
	switch c.op {
	case "==":
		return have == c.value
	case "!=":
		return have != c.value
	case "contains":
		return strings.Contains(have, c.value)
	case "matches":
		return c.re != nil && c.re.MatchString(have)
	}
	return false
}
