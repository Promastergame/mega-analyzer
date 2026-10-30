// Package purl реализует разбор и каноническую запись Package URL
// (pkg:type/namespace/name@version?qualifiers#subpath) по публичной
// спецификации package-url.
//
// Канонизация здесь — не косметика. PURL служит ключом: по нему SBOM
// связывается с базами уязвимостей, списками известных SDK и bloom-наборами.
// Если «pkg:pypi/Foo_Bar@1» и «pkg:pypi/foo-bar@1» дадут разные ключи, ключ
// молча промахнётся. Поэтому одна функция Key/Identity используется и при
// сборке наборов, и при поиске.
package purl

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// PURL — разобранный Package URL.
type PURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
}

// Parse разбирает строку PURL и возвращает каноническую форму.
func Parse(s string) (PURL, error) {
	var p PURL
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok {
		return p, errors.New("purl: missing \"pkg:\" scheme")
	}
	rest = strings.TrimLeft(rest, "/") // допускается pkg://type/...

	if i := strings.IndexByte(rest, '#'); i >= 0 {
		sub, err := decodeSubpath(rest[i+1:])
		if err != nil {
			return p, err
		}
		p.Subpath, rest = sub, rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		q, err := decodeQualifiers(rest[i+1:])
		if err != nil {
			return p, err
		}
		p.Qualifiers, rest = q, rest[:i]
	}

	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return p, errors.New("purl: missing type or name")
	}
	p.Type = strings.ToLower(rest[:slash])
	if !validType(p.Type) {
		return p, fmt.Errorf("purl: invalid type %q", p.Type)
	}
	rest = strings.Trim(rest[slash+1:], "/")

	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		v, err := unescape(rest[i+1:])
		if err != nil {
			return p, err
		}
		p.Version, rest = v, rest[:i]
	}

	segs := strings.Split(rest, "/")
	decoded := make([]string, 0, len(segs))
	for _, seg := range segs {
		if seg == "" {
			continue
		}
		d, err := unescape(seg)
		if err != nil {
			return p, err
		}
		decoded = append(decoded, d)
	}
	if len(decoded) == 0 {
		return p, errors.New("purl: missing name")
	}
	p.Name = decoded[len(decoded)-1]
	p.Namespace = strings.Join(decoded[:len(decoded)-1], "/")

	p.normalize()
	if p.Name == "" {
		return p, errors.New("purl: empty name after normalization")
	}
	return p, nil
}

// New собирает PURL из частей и канонизирует его.
func New(typ, namespace, name, version string) (PURL, error) {
	p := PURL{Type: strings.ToLower(typ), Namespace: namespace, Name: name, Version: version}
	if !validType(p.Type) {
		return p, fmt.Errorf("purl: invalid type %q", typ)
	}
	p.normalize()
	if p.Name == "" {
		return p, errors.New("purl: missing name")
	}
	return p, nil
}

// Maven — pkg:maven/<group>/<artifact>@<version>.
func Maven(group, artifact, version string) (PURL, error) {
	return New("maven", group, artifact, version)
}

// Golang разбивает модульный путь на namespace/name: github.com/a/b → a/b под github.com.
func Golang(modulePath, version string) (PURL, error) {
	modulePath = strings.Trim(modulePath, "/")
	ns, name := "", modulePath
	if i := strings.LastIndexByte(modulePath, '/'); i >= 0 {
		ns, name = modulePath[:i], modulePath[i+1:]
	}
	return New("golang", ns, name, version)
}

// normalize приводит имя и namespace к каноническому виду по правилам типа.
func (p *PURL) normalize() {
	p.Namespace = strings.Trim(p.Namespace, "/")
	switch p.Type {
	case "pypi":
		p.Name = strings.ToLower(strings.ReplaceAll(p.Name, "_", "-"))
	case "npm", "golang", "github", "bitbucket", "composer", "hex":
		p.Namespace = strings.ToLower(p.Namespace)
		p.Name = strings.ToLower(p.Name)
	case "deb", "rpm", "apk":
		p.Namespace = strings.ToLower(p.Namespace)
	}
	// Пустые квалификаторы не несут смысла.
	for k, v := range p.Qualifiers {
		if v == "" {
			delete(p.Qualifiers, k)
		}
	}
	if len(p.Qualifiers) == 0 {
		p.Qualifiers = nil
	}
}

// String — каноническая запись.
func (p PURL) String() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	b.WriteByte('/')
	b.WriteString(p.coordinate())
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(escape(p.Version))
	}
	if len(p.Qualifiers) > 0 {
		keys := make([]string, 0, len(p.Qualifiers))
		for k := range p.Qualifiers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('?')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte('&')
			}
			b.WriteString(strings.ToLower(k))
			b.WriteByte('=')
			b.WriteString(escape(p.Qualifiers[k]))
		}
	}
	if p.Subpath != "" {
		b.WriteByte('#')
		segs := strings.Split(p.Subpath, "/")
		for i, s := range segs {
			segs[i] = escape(s)
		}
		b.WriteString(strings.Join(segs, "/"))
	}
	return b.String()
}

func (p PURL) coordinate() string {
	if p.Namespace == "" {
		return escape(p.Name)
	}
	segs := strings.Split(p.Namespace, "/")
	for i, s := range segs {
		segs[i] = escape(s)
	}
	return strings.Join(segs, "/") + "/" + escape(p.Name)
}

// Identity — пакет без версии: pkg:type/namespace/name. Ключ для вопросов
// «известен ли такой пакет вообще».
func (p PURL) Identity() string {
	return "pkg:" + p.Type + "/" + p.coordinate()
}

// Key — пакет с версией, без квалификаторов и subpath: два артефакта одного
// релиза (например, разные архитектуры) дают один ключ.
func (p PURL) Key() string {
	if p.Version == "" {
		return p.Identity()
	}
	return p.Identity() + "@" + escape(p.Version)
}

// Normalize принимает любую запись PURL и возвращает каноническую.
func Normalize(s string) (string, bool) {
	p, err := Parse(s)
	if err != nil {
		return "", false
	}
	return p.String(), true
}

// KeyOf — ключ версии для строки PURL ("", false, если строка не разбирается).
// Строка, которая не разбирается, ключа не даёт: пробовать по ней поиск значило
// бы получить только ложное срабатывание.
func KeyOf(s string) (string, bool) {
	p, err := Parse(s)
	if err != nil {
		return "", false
	}
	return p.Key(), true
}

func validType(t string) bool {
	if t == "" {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9', c == '.', c == '+', c == '-':
			if i == 0 && c >= '0' && c <= '9' {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ── percent-encoding ───────────────────────────────────────────────────────

const hexDigits = "0123456789ABCDEF"

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '.' || c == '-' || c == '_' || c == '~'
}

func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func unescape(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out = append(out, s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", errors.New("purl: truncated percent-escape")
		}
		hi, ok1 := unhex(s[i+1])
		lo, ok2 := unhex(s[i+2])
		if !ok1 || !ok2 {
			return "", errors.New("purl: invalid percent-escape")
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return string(out), nil
}

func decodeQualifiers(s string) (map[string]string, error) {
	q := make(map[string]string)
	for _, pair := range strings.Split(s, "&") {
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("purl: malformed qualifier %q", pair)
		}
		dv, err := unescape(v)
		if err != nil {
			return nil, err
		}
		q[strings.ToLower(k)] = dv
	}
	return q, nil
}

func decodeSubpath(s string) (string, error) {
	var parts []string
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || seg == "." || seg == ".." {
			continue // «..» в subpath недопустим, не даём ему проскользнуть
		}
		d, err := unescape(seg)
		if err != nil {
			return "", err
		}
		parts = append(parts, d)
	}
	return strings.Join(parts, "/"), nil
}
