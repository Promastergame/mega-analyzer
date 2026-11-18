package semai

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var tokRE = regexp.MustCompile(`\d+(?:[.,]\d+)?(?:/\d+)?|[\p{L}]+(?:['’-][\p{L}]+)*|[^\s\p{L}\d]`)

// normText lower-cases, folds ё→е and unifies quotes/dashes. Offsets are not preserved.
func normText(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer("ё", "е", "’", "'", "–", "-", "—", "-", "×", "*", "÷", "/", "−", "-", "\u00a0", " ").Replace(s)
	return s
}

func tokens(s string) []string { return tokRE.FindAllString(normText(s), -1) }

func isWord(t string) bool {
	for _, r := range t {
		return unicode.IsLetter(r)
	}
	return false
}
func isNumTok(t string) bool { return t != "" && t[0] >= '0' && t[0] <= '9' }

var ruEnd = []string{"ироваться", "ировать", "ыми", "ими", "его", "ого", "ему", "ому", "ами", "ями", "ией", "иям", "иях", "ов", "ев", "ей", "ом", "ем", "ах", "ях", "ям", "ам", "ую", "юю", "ая", "яя", "ое", "ее", "ые", "ие", "ый", "ий", "ой", "ых", "их", "ет", "ут", "ют", "ит", "ат", "ят", "ла", "ли", "ло", "ал", "ил", "ся", "сь", "ть", "а", "я", "ы", "и", "у", "ю", "е", "о", "ь", "й"}
var enEnd = []string{"ing", "ed", "es", "s"}

// stem is a deliberately small ru/en suffix stripper. It is only used for matching, never shown as a word.
func stem(w string) string {
	if !isWord(w) || len([]rune(w)) <= 3 {
		return w
	}
	r := []rune(w)
	latin := r[0] < 0x250
	list := ruEnd
	if latin {
		list = enEnd
	}
	for _, e := range list {
		if strings.HasSuffix(w, e) && len([]rune(w))-len([]rune(e)) >= 3 {
			return strings.TrimSuffix(w, e)
		}
	}
	return w
}

var stopWords = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`и в во не что он на я с со как а то все она так его но да ты к у же вы за бы по только ее мне было вот от меня еще нет о из ему теперь когда даже ну вдруг ли если уже или ни быть был него до вас нибудь опять уж вам ведь там потом себя ничего ей может они тут где есть надо ней для мы тебя их чем была сам чтоб без будто чего раз тоже себе под будет ж тогда кто этот того потому этого какой совсем ним здесь этом один почти мой тем чтобы нее сейчас были куда зачем всех никогда можно при наконец два об другой хоть после над больше тот через эти нас про всего них какая много разве три эту моя впрочем хорошо свою этой перед иногда лучше чуть том нельзя такой им более всегда конечно всю между
the a an of to in on at is are was were be been it its this that these those and or for with as by from has have had do does did will would can could should may might we you they he she i not no`) {
		stopWords[w] = true
	}
}

// contentStems returns stems of non-stopword, non-negation, non-number words.
func contentStems(s string) []string {
	var out []string
	for _, t := range tokens(s) {
		if !isWord(t) || stopWords[t] || negWords[t] {
			continue
		}
		out = append(out, stem(t))
	}
	return out
}

func jaccardStems(a, b []string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	inter, union := 0, len(set)
	seen := map[string]bool{}
	for _, y := range b {
		if seen[y] {
			continue
		}
		seen[y] = true
		if set[y] {
			inter++
		} else {
			union++
		}
	}
	return float64(inter) / float64(union)
}

// overlapCoverage = share of a's stems that occur in b (prefix matches of >=4 runes count).
func overlapCoverage(a, b []string) float64 {
	if len(a) == 0 {
		return 0
	}
	hit := 0
	for _, x := range a {
		for _, y := range b {
			if x == y || (len([]rune(x)) >= 4 && len([]rune(y)) >= 4 && (strings.HasPrefix(x, y) || strings.HasPrefix(y, x))) {
				hit++
				break
			}
		}
	}
	return float64(hit) / float64(len(a))
}

func fmtNum(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

var clauseSplit = regexp.MustCompile(`[.;!?\n]+|\s+(?:но|а также|однако|but|however)\s+|,\s*(?:и|а|но|and|but)\s+|\s+(?:и|and)\s+(?:при этом|also)\s+`)

// clauses splits free text into short claims.
func clauses(s string) []string {
	var out []string
	for _, c := range clauseSplit.Split(s, -1) {
		c = strings.Trim(strings.TrimSpace(c), "-•*,: ")
		if len([]rune(c)) >= 3 {
			out = append(out, c)
		}
	}
	return out
}
