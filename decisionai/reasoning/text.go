package reasoning

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// The text reader accepts complete, simple relation clauses. Conditional,
// quoted, compound and pronoun-dependent statements are deliberately left out.
var relationClause = regexp.MustCompile(`(?i)^([\p{L}\p{N}_-]+)\s+(?:(?:is|was)\s+)?(?:(not|не)\s+)?(taller|shorter|older|younger|heavier|lighter|larger|smaller|faster|slower|before|after|inside|выше|ниже|старше|младше|тяжелее|легче|больше|меньше|быстрее|медленнее|раньше|позже|внутри)\s+(?:(?:than|чем)\s+)?([\p{L}\p{N}_-]+)(?:\s+(today|yesterday|tomorrow|сегодня|вчера|завтра))?$`)

var relationNames = map[string]struct {
	predicate string
	reverse   bool
}{
	"taller": {"taller", false}, "выше": {"taller", false}, "shorter": {"taller", true}, "ниже": {"taller", true},
	"older": {"older", false}, "старше": {"older", false}, "younger": {"older", true}, "младше": {"older", true},
	"heavier": {"heavier", false}, "тяжелее": {"heavier", false}, "lighter": {"heavier", true}, "легче": {"heavier", true},
	"larger": {"larger", false}, "больше": {"larger", false}, "smaller": {"larger", true}, "меньше": {"larger", true},
	"faster": {"faster", false}, "быстрее": {"faster", false}, "slower": {"faster", true}, "медленнее": {"faster", true},
	"before": {"before", false}, "раньше": {"before", false}, "after": {"before", true}, "позже": {"before", true},
	"inside": {"inside", false}, "внутри": {"inside", false},
}

var nonEntities = map[string]bool{
	"он": true, "она": true, "они": true, "это": true, "если": true, "кто": true, "что": true,
	"he": true, "she": true, "they": true, "it": true, "if": true, "who": true, "what": true,
}

func ParseClaim(text string) (Atom, bool) {
	text = strings.ToLower(strings.TrimSpace(text))
	text = strings.TrimRight(text, ".?!")
	for _, prefix := range []string{"верно ли, что ", "правда ли, что ", "можно ли утверждать, что ", "is it true that ", "can we conclude that ", "is ", "was "} {
		if strings.HasPrefix(text, prefix) {
			text = strings.TrimPrefix(text, prefix)
			break
		}
	}
	m := relationClause.FindStringSubmatch(text)
	if m == nil || nonEntities[m[1]] || nonEntities[m[4]] {
		return Atom{}, false
	}
	r := relationNames[m[3]]
	a := Atom{Subject: m[1], Predicate: r.predicate, Object: m[4], Negated: m[2] != "", Time: m[5]}
	if r.reverse {
		a.Subject, a.Object = a.Object, a.Subject
	}
	switch a.Time {
	case "сегодня":
		a.Time = "today"
	case "вчера":
		a.Time = "yesterday"
	case "завтра":
		a.Time = "tomorrow"
	}
	return a, true
}

// Russian name inflections are resolved only against subjects present in this
// input, and only when an alias identifies one entity. No global name dictionary.
func entityAliases(names []string) map[string]string {
	aliases := map[string]string{}
	for _, name := range names {
		name = Entity(name)
		forms := []string{name}
		runes := []rune(name)
		if len(runes) > 1 && unicode.In(runes[0], unicode.Cyrillic) {
			base := string(runes[:len(runes)-1])
			switch runes[len(runes)-1] {
			case 'а':
				forms = append(forms, base+"ы", base+"и")
			case 'я':
				forms = append(forms, base+"и")
			case 'й', 'ь':
				forms = append(forms, base+"я")
			default:
				forms = append(forms, name+"а", name+"я")
			}
		}
		for _, form := range forms {
			if old, ok := aliases[form]; ok && old != name {
				aliases[form] = ""
			} else if !ok {
				aliases[form] = name
			}
		}
	}
	return aliases
}

func (w *World) ReadText(text string, queries []Atom) []Atom {
	var facts []Fact
	var names []string
	clauses := strings.FieldsFunc(text, func(r rune) bool { return r == '.' || r == ';' || r == '\n' || r == '\r' })
	for i, clause := range clauses {
		// A question or an instruction is not an input fact. ParseClaim's
		// question-prefix support is reserved for the separately supplied query.
		clause = strings.TrimSpace(clause)
		if !relationClause.MatchString(strings.ToLower(clause)) {
			continue
		}
		a, ok := ParseClaim(clause)
		if !ok {
			continue
		}
		facts = append(facts, Fact{Atom: a, Source: fmt.Sprintf("text[%d]: %s", i, clause)})
		// Capture the grammatical subject before inverse normalization.
		m := relationClause.FindStringSubmatch(strings.ToLower(clause))
		names = append(names, m[1])
	}
	aliases := entityAliases(names)
	// A concrete query entity can name an object that only appeared in its
	// inflected form in the text. Existing aliases keep their original identity.
	for _, query := range queries {
		for _, name := range []string{query.Subject, query.Object} {
			if _, known := aliases[Entity(name)]; !known {
				names = append(names, name)
			}
		}
	}
	aliases = entityAliases(names)
	resolve := func(a Atom) Atom {
		if name := aliases[Entity(a.Subject)]; name != "" {
			a.Subject = name
		}
		if name := aliases[Entity(a.Object)]; name != "" {
			a.Object = name
		}
		return a
	}
	for _, fact := range facts {
		w.Add(resolve(fact.Atom), fact.Source)
	}
	out := make([]Atom, len(queries))
	for i, a := range queries {
		out[i] = resolve(a)
	}
	return out
}

func FormatClaim(a Atom) string {
	relation := a.Predicate
	if a.Negated {
		relation = "not " + relation
	}
	text := a.Subject + " " + relation
	if a.Object != "" {
		text += " " + a.Object
	}
	if a.Time != "" {
		text += " (" + a.Time + ")"
	}
	return text
}
