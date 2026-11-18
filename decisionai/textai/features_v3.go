package textai

import (
	"math"
	"sort"
	"strings"
	"unicode"
)

const FeatureSchema = "word-char-tfidf-v2"
const FeatureSchemaV1 = "word-char-tfidf-v1"
const maxTokens = 2048

var fieldNames = []string{"state", "question", "true", "false"}

type textFeatures struct {
	terms     map[string]float64
	words     [4][]string
	truncated [4]bool
}

// A sorted sparse vector is built once, rather than sorting a map in every epoch.
type coordinate struct {
	index int
	value float64
}
type vector []coordinate

func (x vector) dot(weights []float64, bias float64) float64 {
	for _, c := range x {
		bias += weights[c.index] * c.value
	}
	return bias
}

func normalizedWords(s string) []string {
	s = strings.NewReplacer("ё", "е", "’", "'").Replace(strings.ToLower(s))
	ws := strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '\''
	})
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		w = strings.Trim(w, "'")
		if w == "" {
			continue
		}
		switch w {
		case "cannot", "can't":
			out = append(out, "can", "not")
		case "won't":
			out = append(out, "will", "not")
		case "isn't":
			out = append(out, "is", "not")
		case "aren't":
			out = append(out, "are", "not")
		case "wasn't":
			out = append(out, "was", "not")
		case "weren't":
			out = append(out, "were", "not")
		case "hasn't":
			out = append(out, "has", "not")
		case "haven't":
			out = append(out, "have", "not")
		case "didn't":
			out = append(out, "did", "not")
		case "doesn't":
			out = append(out, "does", "not")
		case "don't":
			out = append(out, "do", "not")
		default:
			out = append(out, w)
		}
	}
	return out
}

func canonicalText(s string) string { return strings.Join(normalizedWords(s), " ") }

func normalizedSignature(r Request) string {
	return SHA256(r.TaskID + "\x00" + canonicalText(r.State) + "\x00" + canonicalText(r.Question) + "\x00" + canonicalText(r.TrueWhen) + "\x00" + canonicalText(r.FalseWhen))
}

func charGrams(w string) []string {
	runes := []rune(w)
	if len(runes) < 3 || len(runes) > 40 {
		return nil
	}
	runes = append(append([]rune{'^'}, runes...), '$')
	grams := make([]string, 0, len(runes)*3)
	for n := 3; n <= 5; n++ {
		for i := 0; i+n <= len(runes); i++ {
			grams = append(grams, string(runes[i:i+n]))
		}
	}
	return grams
}

func extract(r Request) textFeatures {
	out := textFeatures{terms: make(map[string]float64)}
	for fi, text := range []string{r.State, r.Question, r.TrueWhen, r.FalseWhen} {
		prefix := fieldNames[fi] + ":"
		// Keep n-grams inside sentences so negation cannot cross a sentence boundary.
		sentences := strings.FieldsFunc(text, func(r rune) bool { return strings.ContainsRune(".!?;\r\n", r) })
		for _, sentence := range sentences {
			ws := normalizedWords(sentence)
			remaining := maxTokens - len(out.words[fi])
			if len(ws) > remaining {
				out.truncated[fi] = true
				ws = ws[:remaining]
			}
			out.words[fi] = append(out.words[fi], ws...)
			for i, w := range ws {
				out.terms[prefix+"w:"+w]++
				if i > 0 {
					out.terms[prefix+"b:"+ws[i-1]+" "+w]++
				}
				if i > 1 {
					out.terms[prefix+"t:"+ws[i-2]+" "+ws[i-1]+" "+w]++
				}
				for _, gram := range charGrams(w) {
					out.terms[prefix+"c:"+gram]++
				}
			}
			if out.truncated[fi] {
				break
			}
		}
	}
	// Cross-field attention: which words of the whole state reappear in the
	// whole true/false criteria. Local n-grams only see neighbours; these see
	// the full text at once, like cross-attention between premise and
	// hypothesis in NLI. Fires on word identity across fields, so a state
	// that merely sounds positive but matches false_when gets counter-votes.
	addMatches(out, 0, 2, "match_true")
	addMatches(out, 0, 3, "match_false")
	return out
}

// addMatches links field si (state) with field ti (a criterion): one feature
// per shared unique word plus coarse overlap buckets. Binary per word, so long
// paraphrases do not outshout a single decisive mismatch.
func addMatches(out textFeatures, si, ti int, tag string) {
	set := make(map[string]bool, len(out.words[ti]))
	for _, w := range out.words[ti] {
		set[w] = true
	}
	shared := 0
	for _, w := range out.words[si] {
		if !set[w] {
			continue
		}
		delete(set, w) // count each shared word once, not per repetition
		shared++
		out.terms[fieldNames[si]+":w:"+tag+":"+w]++
	}
	if shared >= 3 {
		out.terms[fieldNames[si]+":w:"+tag+"_ge3"]++
	}
	if shared >= 5 {
		out.terms[fieldNames[si]+":w:"+tag+"_ge5"]++
	}
}

func featureChannel(feature string) (int, float64) {
	fi := 0
	for i, field := range fieldNames {
		if strings.HasPrefix(feature, field+":") {
			fi = i
			break
		}
	}
	weight := [4]float64{1, .25, .35, .35}[fi]
	if strings.HasPrefix(feature, fieldNames[fi]+":c:") {
		return fi*2 + 1, weight * .45
	}
	return fi * 2, weight
}

func (m *Model) encode(f textFeatures) vector {
	keys := make([]string, 0, len(f.terms))
	for k := range f.terms {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	x := make(vector, 0, len(keys))
	norms := [8]float64{}
	for _, key := range keys {
		i := sort.SearchStrings(m.Vocabulary, key)
		// Unknown features never alias a learned feature or alter its TF-IDF norm.
		if i == len(m.Vocabulary) || m.Vocabulary[i] != key {
			continue
		}
		v := (1 + math.Log(math.Min(f.terms[key], 4))) * m.IDF[i]
		channel, _ := featureChannel(key)
		norms[channel] += v * v
		x = append(x, coordinate{i, v})
	}
	norm := 0.0
	for i := range x {
		channel, weight := featureChannel(m.Vocabulary[x[i].index])
		x[i].value *= weight / math.Sqrt(norms[channel])
		norm += x[i].value * x[i].value
	}
	if norm > 0 {
		norm = math.Sqrt(norm)
		for i := range x {
			x[i].value /= norm
		}
	}
	return x
}

func (m *Model) known(feature string) bool {
	i := sort.SearchStrings(m.Vocabulary, feature)
	return i < len(m.Vocabulary) && m.Vocabulary[i] == feature
}

func (m *Model) coverage(f textFeatures) (float64, float64, []FieldCoverage) {
	coverage, support := 1.0, 1.0
	fields := make([]FieldCoverage, 0, 4)
	for fi, name := range fieldNames {
		unique := make(map[string]bool)
		for _, w := range f.words[fi] {
			unique[w] = true
		}
		ws := make([]string, 0, len(unique))
		for w := range unique {
			ws = append(ws, w)
		}
		sort.Strings(ws)
		field := FieldCoverage{Field: name, Tokens: len(ws), Truncated: f.truncated[fi]}
		partial, charKnown, charTotal := 0.0, 0, 0
		for _, w := range ws {
			known := m.known(name + ":w:" + w)
			if known {
				field.Known++
			} else if len(field.Unknown) < 8 {
				field.Unknown = append(field.Unknown, w)
			}
			grams := charGrams(w)
			matched := 0
			for _, gram := range grams {
				if m.known(name + ":c:" + gram) {
					matched++
				}
			}
			charKnown += matched
			charTotal += len(grams)
			// Subwords give only half credit: familiar fragments alone cannot pass 0.6.
			if !known && len(grams) > 0 {
				partial += .5 * float64(matched) / float64(len(grams))
			}
		}
		if field.Tokens > 0 {
			field.Coverage = float64(field.Known) / float64(field.Tokens)
			field.Support = (float64(field.Known) + partial) / float64(field.Tokens)
		}
		if charTotal > 0 {
			field.Subwords = float64(charKnown) / float64(charTotal)
		}
		coverage = math.Min(coverage, field.Coverage)
		support = math.Min(support, field.Support)
		fields = append(fields, field)
	}
	return coverage, support, fields
}

func entropy(p float64) float64 {
	if p <= 0 || p >= 1 {
		return 0
	}
	return -(p*math.Log2(p) + (1-p)*math.Log2(1-p))
}

func (m *Model) predictV3(r Request) Prediction {
	f := extract(r)
	x := m.encode(f)
	intercept := m.CalibrationA*m.Bias + m.CalibrationB
	z := m.CalibrationA*x.dot(m.Weights, m.Bias) + m.CalibrationB
	p := Prediction{Value: sigmoid(z), Kind: "heldout_calibrated_text_estimate", Logit: z, Intercept: intercept,
		Notes: []string{"Оценка обученного классификатора; эффект патча проверяется отдельно.", "Вклады — точные слагаемые логита для известных признаков, не причинное объяснение."}}
	p.Coverage, p.Support, p.Fields = m.coverage(f)
	p.Entropy = entropy(p.Value)
	p.Contributions = []Contribution{}
	for _, c := range x {
		v := m.CalibrationA * m.Weights[c.index] * c.value
		if math.Abs(v) > 1e-9 {
			p.Contributions = append(p.Contributions, Contribution{m.Vocabulary[c.index], v})
		}
	}
	sort.Slice(p.Contributions, func(i, j int) bool {
		a, b := math.Abs(p.Contributions[i].Contribution), math.Abs(p.Contributions[j].Contribution)
		if a == b {
			return p.Contributions[i].Feature < p.Contributions[j].Feature
		}
		return a > b
	})
	if len(p.Contributions) > 12 {
		p.Contributions = p.Contributions[:12]
	}
	p.OtherContribution = z - intercept
	for _, c := range p.Contributions {
		p.OtherContribution -= c.Contribution
	}
	if m.Synthetic {
		p.Kind = "synthetic_demo_estimate"
		p.Notes = append(p.Notes, "Синтетический корпус: качество на реальных приложениях пока не измерено.")
	}
	return p
}
