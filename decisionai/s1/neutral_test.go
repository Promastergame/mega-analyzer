package s1

import (
	"hash/fnv"
	"math"
	"strings"
	"testing"

	"decisionai/semai"
)

// cachedEmbedBackend wraps EmbedBackend so Engine.Decide can run EmbedBackend.JudgeBatch
// in unit tests without loading a 37 MB .dte model file from disk.
type cachedEmbedBackend struct {
	*EmbedBackend
}

func newCachedEmbedBackend(texts ...string) *cachedEmbedBackend {
	b := &EmbedBackend{
		cache: weightedCache[string, *semai.Encoding]{limit: DefaultEncodingCacheBytes},
		Label: "bi-encoder:test",
		Scale: 12,
		Bias:  0.55,
	}
	cb := &cachedEmbedBackend{EmbedBackend: b}
	for _, t := range texts {
		cb.seed(t)
	}
	return cb
}

func (b *cachedEmbedBackend) Name() string        { return "bi-encoder:test" }
func (b *cachedEmbedBackend) Tokens(s string) int { return len(strings.Fields(s)) }

func (b *cachedEmbedBackend) seed(text string) {
	add := func(s string) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.cache.get(s); !ok {
			e := syntheticEncoding(s)
			b.cache.put(s, e, encodingBytes(s, e))
		}
	}
	add(text)
	add(statement(text))
	for _, ch := range Chunk(text, 45, 0) {
		add(ch)
	}
}

func (b *cachedEmbedBackend) JudgeBatch(pairs []Pair) []Judgement {
	for _, p := range pairs {
		b.seed(p.Premise)
		b.seed(p.Hypothesis)
	}
	return b.EmbedBackend.JudgeBatch(pairs)
}

// syntheticEncoding builds a bag-of-stems L2-normalised encoding that mimics a bi-encoder:
// sentences sharing content words have cosine similarity ~0.85–1.0 regardless of word order or negation,
// while unrelated sentences have cosine similarity ~0.0–0.15.
func syntheticEncoding(s string) *semai.Encoding {
	const dim = 64
	norm := func(v []float32) []float32 {
		var sum float64
		for _, x := range v {
			sum += float64(x) * float64(x)
		}
		if sum > 0 {
			inv := float32(1 / math.Sqrt(sum))
			for i := range v {
				v[i] *= inv
			}
		}
		return v
	}
	stem := func(w string) string {
		rs := []rune(w)
		for i, r := range rs {
			if r == 'ё' {
				rs[i] = 'е'
			}
		}
		if len(rs) > 5 {
			rs = rs[:5]
		}
		for len(rs) > 3 {
			switch rs[len(rs)-1] {
			case 'а', 'я', 'ы', 'и', 'е', 'у', 'ю', 'о', 'ь', 'й', 's':
				rs = rs[:len(rs)-1]
			default:
				return string(rs)
			}
		}
		return string(rs)
	}
	vecFor := func(tok string) []float32 {
		v := make([]float32, dim)
		h := fnv.New64a()
		_, _ = h.Write([]byte(stem(tok)))
		seed := h.Sum64()
		for d := 0; d < 4; d++ {
			idx := int((seed >> (d * 12)) & (dim - 1))
			v[idx] += 1.0
		}
		return norm(v)
	}
	toks := lexDocOf(s).toks
	mean := make([]float32, dim)
	pieces := []string{"[CLS]"}
	tokVecs := [][]float32{make([]float32, dim)}
	for _, t := range toks {
		if stop[t] || retrievalStop[t] || t == "был" || t == "была" || t == "было" {
			continue
		}
		tv := vecFor(t)
		for i := range mean {
			mean[i] += tv[i]
		}
		pieces = append(pieces, t)
		tokVecs = append(tokVecs, tv)
	}
	if len(tokVecs) == 1 {
		tv := vecFor(s)
		mean = append([]float32(nil), tv...)
		tokVecs = append(tokVecs, tv)
	}
	mean = norm(mean)
	pieces = append(pieces, "[SEP]")
	tokVecs = append(tokVecs, make([]float32, dim))
	return &semai.Encoding{Pieces: pieces, CLS: mean, Mean: mean, Tokens: tokVecs}
}

func checkJudgementInvariants(t *testing.T, j Judgement) {
	t.Helper()
	if j.Entail < 0 || j.Entail > 1 || j.Neutral < 0 || j.Neutral > 1 || j.Contra < 0 || j.Contra > 1 {
		t.Fatalf("judgement out of [0,1] bounds: %+v", j)
	}
	sum := j.Entail + j.Neutral + j.Contra
	if math.Abs(sum-1) > 1e-6 {
		t.Fatalf("judgement probabilities do not sum to 1 (got %.6f): %+v", sum, j)
	}
}

// 1. «Лена выше Тимура» и «Тимур выше Лены» не могут быть подтверждены одновременно;
// противоречие между кусками даёт высокий Neutral и неуверенность.
func TestContradictoryHypothesesAndChunks(t *testing.T) {
	b := newCachedEmbedBackend()
	js := b.JudgeBatch([]Pair{
		{Premise: "Лена выше Тимура.", Hypothesis: "Лена выше Тимура"},
		{Premise: "Лена выше Тимура.", Hypothesis: "Тимур выше Лены"},
	})
	for _, j := range js {
		checkJudgementInvariants(t, j)
	}
	if js[0].Entail < 0.8 || js[1].Entail > 0.1 || js[1].Contra < 0.8 {
		t.Fatalf("expected first confirmed and inverse refuted, got js[0]=%+v js[1]=%+v", js[0], js[1])
	}

	// Противоречие между двумя чанками текста (>45 слов между фактами)
	filler1 := "В первом разделе отчёта подробно рассматриваются результаты плановых замеров участников спортивной секции за прошлый сезон в городском центре подготовки резерва."
	filler2 := "Во втором разделе отчёта приводятся альтернативные протоколы измерений от независимой судейской бригады после повторной сверки антропометрических таблиц на сборах."
	state := filler1 + " Лена выше Тимура. " + filler2 + " Тимур выше Лены."

	e := NewEngine(b, DefaultCalibration())
	e.NoLex = true
	e.MaxChunkWords = 20
	resp, err := e.Decide(req(t, `{
		"state": `+`"`+state+`"`+`,
		"questions": {
			"lena": {"type": "noul", "instructions": "Лена выше Тимура?"},
			"timur": {"type": "noul", "instructions": "Тимур выше Лены?"},
			"who": {
				"type": "choice",
				"instructions": "Кто выше?",
				"criteria": {
					"lena": "Лена выше Тимура",
					"timur": "Тимур выше Лены",
					"other": "Другое"
				}
			}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	pLena := *resp.Answers["lena"].Noul
	pTimur := *resp.Answers["timur"].Noul
	if pLena > 0.6 || pTimur > 0.6 {
		t.Fatalf("contradictory chunks must not confirm either hypothesis: lena=%.4f timur=%.4f", pLena, pTimur)
	}
	if resp.Answers["lena"].Route != "human" || resp.Answers["timur"].Route != "human" {
		t.Fatalf("expected human route on contradiction, got lena=%s timur=%s", resp.Answers["lena"].Route, resp.Answers["timur"].Route)
	}
	if got := resp.Answers["who"]; got.Choice != "other" || !got.Abstained || got.Route != "human" {
		t.Fatalf("expected abstention on contradictory choice, got %+v", got)
	}
}

// 2. Нерелевантный гипотезе текст даёт высокий Neutral и низкий Contra (а не «опровергнуто»).
func TestUnrelatedTextProducesHighNeutralLowContra(t *testing.T) {
	b := newCachedEmbedBackend()
	js := b.JudgeBatch([]Pair{
		{Premise: "На улице с утра идёт тёплый грибной дождь и дует южный ветер.", Hypothesis: "Магазин закрыт сегодня"},
	})
	checkJudgementInvariants(t, js[0])
	if js[0].Neutral < 0.8 || js[0].Contra > 0.1 || js[0].Entail > 0.1 {
		t.Fatalf("expected high Neutral and low Contra on unrelated text, got %+v", js[0])
	}

	e := NewEngine(b, DefaultCalibration())
	e.NoLex = true
	resp, err := e.Decide(req(t, `{
		"state": "На улице с утра идёт тёплый грибной дождь и дует южный ветер.",
		"questions": {
			"q": {"type": "noul", "instructions": "Магазин закрыт сегодня?"}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	got := resp.Answers["q"]
	if math.Abs(*got.Noul-0.5) > 0.1 || got.Route != "human" {
		t.Fatalf("unrelated text should stay uncertain (~0.5) and route to human, got noul=%.4f route=%s", *got.Noul, got.Route)
	}
}

// 3. Привязка времени и отрицания: «магазин был закрыт вчера» не подтверждает «магазин закрыт сегодня»;
// «Артём не прошёл» не подтверждает «Артём прошёл».
func TestTemporalAndNegationConstraints(t *testing.T) {
	b := newCachedEmbedBackend()
	js := b.JudgeBatch([]Pair{
		{Premise: "Магазин был закрыт вчера.", Hypothesis: "Магазин закрыт сегодня"},
		{Premise: "Артём не прошёл.", Hypothesis: "Артём прошёл"},
	})
	for _, j := range js {
		checkJudgementInvariants(t, j)
	}
	if js[0].Entail >= minSubstantiveSupport || js[0].Neutral < 0.5 {
		t.Fatalf("temporal mismatch must not confirm hypothesis: %+v", js[0])
	}
	if js[1].Entail >= minSubstantiveSupport || js[1].Contra < 0.8 {
		t.Fatalf("negated premise must refute affirmative hypothesis: %+v", js[1])
	}

	e := NewEngine(b, DefaultCalibration())
	e.NoLex = true
	respTime, err := e.Decide(req(t, `{
		"state": "Магазин был закрыт вчера.",
		"questions": {
			"shop": {"type": "noul", "instructions": "Магазин закрыт сегодня?"}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if *respTime.Answers["shop"].Noul >= 0.5 {
		t.Fatalf("yesterday state must not confirm today hypothesis: noul=%.4f", *respTime.Answers["shop"].Noul)
	}

	respNeg, err := e.Decide(req(t, `{
		"state": "Артём не прошёл.",
		"questions": {
			"artem": {"type": "noul", "instructions": "Артём прошёл?"}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if *respNeg.Answers["artem"].Noul > 0.15 {
		t.Fatalf("negated state must refute hypothesis: noul=%.4f", *respNeg.Answers["artem"].Noul)
	}
}

// 4. Один и тот же факт в начале, середине и конце длинного текста даёт одинаковый ответ.
func TestFactPositionInvarianceInLongText(t *testing.T) {
	fact := "Сервер резервного копирования успешно прошёл проверку."
	chunks := []string{
		"Первый фоновый абзац описывает расписание дежурств инженеров технической поддержки в зимний период.",
		"Второй фоновый абзац содержит сведения о закупке новых офисных кресел и столов для переговорной комнаты.",
		"Третий фоновый абзац перечисляет правила оформления командировочных удостоверений в бухгалтерии предприятия.",
		"Четвёртый фоновый абзац посвящён графику полива комнатных растений и уборки коридоров на третьем этаже.",
		"Пятый фоновый абзац рассказывает о меню в корпоративной столовой на следующую рабочую неделю.",
		"Шестой фоновый абзац напоминает сотрудникам о необходимости вовремя сдавать книги в техническую библиотеку.",
	}

	buildState := func(pos int) string {
		var parts []string
		parts = append(parts, chunks[:pos]...)
		parts = append(parts, fact)
		parts = append(parts, chunks[pos:]...)
		return strings.Join(parts, " ")
	}

	states := []string{
		buildState(0),               // начало
		buildState(len(chunks) / 2), // середина
		buildState(len(chunks)),     // конец
	}

	b := newCachedEmbedBackend()
	e := NewEngine(b, DefaultCalibration())
	e.NoLex = true
	e.MaxChunkWords = 15

	var wantNoul float64
	var wantRoute string
	for idx, st := range states {
		resp, err := e.Decide(req(t, `{
			"state": "`+st+`",
			"questions": {
				"q": {"type": "noul", "instructions": "Сервер резервного копирования успешно прошёл проверку?"}
			}
		}`))
		if err != nil {
			t.Fatal(err)
		}
		got := resp.Answers["q"]
		if *got.Noul < 0.85 {
			t.Fatalf("pos %d: expected strong confirmation, got noul=%.4f", idx, *got.Noul)
		}
		if idx == 0 {
			wantNoul = *got.Noul
			wantRoute = got.Route
		} else if math.Abs(*got.Noul-wantNoul) > 0.01 || got.Route != wantRoute {
			t.Fatalf("pos %d answer differs from pos 0 beyond tolerance: got (%.4f, %s), want (%.4f, %s)", idx, *got.Noul, got.Route, wantNoul, wantRoute)
		}
	}
}

// 5. Double negation reads as support: the negation scopes the tested
// predicate ("not CLOSED" vs "open"), so the XOR still resolves to support.
// A cue scoping another fact ("no BACKUP ... DELETE" vs "reversible") must
// not cancel the relation signal (decision-blind blind-0).
func TestDoubleNegationIsSupport(t *testing.T) {
	b := newCachedEmbedBackend()
	js := b.JudgeBatch([]Pair{
		{Premise: "The store is not closed.", Hypothesis: "The store is open"},
		{Premise: "The store is open.", Hypothesis: "The store is not closed"},
	})
	for i, j := range js {
		checkJudgementInvariants(t, j)
		if j.Entail <= j.Contra {
			t.Fatalf("pair %d: scoped negation must support, got %+v", i, j)
		}
	}

	e := NewEngine(b, DefaultCalibration())
	e.NoLex = true
	resp, err := e.Decide(req(t, `{
		"state": "The store is not closed.",
		"questions": {
			"q": {"type": "noul", "instructions": "The store is open?"}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Answers["q"]; *got.Noul <= 0.5 {
		t.Fatalf("scoped negation must confirm, got noul=%.4f", *got.Noul)
	}
}
