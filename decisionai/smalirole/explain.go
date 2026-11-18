package smalirole

import (
	"fmt"
	"strings"
)

var labelRU = map[string]string{
	"bitmask": "битовая маска", "flag_bit": "флаг-бит", "sentinel": "значение-маркер",
	"color_argb": "цвет ARGB", "layout_param": "размер LayoutParams", "boolean": "булево значение",
	"limit_threshold": "порог / лимит", "counter_step": "шаг счётчика / слагаемое", "duration_ms": "длительность / таймаут",
	"resource_id": "ID ресурса", "index_or_size": "индекс или размер", "api_constant": "константа API", "unknown": "не установлено",
}

var labelWhat = map[string]string{
	"bitmask":         "участвует в побитовых операциях: выделяет, сбрасывает или инвертирует биты",
	"flag_bit":        "один бит в наборе флагов, объединяется через or",
	"sentinel":        "служебный маркер: обычно -1 означает «не найдено», «не задано» или «без ограничения»",
	"color_argb":      "цвет в формате 0xAARRGGBB, уходит в API отрисовки",
	"layout_param":    "размер вида: -1 = MATCH_PARENT, -2 = WRAP_CONTENT",
	"boolean":         "true/false (0/1): метод возвращает или передаёт булев флаг",
	"limit_threshold": "граница, с которой сравнивают другое значение",
	"counter_step":    "прибавляется к другому значению или вычитается из него",
	"duration_ms":     "время ожидания, задержки или анимации (обычно в миллисекундах)",
	"resource_id":     "ссылка на ресурс приложения из R.java",
	"index_or_size":   "позиция в массиве или размер нового массива",
	"api_constant":    "именованная константа Android API (флаги Intent, видимость View и т.п.)",
	"unknown":         "по коду метода роль установить не удалось",
}

func literalFacts(lit string, v int64, u uint64) []string {
	var f []string
	if v < 0 || (strings.Contains(strings.ToLower(lit), "0x") && u > 0xffff && u>>24 != 0x7f) {
		f = append(f, fmt.Sprintf("%s = %d как int32 (беззнаково %d, 0x%08X)", lit, v, u, u))
	}
	switch {
	case v == -1:
		f = append(f, "все 32 бита равны 1: x & -1 = x (маска ничего не меняет), x ^ -1 = ~x (инверсия); как цвет — непрозрачный белый")
	case v == 0x7fffffff:
		f = append(f, "это Integer.MAX_VALUE — часто «без ограничения»")
	case u>>24 == 0x7f:
		f = append(f, fmt.Sprintf("формат ресурса 0xPPTTEEEE: пакет 0x7f (приложение), тип 0x%02X, индекс 0x%04X", (u>>16)&0xff, u&0xffff))
	case u>>24 >= 0x80:
		f = append(f, fmt.Sprintf("как цвет: альфа 0x%02X, R 0x%02X, G 0x%02X, B 0x%02X", u>>24, (u>>16)&0xff, (u>>8)&0xff, u&0xff))
	case v > 1 && v&(v-1) == 0:
		f = append(f, fmt.Sprintf("степень двойки: установлен только бит %d", bitIndex(u)))
	}
	return f
}

func bitIndex(u uint64) int {
	n := 0
	for u > 1 {
		u >>= 1
		n++
	}
	return n
}

// Explain generates a grounded Russian explanation from the decision and its evidence.
// Every sentence is built from a traced fact, so the text cannot claim anything the trace did not see.
func Explain(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Строка %d загружает %s в %s.", r.ConstLine, r.Literal, r.Register)
	facts := literalFacts(r.Literal, r.Int32, r.Uint32)
	if r.Wide {
		facts = []string{fmt.Sprintf("это 64-битный литерал (long/double) = %d", r.Int32)}
	}
	for _, f := range facts {
		fmt.Fprintf(&b, " %s.", capitalize(f))
	}
	if len(r.Evidence) == 0 {
		b.WriteString(" Дальше значение в этом методе не читается.")
	} else {
		b.WriteString(" Дальше значение:")
		for i, e := range r.Evidence {
			if i == 6 {
				fmt.Fprintf(&b, " … ещё %d.", len(r.Evidence)-6)
				break
			}
			where := fmt.Sprintf("строка %d", e.Line)
			if e.Via != "" {
				where = "внутри " + e.Via
			}
			sep := ";"
			if i == len(r.Evidence)-1 {
				sep = "."
			}
			fmt.Fprintf(&b, " %s — `%s` (%s)%s", where, e.Text, e.Signal, sep)
		}
	}
	top := r.Probs[0]
	if r.FloatValue != nil {
		fmt.Fprintf(&b, " Вывод: это не целое число, а float %gf (биты 0x%08X по IEEE 754) — роли из int-схемы к нему не применяются.", *r.FloatValue, r.Uint32)
		return b.String()
	}
	if r.Answer == "duration_ms" && !r.Abstained {
		if r.TimeUnit {
			fmt.Fprintf(&b, " Единица задаётся отдельным аргументом TimeUnit — это %d единиц (секунд, минут…), а не обязательно миллисекунд.", r.Int32)
		} else {
			fmt.Fprintf(&b, " Если это миллисекунды: %s.", humanMillis(r.Int32))
		}
	}
	if r.SDKLevel() && r.Answer == "api_constant" {
		fmt.Fprintf(&b, " Сравнивается с Build.VERSION.SDK_INT: это уровень Android API %d%s, а не лимит.", r.Int32, androidName(r.Int32))
	}
	if hasTag(r.Evidence, "field:enum_code") && r.Answer == "api_constant" {
		fmt.Fprintf(&b, " Пишется в именованную константу-код (%s) — это номер варианта, а не время/лимит.", strings.Join(r.Stored, ", "))
	}
	if r.Abstained {
		fmt.Fprintf(&b, " Вывод: уверенно сказать нельзя. Ближе всего «%s» (%.0f%%), но это ниже порога %.0f%%.", labelRU[top.Label], 100*top.P, 100*r.Threshold)
	} else {
		what := labelWhat[r.Answer]
		if r.Answer == "color_argb" && hasTag(r.Evidence, "call:rgb", "call:argb") {
			what = "один канал цвета (0..255), уходит в Color.rgb/argb"
		}
		fmt.Fprintf(&b, " Вывод: %s (%.0f%%) — %s.", labelRU[r.Answer], 100*r.Confidence, what)
	}
	var alts []string
	for _, p := range r.Probs[1:] {
		if p.P >= 0.05 && p.Label != "unknown" && len(alts) < 2 {
			alts = append(alts, fmt.Sprintf("%s %.0f%%", labelRU[p.Label], 100*p.P))
		}
	}
	if len(alts) > 0 {
		fmt.Fprintf(&b, " Альтернативы: %s.", strings.Join(alts, ", "))
	}
	return b.String()
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return strings.ToUpper(string(r[0])) + string(r[1:])
}

func hasTag(ev []Evidence, tags ...string) bool {
	for _, e := range ev {
		for _, t := range e.Tags {
			for _, x := range tags {
				if strings.TrimPrefix(t, "callee:") == x {
					return true
				}
			}
		}
	}
	return false
}

// humanMillis renders a millisecond count as a human duration (assumes ms; Android APIs mostly use ms).
// HumanMillis is exported for patch reports.
func HumanMillis(ms int64) string { return humanMillis(ms) }

func humanMillis(ms int64) string {
	switch {
	case ms < 0:
		return "отрицательное время — обычно значит «без ограничения» или ошибку"
	case ms == 0:
		return "0 мс — без задержки (или «ждать бесконечно» для некоторых API таймаутов)"
	case ms < 1000:
		return fmt.Sprintf("%d мс", ms)
	case ms < 60000:
		return fmt.Sprintf("%.3g с", float64(ms)/1000)
	case ms < 3600000:
		return fmt.Sprintf("%.3g мин", float64(ms)/60000)
	case ms < 86400000:
		return fmt.Sprintf("%.3g ч", float64(ms)/3600000)
	}
	return fmt.Sprintf("%.3g сут", float64(ms)/86400000)
}

func androidName(api int64) string {
	names := map[int64]string{16: "4.1", 17: "4.2", 18: "4.3", 19: "4.4", 21: "5.0", 22: "5.1", 23: "6.0", 24: "7.0", 25: "7.1", 26: "8.0", 27: "8.1",
		28: "9", 29: "10", 30: "11", 31: "12", 32: "12L", 33: "13", 34: "14", 35: "15", 36: "16"}
	if n, ok := names[api]; ok {
		return " (Android " + n + ")"
	}
	return ""
}
