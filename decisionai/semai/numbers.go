package semai

import (
	"strconv"
	"strings"
)

// Num is a numeric mention found in text (digits, decimals, fractions or ru/en number words).
type Num struct {
	Val        float64
	T0, T1     int // token range [T0,T1)
	Fractional bool
}

var unitWords = map[string]float64{
	"ноль": 0, "нуль": 0, "zero": 0,
	"один": 1, "одна": 1, "одно": 1, "одну": 1, "одного": 1, "одной": 1, "one": 1,
	"два": 2, "две": 2, "двух": 2, "двум": 2, "two": 2,
	"три": 3, "трех": 3, "трем": 3, "three": 3,
	"четыре": 4, "четырех": 4, "четырем": 4, "four": 4,
	"пять": 5, "пяти": 5, "five": 5, "шесть": 6, "шести": 6, "six": 6, "семь": 7, "семи": 7, "seven": 7,
	"восемь": 8, "восьми": 8, "eight": 8, "девять": 9, "девяти": 9, "nine": 9, "десять": 10, "десяти": 10, "ten": 10,
	"одиннадцать": 11, "eleven": 11, "двенадцать": 12, "twelve": 12, "тринадцать": 13, "thirteen": 13,
	"четырнадцать": 14, "fourteen": 14, "пятнадцать": 15, "fifteen": 15, "шестнадцать": 16, "sixteen": 16,
	"семнадцать": 17, "seventeen": 17, "восемнадцать": 18, "eighteen": 18, "девятнадцать": 19, "nineteen": 19,
}
var tensWords = map[string]float64{
	"двадцать": 20, "twenty": 20, "тридцать": 30, "thirty": 30, "сорок": 40, "forty": 40, "пятьдесят": 50, "fifty": 50,
	"шестьдесят": 60, "sixty": 60, "семьдесят": 70, "seventy": 70, "восемьдесят": 80, "eighty": 80, "девяносто": 90, "ninety": 90,
}
var hundredWords = map[string]float64{"сто": 100, "hundred": 100, "двести": 200, "триста": 300, "четыреста": 400, "пятьсот": 500, "шестьсот": 600, "семьсот": 700, "восемьсот": 800, "девятьсот": 900}
var fracWords = map[string]float64{
	"полтора": 1.5, "полторы": 1.5, "полутора": 1.5, "половина": 0.5, "половины": 0.5, "половину": 0.5, "половиной": 0.5, "половинка": 0.5, "половинки": 0.5, "пол": 0.5, "half": 0.5,
	"треть": 1.0 / 3, "трети": 1.0 / 3, "third": 1.0 / 3, "четверть": 0.25, "четверти": 0.25, "quarter": 0.25,
}

// FindNumbers scans tokens for numeric mentions.
func FindNumbers(toks []string) []Num {
	var out []Num
	for i := 0; i < len(toks); {
		t := toks[i]
		var n Num
		ok := false
		switch {
		case isNumTok(t):
			n, ok = parseNumTok(t, i)
			// "3 1/2"
			if ok && !n.Fractional && i+1 < len(toks) && strings.Contains(toks[i+1], "/") && isNumTok(toks[i+1]) {
				if f, ok2 := parseNumTok(toks[i+1], i+1); ok2 && f.Val < 1 {
					n.Val += f.Val
					n.T1 = i + 2
					n.Fractional = true
				}
			}
		case isWord(t):
			n, ok = parseWordNum(toks, i)
		}
		if !ok {
			i++
			continue
		}
		// "три с половиной", "three and a half"
		j := n.T1
		if j+1 < len(toks) && (toks[j] == "с" || toks[j] == "и") && (toks[j+1] == "половиной" || toks[j+1] == "половинкой" || toks[j+1] == "половина") {
			n.Val += 0.5
			n.T1 = j + 2
			n.Fractional = true
		} else if j+2 < len(toks) && toks[j] == "and" && toks[j+1] == "a" && toks[j+2] == "half" {
			n.Val += 0.5
			n.T1 = j + 3
			n.Fractional = true
		} else if j+1 < len(toks) && toks[j] == "and" && toks[j+1] == "half" {
			n.Val += 0.5
			n.T1 = j + 2
			n.Fractional = true
		}
		out = append(out, n)
		i = n.T1
	}
	return out
}

func parseNumTok(t string, i int) (Num, bool) {
	if k := strings.Index(t, "/"); k > 0 {
		a, e1 := strconv.ParseFloat(strings.Replace(t[:k], ",", ".", 1), 64)
		b, e2 := strconv.ParseFloat(t[k+1:], 64)
		if e1 != nil || e2 != nil || b == 0 {
			return Num{}, false
		}
		return Num{Val: a / b, T0: i, T1: i + 1, Fractional: a/b != float64(int64(a/b))}, true
	}
	v, err := strconv.ParseFloat(strings.Replace(t, ",", ".", 1), 64)
	if err != nil {
		return Num{}, false
	}
	return Num{Val: v, T0: i, T1: i + 1, Fractional: v != float64(int64(v))}, true
}

func parseWordNum(toks []string, i int) (Num, bool) {
	t := toks[i]
	if v, ok := fracWords[t]; ok {
		n := Num{Val: v, T0: i, T1: i + 1, Fractional: v != float64(int64(v))}
		// "три четверти"
		if i > 0 && (t == "четверти" || t == "трети") {
			if u, ok := unitWords[toks[i-1]]; ok {
				n.Val = u * v
				n.T0 = i - 1
			}
		}
		return n, true
	}
	total, found, j := 0.0, false, i
	for ; j < len(toks); j++ {
		w := toks[j]
		if v, ok := hundredWords[w]; ok && (!found || v >= 100) {
			total += v
			found = true
		} else if v, ok := tensWords[w]; ok {
			total += v
			found = true
		} else if v, ok := unitWords[w]; ok && (!found || (v < 10 && v > 0)) {
			total += v
			found = true
		} else {
			break
		}
	}
	if !found {
		return Num{}, false
	}
	// "two thousand"
	if j < len(toks) && (toks[j] == "тысяч" || toks[j] == "тысячи" || toks[j] == "тысяча" || toks[j] == "thousand") {
		if total == 0 {
			total = 1
		}
		total *= 1000
		j++
	}
	return Num{Val: total, T0: i, T1: j}, true
}
