package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
)

func decodeStrict(data []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected exactly one JSON document")
	}
	return nil
}
func numeric(v any) (float64, bool) {
	var n float64
	switch x := v.(type) {
	case json.Number:
		var e error
		n, e = x.Float64()
		if e != nil {
			return 0, false
		}
	case float64:
		n = x
	case int:
		n = float64(x)
	case int64:
		n = float64(x)
	default:
		return 0, false
	}
	return n, !math.IsInf(n, 0) && !math.IsNaN(n)
}
func equal(a, b any) bool {
	if x, ok := numeric(a); ok {
		y, yes := numeric(b)
		return yes && x == y
	}
	return reflect.DeepEqual(a, b)
}
func lookup(s map[string]any, path string) (any, bool) {
	var cur any = s
	for _, k := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// -1 = unknown, 0 = false, 1 = true; absent data never turns into a false fact.
func condition(s map[string]any, c Condition) (int, string) {
	v, ok := lookup(s, c.Field)
	if c.Op == "exists" {
		want, _ := c.Value.(bool)
		if ok == want {
			return 1, c.Field + ": exists matches"
		}
		return 0, c.Field + ": exists differs"
	}
	if !ok {
		return -1, c.Field + ": отсутствует"
	}
	result := false
	switch c.Op {
	case "eq":
		result = equal(v, c.Value)
	case "ne":
		result = !equal(v, c.Value)
	case "gt", "gte", "lt", "lte":
		a, aok := numeric(v)
		b, bok := numeric(c.Value)
		if !aok || !bok {
			return -1, c.Field + ": требуется число"
		}
		switch c.Op {
		case "gt":
			result = a > b
		case "gte":
			result = a >= b
		case "lt":
			result = a < b
		case "lte":
			result = a <= b
		}
	case "in":
		xs, _ := c.Value.([]any)
		for _, x := range xs {
			if equal(v, x) {
				result = true
			}
		}
	}
	if result {
		return 1, c.Field + " " + c.Op + " " + fmt.Sprint(c.Value)
	}
	return 0, c.Field + ": условие не выполнено"
}
func all(s map[string]any, cs []Condition) (int, []string) {
	if len(cs) == 0 {
		return -1, []string{"ветка не задана"}
	}
	state := 1
	reasons := []string{}
	for _, c := range cs {
		x, r := condition(s, c)
		reasons = append(reasons, r)
		if x == 0 {
			state = 0
		} else if x < 0 && state != 0 {
			state = -1
		}
	}
	return state, reasons
}
func AnswerQuestion(s map[string]any, q Question) Answer {
	t, tr := all(s, q.TrueWhen)
	f, fr := all(s, q.FalseWhen)
	// Keep the branch visible: a flat list mixes both branches and reads as
	// contradictory (e.g. "tests.passed eq true" next to
	// "tests.passed: условие не выполнено" — the latter belongs to false_when).
	reasons := make([]string, 0, len(tr)+len(fr))
	for _, r := range tr {
		reasons = append(reasons, "true_when: "+r)
	}
	for _, r := range fr {
		reasons = append(reasons, "false_when: "+r)
	}
	a := Answer{Question: q.Text, State: "unknown", Reasons: reasons}
	if t == 1 && f == 1 {
		a.State = "conflict"
	} else if t == 1 && f == 0 {
		a.State = "true"
	} else if f == 1 && t == 0 {
		a.State = "false"
	}
	return a
}
func validateCondition(c Condition) error {
	if strings.TrimSpace(c.Field) == "" {
		return fmt.Errorf("condition field is empty")
	}
	switch c.Op {
	case "eq", "ne":
	case "gt", "gte", "lt", "lte":
		if _, ok := numeric(c.Value); !ok {
			return fmt.Errorf("%s needs numeric value", c.Op)
		}
	case "exists":
		if _, ok := c.Value.(bool); !ok {
			return fmt.Errorf("exists needs boolean value")
		}
	case "in":
		if _, ok := c.Value.([]any); !ok {
			return fmt.Errorf("in needs an array")
		}
	default:
		return fmt.Errorf("unsupported operator %q", c.Op)
	}
	return nil
}
func finite(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }
func integer(s string) (int64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(strings.TrimSuffix(s, "L"), "l")
	sign := int64(1)
	if strings.HasPrefix(s, "-") {
		sign = -1
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		base = 16
		s = s[2:]
	}
	n, e := strconv.ParseInt(s, base, 64)
	if e != nil {
		return 0, e
	}
	if sign == 1 && base == 16 && n > 2147483647 && n <= 4294967295 {
		n -= 4294967296
	}
	return sign * n, nil
}
