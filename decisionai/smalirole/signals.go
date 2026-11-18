package smalirole

import (
	"math"
	"strings"
	"unicode"
)

// Labels is the fixed output schema (like a Jev enum). Order is stable and part of the model format.
var Labels = []string{
	"bitmask", "flag_bit", "sentinel", "color_argb", "layout_param", "boolean",
	"limit_threshold", "counter_step", "duration_ms", "resource_id", "index_or_size",
	"api_constant", "unknown",
}

func labelIndex(l string) int {
	for i, x := range Labels {
		if x == l {
			return i
		}
	}
	return len(Labels) - 1
}

func hasAny(s string, xs ...string) bool {
	for _, x := range xs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// camelTokens splits "setTextColor" / "MAX_RETRY" into lower-case words.
func camelTokens(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 1 {
			out = append(out, strings.ToLower(string(cur)))
		}
		cur = cur[:0]
	}
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case !unicode.IsLetter(r):
			flush()
		case unicode.IsUpper(r) && i > 0 && unicode.IsLower(rs[i-1]):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

// UseSignals turns one use into atomic, explainable signals. They are both rule evidence and model features.
func UseSignals(u Use, v int64) []string {
	op, raw := u.Insn.Op, u.Insn.Raw
	base := strings.SplitN(op, "/", 2)[0]
	var s []string
	add := func(x ...string) { s = append(s, x...) }
	if hasAny(op, "-float", "-double", "cmpl-", "cmpg-") {
		add("op:float") // the 32 bits are an IEEE float (0x3f800000 = 1.0f), not an int
	}
	switch {
	case hasAny(base, "and-int", "and-long"):
		add("op:and")
	case hasAny(base, "or-int", "or-long") && !strings.HasPrefix(base, "xor"):
		add("op:or")
	case hasAny(base, "xor-int", "xor-long"):
		add("op:xor")
	case hasAny(base, "shl-", "shr-", "ushr-"):
		if u.Pos == len(u.Insn.Regs)-1 && len(u.Insn.Regs) > 1 {
			add("op:shift_amount")
		} else {
			add("op:shifted")
		}
	case hasAny(base, "add-", "sub-", "rsub-"):
		add("op:addsub")
	case hasAny(base, "mul-", "div-", "rem-"):
		add("op:muldiv")
	case hasAny(base, "int-to-", "long-to-", "float-to-", "double-to-"):
		add("op:convert")
	case strings.HasPrefix(op, "if-") && len(u.Insn.Regs) == 2:
		kind := "order"
		if strings.HasPrefix(op, "if-eq") || strings.HasPrefix(op, "if-ne") {
			kind = "eq"
		}
		add("cmp:" + kind)
		if v == -1 && kind == "eq" {
			add("cmp:eq_neg1")
		}
		o := u.Other
		switch {
		case strings.HasPrefix(o, "result:"):
			add("cmpwith:result")
			for _, t := range camelTokens(o[7:]) {
				add("cmpwith:tok:" + t)
			}
		case strings.HasPrefix(o, "field:"):
			add("cmpwith:field")
			if o == "field:SDK_INT" {
				add("cmpwith:sdk_int") // Build.VERSION.SDK_INT: the literal is an Android API level
			}
			for _, t := range camelTokens(o[6:]) {
				add("cmpwith:tok:" + t)
			}
		case o == "param":
			add("cmpwith:param")
		case strings.HasPrefix(o, "aget"):
			add("cmpwith:array")
		case strings.Contains(o, "array-length"):
			add("cmpwith:length")
		}
	case strings.HasPrefix(op, "if-"):
		add("cmp:zero_self")
	case strings.HasPrefix(op, "return"):
		add("ret")
	case strings.HasPrefix(op, "new-array"):
		add("newarray")
	case strings.HasPrefix(op, "aget"), strings.HasPrefix(op, "aput") && u.Pos == 2:
		add("aindex")
	case strings.HasPrefix(op, "aput"):
		add("astore")
	case strings.HasPrefix(op, "iput"), strings.HasPrefix(op, "sput"):
		if f := fieldRE.FindStringSubmatch(raw); f != nil {
			add("field:type:" + f[2])
			if isEnumCodeName(f[1]) {
				add("field:enum_code")
			}
			for _, t := range camelTokens(f[1]) {
				add("field:tok:" + t)
			}
		}
	case strings.HasPrefix(op, "invoke"):
		mm := invokeRE.FindStringSubmatch(raw)
		if mm == nil {
			break
		}
		cls := mm[1][strings.LastIndex(mm[1], "/")+1:]
		cls = strings.TrimSuffix(cls, ";")
		arg := u.Pos
		if !strings.HasPrefix(op, "invoke-static") {
			arg--
		}
		ps := SplitDescriptors(mm[3])
		slot := 0
		for _, p := range ps {
			if slot == arg {
				add("arg:type:" + p)
				break
			}
			slot++
			if p == "J" || p == "D" {
				slot++
			}
		}
		if arg < 0 {
			add("arg:receiver")
		}
		add("call:" + strings.ToLower(mm[2]))
		for _, p := range ps {
			if p == "J" {
				add("call:haswide")
				break
			}
		}
		if strings.Contains(mm[3], "Ljava/util/concurrent/TimeUnit;") {
			add("call:timeunit")
		}
		for _, t := range camelTokens(mm[2]) {
			add("call:tok:" + t)
		}
		for _, t := range camelTokens(cls) {
			add("callcls:tok:" + t)
		}
		if strings.HasPrefix(mm[1], "Landroid/") || strings.HasPrefix(mm[1], "Ljava/") || strings.HasPrefix(mm[1], "Landroidx/") {
			add("call:platform")
		}
	case strings.HasPrefix(op, "packed-switch"), strings.HasPrefix(op, "sparse-switch"):
		add("switch")
	case strings.HasPrefix(op, "move"):
		return nil
	}
	if u.Depth > 0 {
		for i := range s {
			s[i] = "callee:" + s[i]
		}
	}
	return s
}

// LiteralSignals describe the literal's shape, independent of how it is used.
func LiteralSignals(lit string, v int64, u uint64, op string) []string {
	hex := strings.Contains(strings.ToLower(lit), "0x")
	s := []string{"lit:op:" + op}
	if strings.HasPrefix(op, "const-wide") {
		s = append(s, "lit:wide")
		if v >= 1000 && v%1000 == 0 {
			s = append(s, "lit:wide_round1000")
		}
	}
	switch {
	case v == -1:
		s = append(s, "lit:neg1")
	case v == -2:
		s = append(s, "lit:neg2")
	case v == 0:
		s = append(s, "lit:zero")
	case v == 1:
		s = append(s, "lit:one")
	case v == math.MaxInt32 || v == math.MaxInt64:
		s = append(s, "lit:intmax")
	case v < 0:
		s = append(s, "lit:negative")
	}
	if hex {
		s = append(s, "lit:hex")
	}
	if u>>24 == 0x7f {
		s = append(s, "lit:pkg7f")
	}
	if u>>24 == 0x01 {
		s = append(s, "lit:pkg01")
	}
	if u>>24 >= 0x80 && v != -1 {
		s = append(s, "lit:highbyte")
	}
	if v > 1 && v&(v-1) == 0 {
		s = append(s, "lit:pow2")
	}
	if v > 0 && (v+1)&v == 0 && v > 1 {
		s = append(s, "lit:lowmask") // 0xff, 0xffff …
	}
	if v >= 100 && v%100 == 0 {
		s = append(s, "lit:round100")
	}
	if v >= 1000 && v%1000 == 0 {
		s = append(s, "lit:round1000")
	}
	a := math.Abs(float64(v))
	s = append(s, "lit:mag:"+itoa(int(math.Min(10, math.Floor(math.Log10(a+1)*1.5)))))
	return s
}

// Oracle derives a training label only from strong, typed sinks (weak supervision).
// It returns the label and the index of the use that decided it (-1: literal itself), or "" when unsure.
func Oracle(sigs [][]string, v int64, isResource bool, m *Method) (string, int) {
	if isResource {
		return "resource_id", -1
	}
	if IsFloatUse(sigs) { // float literals have different roles; keep them out of the int schema
		return "", -1
	}
	has := func(i int, x string) bool {
		for _, s := range sigs[i] {
			if s == x || s == "callee:"+x {
				return true
			}
		}
		return false
	}
	hasPrefix := func(i int, p string) bool {
		for _, s := range sigs[i] {
			if strings.HasPrefix(strings.TrimPrefix(s, "callee:"), p) {
				return true
			}
		}
		return false
	}
	type rule struct {
		label string
		ok    func(i int) bool
	}
	rules := []rule{
		{"boolean", func(i int) bool {
			return has(i, "arg:type:Z") || has(i, "field:type:Z") || (contains(sigs[i], "ret") && m.Ret == "Z")
		}},
		{"color_argb", func(i int) bool {
			return has(i, "call:rgb") || has(i, "call:argb") || (has(i, "call:tok:color") || has(i, "call:tok:tint") || has(i, "field:tok:color")) && !has(i, "arg:type:Z") && !takesResource(i, has)
		}},
		{"layout_param", func(i int) bool { return has(i, "callcls:tok:params") && (v == -1 || v == -2) }},
		{"duration_ms", func(i int) bool { return isTimingSink(sigs[i]) && !looksLikeResource(v) && v >= 0 }},
		{"api_constant", func(i int) bool {
			return has(i, "call:addflags") || has(i, "call:setflags") || has(i, "call:setvisibility") || has(i, "call:setgravity") || has(i, "call:setinputtype")
		}},
		{"index_or_size", func(i int) bool { return has(i, "newarray") || has(i, "aindex") }},
		{"sentinel", func(i int) bool { return has(i, "cmp:eq_neg1") }},
		{"bitmask", func(i int) bool {
			return (has(i, "op:and") || has(i, "op:xor")) && v != 1 && v != 0
		}},
		{"flag_bit", func(i int) bool { return has(i, "op:or") && v > 1 && v&(v-1) == 0 }},
		{"api_constant", func(i int) bool { return has(i, "cmpwith:sdk_int") || has(i, "field:enum_code") }},
		{"limit_threshold", func(i int) bool { return has(i, "cmp:order") && !hasPrefix(i, "cmpwith:array") }},
		{"counter_step", func(i int) bool { return has(i, "op:addsub") }},
	}
	for _, r := range rules {
		for i := range sigs {
			if r.ok(i) {
				return r.label, i
			}
		}
	}
	return "", -1
}

// timingCalls receive a duration/timeout/delay. Many take a long (J), which is why const-wide matters.
var timingCalls = []string{"sleep", "postdelayed", "postatfrontofqueue", "sendmessagedelayed", "sendemptymessagedelayed", "setduration",
	"setstartdelay", "setconnecttimeout", "setreadtimeout", "setsotimeout", "connecttimeout", "readtimeout", "writetimeout", "calltimeout",
	"awaittermination", "await", "join", "poll", "schedule", "scheduleatfixedrate", "schedulewithfixeddelay", "setminimumlatency",
	"setperiodic", "setoverridedeadline", "setexact", "setrepeating", "setinexactrepeating", "setwindow", "setandallowwhileidle",
	"withtimeout", "delay", "timeout", "setinterval", "setfastestinterval", "setmaxwaittime", "setkeepalive", "setlonglivedtimeout",
	"setautocanceltimeout", "settimeoutafter", "vibrate", "postframecallbackdelayed", "setanimationduration"}

// notTimingCalls look like timing APIs by name but the traced value is not a duration
// (getters take an index/flags, Calendar takes an absolute timestamp, conversions take another unit).
var notTimingCalls = []string{"settimeinmillis", "gettimeinmillis", "settime", "getduration", "getrecommendedtimeoutmillis",
	"tomillis", "toseconds", "tominutes", "tohours", "todays", "tonanos", "tomicros", "convert", "currenttimemillis", "elapsedrealtime",
	"uptimemillis", "nanotime", "setoffset", "setoffSet"}

// isEnumCodeName: UPPER_SNAKE constants such as LOG_OUT_REASON_LOGIN_TIMEOUT or ERROR_TIMEOUT are codes,
// even when a token says "timeout" (found on a real APK: GameApp.LOG_OUT_REASON_LOGIN_TIMEOUT = 4).
func isEnumCodeName(n string) bool {
	if n != strings.ToUpper(n) || !strings.Contains(n, "_") {
		return false
	}
	for _, t := range strings.Split(n, "_") {
		switch t {
		case "REASON", "TYPE", "CODE", "STATE", "STATUS", "MODE", "KIND", "ERROR", "ERR", "EVENT", "ACTION", "MSG", "WHAT", "RESULT", "CAUSE", "ID":
			return true
		}
	}
	return false
}

func isTimingSink(sg []string) bool {
	for _, x := range sg {
		if x == "field:enum_code" || x == "callee:field:enum_code" {
			return false
		}
	}
	typed := false // the traced value must be passed/stored as int or long
	wideCall := false
	for _, x := range sg {
		if strings.TrimPrefix(x, "callee:") == "call:haswide" {
			wideCall = true
		}
	}
	for _, x := range sg {
		x = strings.TrimPrefix(x, "callee:")
		if wideCall && x == "arg:type:I" {
			return false // e.g. sendEmptyMessageDelayed(IJ): the int is message.what, the long is the delay
		}
		if x == "arg:receiver" {
			return false
		}
		if x == "arg:type:J" || x == "arg:type:I" || x == "field:type:J" || x == "field:type:I" {
			typed = true
		}
		if strings.HasPrefix(x, "call:") && !strings.Contains(x, "tok:") {
			name := x[5:]
			if strings.HasPrefix(name, "get") || strings.HasPrefix(name, "is") || strings.HasPrefix(name, "access$") || strings.HasPrefix(name, "new") {
				return false
			}
			for _, n := range notTimingCalls {
				if name == strings.ToLower(n) {
					return false
				}
			}
		}
	}
	if !typed {
		return false
	}
	for _, x := range sg {
		x = strings.TrimPrefix(x, "callee:")
		for _, c := range timingCalls {
			if x == "call:"+c {
				return true
			}
		}
		if x == "call:tok:timeout" || x == "call:tok:delay" || x == "call:tok:duration" || x == "call:tok:millis" || x == "call:tok:interval" ||
			x == "field:tok:timeout" || x == "field:tok:delay" || x == "field:tok:duration" || x == "field:tok:interval" || x == "field:tok:millis" {
			return true
		}
	}
	return false
}

// resourceCalls take an R.* id, not a raw value (getColor(R.color.x) gets a resource id!).
var resourceCalls = []string{"getcolor", "getcolorstatelist", "getdrawable", "getstring", "gettext", "getdimension", "getdimensionpixelsize",
	"findviewbyid", "setcontentview", "inflate", "setimageresource", "setbackgroundresource", "settextappearance", "getquantitystring",
	"getinteger", "getboolean", "getstringarray", "getintarray", "makeText", "settitle", "setmessage", "setpositivebutton", "setnegativebutton"}

func takesResource(i int, has func(int, string) bool) bool {
	for _, c := range resourceCalls {
		if has(i, "call:"+strings.ToLower(c)) {
			return true
		}
	}
	return false
}

func init() {
	for _, c := range timingCalls {
		expertVotes["call:"+c] = map[string]float64{"duration_ms": 3.0}
	}
	for _, c := range resourceCalls {
		expertVotes["call:"+strings.ToLower(c)] = map[string]float64{"resource_id": 2.5}
	}
}

// expertVotes are the hand-written rule weights (logit units). They are used on top of the learned model.
var expertVotes = map[string]map[string]float64{
	"op:and": {"bitmask": 2.5}, "op:xor": {"bitmask": 2.0}, "op:or": {"bitmask": 1.4, "flag_bit": 1.2},
	"op:shifted": {"bitmask": 1.0}, "op:shift_amount": {"bitmask": 0.6},
	"op:addsub": {"counter_step": 2.0}, "op:muldiv": {"counter_step": 0.6, "limit_threshold": 0.4},
	"cmp:order": {"limit_threshold": 2.5}, "cmp:eq_neg1": {"sentinel": 3.0}, "cmp:eq": {"sentinel": 0.6, "api_constant": 0.6},
	"newarray": {"index_or_size": 3.0}, "aindex": {"index_or_size": 3.0},
	"arg:type:Z": {"boolean": 3.5}, "field:type:Z": {"boolean": 3.5},
	"call:tok:color": {"color_argb": 3.0}, "call:rgb": {"color_argb": 3.0}, "call:argb": {"color_argb": 3.0}, "call:tok:tint": {"color_argb": 2.0}, "field:tok:color": {"color_argb": 2.5},
	"callcls:tok:params": {"layout_param": 1.5},
	"call:sleep":         {"duration_ms": 3.5}, "call:postdelayed": {"duration_ms": 3.5}, "call:setduration": {"duration_ms": 3.5},
	"call:tok:timeout": {"duration_ms": 3.0}, "call:tok:delay": {"duration_ms": 2.5}, "field:tok:timeout": {"duration_ms": 2.5},
	"call:addflags": {"api_constant": 3.0}, "call:setflags": {"api_constant": 3.0}, "call:setvisibility": {"api_constant": 3.0},
	"call:setgravity": {"api_constant": 3.0}, "call:setinputtype": {"api_constant": 3.0},
	"field:tok:max": {"limit_threshold": 2.0}, "field:tok:limit": {"limit_threshold": 2.5}, "call:tok:max": {"limit_threshold": 1.5},
	"lit:pkg7f": {"resource_id": 3.0},
	// literal returned directly by a method whose name describes it
	"ret:self:tok:max": {"limit_threshold": 3.5}, "ret:self:tok:limit": {"limit_threshold": 3.5}, "ret:self:tok:threshold": {"limit_threshold": 3.0},
	"ret:self:tok:cap": {"limit_threshold": 2.0}, "ret:self:tok:min": {"limit_threshold": 2.5},
	"ret:self:tok:timeout": {"duration_ms": 3.5}, "ret:self:tok:delay": {"duration_ms": 3.5}, "ret:self:tok:interval": {"duration_ms": 3.0},
	"ret:self:tok:duration": {"duration_ms": 3.5}, "ret:self:tok:millis": {"duration_ms": 3.0},
	"ret:self:tok:color": {"color_argb": 3.5}, "ret:self:tok:tint": {"color_argb": 2.5},
	"cmpwith:sdk_int": {"api_constant": 6.0}, "field:enum_code": {"api_constant": 4.0},
}

// looksLikeResource: 0x01xxxxxx (android framework) and 0x7fxxxxxx (app) resource ids.
func looksLikeResource(v int64) bool {
	u := uint32(v)
	return (u>>24 == 0x01 || u>>24 == 0x7f) && u&0x00ff0000 != 0
}

// HasTimeUnit reports whether a timing call takes java.util.concurrent.TimeUnit (unit is not necessarily ms).
func HasTimeUnit(sigs [][]string) bool {
	for _, sg := range sigs {
		for _, x := range sg {
			if strings.TrimPrefix(x, "callee:") == "call:timeunit" {
				return true
			}
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// IsFloatUse reports whether the traced bits are consumed as float/double.
func IsFloatUse(sigs [][]string) bool {
	for _, sg := range sigs {
		for _, x := range sg {
			switch strings.TrimPrefix(x, "callee:") {
			case "op:float", "arg:type:F", "field:type:F":
				return true
			}
		}
	}
	return false
}
