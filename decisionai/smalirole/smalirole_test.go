package smalirole

import (
	"os"
	"strings"
	"testing"
)

func load(t *testing.T, f string) string {
	b, err := os.ReadFile("testdata/" + f + ".smali")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRolesExpertOnly(t *testing.T) {
	cases := []struct {
		file string
		line int
		want string
	}{
		{"mask", 3, "bitmask"}, {"color", 3, "color_argb"}, {"sentinel", 6, "sentinel"},
		{"limit", 3, "limit_threshold"}, {"unused", 3, "unknown"}, {"res", 3, "resource_id"},
	}
	for _, c := range cases {
		r, err := Analyze(Request{Code: load(t, c.file), Line: c.line}, nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if r.Answer != c.want {
			t.Errorf("%s: got %s (%.2f), want %s", c.file, r.Answer, r.Confidence, c.want)
		}
		if !strings.Contains(r.Explanation, "Вывод") {
			t.Errorf("%s: explanation missing conclusion", c.file)
		}
	}
}

func TestBundledModel(t *testing.T) {
	m, err := LoadModel("../models/smalirole-model.json")
	if err != nil {
		t.Skip("no bundled model:", err)
	}
	for _, c := range []struct {
		file, want string
		line       int
	}{{"mask", "bitmask", 3}, {"color", "color_argb", 3}, {"sentinel", "sentinel", 6}, {"res", "resource_id", 3}} {
		r, err := Analyze(Request{Code: load(t, c.file), Line: c.line}, m, nil)
		if err != nil || r.Answer != c.want {
			t.Errorf("%s: got %s %.2f err=%v", c.file, r.Answer, r.Confidence, err)
		}
	}
}

func TestFFFFFFFFIsMinusOne(t *testing.T) {
	v, u, err := parseLiteral("0xFFFFFFFF")
	if err != nil || v != -1 || u != 0xFFFFFFFF {
		t.Fatalf("got %d %d %v", v, u, err)
	}
	if v, _, _ := parseLiteral("-0x80000000"); v != -2147483648 {
		t.Fatal(v)
	}
	if _, _, err := parseLiteral("0xZZ"); err == nil {
		t.Fatal("expected error")
	}
}

func TestInterprocedural(t *testing.T) {
	caller := ParseMethod("LA;", ".method public a()V\n.registers 2\nconst v0, 0xFFFFFFFF\ninvoke-static {v0}, LA;->paint(I)V\nreturn-void\n.end method")
	callee := ParseMethod("LA;", ".method public static paint(I)V\n.registers 3\nnew-instance v0, Landroid/graphics/Paint;\ninvoke-virtual {v0, p0}, Landroid/graphics/Paint;->setColor(I)V\nreturn-void\n.end method")
	res := func(c, n, p string) *Method {
		if n == "paint" {
			return callee
		}
		return nil
	}
	s, ok := NewSite(caller, 0, res)
	if !ok {
		t.Fatal("no site")
	}
	label, _ := Oracle(s.Sigs, s.V, false, caller)
	if label != "color_argb" {
		t.Fatalf("got %q, sigs=%v", label, s.Sigs)
	}
}

func TestRangeAndWideParams(t *testing.T) {
	m := ParseMethod("LA;", ".method public static f(JI)V\n.registers 4\nconst/4 v0, 0x1\ninvoke-static/range {v0 .. v0}, LB;->g(Z)V\nreturn-void\n.end method")
	if got := m.ParamRegister(1); got != "p2" {
		t.Fatalf("wide param register: %s", got)
	}
	s, _ := NewSite(m, 0, nil)
	if l, _ := Oracle(s.Sigs, s.V, false, m); l != "boolean" {
		t.Fatalf("range call: %q %v", l, s.Sigs)
	}
}

func TestRejectsNonConst(t *testing.T) {
	if _, err := Analyze(Request{Code: ".method a()V\nreturn-void\n.end method", Line: 2}, nil, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestWideDelay(t *testing.T) {
	m, err := LoadModel("../models/smalirole-model.json")
	if err != nil {
		t.Skip()
	}
	r, err := Analyze(Request{Code: load(t, "delay"), Line: 6}, m, nil)
	if err != nil || r.Answer != "duration_ms" || !r.Wide || r.Int32 != 5000 {
		t.Fatalf("got %s wide=%v v=%d err=%v", r.Answer, r.Wide, r.Int32, err)
	}
	if !strings.Contains(r.Explanation, "5 с") {
		t.Fatal(r.Explanation)
	}
}

func TestFieldFlowWideTimeout(t *testing.T) {
	clinit := ParseMethod("Lcom/app/Net;", ".method static constructor <clinit>()V\n.registers 2\nconst-wide/16 v0, 0x3a98\nsput-wide v0, Lcom/app/Net;->TIMEOUT:J\nreturn-void\n.end method")
	user := ParseMethod("Lcom/app/Net;", ".method public retry(Landroid/os/Handler;Ljava/lang/Runnable;)V\n.registers 6\nsget-wide v0, Lcom/app/Net;->TIMEOUT:J\ninvoke-virtual {p1, p2, v0, v1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z\nreturn-void\n.end method")
	a := &App{Methods: map[string]*Method{}, Reads: map[string][]FieldRead{}}
	a.Add(clinit)
	a.Add(user)
	s, ok := NewSiteCtx(clinit, 0, a.Ctx())
	if !ok {
		t.Fatal("no site")
	}
	if l, _ := Oracle(s.Sigs, s.V, false, clinit); l != "duration_ms" {
		t.Fatalf("got %q sigs=%v", l, s.Sigs)
	}
	via := false
	for _, u := range s.Uses {
		if strings.Contains(u.Via, "TIMEOUT") {
			via = true
		}
	}
	if !via {
		t.Fatal("field read not followed")
	}
}

func TestTimingAuditExclusions(t *testing.T) {
	for _, c := range []struct{ code, name string }{
		{".method a(Landroid/graphics/drawable/AnimationDrawable;)V\n.registers 3\nconst/4 v0, 0x0\ninvoke-virtual {p1, v0}, Landroid/graphics/drawable/AnimationDrawable;->getDuration(I)I\nreturn-void\n.end method", "getDuration index"},
		{".method a(Ljava/util/Calendar;)V\n.registers 4\nconst-wide/16 v0, 0x1e\ninvoke-virtual {p1, v0, v1}, Ljava/util/Calendar;->setTimeInMillis(J)V\nreturn-void\n.end method", "Calendar timestamp"},
		{".method a(Ld3/g;Ljava/io/IOException;)V\n.registers 3\nconst/4 v0, 0x0\ninvoke-virtual {p1, v0}, Ld3/g;->access$newTimeoutException(Ljava/io/IOException;)Ljava/io/IOException;\nreturn-void\n.end method", "exception arg"},
		{".method a(Landroid/animation/ValueAnimator;)V\n.registers 4\nconst-wide v0, 0x10100aa\ninvoke-virtual {p1, v0, v1}, Landroid/animation/ValueAnimator;->setDuration(J)Landroid/animation/ValueAnimator;\nreturn-void\n.end method", "framework resource literal"},
	} {
		m := ParseMethod("LX;", c.code)
		s, ok := NewSite(m, 0, nil)
		if !ok {
			t.Fatalf("%s: no site", c.name)
		}
		if l, _ := Oracle(s.Sigs, s.V, false, m); l == "duration_ms" {
			t.Errorf("%s: wrongly labelled duration", c.name)
		}
	}
}

func TestTimeUnitExplanation(t *testing.T) {
	code := ".method a(Ljava/util/concurrent/ScheduledExecutorService;Ljava/lang/Runnable;)V\n.registers 6\nsget-object v2, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;\nconst-wide/16 v0, 0x1e\ninvoke-interface {p1, p2, v0, v1, v2}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;\nreturn-void\n.end method"
	r, err := Analyze(Request{Code: code, Line: 4}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r.TimeUnit {
		t.Fatal("TimeUnit not detected")
	}
}

func TestTimingAuditRound2(t *testing.T) {
	for _, c := range []struct{ code, name string }{
		{".method a(Landroid/os/Handler;)V\n.registers 5\nconst/4 v0, 0x0\nconst-wide/16 v1, 0x64\ninvoke-virtual {p1, v0, v1, v2}, Landroid/os/Handler;->sendEmptyMessageDelayed(IJ)Z\nreturn-void\n.end method", "message.what is not a delay"},
		{".method a(Landroid/animation/Animator;)V\n.registers 4\nconst-wide/16 v0, -0x1\ninvoke-virtual {p1, v0, v1}, Landroid/animation/Animator;->setDuration(J)Landroid/animation/Animator;\nreturn-void\n.end method", "-1 is a sentinel"},
	} {
		m := ParseMethod("LX;", c.code)
		s, _ := NewSite(m, 0, nil)
		if l, _ := Oracle(s.Sigs, s.V, false, m); l == "duration_ms" {
			t.Errorf("%s: wrongly labelled duration", c.name)
		}
	}
	// the long in the same call is still a delay
	m := ParseMethod("LX;", ".method a(Landroid/os/Handler;)V\n.registers 5\nconst/4 v0, 0x0\nconst-wide/16 v1, 0x64\ninvoke-virtual {p1, v0, v1, v2}, Landroid/os/Handler;->sendEmptyMessageDelayed(IJ)Z\nreturn-void\n.end method")
	s, _ := NewSite(m, 1, nil)
	if l, _ := Oracle(s.Sigs, s.V, false, m); l != "duration_ms" {
		t.Errorf("delay long: got %q %v", l, s.Sigs)
	}
}

// Found on a real APK (Brawl Stars mod): SDK_INT checks were reported as 100% limits,
// and LOG_OUT_REASON_LOGIN_TIMEOUT = 4 as a 4 ms duration.
func TestRealAPKApiLevelAndEnumCode(t *testing.T) {
	m, err := LoadModel("../models/smalirole-model.json")
	if err != nil {
		t.Fatal(err)
	}
	sdk := ".method public a()V\n    .registers 2\n    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I\n    const/16 v1, 0x17\n    if-ge v0, v1, :cond_0\n    return-void\n    :cond_0\n    return-void\n.end method\n"
	r, err := AnalyzeCtx(Request{Code: sdk, Line: 4}, m, nil)
	if err != nil || r.Answer != "api_constant" || !strings.Contains(r.Explanation, "Android 6.0") {
		t.Fatalf("sdk: %v %s %.2f %s", err, r.Answer, r.Confidence, r.Explanation)
	}
	enum := ".method static constructor <clinit>()V\n    .registers 1\n    const/4 v0, 0x4\n    sput v0, Lcom/x/G;->LOG_OUT_REASON_LOGIN_TIMEOUT:I\n    return-void\n.end method\n"
	r, err = AnalyzeCtx(Request{Code: enum, Line: 3, Class: "Lcom/x/G;"}, m, nil)
	if err != nil || r.Answer == "duration_ms" {
		t.Fatalf("enum: %v %s %.2f", err, r.Answer, r.Confidence)
	}
	real := ".method static constructor <clinit>()V\n    .registers 2\n    const-wide/32 v0, 0xea60\n    sput-wide v0, Lcom/x/G;->LOGIN_TIMEOUT:J\n    return-void\n.end method\n"
	r, _ = AnalyzeCtx(Request{Code: real, Line: 3, Class: "Lcom/x/G;"}, m, nil)
	if r.Answer != "duration_ms" {
		t.Fatalf("real timeout lost: %s %.2f", r.Answer, r.Confidence)
	}
}

func TestMethodNameRule(t *testing.T) {
	for name, want := range map[string]string{"getMaxCoins": "limit_threshold", "getTimeoutMs": "duration_ms", "getButtonColor": "color_argb"} {
		if l, ok := NameVote(name); !ok || l != want {
			t.Errorf("%s → %s %v", name, l, ok)
		}
	}
	if _, ok := NameVote("getMaxDelay"); ok {
		t.Error("conflicting name must abstain")
	}
	if _, ok := NameVote("run"); ok {
		t.Error("silent name must abstain")
	}
}
