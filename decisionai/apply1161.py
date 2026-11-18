# apply1161.py — DecisionAI v1.16 → v1.16.1
# Run from the project root: python apply1161.py   (or: python apply1161.py path\to\proj)
import os, sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
os.chdir(root)
if not os.path.exists("go.mod"):
    sys.exit("Run from the project folder (go.mod not found)")


def edit(p, pairs):
    raw = open(p, encoding="utf-8", newline="").read()
    crlf = "\r\n" in raw
    s = raw.replace("\r\n", "\n")
    for a, b in pairs:
        if a in s:
            s = s.replace(a, b, 1)
        elif b in s:
            continue  # already applied
        else:
            sys.exit(f"Snippet not found in {p}: {a[:60]!r}")
    if crlf:
        s = s.replace("\n", "\r\n")
    open(p, "w", encoding="utf-8", newline="").write(s)
    print("ok", p)


# 1) one shared encode per text (it used to be recomputed by parallel pairs) + display name
edit("s1/embed.go", [
('''	cache map[string]*semai.Encoding
	Scale float64''', '''	cache map[string]*semai.Encoding
	// v1.16.1: in-flight encodes, so parallel pairs sharing a state chunk encode it once
	busy  map[string]chan struct{}
	Label string // display name (default: encoder source)
	Scale float64'''),
('''return &EmbedBackend{enc: enc, cache: map[string]*semai.Encoding{}, Scale: 12, Bias: 0.55}''',
 '''return &EmbedBackend{enc: enc, cache: map[string]*semai.Encoding{}, busy: map[string]chan struct{}{}, Scale: 12, Bias: 0.55}'''),
('''func (b *EmbedBackend) Name() string        { return "bi-encoder:" + b.enc.Source }''', '''func (b *EmbedBackend) Name() string {
	if b.Label != "" {
		return b.Label
	}
	return "bi-encoder:" + b.enc.Source
}'''),
('''	b.mu.Lock()
	e, ok := b.cache[t]
	b.mu.Unlock()
	if ok {
		return e
	}
	e = b.enc.Encode(t)
	b.mu.Lock()
''', '''	for {
		b.mu.Lock()
		if e, ok := b.cache[t]; ok {
			b.mu.Unlock()
			return e
		}
		ch, running := b.busy[t]
		if !running {
			ch = make(chan struct{})
			b.busy[t] = ch
			b.mu.Unlock()
			break
		}
		b.mu.Unlock()
		<-ch // another goroutine is encoding the same text: wait and reuse it
	}
	e := b.enc.Encode(t)
	b.mu.Lock()
	if ch, ok := b.busy[t]; ok {
		close(ch)
		delete(b.busy, t)
	}
'''),
])

# 2) ensemble display name
edit("s1/ensemble.go", [
('''type EnsembleBackend struct{ Members []Backend }

func (e EnsembleBackend) Name() string {
''', '''type EnsembleBackend struct {
	Members []Backend
	Label   string // display name (default: ensemble(member | member))
}

func (e EnsembleBackend) Name() string {
	if e.Label != "" {
		return e.Label
	}
'''),
])

# 3) readable model names, accel in /v1/health and in the startup line
edit("cmd/dai/main.go", [
('''			members = append(members, s1.NewEmbedBackend(de))''', '''			mb := s1.NewEmbedBackend(de)
			mb.Label = fmt.Sprintf("System One %c", 'A'+len(members))
			members = append(members, mb)'''),
('''		var general s1.Backend = members[0]
		if len(members) > 1 {
			general = s1.EnsembleBackend{Members: members}
		}''', '''		// v1.16.1: readable names (the .dte metadata still lists the v1.8 teachers)
		var general s1.Backend = members[0]
		members[0].(*s1.EmbedBackend).Label = "System One v" + s1.Version
		if len(members) > 1 {
			general = s1.EnsembleBackend{Members: members, Label: fmt.Sprintf("System One v%s · ансамбль из %d моделей", s1.Version, len(members))}
		}'''),
('''		eng.SkillBackend = s1.NewEmbedBackend(enc)''', '''		sk := s1.NewEmbedBackend(enc)
		sk.Label = "System One · выбор скилла"
		eng.SkillBackend = sk'''),
('''"backend": eng.Backend.Name(), "model": eng.ModelName, "experts": names})''',
 '''"backend": eng.Backend.Name(), "model": eng.ModelName, "experts": names, "accel": semai.AccelName()})'''),
('''"DecisionAI System One %s on http://%s  (backend: %s)\\n", s1.Version, addr, eng.Backend.Name())''',
 '''"DecisionAI System One %s on http://%s  (модель: %s, ядро: %s)\\n", s1.Version, addr, eng.Backend.Name(), semai.AccelName())'''),
])

# 4) Nim reports its build flavour (FASM / OpenMP)
edit("nim/dainim.nim", [
('{.pop.}', '''proc dn_kind(): cint {.exportc, dynlib, cdecl.} =
  ## v1.16.1: bit 1 = FASM AVX kernel linked, bit 2 = OpenMP multi-core forward
  result = 0
  when defined(fasm): result = result or 1
  when defined(omp): result = result or 2

{.pop.}'''),
])

edit("semai/accel_nim.go", [
('void NimMain(void);', 'void NimMain(void);\nint dn_kind(void);'),
('func init() {\n\tnewAccel = func', 'func init() {\n\tnimKind = func() int { return int(C.dn_kind()) }\n\tnewAccel = func'),
])

edit("semai/accel.go", [
('package semai\n', 'package semai\n\nimport "os"\n'),
('''// Native reports which''', '''// nimKind reports the Nim build flavour (bit 1 = FASM kernel, bit 2 = OpenMP).
var nimKind func() int

// AccelName is a human-readable name of what runs the Transformer layers in this binary.
func AccelName() string {
	if newAccel == nil || nimKind == nil {
		return "Go"
	}
	if os.Getenv("DAI_NO_NIM") != "" {
		return "Go (Nim выключен DAI_NO_NIM)"
	}
	k, n := nimKind(), "Nim"
	if k&1 != 0 {
		n += "+FASM"
	}
	if k&2 != 0 {
		n += "+OpenMP"
	}
	return n
}

// Native reports which'''),
])

# 5) playground: "ядро" field and "Всего с HTTP" instead of "С сетью"
edit("cmd/dai/playground.html", [
('''  <span class="opt">эксперты <b id="exp">-</b></span>''', '''  <span class="opt">эксперты <b id="exp">-</b></span>
  <span class="opt" title="Что считает слои нейросети: Go — чистый Go (медленно); Nim+FASM — ускоренная сборка BUILD-NIM-WINDOWS.cmd / build-nim.sh">ядро <b id="acc">-</b></span>'''),
('<div><span>С сетью</span><b>${rtt}<small>мс</small></b></div>',
 '<div title="Полное время запроса из браузера до локального сервера 127.0.0.1 и обратно: движок + HTTP + разбор JSON. Интернет не используется, всё считается на этом компьютере."><span>Всего с HTTP</span><b>${rtt}<small>мс</small></b></div>'),
("$('exp').textContent=(h.experts||[]).length||'выкл'}",
 "$('exp').textContent=(h.experts||[]).length||'выкл';$('acc').textContent=h.accel||'Go'}"),
])

# 6) build hint, training metadata, version
edit("BUILD-S1.cmd", [
('echo Done. Run: bin\\dai.exe serve   then open http://127.0.0.1:7480/playground',
 'echo Done. Run: bin\\dai.exe serve   then open http://127.0.0.1:7480/playground\necho NOTE: this is the pure-Go build (slowest). For a 5-10x faster engine use BUILD-NIM-WINDOWS.cmd (Nim + FASM).'),
])
edit("scripts/distill/train_embed.py", [
('" + System One distillation v1.8 (teachers: Jev, mDeBERTa-v3)"',
 '" + System One distillation (teachers: Jev, mDeBERTa-v3, Gemma, Qwen)"'),
])
edit("s1/types.go", [('const Version = "1.16.0"', 'const Version = "1.16.1"')])

# 7) latency test for one request (skipped unless DAI_COLD is set)
open("cmd/dai/cold_test.go", "w", encoding="utf-8").write('''package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/mega-analyzer/decisionai/s1"
)

// TestColdRequest times the first (uncached) and warm calls on a request file:
// DAI_COLD=/path/request.json go test [-tags nim] ./cmd/dai -run ColdRequest -v
func TestColdRequest(t *testing.T) {
	path := os.Getenv("DAI_COLD")
	if path == "" {
		t.Skip("set DAI_COLD=request.json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	os.Chdir("../..")
	t0 := time.Now()
	eng, err := buildEngine("s1", "", "", "", 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("load %v", time.Since(t0))
	for i := 0; i < 3; i++ {
		var r s1.Request
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		t1 := time.Now()
		if _, err := eng.Decide(r); err != nil {
			t.Fatal(err)
		}
		t.Logf("call %d %v", i, time.Since(t1))
	}
}
''')
print("ok cmd/dai/cold_test.go")
print("\nDONE: v1.16.1. Now build: BUILD-NIM-WINDOWS.cmd (fast) or BUILD-S1.cmd (pure Go)")
