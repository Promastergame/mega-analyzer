package s1

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const lazySkillRequest = `{"state":"merge two PDF files","questions":{
"skill":{"type":"choice","task":"skill_routing","instructions":"Which skill should handle this?",
"criteria":{"pdf":"Read, merge and split PDF files","xlsx":"Spreadsheets, Excel formulas and charts"}},
"urgent":{"type":"noul","instructions":"The request is urgent"}}}`

func TestLazySkillBackendLoadsOnlyForSkills(t *testing.T) {
	var loads atomic.Int64
	skill := &countingBackend{name: "skills", hyps: map[string]bool{}}
	general := &countingBackend{name: "general", hyps: map[string]bool{}}
	e := NewEngine(general, DefaultCalibration())
	e.SkillBackendLoader = NewBackendLoader(func() (Backend, error) {
		loads.Add(1)
		return skill, nil
	})
	if _, err := e.Decide(req(t, ticket)); err != nil {
		t.Fatal(err)
	}
	if loads.Load() != 0 {
		t.Fatal("general request loaded the skill model")
	}
	r := req(t, lazySkillRequest)
	got, err := e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	eager := NewEngine(general, DefaultCalibration())
	eager.SkillBackend = skill
	want, err := eager.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Answers, want.Answers) || got.Backend != want.Backend {
		t.Fatal("lazy loading changed answers or backend labels")
	}
	if loads.Load() != 1 || e.SkillBackend != nil {
		t.Fatal("loader mutated the engine or reloaded")
	}
	if skill.hyps["The request is urgent"] {
		t.Fatal("general hypothesis sent to skill model")
	}
	for h := range general.hyps {
		if strings.Contains(h, "PDF") {
			t.Fatalf("skill hypothesis sent to general model: %q", h)
		}
	}
	// An explicitly installed backend retains precedence over a loader.
	e.SkillBackend = skill
	e.SkillBackendLoader = NewBackendLoader(func() (Backend, error) { t.Error("loader used despite SkillBackend"); return nil, nil })
	if _, err := e.Decide(r); err != nil {
		t.Fatal(err)
	}
}

func TestLazySkillBackendConcurrentEngineCopies(t *testing.T) {
	var loads atomic.Int64
	e := NewEngine(fake{}, DefaultCalibration())
	e.SkillBackendLoader = NewBackendLoader(func() (Backend, error) {
		loads.Add(1)
		return &countingBackend{name: "skills", hyps: map[string]bool{}}, nil
	})
	r := req(t, lazySkillRequest)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		copy := *e
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := copy.Decide(r)
			if err != nil {
				t.Error(err)
				return
			}
			if resp.Answers["skill"].Source != "skills" {
				t.Error("wrong skill backend")
			}
		}()
	}
	wg.Wait()
	if loads.Load() != 1 {
		t.Fatalf("loaded %d models", loads.Load())
	}
}

func TestBackendLoaderCancellationDoesNotPoisonInitialization(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var loads atomic.Int64
	l := NewBackendLoader(func() (Backend, error) {
		loads.Add(1)
		close(entered)
		<-release
		return fake{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := l.Load(ctx); done <- err }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	close(release)
	b, err := l.Load(context.Background())
	if err != nil || b == nil || loads.Load() != 1 {
		t.Fatalf("later caller: %v, loads %d", err, loads.Load())
	}
	if _, err := l.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("completed loader ignored cancellation")
	}
}

func TestLazySkillBackendFailureIsReturned(t *testing.T) {
	boom := errors.New("skill weights unavailable")
	var loads atomic.Int64
	e := NewEngine(fake{}, DefaultCalibration())
	e.SkillBackendLoader = NewBackendLoader(func() (Backend, error) { loads.Add(1); return nil, boom })
	for i := 0; i < 2; i++ {
		if _, err := e.Decide(req(t, lazySkillRequest)); !errors.Is(err, boom) {
			t.Fatalf("load error hidden: %v", err)
		}
	}
	if loads.Load() != 1 {
		t.Fatal("failed initialization was repeated")
	}
	if _, err := e.Decide(req(t, ticket)); err != nil {
		t.Fatalf("failed skill loader broke general requests: %v", err)
	}
	if _, err := NewBackendLoader(func() (Backend, error) { return nil, nil }).Load(context.Background()); err == nil {
		t.Fatal("nil backend was accepted")
	}
}

func TestLazySkillCacheUsageIncludesBothBackends(t *testing.T) {
	e := NewEngine(NewCachedBackend(fake{}, DefaultJudgementCacheBytes), DefaultCalibration())
	e.SkillBackendLoader = NewBackendLoader(func() (Backend, error) {
		return NewCachedBackend(fake{}, DefaultJudgementCacheBytes), nil
	})
	r := req(t, lazySkillRequest)
	cold, err := e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	warm, err := e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	if cold.Usage.ModelCalls != 3 || warm.Usage.ModelCalls != 0 || warm.Usage.CacheHits != 3 {
		t.Fatalf("usage omitted a backend: cold=%+v warm=%+v", cold.Usage, warm.Usage)
	}
}
