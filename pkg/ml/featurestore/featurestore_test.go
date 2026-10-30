package featurestore

import (
	"sync"
	"testing"
)

func TestSetGet(t *testing.T) {
	fs := New()
	if err := fs.Set("foo", 1.5, OriginStructural); err != nil {
		t.Fatal(err)
	}
	f, ok := fs.Get("foo")
	if !ok || f.Value != 1.5 || f.Origin != OriginStructural {
		t.Fatalf("got %+v, ok=%v", f, ok)
	}
	if err := fs.Set("", 0, OriginStructural); err == nil {
		t.Errorf("expected error on empty name")
	}
}

func TestAutoVectorIsDeterministic(t *testing.T) {
	fs := New()
	for k, v := range map[string]float64{"b": 2, "a": 1, "c": 3} {
		_ = fs.Set(k, v, OriginStructural)
	}
	keys1, vals1 := fs.AutoVector()
	keys2, vals2 := fs.AutoVector()
	if len(keys1) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys1))
	}
	for i := range keys1 {
		if keys1[i] != keys2[i] || vals1[i] != vals2[i] {
			t.Errorf("non-deterministic AutoVector: run1=%v run2=%v", keys1, keys2)
		}
	}
	want := []string{"a", "b", "c"}
	for i, w := range want {
		if keys1[i] != w {
			t.Errorf("expected sorted %v, got %v", want, keys1)
		}
	}
}

func TestVectorWithSchemaAndMissing(t *testing.T) {
	fs := New()
	_ = fs.Set("a", 10, OriginStructural)
	schema := []string{"a", "b", "c"}
	names, values := fs.Vector(schema, -1)
	if len(values) != 3 {
		t.Fatalf("expected 3 values, got %d", len(values))
	}
	if names[1] != "b" || values[1] != -1 {
		t.Errorf("missing-fill failed: names=%v values=%v", names, values)
	}
}

func TestFilterByOrigin(t *testing.T) {
	fs := New()
	_ = fs.Set("s1", 1, OriginStructural)
	_ = fs.Set("h1", 2, OriginHDC)
	_ = fs.Set("h2", 3, OriginHDC)
	hdc := fs.FilterByOrigin(OriginHDC)
	if len(hdc) != 2 || hdc[0] != "h1" || hdc[1] != "h2" {
		t.Errorf("unexpected HDC subset: %v", hdc)
	}
}

func TestMerge(t *testing.T) {
	a := New()
	b := New()
	_ = a.Set("x", 1, OriginStructural)
	_ = a.Set("y", 2, OriginStructural)
	_ = b.Set("y", 99, OriginHDC)
	_ = b.Set("z", 3, OriginHDC)

	// Without overwrite: y stays = 2.
	cl := a.Clone()
	if err := cl.Merge(b, false); err != nil {
		t.Fatal(err)
	}
	if cl.Value("y", -1) != 2 {
		t.Errorf("non-overwrite merge changed y: %f", cl.Value("y", -1))
	}
	if cl.Value("z", -1) != 3 {
		t.Errorf("merge dropped new key z")
	}

	// With overwrite: y should now be 99 with HDC origin.
	cl = a.Clone()
	if err := cl.Merge(b, true); err != nil {
		t.Fatal(err)
	}
	if cl.Value("y", -1) != 99 {
		t.Errorf("overwrite merge failed: %f", cl.Value("y", -1))
	}
	f, _ := cl.Get("y")
	if f.Origin != OriginHDC {
		t.Errorf("overwrite didn't propagate origin: %v", f.Origin)
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Smoke test: parallel writers + readers shouldn't race or panic.
	fs := New()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			_ = fs.Set("k", float64(idx), OriginStructural)
		}(i)
		go func() {
			defer wg.Done()
			_ = fs.Value("k", 0)
		}()
	}
	wg.Wait()
}
