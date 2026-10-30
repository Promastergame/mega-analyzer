package gnncache

import (
	"testing"

	"mega-analyzer/pkg/internal/contentcache"
)

func bodyGraph() *GraphTensor { return sampleGraph() }

// TestBodyBindingSeparatesIdenticalTensors is the regression test for the
// collision that motivated the body key: two unrelated methods can produce
// byte-identical tensors, and before this change they shared one prediction.
func TestBodyBindingSeparatesIdenticalTensors(t *testing.T) {
	c, err := Open(t.TempDir(), 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	digest := TensorDigest(bodyGraph())

	ctxA := ContextFromBody(digest, []string{"invoke-static {v0}, Lcrypto;->weakHash(I)V"})
	ctxB := ContextFromBody(digest, []string{"invoke-static {v0}, Lnet;->openSocket(I)V"})

	if !ctxA.HasBody || !ctxB.HasBody {
		t.Fatal("body presence flag not set")
	}
	if ctxA.BodyKey == ctxB.BodyKey {
		t.Fatal("different bodies produced the same body key")
	}
	if c.KeyFromContext(ctxA) == c.KeyFromContext(ctxB) {
		t.Fatal("different bodies produced the same cache key")
	}
	if GraphKeyFromContext(ctxA) == GraphKeyFromContext(ctxB) {
		t.Fatal("different bodies produced the same memo key")
	}
}

func TestSameBodyDifferentTensorsDiffer(t *testing.T) {
	c, err := Open(t.TempDir(), 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	body := []string{"const/4 v0, 0x1", "return-void"}

	g1 := bodyGraph()
	g2 := bodyGraph()
	g2.Features[0] = 0.95

	ctx1 := ContextFromBody(TensorDigest(g1), body)
	ctx2 := ContextFromBody(TensorDigest(g2), body)
	if ctx1.BodyKey != ctx2.BodyKey {
		t.Fatal("identical bodies produced different body keys")
	}
	if c.KeyFromContext(ctx1) == c.KeyFromContext(ctx2) {
		t.Fatal("different tensors produced the same cache key")
	}
}

// TestBodyKeyIgnoresCommentsAndWhitespace pins the reuse of the existing
// contentcache normalizer: cosmetic smali differences must not split the cache.
func TestBodyKeyIgnoresCommentsAndWhitespace(t *testing.T) {
	c, err := Open(t.TempDir(), 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	digest := TensorDigest(bodyGraph())
	plain := []string{"const/4 v0, 0x1", "return-void"}
	noisy := []string{"  const/4 v0, 0x1  ", "# line 42", "return-void\t"}

	if got, want := ContextFromBody(digest, noisy), ContextFromBody(digest, plain); got.BodyKey != want.BodyKey {
		t.Fatal("comment/whitespace noise changed the body key")
	}
	if c.KeyFromContext(ContextFromBody(digest, noisy)) != c.KeyFromContext(ContextFromBody(digest, plain)) {
		t.Fatal("comment/whitespace noise changed the cache key")
	}
}

func TestMissingBodyFallsBackToLegacyKey(t *testing.T) {
	c, err := Open(t.TempDir(), 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	digest := TensorDigest(bodyGraph())

	for _, empty := range [][]string{nil, {}, {"", "   ", "# only a comment"}} {
		ctx := ContextFromBody(digest, empty)
		if ctx.HasBody {
			t.Fatalf("body %q should not count as a body", empty)
		}
		if ctx.BodyKey != (contentcache.ContentKey{}) {
			t.Fatal("bodyless context carries a body key")
		}
		if c.KeyFromContext(ctx) != c.KeyFromDigest(digest) {
			t.Fatal("bodyless key is not the deterministic legacy key")
		}
		if GraphKeyFromContext(ctx) != GraphKeyFromDigest(digest) {
			t.Fatal("bodyless memo key is not the deterministic legacy key")
		}
	}

	// A body-bound key must never collide with the legacy one.
	withBody := ContextFromBody(digest, []string{"return-void"})
	if c.KeyFromContext(withBody) == c.KeyFromDigest(digest) {
		t.Fatal("body-bound key equals the legacy key")
	}
}

func TestKeyFromContextBindsFingerprint(t *testing.T) {
	ca, err := Open(t.TempDir(), 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := Open(t.TempDir(), 0, testFingerprintB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := ContextFromBody(TensorDigest(bodyGraph()), []string{"return-void"})
	if ca.KeyFromContext(ctx) == cb.KeyFromContext(ctx) {
		t.Fatal("cache key does not depend on the model fingerprint")
	}
}

// TestPredictionsAreNotSharedAcrossBodies exercises the full store path.
func TestPredictionsAreNotSharedAcrossBodies(t *testing.T) {
	c, err := Open(t.TempDir(), 0, testFingerprintA)
	if err != nil {
		t.Fatal(err)
	}
	digest := TensorDigest(bodyGraph())
	keyA := c.KeyFromContext(ContextFromBody(digest, []string{"invoke-static {}, La;->x()V"}))
	keyB := c.KeyFromContext(ContextFromBody(digest, []string{"invoke-static {}, Lb;->y()V"}))

	pred := &Prediction{PredictedClass: 2, Confidence: 0.91, ClassProbs: []float32{0.02, 0.02, 0.91, 0.01, 0.01, 0.01, 0.01, 0.01}}
	if err := c.Put(keyA, pred); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(keyB); ok {
		t.Fatal("prediction leaked to a method with a different body")
	}
	if _, ok := c.Get(keyA); !ok {
		t.Fatal("prediction not readable under its own key")
	}
}

func BenchmarkKeyFromContext(b *testing.B) {
	c, err := Open(b.TempDir(), 0, testFingerprintA)
	if err != nil {
		b.Fatal(err)
	}
	digest := TensorDigest(bodyGraph())
	body := make([]string, 200)
	for i := range body {
		body[i] = "invoke-virtual {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.KeyFromContext(ContextFromBody(digest, body))
	}
}
