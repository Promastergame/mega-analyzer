package deobfuscation

import (
	"fmt"
	"sync"
	"testing"
)

// referenceBestColumnKey is the pre-optimisation implementation, kept verbatim
// so the rewritten bestColumnKey can be proven to pick identical keys. The
// rewrite was meant to be a pure speedup; without this the only thing standing
// behind that claim is the commit message.
func referenceBestColumnKey(data []byte, pos, keyLen int) byte {
	bestKey := byte(0)
	bestScore := -1.0
	col := make([]byte, 0, len(data)/keyLen+1)
	for k := 0; k < 256; k++ {
		col = col[:0]
		for i := pos; i < len(data); i += keyLen {
			col = append(col, data[i]^byte(k))
		}
		score := englishScore(col)
		for _, c := range col {
			if c < 32 || c > 126 {
				score -= 1.0
			}
		}
		if score > bestScore {
			bestScore = score
			bestKey = byte(k)
		}
	}
	return bestKey
}

func TestBestColumnKeyMatchesReference(t *testing.T) {
	plaintexts := []string{
		"https://c2.example.net/collect",
		"the quick brown fox jumps over the lazy dog",
		"AKIAIOSFODNN7EXAMPLE",
		"",
		"a",
		"short",
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b",
	}
	keys := []string{"\x5a", "ab", "key", "\x00\x20", "LONGERKEY"}

	for _, pt := range plaintexts {
		for _, key := range keys {
			data := []byte(pt)
			for i := range data {
				data[i] ^= key[i%len(key)]
			}
			for keyLen := 2; keyLen <= maxRepeatingKeyLen; keyLen++ {
				for pos := 0; pos < keyLen; pos++ {
					got := bestColumnKey(data, pos, keyLen)
					want := referenceBestColumnKey(data, pos, keyLen)
					if got != want {
						t.Fatalf("bestColumnKey(%q, pos=%d, keyLen=%d) = 0x%02X, reference = 0x%02X",
							pt, pos, keyLen, got, want)
					}
				}
			}
		}
	}
}

// TestDecryptMemoAgreesWithUncached is the correctness half of the memo: a
// cached answer has to be the answer the search would have produced.
func TestDecryptMemoAgreesWithUncached(t *testing.T) {
	ResetDecryptCache()

	inputs := []string{
		"SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Q=",
		"aHR0cHM6Ly9jMi5leGFtcGxlLm5ldC9jb2xsZWN0",
		"deadbeefdeadbeefdeadbeef",
		"IconCompat",
		"zzzzzzzzzzzzzzzz",
		"",
		"ab",
	}

	for _, in := range inputs {
		wantPlain, wantTransform := tryDecryptStringUncached(in)

		// First call populates, second call must be served from the memo.
		for pass := 0; pass < 2; pass++ {
			gotPlain, gotTransform := tryDecryptString(in)
			if gotPlain != wantPlain || gotTransform != wantTransform {
				t.Fatalf("tryDecryptString(%q) pass %d = (%q, %q), want (%q, %q)",
					in, pass, gotPlain, gotTransform, wantPlain, wantTransform)
			}
		}
	}
}

// TestDecryptMemoCachesNegativeResults guards the expensive half. A literal
// that survives the whole chain is the one that cost the most to reject, so if
// only successes were cached the worst case would never be memoised at all.
func TestDecryptMemoCachesNegativeResults(t *testing.T) {
	ResetDecryptCache()

	// Long enough to enter the search, structured so nothing readable falls out.
	const stubborn = "IconCompatParcelizerHolder"

	if plain, _ := tryDecryptString(stubborn); plain != "" {
		t.Skipf("input %q unexpectedly decrypted to %q; pick another fixture", stubborn, plain)
	}

	hits, misses := DecryptCacheStats()
	if hits != 0 || misses != 1 {
		t.Fatalf("after first call: hits=%d misses=%d, want 0/1", hits, misses)
	}

	for i := 0; i < 5; i++ {
		if plain, _ := tryDecryptString(stubborn); plain != "" {
			t.Fatalf("memo returned %q for a literal that does not decrypt", plain)
		}
	}

	hits, misses = DecryptCacheStats()
	if misses != 1 {
		t.Errorf("failed lookup re-ran the search: misses=%d, want 1", misses)
	}
	if hits != 5 {
		t.Errorf("negative result was not served from cache: hits=%d, want 5", hits)
	}
}

// TestDecryptMemoSkipsShortLiterals confirms the length guard runs before the
// cache, so trivial inputs never occupy an entry.
func TestDecryptMemoSkipsShortLiterals(t *testing.T) {
	ResetDecryptCache()

	if plain, transform := tryDecryptString("ab"); plain != "" || transform != "" {
		t.Fatalf("short literal returned (%q, %q), want empty", plain, transform)
	}
	if hits, misses := DecryptCacheStats(); hits != 0 || misses != 0 {
		t.Errorf("short literal touched the memo: hits=%d misses=%d, want 0/0", hits, misses)
	}
}

// TestDecryptMemoIsConcurrencySafe matters because the callers are the per-file
// scan workers, which run in parallel over one process-wide cache.
func TestDecryptMemoIsConcurrencySafe(t *testing.T) {
	ResetDecryptCache()

	const goroutines = 16
	inputs := make([]string, 32)
	for i := range inputs {
		inputs[i] = fmt.Sprintf("SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Q%02d", i)
	}

	want := make([]string, len(inputs))
	for i, in := range inputs {
		want[i], _ = tryDecryptStringUncached(in)
	}

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, in := range inputs {
				if got, _ := tryDecryptString(in); got != want[i] {
					t.Errorf("concurrent tryDecryptString(%q) = %q, want %q", in, got, want[i])
					return
				}
			}
		}()
	}
	wg.Wait()
}

// BenchmarkTryDecryptStringCold measures the search itself. The existing
// BenchmarkTryDecryptString now measures the memo, which is the point, but it
// no longer tells you anything about the cost being avoided.
func BenchmarkTryDecryptStringCold(b *testing.B) {
	in := "SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Q="
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = tryDecryptStringUncached(in)
	}
}

func BenchmarkBestColumnKey(b *testing.B) {
	data := benchXORData()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bestColumnKey(data, 0, 4)
	}
}
