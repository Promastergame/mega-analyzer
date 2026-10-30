package ncer

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"mega-analyzer/pkg/ncer/reconcile"
)

// BenchmarkEventParsing measures the throughput and latency of accumulating
// HTTP telemetry events and converting them into a structured MitmCapture.
func BenchmarkEventParsing(b *testing.B) {
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		c := NewCollector(base)
		for j := 0; j < 100; j++ {
			c.ObserveHTTP("GET", "https://api.example.com/v1/user", "200", "api.example.com", "10:00:01.100")
		}
		_ = c.buildCapture()
	}
}

// BenchmarkReconciliation_100 measures reconciliation throughput over 100 events.
func BenchmarkReconciliation_100(b *testing.B) {
	c := generateSyntheticCollector(80, 20)
	cap := c.buildCapture()
	jsonBytes, _ := json.Marshal(cap)
	b.SetBytes(int64(len(jsonBytes)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = reconcile.RunReconcile(jsonBytes)
	}
}

// BenchmarkReconciliation_1000 measures reconciliation throughput over 1,000 events.
func BenchmarkReconciliation_1000(b *testing.B) {
	c := generateSyntheticCollector(800, 200)
	cap := c.buildCapture()
	jsonBytes, _ := json.Marshal(cap)
	b.SetBytes(int64(len(jsonBytes)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = reconcile.RunReconcile(jsonBytes)
	}
}

// BenchmarkReconciliation_10000 measures reconciliation throughput over 10,000 events.
func BenchmarkReconciliation_10000(b *testing.B) {
	c := generateSyntheticCollector(8000, 2000)
	cap := c.buildCapture()
	jsonBytes, _ := json.Marshal(cap)
	b.SetBytes(int64(len(jsonBytes)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = reconcile.RunReconcile(jsonBytes)
	}
}

// BenchmarkReconciliation_Combined_1000 measures reconciliation throughput
// with all three Rust binders exercised at once (HTTP causal, authority,
// DNS/flow) — the shape the run_pipeline parallelization in
// omnisec-ncer-reconcile-ffi targets, versus BenchmarkReconciliation_1000's
// HTTP-only capture which never touches bind_authority/bind_dns_flow's
// std::thread::scope path with meaningful work on those threads.
func BenchmarkReconciliation_Combined_1000(b *testing.B) {
	c := generateSyntheticCollector(800, 200)
	for i := 0; i < 500; i++ {
		ip := fmt.Sprintf("93.184.%d.%d", i/256, i%256)
		c.ObserveDNS(fmt.Sprintf("host-%d.example.com", i), 1, []string{ip}, "")
		c.ObserveFlow("192.168.1.2", 51234, ip, 443, 4096, 250, "tcp", "")
	}
	ctx := sampleAuthorityContext()
	for i := 0; i < 200; i++ {
		ctx.Observed = append(ctx.Observed, ObservedAction{
			Action: "network_connect", Target: fmt.Sprintf("host-%d.example.com", i), TimestampMs: int64(i),
		})
	}
	c.ObserveAuthority(FromAuthorityContextGranular(ctx, "bench", 0))

	input := c.buildReconcileInput()
	jsonBytes, _ := json.Marshal(input)
	b.SetBytes(int64(len(jsonBytes)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = reconcile.RunReconcile(jsonBytes)
	}
}

// BenchmarkReconciliation_Combined_10000 is BenchmarkReconciliation_Combined_1000
// scaled up 10x, to check whether run_pipeline's three-way parallel binder
// split (see omnisec-ncer-reconcile-ffi::run_pipeline) pays for its thread
// spawn overhead once each binder has enough work to actually overlap.
func BenchmarkReconciliation_Combined_10000(b *testing.B) {
	c := generateSyntheticCollector(8000, 2000)
	for i := 0; i < 5000; i++ {
		ip := fmt.Sprintf("93.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256)
		c.ObserveDNS(fmt.Sprintf("host-%d.example.com", i), 1, []string{ip}, "")
		c.ObserveFlow("192.168.1.2", 51234, ip, 443, 4096, 250, "tcp", "")
	}
	ctx := sampleAuthorityContext()
	for i := 0; i < 2000; i++ {
		ctx.Observed = append(ctx.Observed, ObservedAction{
			Action: "network_connect", Target: fmt.Sprintf("host-%d.example.com", i), TimestampMs: int64(i),
		})
	}
	c.ObserveAuthority(FromAuthorityContextGranular(ctx, "bench", 0))

	input := c.buildReconcileInput()
	jsonBytes, _ := json.Marshal(input)
	b.SetBytes(int64(len(jsonBytes)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = reconcile.RunReconcile(jsonBytes)
	}
}

// BenchmarkReconciliation_Combined_100000 pushes BenchmarkReconciliation_Combined_1000
// to 100x scale, to find whether run_pipeline's parallel binder split ever
// pays for its thread-spawn cost at all, or whether the binders are simply
// too fast (O(n log n) BTreeMap lookups, not O(n^2) scans) for splitting
// them across threads to be worthwhile at any realistic capture size.
func BenchmarkReconciliation_Combined_100000(b *testing.B) {
	c := generateSyntheticCollector(80000, 20000)
	for i := 0; i < 50000; i++ {
		ip := fmt.Sprintf("%d.%d.%d.%d", 10+(i/16777216)%200, (i/65536)%256, (i/256)%256, i%256)
		c.ObserveDNS(fmt.Sprintf("host-%d.example.com", i), 1, []string{ip}, "")
		c.ObserveFlow("192.168.1.2", 51234, ip, 443, 4096, 250, "tcp", "")
	}
	ctx := sampleAuthorityContext()
	for i := 0; i < 20000; i++ {
		ctx.Observed = append(ctx.Observed, ObservedAction{
			Action: "network_connect", Target: fmt.Sprintf("host-%d.example.com", i), TimestampMs: int64(i),
		})
	}
	c.ObserveAuthority(FromAuthorityContextGranular(ctx, "bench", 0))

	input := c.buildReconcileInput()
	jsonBytes, _ := json.Marshal(input)
	b.SetBytes(int64(len(jsonBytes)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = reconcile.RunReconcile(jsonBytes)
	}
}

// BenchmarkReconciliation_Combined_30000 sits between the 10,000 and 100,000
// combined benchmarks, where those two showed a crossover (parallel binders
// lose by ~10-15% at 1,000 events, roughly break even at 10,000, and win by
// ~8-10% at 100,000) — this narrows down where run_pipeline's size-based
// fast path (see PARALLEL_BINDER_THRESHOLD in omnisec-ncer-reconcile-ffi)
// should switch from serial to parallel binding.
func BenchmarkReconciliation_Combined_30000(b *testing.B) {
	c := generateSyntheticCollector(24000, 6000)
	for i := 0; i < 15000; i++ {
		ip := fmt.Sprintf("%d.%d.%d.%d", 10+(i/65536)%200, (i/65536)%256, (i/256)%256, i%256)
		c.ObserveDNS(fmt.Sprintf("host-%d.example.com", i), 1, []string{ip}, "")
		c.ObserveFlow("192.168.1.2", 51234, ip, 443, 4096, 250, "tcp", "")
	}
	ctx := sampleAuthorityContext()
	for i := 0; i < 6000; i++ {
		ctx.Observed = append(ctx.Observed, ObservedAction{
			Action: "network_connect", Target: fmt.Sprintf("host-%d.example.com", i), TimestampMs: int64(i),
		})
	}
	c.ObserveAuthority(FromAuthorityContextGranular(ctx, "bench", 0))

	input := c.buildReconcileInput()
	jsonBytes, _ := json.Marshal(input)
	b.SetBytes(int64(len(jsonBytes)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = reconcile.RunReconcile(jsonBytes)
	}
}

// BenchmarkEvidenceStorage_New measures latency/throughput when storing new evidence payloads.
func BenchmarkEvidenceStorage_New(b *testing.B) {
	tmpDir := b.TempDir()
	store, err := OpenEvidenceStore(tmpDir)
	if err != nil {
		b.Fatalf("OpenEvidenceStore: %v", err)
	}

	payload := []byte(`{"http_requests":[{"timestamp_ms":1700000000000,"method":"GET","url":"https://api.example.com/v1/test"}]}`)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = store.Store(payload)
	}
}

// BenchmarkEvidenceStorage_Verify measures evidence verification latency.
func BenchmarkEvidenceStorage_Verify(b *testing.B) {
	tmpDir := b.TempDir()
	store, err := OpenEvidenceStore(tmpDir)
	if err != nil {
		b.Fatalf("OpenEvidenceStore: %v", err)
	}

	payload := []byte(`{"http_requests":[{"timestamp_ms":1700000000000,"method":"GET","url":"https://api.example.com/v1/test"}]}`)
	hash, err := store.Store(payload)
	if err != nil {
		b.Fatalf("Store: %v", err)
	}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = store.Verify(hash)
	}
}

// BenchmarkEndToEndPipeline measures the full pipeline from telemetry ingestion
// through capture building, reconciliation, and evidence verification.
func BenchmarkEndToEndPipeline(b *testing.B) {
	tmpDir := b.TempDir()
	store, err := OpenEvidenceStore(filepath.Join(tmpDir, "evidence"))
	if err != nil {
		b.Fatalf("OpenEvidenceStore: %v", err)
	}

	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		c := NewCollector(base)
		c.SetEvidenceStore(store)
		for j := 0; j < 100; j++ {
			c.ObserveHTTP("GET", "https://api.example.com/v1/user", "200", "api.example.com", "10:00:01.100")
		}
		_, _ = c.Reconcile()
	}
}
