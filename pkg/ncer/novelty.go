package ncer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"mega-analyzer/pkg/internal/types"
)

// noveltyBaselineFile is the fixed filename inside a Collector's baseline
// directory (see SetBaselineDir). One file per directory keeps the format
// simple; callers that want per-target baselines pass a per-target
// directory (e.g. alongside the per-target evidence store).
const noveltyBaselineFile = "baseline.json"

// noveltyBaseline is the on-disk shape of the fingerprint baseline: a set of
// content-hashed fingerprints seen across all prior sessions recorded at
// this baseline directory.
type noveltyBaseline struct {
	Fingerprints map[string]bool `json:"fingerprints"`
}

// fingerprint hashes a "kind:value" pair (e.g. "http:GET https://x/y" or
// "dns:example.com") into a short hex digest so the baseline file never
// stores raw URLs/hostnames verbatim, matching the evidence store's
// content-addressing convention.
func fingerprint(kind, value string) string {
	h := sha256.Sum256([]byte(kind + ":" + value))
	return hex.EncodeToString(h[:])
}

// sessionFingerprints derives the set of fingerprints this session observed,
// across every collected signal type so novelty reflects the whole session,
// not just its HTTP/DNS surface:
//   - one per distinct (method, url) HTTP pair;
//   - one per distinct DNS query name;
//   - one per distinct TLS client fingerprint (JA3 hash when present, else the
//     SNI+cipher pair) — a new JA3 is a strong novelty signal, e.g. an unseen
//     client stack or an evasion attempt, and it was previously ignored even
//     though ObserveTLS already collects it;
//   - one per distinct outbound flow shape (dst IP, dst port, protocol).
//
// Distinctness is per-kind, so an HTTP URL that happens to hash to the same
// string as a DNS name can't collide (the "kind:" prefix in fingerprint
// separates them).
func (c *Collector) sessionFingerprints() []string {
	c.mu.Lock()
	evs := make([]httpEvent, len(c.events))
	copy(evs, c.events)
	dnsEvs := make([]dnsEvent, len(c.dnsEvents))
	copy(dnsEvs, c.dnsEvents)
	tlsEvs := make([]tlsEvent, len(c.tlsEvents))
	copy(tlsEvs, c.tlsEvents)
	flowEvs := make([]flowEvent, len(c.flowEvents))
	copy(flowEvs, c.flowEvents)
	c.mu.Unlock()

	seen := make(map[string]bool, len(evs)+len(dnsEvs)+len(tlsEvs)+len(flowEvs))
	for _, ev := range evs {
		seen[fingerprint("http", ev.method+" "+ev.url)] = true
	}
	for _, ev := range dnsEvs {
		seen[fingerprint("dns", ev.queryName)] = true
	}
	for _, ev := range tlsEvs {
		// Prefer the JA3 hash — it canonically identifies the client's TLS
		// stack. Fall back to SNI+cipher for handshakes captured before the
		// JA3 path existed (see mitmTLSHandshake's doc comment).
		val := ev.ja3Hash
		if val == "" {
			val = ev.sni + "|" + ev.cipherSuite
		}
		if val == "|" {
			continue // neither JA3 nor SNI/cipher: no signal
		}
		seen[fingerprint("tls", val)] = true
	}
	for _, ev := range flowEvs {
		if ev.dstIP == "" {
			continue
		}
		val := ev.dstIP + ":" + strconv.Itoa(int(ev.dstPort)) + "/" + ev.protocol
		seen[fingerprint("flow", val)] = true
	}

	out := make([]string, 0, len(seen))
	for fp := range seen {
		out = append(out, fp)
	}
	sort.Strings(out)
	return out
}

// scoreNovelty fills in result.DNovelty: the fraction of this session's
// fingerprints absent from the baseline recorded at c.baselineDir, then
// merges this session's fingerprints into that baseline for next time.
//
// A missing or unset baselineDir is a safe no-op: DNovelty stays 0.0, since
// "no baseline configured" is a deployment choice, not a genuine
// zero-novelty measurement (same convention as Rust's always-zero
// placeholder fields).
//
// The whole load→score→merge→save cycle runs under a cross-process file lock
// (see fileLock): two sessions sharing a baseline directory would otherwise
// race, and the second writer would silently drop the first's just-learned
// fingerprints (a lost update). Scoring and learning are separated internally
// (noveltyFraction is pure) so callers that need to evaluate novelty without
// mutating the baseline can use ScoreNoveltyReadOnly.
func (c *Collector) scoreNovelty(result *types.NcerCausalResult) {
	c.mu.Lock()
	dir := c.baselineDir
	c.mu.Unlock()
	if dir == "" {
		return
	}

	fps := c.sessionFingerprints()
	if len(fps) == 0 {
		return
	}

	// Ensure the directory exists before locking inside it.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}

	lock := newBaselineLock(dir)
	if err := lock.acquire(); err != nil {
		// Could not serialise: skip persistence entirely rather than risk a
		// lost update. Score read-only against whatever is currently on disk
		// so the caller still gets a best-effort DNovelty.
		if baseline, loadErr := loadNoveltyBaseline(dir); loadErr == nil {
			result.DNovelty = noveltyFraction(fps, baseline)
		}
		return
	}
	defer lock.release()

	baseline, err := loadNoveltyBaseline(dir)
	if err != nil {
		return
	}

	// Score first (pure), then learn: the fraction reflects the baseline as it
	// was *before* this session, and only afterwards do we fold this session's
	// fingerprints in.
	result.DNovelty = noveltyFraction(fps, baseline)
	for _, fp := range fps {
		baseline.Fingerprints[fp] = true
	}

	// Best-effort persistence: a failed write only costs this session's
	// baseline update, not correctness of the score just computed.
	_ = saveNoveltyBaseline(dir, baseline)
}

// ScoreNoveltyReadOnly returns the novelty fraction of this session's
// fingerprints against the baseline at dir without mutating that baseline. It
// is the pure "score" half of scoreNovelty, exposed for A/B evaluation and
// reproducible measurement: repeated calls return the same value because they
// never fold the session into the baseline. A missing baseline scores every
// fingerprint as novel (1.0); no observed fingerprints scores 0.0.
func (c *Collector) ScoreNoveltyReadOnly(dir string) float32 {
	if dir == "" {
		return 0.0
	}
	fps := c.sessionFingerprints()
	if len(fps) == 0 {
		return 0.0
	}
	baseline, err := loadNoveltyBaseline(dir)
	if err != nil {
		return 0.0
	}
	return noveltyFraction(fps, baseline)
}

// noveltyFraction is the pure scoring core: the fraction of fps absent from
// baseline. It does not mutate baseline, so scoring is separable from
// learning. An empty fps returns 0.0.
func noveltyFraction(fps []string, baseline *noveltyBaseline) float32 {
	if len(fps) == 0 {
		return 0.0
	}
	var novel int
	for _, fp := range fps {
		if !baseline.Fingerprints[fp] {
			novel++
		}
	}
	return float32(novel) / float32(len(fps))
}

func loadNoveltyBaseline(dir string) (*noveltyBaseline, error) {
	path := filepath.Join(dir, noveltyBaselineFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &noveltyBaseline{Fingerprints: map[string]bool{}}, nil
	}
	if err != nil {
		return nil, err
	}

	var b noveltyBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		return &noveltyBaseline{Fingerprints: map[string]bool{}}, nil //nolint:nilerr // corrupt baseline: start fresh rather than fail the session
	}
	if b.Fingerprints == nil {
		b.Fingerprints = map[string]bool{}
	}
	return &b, nil
}

func saveNoveltyBaseline(dir string, b *noveltyBaseline) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, noveltyBaselineFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
