package labtest

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/labdns"
	"mega-analyzer/pkg/ncer"
)

// trackerHostname mirrors the TRACKER_URL hostname convention documented in
// labs/servers/django/tracker-beacon/README.md: a fake local-only hostname
// resolved via pkg/internal/labdns rather than a raw IP, so DNS-level
// sinkholing has something to intercept.
const trackerHostname = "tracker.lab.local"

// hitSink is a minimal stand-in for labs/servers/trackercollector: it just
// counts how many beacon requests reached it. Deliberately self-contained
// (no import of the separate trackercollector module) since these tests
// must not depend on that independent lab module.
type hitSink struct {
	mu   sync.Mutex
	hits int
}

func newHitSinkServer() (*httptest.Server, *hitSink) {
	sink := &hitSink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sink.mu.Lock()
		sink.hits++
		sink.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	return srv, sink
}

func (s *hitSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

func beaconBody(event string) *bytes.Reader {
	b, _ := json.Marshal(map[string]string{"event": event})
	return bytes.NewReader(b)
}

// TestTrackerBeaconReachesCollectorWhenAllowed models the "before" state: the
// lab's DNS resolver has no block rule for tracker.lab.local yet, so it
// resolves straight through to the real tracker collector and the beacon
// lands there.
func TestTrackerBeaconReachesCollectorWhenAllowed(t *testing.T) {
	sinkSrv, sink := newHitSinkServer()
	defer sinkSrv.Close()
	sinkAddr := sinkSrv.Listener.Addr().(*net.TCPAddr)

	rules := labdns.NewSinkholeRules(false, []labdns.SinkholeRuleConfig{
		{Pattern: trackerHostname, Target: sinkAddr.IP.String(), Name: "allow-tracker"},
	})
	dnsSrv := labdns.NewDNSServer(&labdns.Config{ListenAddr: "127.0.0.1:15354", Rules: rules})
	if err := dnsSrv.StartBackground(); err != nil {
		t.Fatalf("start labdns: %v", err)
	}
	defer dnsSrv.Stop()

	client := newResolvingClient(dnsSrv.Addr(), 2*time.Second)
	url := "http://" + net.JoinHostPort(trackerHostname, strconv.Itoa(sinkAddr.Port)) + "/beacon"

	resp, err := client.Post(url, "application/json", beaconBody("note_created"))
	if err != nil {
		t.Fatalf("beacon request failed: %v", err)
	}
	resp.Body.Close()

	if got := sink.count(); got != 1 {
		t.Fatalf("collector hits = %d, want 1 (beacon should reach it while unblocked)", got)
	}

	// Feed the observed traffic into ncer so the reconciliation pipeline
	// sees it too -- this is the "real traffic to detect" half of the story.
	c := ncer.NewCollector(time.Now())
	c.ObserveHTTP("POST", url, "204", "", "")
	c.ObserveDNS(trackerHostname, 1, []string{sinkAddr.IP.String()}, "")
	if _, err := c.Reconcile(); err != nil {
		t.Fatalf("ncer Reconcile: %v", err)
	}
	if c.Len() != 1 {
		t.Fatalf("ncer collector recorded %d HTTP events, want 1", c.Len())
	}
}

// TestTrackerBeaconBlockedByLabDNS models the "after" state: a block rule for
// tracker.lab.local now sinkholes it to a dead address, so the beacon's POST
// never reaches the real collector -- proving the pipeline can both detect
// and block the tracker.
func TestTrackerBeaconBlockedByLabDNS(t *testing.T) {
	sinkSrv, sink := newHitSinkServer()
	defer sinkSrv.Close()
	sinkAddr := sinkSrv.Listener.Addr().(*net.TCPAddr)

	// A loopback address distinct from the collector's, with nothing
	// listening on it. Everything in this lab runs on 127.0.0.1, so the
	// sinkhole target must be a *different* loopback address to actually
	// divert traffic away from a same-host collector rather than
	// coincidentally still reaching it.
	const deadIP = "127.0.0.2"

	rules := labdns.NewSinkholeRules(false, nil)
	rules.SetSinkIP(deadIP)
	dnsSrv := labdns.NewDNSServer(&labdns.Config{ListenAddr: "127.0.0.1:15355", Rules: rules})
	dnsSrv.AddBlockRule(trackerHostname)
	if err := dnsSrv.StartBackground(); err != nil {
		t.Fatalf("start labdns: %v", err)
	}
	defer dnsSrv.Stop()

	client := newResolvingClient(dnsSrv.Addr(), 2*time.Second)
	url := "http://" + net.JoinHostPort(trackerHostname, strconv.Itoa(sinkAddr.Port)) + "/beacon"

	_, err := client.Post(url, "application/json", beaconBody("note_created"))
	if err == nil {
		t.Fatalf("expected the beacon POST to fail once blocked, it succeeded")
	}

	if got := sink.count(); got != 0 {
		t.Fatalf("collector hits = %d, want 0 (beacon must be blocked)", got)
	}

	stats := dnsSrv.Stats()
	if stats.SinkholeCount == 0 {
		t.Fatalf("expected LabDNS to record at least one sinkholed query")
	}
	found := false
	for _, n := range stats.SinkholedNames {
		if n == trackerHostname {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %q in sinkholed names, got %v", trackerHostname, stats.SinkholedNames)
	}

	// The reconciliation pipeline should still see the resolution attempt
	// (to the dead sinkhole address) even though the HTTP request itself
	// never landed -- the DNS query alone is evidence the beacon fired.
	c := ncer.NewCollector(time.Now())
	c.ObserveDNS(trackerHostname, 1, []string{deadIP}, "")
	if _, err := c.Reconcile(); err != nil {
		t.Fatalf("ncer Reconcile: %v", err)
	}
}
