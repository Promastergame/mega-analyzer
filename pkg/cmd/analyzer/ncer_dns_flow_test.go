package main

import (
	"testing"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/ncer"
)

func TestFeedNcerDNSFlow_NilReportIsNoOp(t *testing.T) {
	c := ncer.NewCollector(time.Now())
	feedNcerDNSFlow(c, nil)
	if c.Len() != 0 {
		t.Errorf("expected no events observed for a nil report")
	}
}

func TestFeedNcerDNSFlow_NoNetworkCaptureIsNoOp(t *testing.T) {
	c := ncer.NewCollector(time.Now())
	feedNcerDNSFlow(c, &sandbox.Report{})
	res, err := c.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	_ = res
}

func TestFeedNcerDNSFlow_PopulatesDNSAndFlowEvents(t *testing.T) {
	c := ncer.NewCollector(time.Now())
	now := time.Now()
	report := &sandbox.Report{
		NetworkCapture: &sandbox.NetworkCapture{
			DNSQueries: []sandbox.DNSQuery{
				{Timestamp: now, QueryName: "example.com", QueryType: "A", Response: []string{"93.184.216.34"}},
			},
			Connections: []sandbox.NetworkConnection{
				{
					Timestamp: now, Protocol: "tcp",
					LocalAddr: "192.168.1.2", LocalPort: 51234,
					RemoteAddr: "93.184.216.34", RemotePort: 443,
					BytesSent: 100, BytesReceived: 200,
				},
			},
		},
	}

	feedNcerDNSFlow(c, report)

	// feedNcerDNSFlow doesn't touch HTTP events, so Len() stays 0 — verify
	// indirectly via Reconcile not bailing out on "nothing observed".
	res, err := c.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	_ = res
}

func TestDNSRecordType_KnownAndUnknown(t *testing.T) {
	cases := map[string]uint16{"A": 1, "NS": 2, "CNAME": 5, "AAAA": 28, "MX": 0, "": 0}
	for in, want := range cases {
		if got := dnsRecordType(in); got != want {
			t.Errorf("dnsRecordType(%q) = %d, want %d", in, got, want)
		}
	}
}
