package main

import (
	"time"

	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/ncer"
)

// feedNcerDNSFlow converts a finished sandbox Report's captured DNS queries
// and network connections into NCER DNS/flow events (see
// ncer.Collector.ObserveDNS / ObserveFlow) so Reconcile can compute
// d_information via the Rust dns_flow_binder. A no-op when the report has no
// NetworkCapture (e.g. non-Windows sandbox runs, or runs where traffic
// capture was disabled).
func feedNcerDNSFlow(collector *ncer.Collector, report *sandbox.Report) {
	if report == nil || report.NetworkCapture == nil {
		return
	}
	nc := report.NetworkCapture

	for _, d := range nc.DNSQueries {
		collector.ObserveDNS(d.QueryName, dnsRecordType(d.QueryType), d.Response, stampTime(d.Timestamp))
	}

	for _, c := range nc.Connections {
		collector.ObserveFlow(
			c.LocalAddr, c.LocalPort,
			c.RemoteAddr, c.RemotePort,
			c.BytesSent+c.BytesReceived, 0,
			c.Protocol, stampTime(c.Timestamp),
		)
	}
}

// dnsRecordType maps a human-readable DNS query type string (e.g. "A",
// "AAAA") to its numeric QTYPE. Unrecognized types map to 0 (Rust's
// DnsQueryCapture.record_type is a bare u16 with no reserved "unknown"
// sentinel, but a 0 record_type doesn't affect dns_flow_binder's IP-based
// matching, which never inspects this field).
func dnsRecordType(queryType string) uint16 {
	switch queryType {
	case "A":
		return 1
	case "NS":
		return 2
	case "CNAME":
		return 5
	case "AAAA":
		return 28
	default:
		return 0
	}
}

// stampTime formats t as the HH:MM:SS.mmm string ncer.Collector's timestamp
// parser expects, matching the format used throughout runner_stream.go.
func stampTime(t time.Time) string {
	return t.Format("15:04:05.000")
}
