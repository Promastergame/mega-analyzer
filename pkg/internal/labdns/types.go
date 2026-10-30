// Package labdns provides a local DNS sinkhole server for intercepting,
// logging and selectively resolving DNS queries from an Android emulator
// guest OS during dynamic analysis sessions.
package labdns

import (
	"sync"
	"time"
)

// DNSQueryRecord is a single DNS lookup observed during a session.
type DNSQueryRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	QueryName  string    `json:"query_name"`
	QueryType  string    `json:"query_type"`
	SourceAddr string    `json:"source_addr"`
	Action     string    `json:"action"` // "forwarded", "sinked", "blocked", "nxdomain"
	Answer     string    `json:"answer,omitempty"`
	AnswerIP   string    `json:"answer_ip,omitempty"`
	Upstream   string    `json:"upstream,omitempty"`
	LatencyMs  int64     `json:"latency_ms"`
	RuleName   string    `json:"rule_name,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// DNSStats summarises a session's DNS activity.
type DNSStats struct {
	TotalQueries   int           `json:"total_queries"`
	ForwardedCount int           `json:"forwarded_count"`
	SinkholeCount  int           `json:"sinkhole_count"`
	BlockedCount   int           `json:"blocked_count"`
	BlockedQueries int           `json:"blocked_queries"`
	NXDomainCount  int           `json:"nxdomain_count"`
	ErrorCount     int           `json:"error_count"`
	UniqueNames    int           `json:"unique_names"`
	TopDomains     []DomainCount `json:"top_domains"`
	SinkholedNames []string      `json:"sinkholed_names,omitempty"`
	C2Candidates   []string      `json:"c2_candidates,omitempty"`
}

// DomainCount is a (domain, count) pair for ranking.
type DomainCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// queryLog is a thread-safe append-only DNS query log.
type queryLog struct {
	mu      sync.Mutex
	records []DNSQueryRecord
}

func newQueryLog() *queryLog {
	return &queryLog{
		records: make([]DNSQueryRecord, 0, 256),
	}
}

const maxDNSLogRecords = 10000

func (l *queryLog) Append(r DNSQueryRecord) {
	l.mu.Lock()
	l.records = append(l.records, r)
	if len(l.records) > maxDNSLogRecords {
		copy(l.records, l.records[len(l.records)-maxDNSLogRecords:])
		l.records = l.records[:maxDNSLogRecords]
	}
	l.mu.Unlock()
}

func (l *queryLog) Snapshot() []DNSQueryRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]DNSQueryRecord, len(l.records))
	copy(out, l.records)
	return out
}
