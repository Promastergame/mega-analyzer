package web

import (
	"errors"
	"sync"
)

type queuedScan struct {
	job *scanJob
	run func()
}

// No permanent workers: a bounded FIFO starts another job when a slot opens.
// Tickets bound uploads as well as waiting/running scans.
type scanQueue struct {
	mu      sync.Mutex
	limit   int
	tickets chan struct{}
	pending []*queuedScan
	active  map[*scanJob]bool
	closed  bool
}

func newScanQueue(limit, waiting int) *scanQueue {
	return &scanQueue{limit: limit, tickets: make(chan struct{}, limit+waiting), active: make(map[*scanJob]bool)}
}

func (s *Server) scanQueue() *scanQueue {
	s.queueOnce.Do(func() {
		limit, waiting := s.opts.ScanConcurrency, s.opts.ScanQueueSize
		if limit == 0 {
			limit = 2
		}
		if waiting == 0 {
			waiting = 8
		}
		s.queue = newScanQueue(limit, waiting)
	})
	return s.queue
}

func (q *scanQueue) reserve() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	select {
	case q.tickets <- struct{}{}:
		return true
	default:
		return false
	}
}

func (q *scanQueue) release() { <-q.tickets }

// submit takes ownership of a reserved ticket only on success.
func (q *scanQueue) submit(job *scanJob, run func()) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return errors.New("scan queue is shutting down")
	}
	job.mu.Lock()
	job.state = "queued"
	job.cancel = func() { q.cancelPending(job) }
	job.mu.Unlock()
	job.broadcast("[queue] Waiting for an available scan slot")
	q.pending = append(q.pending, &queuedScan{job: job, run: run})
	q.dispatchLocked()
	return nil
}

func (q *scanQueue) dispatchLocked() {
	for !q.closed && len(q.active) < q.limit && len(q.pending) > 0 {
		entry := q.pending[0]
		q.pending[0] = nil
		q.pending = q.pending[1:]
		q.active[entry.job] = true
		go func() {
			defer func() {
				q.mu.Lock()
				delete(q.active, entry.job)
				q.release()
				q.dispatchLocked()
				q.mu.Unlock()
			}()
			entry.job.mu.Lock()
			entry.job.state = "running"
			entry.job.wakeLocked()
			entry.job.mu.Unlock()
			entry.job.broadcast("[queue] Scan started")
			entry.run()
		}()
	}
}

func (q *scanQueue) cancelPending(job *scanJob) {
	q.mu.Lock()
	for i, e := range q.pending {
		if e.job == job {
			copy(q.pending[i:], q.pending[i+1:])
			q.pending[len(q.pending)-1] = nil
			q.pending = q.pending[:len(q.pending)-1]
			q.release()
			q.mu.Unlock()
			job.broadcast("[queue] Cancelled before starting")
			job.finish(130)
			job.cleanupUpload()
			return
		}
	}
	q.mu.Unlock()
}

func (q *scanQueue) shutdown() {
	q.mu.Lock()
	q.closed = true
	var jobs []*scanJob
	for j := range q.active {
		jobs = append(jobs, j)
	}
	for _, e := range q.pending {
		jobs = append(jobs, e.job)
	}
	q.mu.Unlock()
	for _, j := range jobs {
		j.stop()
	}
}
