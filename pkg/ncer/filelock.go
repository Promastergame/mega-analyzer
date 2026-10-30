package ncer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// fileLock is a minimal cross-process advisory lock built on exclusive file
// creation (O_CREATE|O_EXCL). It exists so two analysis sessions that share a
// baseline directory (see SetBaselineDir) serialise their read-modify-write of
// baseline.json instead of clobbering each other's fingerprints — os.Rename is
// atomic, but the load→merge→save *sequence* around it is not, so without this
// the last writer silently drops the other session's just-learned entries.
//
// It deliberately avoids any third-party or OS-specific locking API so it
// works identically on the platforms this repo targets. The trade-offs of the
// O_EXCL approach — a crashed holder leaves a stale lock — are bounded by
// staleTimeout: a lock file older than that is assumed abandoned and stolen.
type fileLock struct {
	path string
}

const (
	lockAcquireTimeout = 5 * time.Second
	lockRetryInterval  = 5 * time.Millisecond
	lockStaleTimeout   = 30 * time.Second
)

// acquire blocks until the lock is held or lockAcquireTimeout elapses. A lock
// file whose mtime is older than lockStaleTimeout is treated as abandoned by a
// crashed holder and removed so acquisition can proceed.
func (l fileLock) acquire() error {
	deadline := time.Now().Add(lockAcquireTimeout)
	for {
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			_ = f.Close()
			return nil
		}
		// The lock is held (ErrExist) — or, on Windows, another goroutine is
		// mid-Remove of the lock file and the O_EXCL create transiently fails
		// with ERROR_ACCESS_DENIED rather than ERROR_ALREADY_EXISTS. Both are
		// retryable: only give up at the deadline. A genuinely unwritable
		// directory fails every attempt and surfaces at the deadline below.
		if errors.Is(err, os.ErrExist) {
			// Steal the lock if the current holder looks stale (crashed).
			if info, statErr := os.Stat(l.path); statErr == nil {
				if time.Since(info.ModTime()) > lockStaleTimeout {
					_ = os.Remove(l.path)
					continue
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("ncer: timed out acquiring novelty baseline lock: %w", err)
		}
		time.Sleep(lockRetryInterval)
	}
}

func (l fileLock) release() {
	_ = os.Remove(l.path)
}

// newBaselineLock returns the lock guarding the baseline file in dir.
func newBaselineLock(dir string) fileLock {
	return fileLock{path: filepath.Join(dir, noveltyBaselineFile+".lock")}
}
