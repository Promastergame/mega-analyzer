package s1

import (
	"context"
	"fmt"
	"sync"
)

// BackendLoader initializes a backend once, on first use. Share the pointer
// between engine copies so concurrent requests cannot load duplicate models.
// A canceled caller stops waiting; initialization continues for later callers.
// The loader's result (including an error) is retained for its lifetime.
type BackendLoader struct {
	once    sync.Once
	done    chan struct{}
	load    func() (Backend, error)
	backend Backend
	err     error
}

func NewBackendLoader(load func() (Backend, error)) *BackendLoader {
	return &BackendLoader{done: make(chan struct{}), load: load}
}

func (l *BackendLoader) Load(ctx context.Context) (Backend, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.once.Do(func() {
		go func() {
			l.backend, l.err = l.load()
			if l.err == nil && l.backend == nil {
				l.err = fmt.Errorf("backend loader returned no backend")
			}
			l.load = nil // release the captured initialization state
			close(l.done)
		}()
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return l.backend, l.err
	}
}
