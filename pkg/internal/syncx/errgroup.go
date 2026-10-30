// pkg/internal/syncx/errgroup.go
// Zero-dependency errgroup — полный replacement
package syncx

import (
	"context"
	"sync"
)

// Group — аналог errgroup.Group
// Отличие: первая ошибка отменяет контекст, остальные горутины должны
// проверять ctx.Done() и завершаться самостоятельно.
type Group struct {
	cancel func(error) // context.CancelCauseFunc

	wg sync.WaitGroup

	sem chan struct{}

	errOnce sync.Once
	err     error
}

// SetLimit limits the number of active goroutines in this group to at most n.
// A negative value indicates no limit.
func (g *Group) SetLimit(n int) {
	if n < 0 {
		g.sem = nil
		return
	}
	if len(g.sem) != 0 {
		panic("syncx: modify limit while goroutines are active")
	}
	g.sem = make(chan struct{}, n)
}

// WithContext создаёт Group + отменяемый контекст.
// Аналог errgroup.WithContext.
func WithContext(ctx context.Context) (*Group, context.Context) {
	ctx, cancel := context.WithCancelCause(ctx)
	return &Group{cancel: cancel}, ctx
}

// Go запускает f в новой горутине.
// Первая non-nil ошибка отменяет контекст и сохраняется.
func (g *Group) Go(f func() error) {
	if g.sem != nil {
		g.sem <- struct{}{}
	}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		if g.sem != nil {
			defer func() { <-g.sem }()
		}
		if err := f(); err != nil {
			g.errOnce.Do(func() {
				g.err = err
				if g.cancel != nil {
					g.cancel(err)
				}
			})
		}
	}()
}

// TryGo запускает f только если лимит горутин не превышен.
// Аналог errgroup.TryGo (Go 1.22+).
// Возвращает false если лимит исчерпан.
func (g *Group) TryGo(f func() error) bool {
	if g.sem != nil {
		select {
		case g.sem <- struct{}{}:
		default:
			return false
		}
	}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		if g.sem != nil {
			defer func() { <-g.sem }()
		}
		if err := f(); err != nil {
			g.errOnce.Do(func() {
				g.err = err
				if g.cancel != nil {
					g.cancel(err)
				}
			})
		}
	}()
	return true
}

// Wait блокирует до завершения всех горутин.
// Возвращает первую non-nil ошибку.
func (g *Group) Wait() error {
	g.wg.Wait()
	if g.cancel != nil {
		g.cancel(g.err)
	}
	return g.err
}
