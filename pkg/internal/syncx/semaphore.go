// pkg/internal/syncx/semaphore.go
// Zero-dependency semaphore — replacement
package syncx

import "context"

// Semaphore — канальный семафор с поддержкой context
type Semaphore struct {
	ch chan struct{}
}

// NewSemaphore создаёт семафор с лимитом n
func NewSemaphore(n int) *Semaphore {
	return &Semaphore{ch: make(chan struct{}, n)}
}

// Acquire захватывает слот. Блокирует если все заняты.
// Возвращает ошибку если ctx отменён.
func (s *Semaphore) Acquire(ctx context.Context) error {
	select {
	case s.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryAcquire пытается захватить слот без блокировки.
func (s *Semaphore) TryAcquire() bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release освобождает слот.
func (s *Semaphore) Release() {
	<-s.ch
}

// Available возвращает количество свободных слотов.
func (s *Semaphore) Available() int {
	return cap(s.ch) - len(s.ch)
}
