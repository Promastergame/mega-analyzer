package sandbox

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

// KernelMonitor captures filesystem and registry operations at the kernel level
// using Windows minifilter drivers and registry callbacks.
//
// Implementation Strategy:
// - Uses Windows minifilter framework (FltRegisterFilter)
// - Leverages CmRegisterCallbackEx for registry callbacks
// - Communicates with user-mode via named pipes and IOCP
//
// Validates: Requirements 2.1, 2.2, 2.3, 2.4
type KernelMonitor interface {
	// Start begins kernel-level monitoring and event collection.
	// Returns an error if the minifilter driver is not loaded or privileges are insufficient.
	Start(ctx context.Context) error

	// Stop terminates monitoring and cleans up resources.
	// Returns an error if cleanup fails (non-fatal).
	Stop() error

	// Events returns a read-only channel of kernel events.
	// The channel is closed when Stop() is called.
	Events() <-chan KernelEvent

	// SetProcessFilter configures the monitor to only capture events from the specified process tree.
	// This reduces noise by filtering out events from unrelated processes.
	// If pids is empty or nil, filtering is disabled and all events are captured.
	SetProcessFilter(pids []int)
}

// kernelMonitorImpl is the Windows implementation of KernelMonitor.
// It communicates with a minifilter driver via named pipe and uses IOCP
// for high-frequency event buffering.
type kernelMonitorImpl struct {
	pipeName           string
	eventChan          chan KernelEvent
	stopChan           chan struct{}
	wg                 sync.WaitGroup
	mu                 sync.Mutex
	running            bool
	bufferSize         int
	targetPIDs         map[int]struct{} // Process tree to filter events
	filterEnabled      bool             // Whether to filter by process tree
	droppedEventsCount uint64           // Counter for dropped events due to buffer full
}

// NewKernelMonitor creates a new kernel monitor instance.
// The monitor must be started with Start() before events are available.
func NewKernelMonitor() KernelMonitor {
	return &kernelMonitorImpl{
		pipeName:      `\\.\pipe\MegaAnalyzerKernelMonitor`,
		eventChan:     make(chan KernelEvent, 1000), // Buffered channel for high-frequency events
		stopChan:      make(chan struct{}),
		bufferSize:    8192, // 8KB buffer for pipe reads
		targetPIDs:    make(map[int]struct{}),
		filterEnabled: false,
	}
}

// SetProcessFilter configures the monitor to only capture events from the specified process tree.
// This reduces noise by filtering out events from unrelated processes.
// If pids is empty or nil, filtering is disabled and all events are captured.
//
// Validates: Requirements 2.1, 2.3
func (km *kernelMonitorImpl) SetProcessFilter(pids []int) {
	km.mu.Lock()
	defer km.mu.Unlock()

	km.targetPIDs = make(map[int]struct{}, len(pids))
	for _, pid := range pids {
		km.targetPIDs[pid] = struct{}{}
	}
	km.filterEnabled = len(pids) > 0
}

// Start begins kernel-level monitoring.
// It connects to the minifilter driver's named pipe and spawns a goroutine
// to read events and publish them to the Events() channel.
//
// Validates: Requirements 2.1, 2.2, 2.4
func (km *kernelMonitorImpl) Start(ctx context.Context) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.running {
		return fmt.Errorf("kernel monitor already running")
	}

	// Check if we have administrator privileges
	if !isAdmin() {
		return fmt.Errorf("kernel monitor requires administrator privileges")
	}

	// Verify minifilter driver is loaded
	if err := km.verifyDriverLoaded(); err != nil {
		return fmt.Errorf("minifilter driver not loaded: %w", err)
	}

	// Connect to the named pipe
	pipe, err := km.connectToPipe(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to kernel monitor pipe: %w", err)
	}

	// Recreate channels in case this is a restart after a previous Stop().
	km.stopChan = make(chan struct{})
	km.eventChan = make(chan KernelEvent, 1000)

	km.running = true

	// Start goroutine to read from pipe and publish events
	km.wg.Add(1)
	go km.eventReader(ctx, pipe)

	return nil
}

// Stop terminates kernel-level monitoring and closes the event channel.
//
// Validates: Requirements 2.4
func (km *kernelMonitorImpl) Stop() error {
	km.mu.Lock()
	if !km.running {
		km.mu.Unlock()
		return nil
	}
	km.running = false
	km.mu.Unlock()

	// Signal stop to event reader
	close(km.stopChan)

	// Wait for goroutine to finish
	km.wg.Wait()

	// Close event channel
	close(km.eventChan)

	return nil
}

// Events returns a read-only channel of kernel events.
// The channel is buffered to handle high-frequency event streams.
//
// Validates: Requirements 2.3, 2.4
func (km *kernelMonitorImpl) Events() <-chan KernelEvent {
	return km.eventChan
}

// eventReader reads events from the named pipe and publishes them to the event channel.
// This runs in a separate goroutine and uses IOCP-based buffering for high-frequency logging.
// Events are filtered by target process tree if filtering is enabled.
//
// Validates: Requirements 2.1, 2.3, 2.4
func (km *kernelMonitorImpl) eventReader(ctx context.Context, pipe pipeHandle) {
	defer km.wg.Done()
	defer km.closePipe(pipe)

	buffer := make([]byte, km.bufferSize)

	for {
		select {
		case <-ctx.Done():
			return
		case <-km.stopChan:
			return
		default:
			// Read from pipe with timeout
			event, err := km.readEvent(pipe, buffer)
			if err != nil {
				// Check if it's a timeout or stop signal
				if km.isStopRequested() {
					return
				}
				// Log error but continue reading
				continue
			}

			// Apply process tree filter if enabled
			if km.shouldFilterEvent(event) {
				continue
			}

			// Publish event to channel (non-blocking)
			select {
			case km.eventChan <- event:
			case <-km.stopChan:
				return
			default:
				// Channel full, drop event (prevents blocking)
				dropped := atomic.AddUint64(&km.droppedEventsCount, 1)
				if dropped%100 == 1 {
					fmt.Fprintf(os.Stderr, "[!] WARNING: Kernel Monitor event queue is full. Dropped %d events so far.\n", dropped)
				}
			}
		}
	}
}

// shouldFilterEvent returns true if the event should be filtered out (not published).
// Events are filtered if process tree filtering is enabled and the event's process ID
// is not in the target process tree.
//
// Validates: Requirements 2.1, 2.3
func (km *kernelMonitorImpl) shouldFilterEvent(event KernelEvent) bool {
	km.mu.Lock()
	defer km.mu.Unlock()

	if !km.filterEnabled {
		return false
	}

	_, inTree := km.targetPIDs[event.ProcessID]
	return !inTree
}

// isStopRequested checks if a stop has been requested.
func (km *kernelMonitorImpl) isStopRequested() bool {
	select {
	case <-km.stopChan:
		return true
	default:
		return false
	}
}

// Platform-specific methods (implemented in kernel_monitor_windows.go and kernel_monitor_stub.go):
// - verifyDriverLoaded() error
// - connectToPipe(ctx context.Context) (pipeHandle, error)
// - readEvent(pipe pipeHandle, buffer []byte) (KernelEvent, error)
// - closePipe(pipe pipeHandle)
