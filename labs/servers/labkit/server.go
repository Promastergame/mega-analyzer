package labkit

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Service is a supervised network service. Constructors bind their listener
// eagerly so Addr is valid before Start, which lets callers use an ephemeral
// ":0" port and then discover the concrete address.
type Service interface {
	// Name is the operator-facing identifier from the config.
	Name() string
	// Addr is the concrete bound address (host:port).
	Addr() string
	// Start begins serving in the background. It must be non-blocking.
	Start() error
	// Close stops the service, honouring ctx as a shutdown deadline.
	Close(ctx context.Context) error
}

// deps is the shared plumbing handed to every service constructor.
type deps struct {
	log      *Logger
	metrics  *Metrics
	scenario *Scenario
}

// Manager supervises a set of Services and shuts them down together.
type Manager struct {
	log     *Logger
	metrics *Metrics

	mu       sync.Mutex
	services []Service
	started  bool
}

// NewManager returns an empty Manager. If log is nil a default stderr logger
// is used. The returned Manager owns a fresh Metrics registry shared by every
// service it builds.
func NewManager(log *Logger) *Manager {
	if log == nil {
		log = NewLogger(nil, LevelInfo)
	}
	return &Manager{log: log, metrics: NewMetrics()}
}

// Metrics returns the shared registry so callers can snapshot it.
func (m *Manager) Metrics() *Metrics { return m.metrics }

// Add registers a pre-built service.
func (m *Manager) Add(s Service) {
	m.mu.Lock()
	m.services = append(m.services, s)
	m.mu.Unlock()
}

// Services returns a copy of the supervised services.
func (m *Manager) Services() []Service {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Service, len(m.services))
	copy(out, m.services)
	return out
}

// BuildFromConfig constructs every service declared in cfg and registers it.
// Listeners are bound eagerly, so a failure here means nothing was left half
// open: any services bound before the failure are closed again.
func (m *Manager) BuildFromConfig(cfg *Config) error {
	if cfg.LogLevel != "" {
		m.log.SetLevel(ParseLevel(cfg.LogLevel))
	}
	for i := range cfg.Servers {
		sc := cfg.Servers[i]
		d := deps{
			log:      m.log.With(Fields{"server": sc.Name, "kind": sc.Kind}),
			metrics:  m.metrics,
			scenario: NewScenario(sc.Scenario),
		}
		svc, err := buildService(sc, d)
		if err != nil {
			m.closeAll(context.Background())
			return fmt.Errorf("build server %q: %w", sc.Name, err)
		}
		m.Add(svc)
	}
	return nil
}

func buildService(sc ServerConfig, d deps) (Service, error) {
	sc.Addr = normalizeAddr(sc.Addr)
	switch sc.Kind {
	case "http":
		return newHTTPServer(sc, d)
	case "tcp":
		return newTCPServer(sc, d)
	case "udp":
		return newUDPServer(sc, d)
	default:
		return nil, fmt.Errorf("unknown kind %q", sc.Kind)
	}
}

// Start starts every registered service. If any fails to start, the ones that
// already started are stopped before returning the error.
func (m *Manager) Start() error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return errors.New("manager already started")
	}
	m.started = true
	services := make([]Service, len(m.services))
	copy(services, m.services)
	m.mu.Unlock()

	for i, s := range services {
		if err := s.Start(); err != nil {
			// Roll back the services we already started.
			for _, prev := range services[:i] {
				_ = prev.Close(context.Background())
			}
			return fmt.Errorf("start %q: %w", s.Name(), err)
		}
		m.log.Info("service started", Fields{"server": s.Name(), "addr": s.Addr()})
	}
	return nil
}

// Shutdown stops every service, aggregating any errors. ctx bounds how long
// the whole shutdown may take.
func (m *Manager) Shutdown(ctx context.Context) error {
	return m.closeAll(ctx)
}

func (m *Manager) closeAll(ctx context.Context) error {
	m.mu.Lock()
	services := make([]Service, len(m.services))
	copy(services, m.services)
	m.mu.Unlock()

	var errs []error
	for _, s := range services {
		if err := s.Close(ctx); err != nil {
			errs = append(errs, fmt.Errorf("close %q: %w", s.Name(), err))
		} else {
			m.log.Info("service stopped", Fields{"server": s.Name()})
		}
	}
	return errors.Join(errs...)
}
