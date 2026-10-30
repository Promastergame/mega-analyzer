package pipeline

import (
	"context"
	"errors"
	"time"
)

// Config represents a generic pipeline configuration.
type Config struct {
	Workers int
}

// Validate checks the configuration for validity.
func (c *Config) Validate() error {
	if c.Workers <= 0 {
		return errors.New("workers must be greater than zero")
	}
	return nil
}

// Stage represents a processing stage in the pipeline.
type Stage struct {
	Name         string
	processor    func(context.Context, interface{}) (interface{}, error)
	filter       func(interface{}) bool
	errorHandler func(error, interface{})
}

// WithProcessor sets the processor for the stage.
func (s *Stage) WithProcessor(fn func(context.Context, interface{}) (interface{}, error)) *Stage {
	s.processor = fn
	return s
}

// WithFilter sets a filter for the stage.
func (s *Stage) WithFilter(fn func(interface{}) bool) *Stage {
	s.filter = fn
	return s
}

// WithErrorHandler sets an error handler for the stage.
func (s *Stage) WithErrorHandler(fn func(error, interface{})) *Stage {
	s.errorHandler = fn
	return s
}

// GenericPipeline represents a generic processing pipeline.
type GenericPipeline struct {
	stages  []*Stage
	workers int
	timeout time.Duration
}

// New creates a new generic pipeline.
func New(cfg *Config) *GenericPipeline {
	if cfg == nil {
		cfg = &Config{Workers: 4}
	}
	return &GenericPipeline{
		workers: cfg.Workers,
		timeout: 30 * time.Second,
	}
}

// AddStage adds a stage to the pipeline.
func (p *GenericPipeline) AddStage(s *Stage) {
	p.stages = append(p.stages, s)
}

// GenericStats represents statistics for the generic pipeline.
type GenericStats struct {
	ProcessedItems int
}

// Stats returns the pipeline statistics.
func (p *GenericPipeline) Stats() *GenericStats {
	return &GenericStats{}
}

// IsHealthy checks if the pipeline is healthy.
func (p *GenericPipeline) IsHealthy() bool {
	return true
}
