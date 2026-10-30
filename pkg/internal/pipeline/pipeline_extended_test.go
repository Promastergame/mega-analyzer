package pipeline

import (
	"context"
	"testing"
)

func TestNewPipeline(t *testing.T) {
	cfg := &Config{
		Workers: 4,
	}

	pipeline := New(cfg)

	if pipeline == nil {
		t.Fatal("New returned nil")
	}
}

func TestPipeline_AddStage(t *testing.T) {
	cfg := &Config{
		Workers: 4,
	}

	pipeline := New(cfg)

	stage := &Stage{
		Name: "test-stage",
	}

	pipeline.AddStage(stage)

	if len(pipeline.stages) != 1 {
		t.Errorf("AddStage should add stage, got %d stages", len(pipeline.stages))
	}

	if pipeline.stages[0].Name != "test-stage" {
		t.Errorf("Stage name = %q, want test-stage", pipeline.stages[0].Name)
	}
}

func TestPipeline_AddMultipleStages(t *testing.T) {
	cfg := &Config{
		Workers: 4,
	}

	pipeline := New(cfg)

	for i := 0; i < 5; i++ {
		stage := &Stage{
			Name: "stage-" + string(rune('0'+i)),
		}
		pipeline.AddStage(stage)
	}

	if len(pipeline.stages) != 5 {
		t.Errorf("AddStage should add all stages, got %d stages", len(pipeline.stages))
	}
}

func TestStage_Name(t *testing.T) {
	stage := &Stage{
		Name: "test-stage",
	}

	if stage.Name != "test-stage" {
		t.Errorf("Stage.Name = %q, want test-stage", stage.Name)
	}
}

func TestStage_WithProcessor(t *testing.T) {
	stage := &Stage{
		Name: "test-stage",
	}

	processor := func(ctx context.Context, item interface{}) (interface{}, error) {
		return item, nil
	}

	stage.WithProcessor(processor)

	if stage.processor == nil {
		t.Error("WithProcessor should set processor")
	}
}

func TestStage_WithFilter(t *testing.T) {
	stage := &Stage{
		Name: "test-stage",
	}

	filter := func(item interface{}) bool {
		return true
	}

	stage.WithFilter(filter)

	if stage.filter == nil {
		t.Error("WithFilter should set filter")
	}
}

func TestStage_WithErrorHandler(t *testing.T) {
	stage := &Stage{
		Name: "test-stage",
	}

	handler := func(err error, item interface{}) {
		// Handle error
	}

	stage.WithErrorHandler(handler)

	if stage.errorHandler == nil {
		t.Error("WithErrorHandler should set error handler")
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &Config{
				Workers: 4,
			},
			wantErr: false,
		},
		{
			name: "zero workers",
			cfg: &Config{
				Workers: 0,
			},
			wantErr: true,
		},
		{
			name: "negative workers",
			cfg: &Config{
				Workers: -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPipeline_WithTimeout(t *testing.T) {
	cfg := &Config{
		Workers: 4,
	}

	pipeline := New(cfg)

	if pipeline.timeout == 0 {
		t.Error("Pipeline should have default timeout")
	}
}

func TestPipeline_WithWorkers(t *testing.T) {
	cfg := &Config{
		Workers: 4,
	}

	pipeline := New(cfg)

	if pipeline.workers != 4 {
		t.Errorf("Pipeline workers = %d, want 4", pipeline.workers)
	}
}

func TestPipeline_Stats(t *testing.T) {
	cfg := &Config{
		Workers: 4,
	}

	pipeline := New(cfg)

	stats := pipeline.Stats()

	if stats == nil {
		t.Error("Stats should not return nil")
	}

	if stats.ProcessedItems != 0 {
		t.Errorf("ProcessedItems = %d, want 0", stats.ProcessedItems)
	}
}

func TestPipeline_IsHealthy(t *testing.T) {
	cfg := &Config{
		Workers: 4,
	}

	pipeline := New(cfg)

	if !pipeline.IsHealthy() {
		t.Error("Pipeline should be healthy initially")
	}
}

// Benchmark tests
func BenchmarkNewPipeline(b *testing.B) {
	cfg := &Config{
		Workers: 4,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		New(cfg)
	}
}

func BenchmarkPipeline_AddStage(b *testing.B) {
	cfg := &Config{
		Workers: 4,
	}

	pipeline := New(cfg)
	stage := &Stage{
		Name: "test-stage",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pipeline.AddStage(stage)
	}
}

func BenchmarkStage_WithProcessor(b *testing.B) {
	stage := &Stage{
		Name: "test-stage",
	}

	processor := func(ctx context.Context, item interface{}) (interface{}, error) {
		return item, nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stage.WithProcessor(processor)
	}
}
