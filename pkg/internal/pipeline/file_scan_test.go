package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

type testFileExecutor struct {
	worker *FileScanWorker
	fail   bool
}

func (e *testFileExecutor) Start(ctx context.Context, task FileScanTask, content []byte) fileScanFuture {
	result := make(chan struct {
		value FileScanResult
		err   error
	}, 1)
	go func() {
		value, err := e.worker.Scan(ctx, task, content)
		// Exercise the actual JSON wire format used between browser runtimes.
		if err == nil {
			var encoded []byte
			encoded, err = json.Marshal(value)
			if err == nil {
				err = json.Unmarshal(encoded, &value)
			}
		}
		result <- struct {
			value FileScanResult
			err   error
		}{value, err}
	}()
	return func(context.Context) (FileScanResult, error) {
		reply := <-result
		if e.fail {
			return FileScanResult{}, errors.New("test helper failure")
		}
		return reply.value, reply.err
	}
}
func (*testFileExecutor) Yield() {}

func TestIndependentFileScanningPreservesCoordinatorResults(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.EnableCallGraph = true
	cfg.EnableDataFlow = true
	cfg.EnableDeobfuscation = true
	cfg.EnableContentCache = false
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var helperConfig config.Config
	if err := json.Unmarshal(encoded, &helperConfig); err != nil {
		t.Fatal(err)
	}
	worker, err := NewFileScanWorker(&helperConfig)
	if err != nil {
		t.Fatal(err)
	}
	samples := []struct {
		path string
		kind types.FileType
		body string
	}{
		{"smali/example/App.smali", types.FileTypeSmali, ".class public Lexample/App;\n.super Ljava/lang/Object;\n.method public static checkLicense()Z\n.registers 1\nconst-string v0, \"https://4pda.to/forum\"\nconst/4 v0, 0x1\nreturn v0\n.end method\n"},
		{"AndroidManifest.xml", types.FileTypeXML, `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.app"><uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/><application android:usesCleartextTraffic="true"/></manifest>`},
		{"assets/settings.json", types.FileTypeJSON, `{"download":"https://4pda.to/","encoded":"aHR0cHM6Ly80cGRhLnRvL2ZvcnVt"}`},
	}
	for _, sample := range samples {
		for _, fail := range []bool{false, true} {
			local, err := NewPipeline(cfg)
			if err != nil {
				t.Fatal(err)
			}
			local.resetRunState("test")
			remote, err := NewPipeline(cfg)
			if err != nil {
				t.Fatal(err)
			}
			remote.resetRunState("test")
			remote.fileExecutor = &testFileExecutor{worker: worker, fail: fail}
			job := FileJob{Path: sample.path, RelPath: sample.path, Type: sample.kind, Size: int64(len(sample.body)), ForceAppCode: true}
			want := local.processContent(context.Background(), job, []byte(sample.body))
			got := remote.processContent(context.Background(), job, []byte(sample.body))
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("helper changed file analysis for %s (fallback=%v)", sample.path, fail)
			}
			if len(got.Matches) == 0 {
				t.Fatalf("fixture produced no evidence: %s", sample.path)
			}
		}
	}
}
