package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/scanjobs"
	"mega-analyzer/pkg/internal/testutil"
)

type apiRunnerFunc func(context.Context, scanjobs.Request, string) (scanjobs.RunResult, error)

func (f apiRunnerFunc) Run(ctx context.Context, request scanjobs.Request, outputDir string) (scanjobs.RunResult, error) {
	return f(ctx, request, outputDir)
}

func newScanTestServer(t *testing.T) *APIServer {
	t.Helper()
	server := NewAPIServer(0)
	// Keep cleanup registered before closeScanManager (Cleanup is LIFO).
	// Windows can temporarily report ERROR_DIR_NOT_EMPTY after handles close;
	// the shared helper retries that error without hiding persistent failures.
	server.scanConfig.RootDir = testutil.TempDir(t)
	server.scanConfig.Runner = apiRunnerFunc(func(_ context.Context, _ scanjobs.Request, outputDir string) (scanjobs.RunResult, error) {
		if err := os.WriteFile(filepath.Join(outputDir, "analysis.json"), []byte(`{"status":"ok"}`), 0o600); err != nil {
			return scanjobs.RunResult{}, err
		}
		if err := os.WriteFile(filepath.Join(outputDir, "REPORT.html"), []byte(`<html>owned report</html>`), 0o600); err != nil {
			return scanjobs.RunResult{}, err
		}
		return scanjobs.RunResult{}, nil
	})
	t.Cleanup(server.closeScanManager)
	return server
}

func uploadTestArtifact(t *testing.T, server *APIServer) string {
	t.Helper()
	payload := append([]byte{'P', 'K', 3, 4}, bytes.Repeat([]byte{0}, 32)...)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Filename", "sample.apk")
	rr := httptest.NewRecorder()
	server.handleArtifactUpload(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("upload status = %d: %s", rr.Code, rr.Body.String())
	}
	var artifact struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&artifact); err != nil {
		t.Fatal(err)
	}
	return artifact.ID
}

func TestArtifactScanWaitContract(t *testing.T) {
	server := newScanTestServer(t)
	id := uploadTestArtifact(t, server)
	body := strings.NewReader(`{"artifact_id":"` + id + `","wait":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", body)
	rr := httptest.NewRecorder()
	server.handleScanAPK(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("scan status = %d: %s", rr.Code, rr.Body.String())
	}
	var result map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["status"] != "ok" {
		t.Fatalf("unexpected analysis contract: %v", result)
	}
}

func TestArtifactScanAsyncAndOwnedReport(t *testing.T) {
	server := newScanTestServer(t)
	artifactID := uploadTestArtifact(t, server)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{"artifact_id":"`+artifactID+`"}`))
	rr := httptest.NewRecorder()
	server.handleScanAPK(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("submit status = %d: %s", rr.Code, rr.Body.String())
	}
	var response struct {
		Job scanjobs.Snapshot `json:"job"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	manager, err := server.scanManager()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Wait(context.Background(), response.Job.ID); err != nil {
		t.Fatal(err)
	}
	reportReq := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+response.Job.ID+"/report/REPORT.html", nil)
	reportRR := httptest.NewRecorder()
	server.handleScanJob(reportRR, reportReq)
	if reportRR.Code != http.StatusOK || !strings.Contains(reportRR.Body.String(), "owned report") {
		t.Fatalf("report response = %d: %s", reportRR.Code, reportRR.Body.String())
	}
}

func TestLocalPathScanDisabledByDefault(t *testing.T) {
	server := newScanTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/apk", strings.NewReader(`{"target":"C:/private/app.apk"}`))
	rr := httptest.NewRecorder()
	server.handleScanAPK(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rr.Code, rr.Body.String())
	}
}

// The fixture must stop and join active runners before its temporary tree is
// removed. A cancellation acknowledgement alone is not enough: runners may
// still be closing files or writing their final report.
func TestScanTestServerCleanupWaitsForRunner(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan error, 1)
	var root string
	t.Run("active scan", func(t *testing.T) {
		server := newScanTestServer(t)
		root = server.scanConfig.RootDir
		server.scanConfig.Runner = apiRunnerFunc(func(ctx context.Context, _ scanjobs.Request, outputDir string) (scanjobs.RunResult, error) {
			close(started)
			<-ctx.Done()
			err := os.WriteFile(filepath.Join(outputDir, "final.txt"), []byte("closed"), 0o600)
			finished <- err
			return scanjobs.RunResult{}, ctx.Err()
		})
		manager, err := server.scanManager()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Submit(scanjobs.Request{Target: "fixture.apk"}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("scan runner did not start")
		}
		// newScanTestServer's registered cleanups do the shutdown and removal.
	})
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("runner could not finish before directory cleanup: %v", err)
		}
	default:
		t.Fatal("fixture cleanup returned before the runner finished")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("fixture directory survived cleanup: %v", err)
	}
}
