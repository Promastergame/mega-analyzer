package netproxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewAdvancedMITMProxy_NilConfig(t *testing.T) {
	p, err := NewAdvancedMITMProxy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	p.Close()
}

func TestNewAdvancedMITMProxy_DefaultConfig(t *testing.T) {
	cfg := &AdvancedMITMConfig{}
	p, err := NewAdvancedMITMProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	p.Close()
}

func TestNewAdvancedMITMProxy_WithFeatures(t *testing.T) {
	cfg := &AdvancedMITMConfig{
		EnableJA3Analysis:       true,
		EnableProtocolInference: true,
		EnableReplay:            true,
		EnableFuzzing:           true,
		FuzzingMutationRate:     0.1,
		EnableRedaction:         true,
		SecretScannerEnabled:    true,
	}
	p, err := NewAdvancedMITMProxy(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	if p.ja3Analyzer == nil {
		t.Error("expected ja3Analyzer to be initialized")
	}
	if p.protocolInferrer == nil {
		t.Error("expected protocolInferrer to be initialized")
	}
	if p.replayEngine == nil {
		t.Error("expected replayEngine to be initialized")
	}
	if p.fuzzingEngine == nil {
		t.Error("expected fuzzingEngine to be initialized")
	}
	if p.secretScanner == nil {
		t.Error("expected secretScanner to be initialized")
	}
	p.Close()
}

func TestAdvancedMITMProxy_GetEventChannel(t *testing.T) {
	p, err := NewAdvancedMITMProxy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer p.Close()

	ch := p.GetEventChannel()
	if ch == nil {
		t.Fatal("expected non-nil event channel")
	}
}

func TestAdvancedMITMProxy_SendEvent(t *testing.T) {
	p, err := NewAdvancedMITMProxy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer p.Close()

	p.sendEvent(MITMEvent{
		Type:      "test_event",
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"key": "value"},
	})

	select {
	case evt := <-p.GetEventChannel():
		if evt.Type != "test_event" {
			t.Errorf("expected type 'test_event', got %q", evt.Type)
		}
		if evt.Data["key"] != "value" {
			t.Errorf("expected data key 'value', got %v", evt.Data["key"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for event")
	}
}

func TestAdvancedMITMProxy_CloseIdempotent(t *testing.T) {
	p, err := NewAdvancedMITMProxy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Close multiple times — should not panic
	p.Close()
	p.Close()
}

func TestNewCertificateAuthority_GeneratesNewCA(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")
	cachePath := filepath.Join(dir, "cache")

	ca, err := NewCertificateAuthority(keyPath, certPath, cachePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ca == nil {
		t.Fatal("expected non-nil CA")
	}
	if ca.caKey == nil {
		t.Error("expected caKey to be set")
	}
	if ca.caCert == nil {
		t.Error("expected caCert to be set")
	}
	// Check files were written
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("expected key file to be written")
	}
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("expected cert file to be written")
	}
}

func TestNewCertificateAuthority_LoadsExistingCA(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")
	cachePath := filepath.Join(dir, "cache")

	// Generate first
	ca1, err := NewCertificateAuthority(keyPath, certPath, cachePath)
	if err != nil {
		t.Fatalf("unexpected error on first creation: %v", err)
	}

	// Load from existing files
	ca2, err := NewCertificateAuthority(keyPath, certPath, cachePath)
	if err != nil {
		t.Fatalf("unexpected error on second creation: %v", err)
	}
	if ca2 == nil {
		t.Fatal("expected non-nil CA on reload")
	}

	// Both should have same cert fingerprint
	if ca1.caCert.SerialNumber.Cmp(ca2.caCert.SerialNumber) != 0 {
		t.Error("expected same serial number after reload")
	}
}

func TestAdvancedMITMProxy_GenerateLeafCertificate(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")
	cachePath := filepath.Join(dir, "cache")

	ca, err := NewCertificateAuthority(keyPath, certPath, cachePath)
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	cert, err := ca.GenerateLeafCertificate("test.example.com")
	if err != nil {
		t.Fatalf("failed to generate leaf cert: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if len(cert.Certificate) == 0 {
		t.Error("expected non-empty certificate data")
	}
}
