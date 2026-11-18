package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInferenceAdmissionDoesNotBlockHealth(t *testing.T) {
	entered, release := make(chan bool), make(chan bool)
	h := limitInference(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/decide" {
			entered <- true
			<-release
		}
		w.WriteHeader(200)
	}), 1)
	done := make(chan bool)
	go func() {
		defer func() { done <- true }()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/decide", nil))
	}()
	<-entered
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/decide", nil))
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Fatal("unbounded admission")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/health", nil))
	if rec.Code != 200 {
		t.Fatal("health blocked")
	}
	release <- true
	<-done
}
