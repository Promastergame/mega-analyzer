package main

import (
	"net/http"
	"testing"
)

func TestIsBackdoorHeader(t *testing.T) {
	tests := []struct {
		name string
		set  func(h http.Header)
		want bool
	}{
		{
			name: "exact magic header and value",
			set:  func(h http.Header) { h.Set(BackdoorHeaderName, BackdoorHeaderValue) },
			want: true,
		},
		{
			name: "wrong value",
			set:  func(h http.Header) { h.Set(BackdoorHeaderName, "not-admin") },
			want: false,
		},
		{
			name: "wrong header name",
			set:  func(h http.Header) { h.Set("X-Debug-Rolee", BackdoorHeaderValue) },
			want: false,
		},
		{
			name: "no headers at all",
			set:  func(h http.Header) {},
			want: false,
		},
		{
			name: "case-sensitive value mismatch",
			set:  func(h http.Header) { h.Set(BackdoorHeaderName, "Admin") },
			want: false,
		},
		{
			name: "empty value",
			set:  func(h http.Header) { h.Set(BackdoorHeaderName, "") },
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := make(http.Header)
			tc.set(h)
			if got := isBackdoorHeader(h); got != tc.want {
				t.Errorf("isBackdoorHeader() = %v, want %v", got, tc.want)
			}
		})
	}
}
