package main

import "testing"

func TestIsLoopbackURL(t *testing.T) {
	for u, want := range map[string]bool{
		"http://127.0.0.1:8088/decisions":   true,
		"http://localhost:8088/decisions":   true,
		"http://[::1]:8088/decisions":       true,
		"https://openrouter.ai/api/v1/chat": false,
		"http://10.0.0.5:8088/decisions":    false,
		"http://127.0.0.1.evil.com/x":       false,
		"":                                  false,
	} {
		if got := isLoopbackURL(u); got != want {
			t.Errorf("isLoopbackURL(%q) = %v, want %v", u, got, want)
		}
	}
}
