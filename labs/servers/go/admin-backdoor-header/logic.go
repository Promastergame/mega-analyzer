package main

import "net/http"

// BackdoorHeaderName and BackdoorHeaderValue are a hardcoded "ops/debug"
// bypass left in the codebase (CWE-798: Use of Hard-coded Credentials).
// Any request carrying this exact header/value pair is treated as an
// authenticated administrator with zero password check, on top of the
// normal login flow. This is the vulnerability this lab exists to
// demonstrate — see README.md.
const (
	BackdoorHeaderName  = "X-Debug-Role"
	BackdoorHeaderValue = "admin"
)

// isBackdoorHeader reports whether the given request headers carry the
// hardcoded backdoor header/value combination. It is pulled out as a pure,
// dependency-free function so it can be unit tested directly without
// spinning up the HTTP server or a store.
func isBackdoorHeader(h http.Header) bool {
	return h.Get(BackdoorHeaderName) == BackdoorHeaderValue
}
