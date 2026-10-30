// Package main implements labs-path-traversal-download, an intentionally
// vulnerable local lab server. See README.md for the full write-up.
package main

import "errors"

// resolvePath computes the on-disk path that GET /files?name=<name> will
// read from, given the server's configured files directory baseDir.
//
// INTENTIONALLY VULNERABLE: no traversal check. This performs a naive
// string join and never rejects ".." segments, never calls
// filepath.Clean + verifies the result is still contained inside baseDir,
// and never rejects absolute-looking input. A caller-supplied name like
// "../../../../etc/passwd" walks straight out of baseDir and onto the
// host filesystem (CWE-22: Improper Limitation of a Pathname to a
// Restricted Directory / "Path Traversal").
//
// A safe implementation would, at minimum: filepath.Clean(name), reject
// any ".." path element or absolute path outright, then filepath.Join and
// filepath.Rel to confirm the resolved path is still inside baseDir before
// ever touching the filesystem. None of that happens here — on purpose —
// so the lab has a realistic target. See pathresolve_test.go for proof
// this escapes baseDir, and README.md for the end-to-end exploit chain.
func resolvePath(baseDir, name string) (string, error) {
	if name == "" {
		return "", errors.New("empty name")
	}
	return baseDir + "/" + name, nil
}
