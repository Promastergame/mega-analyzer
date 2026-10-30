package ml

import (
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func testTempDir(t testing.TB) string {
	t.Helper()
	return testutil.TempDir(t)
}
