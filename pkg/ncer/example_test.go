package ncer_test

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"mega-analyzer/pkg/ncer"
)

func ExampleCollector_ObserveHTTP() {
	c := ncer.NewCollector(time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))
	c.ObserveHTTP("GET", "https://example.com/api/v1/user", "200", "example.com", "12:00:01.000")
	fmt.Println("Recorded events:", c.Len())
	// Output:
	// Recorded events: 1
}

func ExampleEvidenceStore() {
	dir, err := os.MkdirTemp("", "evidence-example")
	if err != nil {
		return
	}
	defer os.RemoveAll(dir)

	store, err := ncer.OpenEvidenceStore(filepath.Join(dir, "evidence"))
	if err != nil {
		return
	}

	hash, err := store.Store([]byte("sample evidence payload"))
	if err != nil {
		return
	}
	valid, err := store.Verify(hash)
	if err != nil {
		return
	}
	fmt.Println("Stored successfully, verified:", valid)
	// Output:
	// Stored successfully, verified: true
}
