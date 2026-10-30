package report

import (
	"io"
	"os"
	"path/filepath"
)

// writeReportFile replaces a report only after its complete contents have been
// written and closed. A failed export leaves the previous report readable.
func writeReportFile(outputDir, name string, write func(io.Writer) error) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(outputDir, "."+name+"-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()
	if err := write(f); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(outputDir, name))
}
