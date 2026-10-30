package minecraft

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:embed report.html
var reportHTML string

var reportTemplate = template.Must(template.New("minecraft").Funcs(template.FuncMap{
	"raw": func(b []byte) string { return string(b) },
	"mib": func(n uint64) string { return fmt.Sprintf("%.2f", float64(n)/(1<<20)) },
}).Parse(reportHTML))

// HTML produces a self-contained report; all package-controlled text is escaped.
func (r Report) HTML(w io.Writer) error { return reportTemplate.Execute(w, r) }

// WriteReports uses the existing web UI's report filenames. Each file is
// rendered completely before replacing the destination, avoiding truncated
// reports if serialization fails. Input packages are never modified.
func WriteReports(dir string, r Report) error {
	if dir == "" {
		return fmt.Errorf("output directory is required")
	}
	source, err := filepath.Abs(r.Path)
	if err != nil {
		return err
	}
	for _, name := range []string{"analysis.json", "REPORT.html"} {
		dest, err := filepath.Abs(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if strings.EqualFold(source, dest) {
			return fmt.Errorf("report destination would overwrite the input: %s", dest)
		}
	}
	var jsonBuf, htmlBuf bytes.Buffer
	if err := r.JSON(&jsonBuf); err != nil {
		return err
	}
	if err := r.HTML(&htmlBuf); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for _, item := range []struct {
		name string
		data []byte
	}{{"analysis.json", jsonBuf.Bytes()}, {"REPORT.html", htmlBuf.Bytes()}} {
		if err := writeReportFile(filepath.Join(dir, item.name), item.data); err != nil {
			return err
		}
	}
	return nil
}
func writeReportFile(dest string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(dest), ".minecraft-report-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}
