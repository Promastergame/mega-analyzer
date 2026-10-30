package web

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type artifactEntry struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

const artifactPageSize = 2000
const artifactArchiveLimit = 200000

// /api/artifacts/:job[/archive.zip|/files/<relative path>]
// All reads are rooted to the result directory, including ZIP file opens.
func (s *Server) handleArtifacts(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/artifacts/")
	id, sub, _ := strings.Cut(rest, "/")
	jobsMu.Lock()
	job, ok := jobs[id]
	jobsMu.Unlock()
	if !ok {
		httpError(w, r, 404, "No result with that id")
		return
	}
	job.mu.Lock()
	done, code := job.done, job.exitCode
	job.mu.Unlock()
	if strings.HasPrefix(sub, "files/") {
		sandboxDownloadFile(w, r, job.outDir, strings.TrimPrefix(sub, "files/"))
		return
	}
	if sub != "" && sub != "archive.zip" {
		httpError(w, r, 404, "Unknown artifact endpoint")
		return
	}
	if sub == "archive.zip" && !done {
		httpError(w, r, 409, "Wait for the job to finish before downloading its archive")
		return
	}
	root, err := os.OpenRoot(job.outDir)
	if err != nil {
		httpError(w, r, 404, "Result folder is unavailable")
		return
	}
	defer root.Close()
	w.Header().Set("Cache-Control", "no-store")
	offset := 0
	query := strings.ToLower(r.URL.Query().Get("q"))
	if sub == "" {
		if raw := r.URL.Query().Get("offset"); raw != "" {
			offset, err = strconv.Atoi(raw)
			if err != nil || offset < 0 || offset > 10000000 {
				httpError(w, r, 400, "Invalid offset")
				return
			}
		}
		if len(query) > 256 {
			httpError(w, r, 400, "Search query too long")
			return
		}
	}
	entries := []artifactEntry{}
	truncated := false
	limit := artifactPageSize
	if sub == "archive.zip" {
		limit = artifactArchiveLimit
	}
	skipped := 0
	err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if err := r.Context().Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		name := entry.Name()
		if name == ".mega-analyzer-cache.db" || name == ".mega-analyzer-decode-cache.json" || strings.HasPrefix(name, ".mega-analyzer-") {
			return nil
		}
		if sub == "" && query != "" && !strings.Contains(strings.ToLower(path), query) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if skipped < offset {
			skipped++
			return nil
		}
		if len(entries) >= limit {
			truncated = true
			return fs.SkipAll
		}
		entries = append(entries, artifactEntry{Path: path, Size: info.Size()})
		return nil
	})
	if err != nil {
		httpError(w, r, 500, "Cannot enumerate result files")
		return
	}
	if sub == "archive.zip" {
		if truncated {
			httpError(w, r, 413, "Too many files for one archive; use the workspace browser")
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="analysis-%s.zip"`, id))
		if r.Method == http.MethodHead {
			return
		}
		archive := zip.NewWriter(w)
		copied := 0
		for _, entry := range entries {
			if r.Context().Err() != nil {
				break
			}
			file, err := root.Open(filepath.FromSlash(entry.Path))
			if err != nil {
				break
			}
			// Store large binary artifacts rather than burning CPU recompressing APKs.
			header := &zip.FileHeader{Name: entry.Path, Method: zip.Deflate}
			if entry.Size > 32<<20 {
				header.Method = zip.Store
			}
			writer, err := archive.CreateHeader(header)
			if err == nil {
				_, err = io.Copy(writer, file)
			}
			file.Close()
			if err != nil {
				break
			}
			copied++
		}
		// A failed stream remains an invalid ZIP rather than a valid partial archive.
		if copied == len(entries) && r.Context().Err() == nil {
			_ = archive.Close()
		}
		return
	}
	var stages json.RawMessage
	if file, err := root.Open("static_outputs.json"); err == nil {
		data, readErr := io.ReadAll(io.LimitReader(file, 4<<20))
		file.Close()
		if readErr == nil && json.Valid(data) {
			stages = data
		}
	}
	reports := make(map[string]bool)
	for _, name := range []string{"REPORT.html", "REPORT.md", "analysis.json", "analysis.sarif"} {
		info, statErr := root.Lstat(name)
		reports[name] = statErr == nil && info.Mode().IsRegular()
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		Files        []artifactEntry `json:"files"`
		Truncated    bool            `json:"truncated"`
		Done         bool            `json:"done"`
		ExitCode     int             `json:"exit_code"`
		Stages       json.RawMessage `json:"stages,omitempty"`
		Reports      map[string]bool `json:"reports"`
		NextOffset   int             `json:"next_offset"`
		ArchiveLimit int             `json:"archive_limit"`
	}{entries, truncated, done, code, stages, reports, offset + len(entries), artifactArchiveLimit})
}
