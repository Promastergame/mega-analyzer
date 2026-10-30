package web

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type workspaceEntry struct {
	Name      string     `json:"name"`
	Path      string     `json:"path"`
	Directory bool       `json:"directory"`
	Size      int64      `json:"size"`
	Modified  time.Time  `json:"modified"`
	Scan      *savedScan `json:"scan,omitempty"`
}

func (s *Server) handleWorkspaceList(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ws, err := s.workspace()
	if err != nil {
		httpError(w, r, 500, workspaceError(err))
		return
	}
	root, err := os.OpenRoot(ws.path)
	if err != nil {
		httpError(w, r, 500, "Workspace unavailable")
		return
	}
	defer root.Close()
	rel := r.URL.Query().Get("path")
	f, err := openWorkspaceEntry(root, rel)
	if err != nil {
		httpError(w, r, 404, "Folder not found or not allowed")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.IsDir() {
		httpError(w, r, 400, "Not a directory")
		return
	}
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 || offset > 100000 {
			httpError(w, r, 400, "Invalid offset")
			return
		}
	}
	// Pagination bounds both memory and metadata reads for very large outputs.
	for left := offset; left > 0; {
		n := left
		if n > 200 {
			n = 200
		}
		entries, err := f.ReadDir(n)
		left -= len(entries)
		if err == io.EOF {
			break
		}
		if err != nil {
			httpError(w, r, 500, "Cannot read directory")
			return
		}
	}
	entries, err := f.ReadDir(201)
	if err != nil && err != io.EOF {
		httpError(w, r, 500, "Cannot read directory")
		return
	}
	more := len(entries) > 200
	if more {
		entries = entries[:200]
	}
	out := make([]workspaceEntry, 0, len(entries))
	for _, e := range entries {
		p := path.Join(rel, e.Name())
		if !validWorkspacePath(p, false) || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		fi, err := e.Info()
		if err != nil || !(fi.IsDir() || fi.Mode().IsRegular()) {
			continue
		}
		item := workspaceEntry{Name: e.Name(), Path: p, Directory: fi.IsDir(), Size: fi.Size(), Modified: fi.ModTime()}
		if fi.IsDir() {
			if meta, err := readSavedScan(root, p); err == nil {
				refreshSavedStatus(meta, ws.instance)
				meta.Instance = "" // internal session ownership, not a browser token
				meta.ReportPath, meta.ReportDir = findScanReport(root, p)
				item.Scan = meta
			}
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Directory != out[j].Directory {
			return out[i].Directory
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	var scan *savedScan
	if m, err := readSavedScan(root, rel); err == nil {
		scan = m
		refreshSavedStatus(m, ws.instance)
		m.Instance = ""
		m.ReportPath, m.ReportDir = findScanReport(root, rel)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"path": rel, "entries": out, "has_more": more, "next_offset": offset + len(entries), "scan": scan})
}

func refreshSavedStatus(meta *savedScan, instance string) {
	if meta.Instance != instance {
		if meta.Status == "running" || meta.Status == "queued" {
			meta.Status = "interrupted"
		}
		return
	}
	jobsMu.Lock()
	job := jobs[meta.ID]
	jobsMu.Unlock()
	if job != nil {
		meta.Status = job.status()
	}
}

func (s *Server) handleWorkspaceMkdir(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || !validWorkspacePath(body.Path, false) {
		httpError(w, r, 400, "Invalid folder path")
		return
	}
	ws, err := s.workspace()
	if err != nil {
		httpError(w, r, 500, workspaceError(err))
		return
	}
	ws.mu.Lock()
	defer ws.mu.Unlock()
	root, err := os.OpenRoot(ws.path)
	if err != nil {
		httpError(w, r, 500, "Workspace unavailable")
		return
	}
	defer root.Close()
	if _, err := root.Lstat(body.Path); err == nil {
		httpError(w, r, 409, "Folder already exists")
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		httpError(w, r, 400, "Cannot create folder")
		return
	}
	if err := ensureWorkspaceGroup(root, body.Path); err != nil {
		httpError(w, r, 400, workspaceError(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"path": body.Path})
}

func (s *Server) handleWorkspaceFile(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ws, err := s.workspace()
	if err != nil {
		httpError(w, r, 500, workspaceError(err))
		return
	}
	root, err := os.OpenRoot(ws.path)
	if err != nil {
		httpError(w, r, 500, "Workspace unavailable")
		return
	}
	defer root.Close()
	rel := r.URL.Query().Get("path")
	f, err := openWorkspaceEntry(root, rel)
	if err != nil {
		httpError(w, r, 404, "File not found or not allowed")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		httpError(w, r, 404, "Not a regular file")
		return
	}
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": fi.Name()}))
	if r.URL.Query().Get("preview") == "1" {
		switch strings.ToLower(path.Ext(rel)) {
		case ".json", ".txt", ".log", ".md", ".csv", ".html", ".htm", ".xml", ".yml", ".yaml", ".properties", ".java", ".smali":
		default:
			httpError(w, r, 415, "Preview is available for text reports only")
			return
		}
		if fi.Size() > 2<<20 {
			httpError(w, r, 413, "Preview limit is 2 MiB; download the file instead")
			return
		}
		data, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
		if err != nil {
			httpError(w, r, 500, "Cannot read file")
			return
		}
		if len(data) > 2<<20 {
			httpError(w, r, 413, "Preview limit exceeded")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Del("Content-Disposition")
		if r.Method != http.MethodHead {
			w.Write(data)
		}
		return
	}
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}

func findScanReport(root *os.Root, scanDir string) (string, string) {
	resultsDir := path.Join(scanDir, "results")
	f, err := openWorkspaceEntry(root, resultsDir)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	entries, err := f.ReadDir(20)
	if err != nil {
		return "", ""
	}
	for _, e := range entries {
		if !e.IsDir() && (e.Name() == "sandbox_report.md" || e.Name() == "report.md") {
			return path.Join(resultsDir, e.Name()), resultsDir
		}
	}
	for _, e := range entries {
		if e.IsDir() {
			subDir := path.Join(resultsDir, e.Name())
			subF, err := openWorkspaceEntry(root, subDir)
			if err == nil {
				subEntries, err := subF.ReadDir(20)
				subF.Close()
				if err == nil {
					for _, se := range subEntries {
						if !se.IsDir() && (se.Name() == "sandbox_report.md" || se.Name() == "report.md") {
							return path.Join(subDir, se.Name()), subDir
						}
						if se.IsDir() {
							sub2Dir := path.Join(subDir, se.Name())
							sub2F, err := openWorkspaceEntry(root, sub2Dir)
							if err == nil {
								sub2Entries, err := sub2F.ReadDir(20)
								sub2F.Close()
								if err == nil {
									for _, s2e := range sub2Entries {
										if !s2e.IsDir() && (s2e.Name() == "sandbox_report.md" || s2e.Name() == "report.md") {
											return path.Join(sub2Dir, s2e.Name()), sub2Dir
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return "", ""
}
