// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
)

// Upload budgets: a single request is capped so one giant body cannot exhaust
// memory/disk, and all in-flight uploads share an aggregate temp-disk budget
// (queue slots alone do not bound bytes: every waiting job already holds its
// uploaded files). Both are overridable for labs that scan huge inputs.
func maxUploadBytes() int64 {
	return uploadEnvBytes("MEGA_ANALYZER_MAX_UPLOAD_BYTES", 512<<20)
}

func maxUploadTotalBytes() int64 {
	return uploadEnvBytes("MEGA_ANALYZER_MAX_UPLOAD_TOTAL_BYTES", 2<<30)
}

func uploadEnvBytes(name string, def int64) int64 {
	if raw := strings.TrimSpace(os.Getenv(name)); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// uploadInflightBytes tracks reserved request bytes and retained upload files.
// Declared sizes cover streamed bytes rather than counting them twice. Released when the
// owning job's temp dir is cleaned (or the handler rejects the request before
// submitting it). Every increment path has exactly one matching release.
var uploadInflightBytes atomic.Int64

// reserveUpload atomically reserves size bytes of the aggregate budget.
// Unlike a read-then-check, concurrent requests cannot both slip past: only
// one CAS winner takes the last room. False means over budget.
func reserveUpload(size int64) bool {
	if size <= 0 {
		return true
	}
	budget := maxUploadTotalBytes()
	for {
		cur := uploadInflightBytes.Load()
		if size > budget-cur {
			return false
		}
		if uploadInflightBytes.CompareAndSwap(cur, cur+size) {
			return true
		}
	}
}

// releaseUpload returns previously reserved bytes to the budget.
func releaseUpload(size int64) {
	if size > 0 {
		uploadInflightBytes.Add(-size)
	}
}

var errUploadBudgetExceeded = errors.New("aggregate upload budget exceeded")

// budgetReader reserves gauge room for every chunk as it streams, so even
// requests with unknown (chunked) length cannot overshoot the budget: the
// stream aborts the moment the next chunk would breach it.
type budgetReader struct {
	src      io.Reader
	reserved int64
	read     int64
	failed   bool
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.failed {
		return 0, errUploadBudgetExceeded
	}
	n, err := b.src.Read(p)
	if n > 0 {
		needed := b.read + int64(n) - b.reserved
		if needed > 0 && !reserveUpload(needed) {
			// Nothing was taken from the gauge, so do not account the
			// dropped chunk either: report failure with no bytes so the
			// caller releases exactly what was reserved before.
			b.failed = true
			return 0, errUploadBudgetExceeded
		}
		if needed > 0 {
			b.reserved += needed
		}
		b.read += int64(n)
	}
	return n, err
}

// maxErrorDrainBytes bounds the read-back of a request body that is rejected
// before it was consumed. Browsers still mid-upload treat a connection closed
// under them as a network failure ("TypeError: Failed to fetch") and never
// show the server's error text, so rejected uploads are drained first. Legit
// rejections happen below the 512 MiB upload cap; the headroom keeps a hostile
// unbounded body from pinning the server for long.
const maxErrorDrainBytes = 1 << 30

// drainUpload reads and discards up to maxErrorDrainBytes of the remaining
// request body.
func drainUpload(r *http.Request) {
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxErrorDrainBytes))
	}
}

// errorDrainWriter delays an error response until the rejected upload body has
// been drained, so the browser displays the server's message instead of a
// generic network error. Successful responses pass through untouched: the
// handler has then consumed the body itself.
type errorDrainWriter struct {
	http.ResponseWriter
	r       *http.Request
	started bool
}

func (w *errorDrainWriter) WriteHeader(code int) {
	if !w.started {
		w.started = true
		if code >= 400 {
			drainUpload(w.r)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

// errorDrainHandler wraps an upload endpoint so a rejected request drains the
// remaining body before its error response goes out.
func errorDrainHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&errorDrainWriter{ResponseWriter: w, r: r}, r)
	})
}

// saveUpload writes a part whose request body is already budgeted. Each part
// gets its own directory so client filenames cannot overwrite another input.
func saveUpload(dir, name string, src io.Reader) (string, int64, error) {
	p := filepath.Join(dir, filepath.Base(name))
	dst, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", 0, err
	}
	n, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		_ = os.Remove(p)
		return "", 0, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(p)
		return "", 0, closeErr
	}
	return p, n, nil
}

const (
	maxScanFormParts      = 32
	maxScanFormValueBytes = 64 << 10
)

var errScanFormValueTooLarge = errors.New("form field too large")

// scanUpload owns its reservation and temporary files until submission transfers
// both to a job. Every parse/validation error goes through the same cleanup path.
type scanUpload struct {
	dir    string
	bytes  int64
	values map[string]string
	files  map[string]string
}

func (u *scanUpload) cleanup() {
	if u.dir != "" {
		_ = os.RemoveAll(u.dir)
		u.dir = ""
	}
	releaseUpload(u.bytes)
	u.bytes = 0
}

func readScanUpload(r *http.Request) (upload *scanUpload, err error) {
	u := &scanUpload{values: make(map[string]string), files: make(map[string]string)}
	br := &budgetReader{src: r.Body}
	if r.ContentLength > 0 {
		if !reserveUpload(r.ContentLength) {
			return nil, errUploadBudgetExceeded
		}
		br.reserved = r.ContentLength
	}
	defer func() {
		u.bytes = br.reserved
		if err != nil {
			u.cleanup()
		}
	}()
	r.Body = struct {
		io.Reader
		io.Closer
	}{br, r.Body}
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, err
	}
	u.dir, err = os.MkdirTemp("", "mega-web-")
	if err != nil {
		return nil, err
	}
	var fileBytes int64
	for count := 0; ; count++ {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if count >= maxScanFormParts {
			return nil, errors.New("too many form parts")
		}
		field, name := part.FormName(), part.FileName()
		if name == "" {
			data, err := io.ReadAll(io.LimitReader(part, maxScanFormValueBytes+1))
			if err != nil {
				return nil, err
			}
			if len(data) > maxScanFormValueBytes {
				return nil, errScanFormValueTooLarge
			}
			if _, exists := u.values[field]; !exists {
				u.values[field] = string(data)
			}
			continue
		}
		if (field != "file" && field != "file2") || u.files[field] != "" || !filepath.IsLocal(name) || name == "." {
			return nil, errors.New("invalid or duplicate file field")
		}
		dir := filepath.Join(u.dir, field)
		if err := os.Mkdir(dir, 0700); err != nil {
			return nil, err
		}
		p, n, err := saveUpload(dir, name, part)
		if err != nil {
			return nil, err
		}
		u.files[field] = p
		fileBytes += n
	}
	// Multipart framing and fields are no longer needed. Retain only the file
	// reservation for queued/running jobs; known-length bodies were charged once.
	releaseUpload(br.reserved - fileBytes)
	br.reserved = fileBytes
	return u, nil
}

// sandboxListFiles returns a JSON array of all files in a sandbox session dir.
// Directories are included so the UI can show a tree structure.
func sandboxListFiles(w http.ResponseWriter, sessionDir string) {
	type entry struct {
		Name  string `json:"name"`
		Path  string `json:"path"` // slash-separated, relative to sessionDir
		Size  int64  `json:"size"`
		IsDir bool   `json:"is_dir"`
	}
	var entries []entry
	_ = filepath.Walk(sessionDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || p == sessionDir {
			return nil
		}
		rel, _ := filepath.Rel(sessionDir, p)
		entries = append(entries, entry{
			Name:  fi.Name(),
			Path:  filepath.ToSlash(rel),
			Size:  fi.Size(),
			IsDir: fi.IsDir(),
		})
		return nil
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries) //nolint:errcheck
}

// sandboxDownloadFile serves a file from inside a sandbox session directory.
// The lexical local-path check rejects ".." escapes; the file itself is opened
// through os.Root so a symlink planted inside the session can never redirect
// the read outside of it (the open fails instead of serving foreign bytes).
func sandboxDownloadFile(w http.ResponseWriter, r *http.Request, sessionDir, relPath string) {
	rel := filepath.FromSlash(relPath)
	if !filepath.IsLocal(rel) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	root, err := os.OpenRoot(sessionDir)
	if err != nil {
		http.Error(w, "cannot open file", http.StatusInternalServerError)
		return
	}
	defer root.Close()
	fi, err := root.Stat(rel)
	if err != nil || !fi.Mode().IsRegular() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	f, err := root.Open(rel)
	if err != nil {
		http.Error(w, "cannot open file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, fi.Name()))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
	if r.Method == http.MethodHead {
		return
	}
	io.Copy(w, f) //nolint:errcheck
}
