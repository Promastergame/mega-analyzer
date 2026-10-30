package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
)

const workspaceMeta = ".scan.json"
const maxWorkspaceLog = 8 << 20

type workspaceStore struct {
	mu       sync.Mutex
	path     string
	instance string
}

type savedScan struct {
	Version      int        `json:"version"`
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Mode         string     `json:"mode"`
	Started      time.Time  `json:"started"`
	Finished     *time.Time `json:"finished,omitempty"`
	Status       string     `json:"status"`
	ExitCode     int        `json:"exit_code"`
	Instance     string     `json:"instance"`
	LogTruncated bool       `json:"log_truncated,omitempty"`
	ReportPath   string     `json:"report_path,omitempty"`
	ReportDir    string     `json:"report_dir,omitempty"`
}

// Resolve lazily, so constructing a test Server creates no user directories.
func (s *Server) workspace() (*workspaceStore, error) {
	s.workspaceOnce.Do(func() {
		dir := s.opts.Workspace
		if dir == "" {
			dir = os.Getenv("MEGA_ANALYZER_WORKSPACE")
		}
		if dir == "" {
			base, err := os.UserConfigDir()
			if err != nil {
				s.workspaceErr = err
				return
			}
			dir = filepath.Join(base, "Mega-Analyzer", "workspace")
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			s.workspaceErr = err
			return
		}
		if err = os.MkdirAll(abs, 0700); err != nil {
			s.workspaceErr = err
			return
		}
		token := newToken()
		if token == "" {
			s.workspaceErr = errors.New("secure randomness unavailable")
			return
		}
		s.workspaceStore = &workspaceStore{path: abs, instance: token}
	})
	return s.workspaceStore, s.workspaceErr
}

// Slash-only relative paths are portable across Windows and Unix. os.Root is
// the actual containment boundary (including symlink races), not a prefix test.
func validWorkspacePath(p string, rootOK bool) bool {
	if p == "" {
		return rootOK
	}
	if len(p) > 1024 || path.Clean(p) != p || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\:") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || strings.HasPrefix(part, ".") || len(part) > 180 || strings.HasSuffix(part, " ") || strings.HasSuffix(part, ".") {
			return false
		}
		for _, r := range part {
			if unicode.IsControl(r) || strings.ContainsRune("<>\"|?*", r) {
				return false
			}
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" || base == "CONOUT$" {
			return false
		}
		if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9' {
			return false
		}
	}
	return true
}

func openWorkspaceEntry(root *os.Root, name string) (*os.File, error) {
	if !validWorkspacePath(name, true) {
		return nil, os.ErrPermission
	}
	if name == "" {
		name = "."
	}
	// Hide symlinks even when they point inside the root. Root.Open also rejects
	// escapes should a component be exchanged after this check.
	current := ""
	for _, part := range strings.Split(name, "/") {
		current = path.Join(current, part)
		fi, err := root.Lstat(filepath.FromSlash(current))
		if err != nil {
			return nil, err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !(fi.IsDir() || fi.Mode().IsRegular()) {
			return nil, os.ErrPermission
		}
	}
	return root.Open(filepath.FromSlash(name))
}

func readSavedScan(root *os.Root, dir string) (*savedScan, error) {
	f, err := root.Open(filepath.FromSlash(path.Join(dir, workspaceMeta)))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 16<<10 {
		return nil, errors.New("invalid scan metadata")
	}
	var meta savedScan
	if err = json.NewDecoder(io.LimitReader(f, 16<<10)).Decode(&meta); err != nil {
		return nil, err
	}
	if meta.Version != 1 || meta.ID == "" {
		return nil, errors.New("unsupported scan metadata")
	}
	return &meta, nil
}

func atomicWorkspaceWrite(root *os.Root, name string, data []byte) error {
	token := newToken()
	if token == "" {
		return errors.New("secure randomness unavailable")
	}
	tmp := name + ".tmp-" + token
	f, err := root.OpenFile(filepath.FromSlash(tmp), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(filepath.FromSlash(tmp))
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return root.Rename(filepath.FromSlash(tmp), filepath.FromSlash(name))
}

// ensureGroup never nests a new scan inside an existing scan's artifacts.
func ensureWorkspaceGroup(root *os.Root, group string) error {
	if !validWorkspacePath(group, false) {
		return errors.New("use a relative workspace folder, not an absolute output path")
	}
	current := ""
	for _, part := range strings.Split(group, "/") {
		current = path.Join(current, part)
		if err := root.Mkdir(filepath.FromSlash(current), 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		f, err := openWorkspaceEntry(root, current)
		if err != nil {
			return err
		}
		fi, err := f.Stat()
		f.Close()
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return errors.New("not a folder")
		}
		if _, err := root.Lstat(filepath.FromSlash(path.Join(current, workspaceMeta))); err == nil {
			return errors.New("cannot create folders inside a scan")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (ws *workspaceStore) createScan(group, name, mode string) (*scanJob, string, error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	root, err := os.OpenRoot(ws.path)
	if err != nil {
		return nil, "", err
	}
	defer root.Close()
	if group == "" {
		group = "Scans"
	}
	if err = ensureWorkspaceGroup(root, group); err != nil {
		return nil, "", err
	}
	id := newToken()
	if id == "" {
		return nil, "", errors.New("secure randomness unavailable")
	}
	rel := path.Join(group, time.Now().UTC().Format("2006-01-02_150405")+"_"+id)
	if err = root.Mkdir(filepath.FromSlash(rel), 0700); err != nil {
		return nil, "", err
	}
	out := path.Join(rel, "results")
	if err = root.Mkdir(filepath.FromSlash(out), 0700); err != nil {
		root.Remove(filepath.FromSlash(rel))
		return nil, "", err
	}
	job := newScanJob(id, "", filepath.Join(ws.path, filepath.FromSlash(out)))
	job.logDir = filepath.Join(ws.path, filepath.FromSlash(rel))
	job.filename, job.mode = name, mode
	meta := savedScan{Version: 1, ID: id, Name: name, Mode: mode, Started: job.started, Status: "queued", Instance: ws.instance}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, "", err
	}
	if err = atomicWorkspaceWrite(root, path.Join(rel, workspaceMeta), data); err != nil {
		return nil, "", err
	}
	job.onFinish = func(j *scanJob) error {
		j.mu.Lock()
		meta.ExitCode = j.exitCode
		meta.Status = "completed"
		if j.exitCode != 0 {
			meta.Status = "failed"
		}
		if j.stopped {
			meta.Status = "stopped"
		}
		now := time.Now()
		meta.Finished = &now
		meta.LogTruncated = j.logTruncated || j.logErr != nil
		logErr := j.logErr
		j.mu.Unlock()
		r, err := os.OpenRoot(ws.path)
		if err != nil {
			return err
		}
		defer r.Close()
		data, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			return err
		}
		if err = atomicWorkspaceWrite(r, path.Join(rel, workspaceMeta), data); err != nil {
			return err
		}
		return logErr
	}
	return job, rel, nil
}

func workspaceError(err error) string {
	// Do not leak absolute host paths through PathError.
	var pe *os.PathError
	if errors.As(err, &pe) {
		return fmt.Sprintf("workspace: %v", pe.Err)
	}
	return err.Error()
}
