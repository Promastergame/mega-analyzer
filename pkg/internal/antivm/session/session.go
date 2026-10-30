// Package session manages the lifecycle of one analysis run and its on-disk
// artifacts. Each run gets a session_id and a directory holding the profile,
// before/after state, a command log, the verification report, and the final
// report.
package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/planner"
	"mega-analyzer/pkg/internal/antivm/profile"
)

// Session is one analysis run with a stable id and artifact directory.
type Session struct {
	ID      string
	Dir     string
	Profile profile.DeviceProfile
	now     func() time.Time
}

// NewSession creates a session directory under root. The id encodes the
// timestamp and profile so runs sort chronologically. now is injected for
// deterministic tests.
func NewSession(root string, p profile.DeviceProfile, now func() time.Time) (*Session, error) {
	ts := now().UTC().Format("2006-01-02T150405")
	id := fmt.Sprintf("%s-%s", ts, sanitize(p.Name))
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create session dir: %w", err)
	}
	s := &Session{ID: id, Dir: dir, Profile: p, now: now}
	if err := s.writeJSON("profile.json", p); err != nil {
		return nil, err
	}
	return s, nil
}

// SaveBefore records the device state captured before applying changes.
func (s *Session) SaveBefore(st adapter.DeviceState) error {
	return s.writeJSON("before.json", st)
}

// SaveAfter records the device state captured after applying changes.
func (s *Session) SaveAfter(st adapter.DeviceState) error {
	return s.writeJSON("after.json", st)
}

// SaveVerification records the run report (status + per-module verify results).
func (s *Session) SaveVerification(r planner.RunReport) error {
	return s.writeJSON("verification.json", r)
}

// AppendCommand logs an executed command to commands.log.
func (s *Session) AppendCommand(line string) error {
	f, err := os.OpenFile(filepath.Join(s.Dir, "commands.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}

// WriteReport writes a rendered report (any format) to report.<ext>.
func (s *Session) WriteReport(ext string, data []byte) error {
	return os.WriteFile(filepath.Join(s.Dir, "report."+ext), data, 0o644)
}

func (s *Session) writeJSON(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", name, err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, name), data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// sanitize makes a profile name safe for a path segment.
func sanitize(name string) string {
	if name == "" {
		return "session"
	}
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		case r == ' ' || r == '.':
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "session"
	}
	return string(out)
}
