package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// --save_log: mirror the entire console session to a file.
//
// setupSaveLog opens the destination file and builds a tee writer that fans the
// console output out to both os.Stdout (so the live terminal is unchanged) and
// the log file. For the default "txt"/"md" formats the file branch is wrapped
// in an ANSI stripper so the saved log is clean, human-readable plain text;
// "ansi" keeps the raw colored bytes.
func (a *App) setupSaveLog() error {
	path := strings.TrimSpace(a.opts.SaveLogOutput)
	if path == "" {
		// Default to the working directory so -clean-output cannot wipe the log.
		path = "analysis_log." + a.saveLogExt()
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create log directory: %w", err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create log file: %w", err)
	}

	var fileWriter io.Writer = f
	if !strings.EqualFold(a.opts.SaveLogFormat, "ansi") {
		fileWriter = newANSIStripper(f)
	}

	a.logFile = f
	a.logWriter = io.MultiWriter(os.Stdout, fileWriter)
	a.savedLogPath = path
	return nil
}

// saveLogExt maps the requested format to a sensible file extension.
func (a *App) saveLogExt() string {
	switch strings.ToLower(strings.TrimSpace(a.opts.SaveLogFormat)) {
	case "md", "markdown":
		return "md"
	case "ansi", "raw", "color", "colour":
		return "log"
	default:
		return "txt"
	}
}

// ansiStripper is a streaming io.Writer that removes ANSI CSI escape sequences
// ("ESC [ ... final") so a colored terminal session is saved as clean text. It
// carries an incomplete escape across Write boundaries.
type ansiStripper struct {
	w          io.Writer
	inEscape   bool
	pendingESC bool
}

func newANSIStripper(w io.Writer) io.Writer {
	return &ansiStripper{w: w}
}

func (s *ansiStripper) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p))
	for i := 0; i < len(p); i++ {
		b := p[i]
		if s.inEscape {
			// CSI sequences end at a final byte in the range 0x40..0x7E.
			if b >= 0x40 && b <= 0x7E {
				s.inEscape = false
			}
			continue
		}
		if s.pendingESC {
			s.pendingESC = false
			if b == '[' {
				s.inEscape = true
				continue
			}
			// Lone ESC that does not start a CSI sequence: drop ESC, keep byte.
		}
		if b == 0x1b {
			s.pendingESC = true
			continue
		}
		out = append(out, b)
	}
	if len(out) > 0 {
		if _, err := s.w.Write(out); err != nil {
			return 0, err
		}
	}
	// Report the whole input as consumed so io.MultiWriter stays satisfied even
	// though we dropped escape bytes.
	return len(p), nil
}
