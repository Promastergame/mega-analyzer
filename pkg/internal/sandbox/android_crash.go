package sandbox

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
)

type androidAppCrash struct {
	PID     int
	Process string
	Detail  string
}

var androidCrashProcessRE = regexp.MustCompile(`^Process: ([^,]+), PID: ([0-9]+)$`)

// readAndroidAppCrashes attributes AndroidRuntime fatal exceptions to the exact
// package (including its subprocesses). A fatal exception in another app or an
// unconfirmed PID must not become evidence against the sample.
func readAndroidAppCrashes(r io.Reader, pkg string) ([]androidAppCrash, error) {
	if pkg == "" {
		return nil, nil
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	fatal := map[int]string{}
	pending := map[int]int{}
	var crashes []androidAppCrash
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, "AndroidRuntime:")
		if idx < 0 {
			continue
		}
		fields := strings.Fields(line[:idx])
		if len(fields) != 5 { // logcat -v threadtime: date time PID TID priority
			continue
		}
		pid, err := strconv.Atoi(fields[2])
		if err != nil || pid <= 0 {
			continue
		}
		msg := strings.TrimSpace(line[idx+len("AndroidRuntime:"):])
		if strings.HasPrefix(msg, "FATAL EXCEPTION:") {
			fatal[pid] = msg
			continue
		}
		if match := androidCrashProcessRE.FindStringSubmatch(msg); match != nil {
			process := strings.TrimSpace(match[1])
			if match[2] != fields[2] || fatal[pid] == "" ||
				(process != pkg && !strings.HasPrefix(process, pkg+":")) {
				continue
			}
			// Bound evidence when a sample repeatedly crashes and restarts.
			if len(crashes) >= 256 {
				continue
			}
			pending[pid] = len(crashes)
			crashes = append(crashes, androidAppCrash{PID: pid, Process: process, Detail: fatal[pid]})
			delete(fatal, pid)
			continue
		}
		if crashIndex, ok := pending[pid]; ok && msg != "" {
			if len(msg) > 4096 {
				msg = msg[:4096]
			}
			crashes[crashIndex].Detail += ": " + msg
			delete(pending, pid)
		}
	}
	return crashes, scanner.Err()
}
