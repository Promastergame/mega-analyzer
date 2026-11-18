package boundedfile

import (
	"errors"
	"fmt"
	"io"
	"os"
)

var ErrLimit = errors.New("file exceeds bounded read limit")

// ReadFile enforces the limit on actual bytes, even when a file grows after
// Stat. It never allocates according to untrusted ZIP metadata.
func ReadFile(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit == 1<<63-1 {
		return nil, fmt.Errorf("invalid read limit: %d", limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%w: %s (%d bytes, limit %d)", ErrLimit, path, info.Size(), limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %s (limit %d)", ErrLimit, path, limit)
	}
	return data, nil
}
