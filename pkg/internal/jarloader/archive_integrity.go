package jarloader

import (
	"archive/zip"
	"fmt"
	"io"
	"strings"
)

func (r *Report) issue(entry, reason string) {
	r.Complete = false
	if len(r.InspectionIssues) < 1000 {
		r.InspectionIssues = append(r.InspectionIssues, InspectionIssue{Entry: entry, Reason: reason})
	}
}

// Read one entry to EOF (including CRC verification), never accept a prefix as
// a complete file. The declared size is checked before allocation/decompression.
func readJAREntry(f *zip.File, limit int64) ([]byte, error) {
	if limit < 0 || f.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("entry exceeds %d byte inspection limit", limit)
	}
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit || uint64(len(data)) != f.UncompressedSize64 {
		return nil, fmt.Errorf("entry size mismatch or inspection limit exceeded")
	}
	return data, nil
}

func unsafeJARPath(name string) bool {
	n := strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(n, "/") || strings.ContainsAny(n, ":\x00") {
		return true
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
