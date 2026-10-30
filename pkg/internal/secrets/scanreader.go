package secrets

import (
	"io"
	"strings"
)

// scanOverlap is how many trailing bytes of each chunk are re-scanned together
// with the next chunk so a token crossing a chunk boundary is still matched
// whole. Larger than any secret format this package detects.
const scanOverlap = 4096

// ScanReader detects secrets in a stream without loading it all into memory,
// so multi-gigabyte logs, dumps and binaries can be scanned within a fixed
// memory budget. chunkSize <= 0 (or too small) picks a sane default. Line
// numbers are absolute within the stream. Identical (rule, value) pairs are
// reported once. Fully offline, like everything else in this package.
func ScanReader(r io.Reader, context string, chunkSize int) ([]ProviderFinding, error) {
	if chunkSize < 4*scanOverlap {
		chunkSize = 256 * 1024
	}
	var out []ProviderFinding
	seen := make(map[string]struct{})
	carry := ""
	baseLine := 0 // newlines already consumed before the carry window
	buf := make([]byte, chunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			text := carry + string(buf[:n])
			for _, f := range DetectProviders(text, context) {
				key := f.RuleID + "\x00" + f.Value
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				f.Line += baseLine
				out = append(out, f)
			}
			if len(text) > scanOverlap {
				cut := len(text) - scanOverlap
				baseLine += strings.Count(text[:cut], "\n")
				carry = text[cut:]
			} else {
				carry = text
			}
		}
		if err != nil {
			if err == io.EOF {
				return out, nil
			}
			return out, err
		}
	}
}
