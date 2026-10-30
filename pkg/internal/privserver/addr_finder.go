package privserver

import (
	"bytes"
	"encoding/binary"
	"net"
	"regexp"
	"strings"
)

// ServerAddress represents a found server address in the binary.
type ServerAddress struct {
	Address    string
	Port       uint16
	Offset     int64
	FileType   string
	FilePath   string
	Confidence float64
}

// PatchResult describes the result of a binary patching operation.
type PatchResult struct {
	OriginalValue string
	NewValue      string
	Offset        int64
	Size          int
	FilePath      string
}

// FindServerAddresses scans binary data for potential server addresses.
// It looks for IP addresses, domain names, and URL patterns.
func FindServerAddresses(data []byte, filePath string) []ServerAddress {
	var results []ServerAddress
	fileType := addrDetectFileType(filePath)

	// Pattern 1: IPv4 addresses
	ipRegex := regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	for _, loc := range ipRegex.FindAllIndex(data, -1) {
		ipStr := string(data[loc[0]:loc[1]])
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			if v4[0] == 255 || v4[0] >= 224 {
				continue
			}
		}
		confidence := 0.5
		if !ip.IsPrivate() {
			confidence = 0.8
		}
		port := addrFindPortNearby(data, loc[1], 20)
		if port > 0 {
			confidence += 0.1
		}
		results = append(results, ServerAddress{
			Address:    ipStr,
			Port:       port,
			Offset:     int64(loc[0]),
			FileType:   fileType,
			FilePath:   filePath,
			Confidence: confidence,
		})
	}

	// Pattern 2: Domain names and URLs
	domainPatterns := []string{
		`https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}`,
		`wss?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}`,
		`[a-zA-Z0-9\-]+\.(supercell|game-?server|api-?server)\.[a-zA-Z]{2,}`,
	}
	for _, pattern := range domainPatterns {
		re := regexp.MustCompile(pattern)
		for _, loc := range re.FindAllIndex(data, -1) {
			domain := string(data[loc[0]:loc[1]])
			results = append(results, ServerAddress{
				Address:    domain,
				Offset:     int64(loc[0]),
				FileType:   fileType,
				FilePath:   filePath,
				Confidence: 0.9,
			})
		}
	}

	return results
}

// PatchServerAddress replaces a server address in binary data with null-padded replacement.
func PatchServerAddress(data []byte, original, replacement string) ([]byte, []PatchResult) {
	var results []PatchResult
	origBytes := []byte(original)
	replBytes := []byte(replacement)
	if len(replBytes) < len(origBytes) {
		padded := make([]byte, len(origBytes))
		copy(padded, replBytes)
		replBytes = padded
	}
	if len(replBytes) > len(origBytes) {
		replBytes = replBytes[:len(origBytes)]
	}
	result := make([]byte, len(data))
	copy(result, data)
	offset := 0
	for {
		idx := bytes.Index(result[offset:], origBytes)
		if idx < 0 {
			break
		}
		absOffset := offset + idx
		copy(result[absOffset:absOffset+len(origBytes)], replBytes)
		results = append(results, PatchResult{
			OriginalValue: original,
			NewValue:      replacement,
			Offset:        int64(absOffset),
			Size:          len(origBytes),
		})
		offset = absOffset + len(origBytes)
	}
	return result, results
}

func addrDetectFileType(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".dex"):
		return "dex"
	case strings.HasSuffix(lower, ".so"):
		return "so"
	case strings.HasSuffix(lower, ".smali"):
		return "smali"
	case strings.HasSuffix(lower, ".xml"):
		return "config"
	case strings.HasSuffix(lower, ".json"):
		return "config"
	default:
		return "binary"
	}
}

func addrFindPortNearby(data []byte, offset, window int) uint16 {
	end := offset + window
	if end > len(data)-1 {
		end = len(data) - 1
	}
	if offset+2 <= end {
		port := binary.BigEndian.Uint16(data[offset : offset+2])
		if port > 1024 && port < 65535 {
			return port
		}
	}
	return 0
}
