// Package piracy — obfuscation_v2_fixed.go
// FIXED: Smart XOR, recursion limit, memory safety
package piracy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"mega-analyzer/pkg/internal/matcher"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SAFETY LIMITS
// ═══════════════════════════════════════════════════════════════════════════════

const (
	MaxDecodedSize    = 5 * 1024 * 1024 // 5MB
	MaxRecursionDepth = 3
	MaxXORAttempts    = 256 // Instead of 65k
	MaxDeobfuscations = 100 // Per file
	XORSampleSize     = 512
	MinPrintableRatio = 0.7
)

// ═══════════════════════════════════════════════════════════════════════════════
// DEOBFUSCATION ENGINE V2 (FIXED)
// ═══════════════════════════════════════════════════════════════════════════════

type DeobfuscationEngineV2 struct {
	knownDomains      map[string]bool
	knownDomainsBytes [][]byte // ✅ For []byte matching
	domainMatcher     *matcher.AhoCorasick
	reBase64          *regexp.Regexp
	reBase64Multi     *regexp.Regexp
	reHex             *regexp.Regexp
	reURLEncoded      *regexp.Regexp
	rePunycode        *regexp.Regexp
}

func NewDeobfuscationEngineV2(sites []Site) *DeobfuscationEngineV2 {
	domains := make(map[string]bool)
	domainsBytes := make([][]byte, 0)

	for _, site := range sites {
		for _, domain := range site.Domains {
			lower := strings.ToLower(domain)
			domains[lower] = true
			domainsBytes = append(domainsBytes, []byte(lower))
		}
	}

	domainPatterns := make([]string, len(domainsBytes))
	for i := range domainsBytes {
		domainPatterns[i] = string(domainsBytes[i])
	}

	return &DeobfuscationEngineV2{
		knownDomains:      domains,
		knownDomainsBytes: domainsBytes,
		domainMatcher:     matcher.NewAhoCorasick(domainPatterns),
		reBase64:          regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`),
		reBase64Multi:     regexp.MustCompile(`(?m)([A-Za-z0-9+/]{8,}\s*)+={0,2}`),
		reHex:             regexp.MustCompile(`[0-9a-fA-F]{20,}`),
		reURLEncoded:      regexp.MustCompile(`%[0-9A-Fa-f]{2}`),
		rePunycode:        regexp.MustCompile(`xn--[a-z0-9-]+`),
	}
}

// Detect с depth limiter
func (e *DeobfuscationEngineV2) Detect(content []byte) []ObfuscatedURL {
	count := 0
	return e.detectWithDepth(content, 0, &count)
}

func (e *DeobfuscationEngineV2) detectWithDepth(content []byte, depth int, deobfCount *int) []ObfuscatedURL {
	// ✅ Recursion guard
	if depth > MaxRecursionDepth {
		return nil
	}

	// ✅ Deobfuscation limit per file (local to this Detect() call, no shared state)
	if *deobfCount >= MaxDeobfuscations {
		return nil
	}

	var results []ObfuscatedURL

	// Base64 single-line
	appendDeobfCapped(&results, deobfCount, e.detectBase64(content))
	if *deobfCount >= MaxDeobfuscations {
		return results
	}

	// Base64 multi-line
	appendDeobfCapped(&results, deobfCount, e.detectBase64MultiLine(content))
	if *deobfCount >= MaxDeobfuscations {
		return results
	}

	// Hex
	appendDeobfCapped(&results, deobfCount, e.detectHex(content))
	if *deobfCount >= MaxDeobfuscations {
		return results
	}

	// URL encoding
	appendDeobfCapped(&results, deobfCount, e.detectURLEncoded(content))
	if *deobfCount >= MaxDeobfuscations {
		return results
	}

	// ROT13
	appendDeobfCapped(&results, deobfCount, e.detectROT13(content))
	if *deobfCount >= MaxDeobfuscations {
		return results
	}

	// ✅ Smart XOR (not brute-force)
	appendDeobfCapped(&results, deobfCount, e.detectXORSmart(content))
	if *deobfCount >= MaxDeobfuscations {
		return results
	}

	// Reversed strings
	appendDeobfCapped(&results, deobfCount, e.detectReversed(content))
	if *deobfCount >= MaxDeobfuscations {
		return results
	}

	// Punycode
	appendDeobfCapped(&results, deobfCount, e.detectPunycode(content))
	if *deobfCount >= MaxDeobfuscations {
		return results
	}

	// Compressed (with depth)
	// detectCompressed recurses into detectWithDepth and shares the same counter.
	// The recursive call will account for its own results, so we don't increment here.
	results = append(results, e.detectCompressed(content, depth, deobfCount)...)

	return results
}

func appendDeobfCapped(dst *[]ObfuscatedURL, deobfCount *int, src []ObfuscatedURL) {
	if len(src) == 0 {
		return
	}
	remaining := MaxDeobfuscations - *deobfCount
	if remaining <= 0 {
		return
	}
	if len(src) > remaining {
		src = src[:remaining]
	}
	*dst = append(*dst, src...)
	*deobfCount += len(src)
}

func decodeBase64Bytes(src []byte) ([]byte, bool) {
	// Prevent large allocations from pathological matches.
	stdLen := base64.StdEncoding.DecodedLen(len(src))
	rawLen := base64.RawStdEncoding.DecodedLen(len(src))
	decodedLen := stdLen
	if rawLen > decodedLen {
		decodedLen = rawLen
	}
	if decodedLen > MaxDecodedSize {
		return nil, false
	}

	// Raw (unpadded) Base64 can decode to one byte more than the padded
	// encoding's DecodedLen estimate. Allocate for the larger form before
	// attempting the fallback to avoid a runtime panic on valid raw input.
	buf := make([]byte, decodedLen)
	n, err := base64.StdEncoding.Decode(buf, src)
	if err != nil {
		n, err = base64.RawStdEncoding.Decode(buf, src)
		if err != nil {
			return nil, false
		}
	}
	return buf[:n], true
}

func decodeHexBytes(src []byte) ([]byte, error) {
	if len(src)%2 != 0 {
		return nil, hex.ErrLength
	}
	if hex.DecodedLen(len(src)) > MaxDecodedSize {
		return nil, fmt.Errorf("decoded hex too large: %d bytes", hex.DecodedLen(len(src)))
	}
	buf := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(buf, src)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMART XOR (Known Plaintext Attack)
// ═══════════════════════════════════════════════════════════════════════════════

func (e *DeobfuscationEngineV2) detectXORSmart(content []byte) []ObfuscatedURL {
	// ✅ Sample only
	sample := content
	if len(sample) > XORSampleSize {
		sample = sample[:XORSampleSize]
	}

	// ✅ Quick entropy check
	if !hasLowEntropy(sample) {
		return nil // Skip high-entropy (likely encrypted, not XOR)
	}

	// Reuse one decode buffer for every candidate key. The previous loop
	// allocated 256 x len(sample) bytes for virtually every text file.
	if len(sample) == 0 {
		return nil
	}
	decoded := make([]byte, len(sample))
	lowerScratch := make([]byte, len(sample))
	counts := xorPrintableCounts(sample)
	for key := 0; key < 256; key++ {
		printable := counts[key]
		if float64(printable)/float64(len(decoded)) < MinPrintableRatio {
			continue
		}
		xorDecodeSingleByteInto(decoded, sample, byte(key))
		if !containsXORPlaintext(decoded) {
			continue
		}

		if url := e.extractURLFromBytesLowered(decoded, lowerASCIIInto(lowerScratch, decoded)); url != nil {
			url.Original = fmt.Sprintf("xor_key_0x%02x", key)
			url.Method = string(ObfXOR)
			url.Confidence = 0.85
			return []ObfuscatedURL{*url}
		}
	}

	// Try 2-byte XOR (limited)
	if len(sample) > 32 {
		return e.detectXOR2Byte(sample)
	}
	return nil
}

func (e *DeobfuscationEngineV2) detectXOR2Byte(sample []byte) []ObfuscatedURL {
	decoded := make([]byte, len(sample))
	lowerScratch := make([]byte, len(sample))
	evenCounts, oddCounts := xorPrintableCountsStride(sample, 0, 2), xorPrintableCountsStride(sample, 1, 2)
	attempts := 0
	for key1 := 0; key1 < 256; key1++ {
		if attempts >= MaxXORAttempts {
			return nil
		}
		possibleKeys := e.xor2ByteDomainKeys(sample, byte(key1))
		for key2 := 0; key2 < 256; key2++ {
			attempts++
			if attempts > MaxXORAttempts {
				return nil
			}
			if !possibleKeys[key2] {
				continue
			}

			printable := evenCounts[key1] + oddCounts[key2]
			if float64(printable)/float64(len(decoded)) <= MinPrintableRatio {
				continue
			}
			xorDecode2ByteInto(decoded, sample, byte(key1), byte(key2))
			if url := e.extractURLFromBytesLowered(decoded, lowerASCIIInto(lowerScratch, decoded)); url != nil {
				url.Original = fmt.Sprintf("xor_key_0x%02x%02x", key1, key2)
				url.Method = string(ObfXOR)
				url.Confidence = 0.8
				return []ObfuscatedURL{*url}
			}
		}
	}

	return nil
}

// Determine which second-byte keys can produce a configured domain before
// decoding and running the domain automaton for each key. Even positions have
// a fixed key; odd positions constrain key2 to at most two case variants. This
// is an exact prefilter, including matches at odd offsets and uppercase ASCII.
func (e *DeobfuscationEngineV2) xor2ByteDomainKeys(data []byte, key1 byte) (keys [256]bool) {
	for _, domain := range e.knownDomainsBytes {
		if len(domain) == 0 {
			continue
		}
		for start := 0; start <= len(data)-len(domain); start++ {
			fixedOffset := start & 1
			fixedMatch := true
			for j := fixedOffset; j < len(domain); j += 2 {
				if asciiLowerByte(data[start+j]^key1) != domain[j] {
					fixedMatch = false
					break
				}
			}
			if !fixedMatch {
				continue
			}
			variableOffset := 1 - fixedOffset
			if variableOffset >= len(domain) {
				// A one-byte match at a fixed position is valid for every key2.
				for i := range keys {
					keys[i] = true
				}
				return keys
			}
			first := domain[variableOffset]
			key := data[start+variableOffset] ^ first
			variants := 1
			if first >= 'a' && first <= 'z' {
				variants = 2
			}
			for variant := 0; variant < variants; variant++ {
				candidate := key ^ byte(variant*0x20)
				if keys[candidate] {
					continue
				}
				matched := true
				for j := variableOffset; j < len(domain); j += 2 {
					if asciiLowerByte(data[start+j]^candidate) != domain[j] {
						matched = false
						break
					}
				}
				if matched {
					keys[candidate] = true
				}
			}
		}
	}
	return keys
}

func asciiLowerByte(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

// Counting printable bytes depends on their frequencies, not their order.
// Reject impossible keys before decoding the same sample hundreds of times.
func xorPrintableCounts(data []byte) (counts [256]int) {
	return xorPrintableCountsStride(data, 0, 1)
}

func xorPrintableCountsStride(data []byte, start, stride int) (counts [256]int) {
	var frequencies [256]int
	for i := start; i < len(data); i += stride {
		frequencies[data[i]]++
	}
	for value, frequency := range frequencies {
		if frequency == 0 {
			continue
		}
		for key := range counts {
			if isPrintableByte(byte(value) ^ byte(key)) {
				counts[key] += frequency
			}
		}
	}
	return counts
}

func containsXORPlaintext(data []byte) bool {
	return bytes.Contains(data, []byte("http://")) ||
		bytes.Contains(data, []byte("https://")) ||
		bytes.Contains(data, []byte(".com")) ||
		bytes.Contains(data, []byte(".ru")) ||
		bytes.Contains(data, []byte("4pda"))
}

func xorDecodeSingleByteInto(dst, data []byte, key byte) int {
	printable := 0
	for i, b := range data {
		decoded := b ^ key
		dst[i] = decoded
		if isPrintableByte(decoded) {
			printable++
		}
	}
	return printable
}

func xorDecode2ByteInto(dst, data []byte, key1, key2 byte) int {
	printable := 0
	for i, b := range data {
		key := key1
		if i&1 != 0 {
			key = key2
		}
		decoded := b ^ key
		dst[i] = decoded
		if isPrintableByte(decoded) {
			printable++
		}
	}
	return printable
}

func isPrintableByte(b byte) bool {
	return (b >= 0x20 && b < 0x7f) || b == '\n' || b == '\r' || b == '\t'
}

func lowerASCIIInto(dst, src []byte) []byte {
	for i, b := range src {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		dst[i] = b
	}
	return dst[:len(src)]
}

func xorDecodeSingleByte(data []byte, key byte) []byte {
	decoded := make([]byte, len(data))
	xorDecodeSingleByteInto(decoded, data, key)
	return decoded
}

func xorDecode(data, key []byte) []byte {
	decoded := make([]byte, len(data))
	keyLen := len(key)
	for i, b := range data {
		decoded[i] = b ^ key[i%keyLen]
	}
	return decoded
}

// ✅ Entropy check
func hasLowEntropy(data []byte) bool {
	if len(data) < 32 {
		return true
	}

	entropy := CalculateEntropy(data)
	return entropy < 6.0 // Low entropy suggests XOR, not AES
}

// ✅ Printable ratio check
func getPrintableRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	printable := 0
	for _, b := range data {
		if isPrintableByte(b) {
			printable++
		}
	}

	return float64(printable) / float64(len(data))
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPRESSED (WITH DEPTH LIMIT)
// ═══════════════════════════════════════════════════════════════════════════════

func (e *DeobfuscationEngineV2) detectCompressed(content []byte, depth int, deobfCount *int) []ObfuscatedURL {
	// ✅ Recursion guard
	if depth >= MaxRecursionDepth {
		return nil
	}

	// Gzip magic: 1f 8b
	if len(content) > 2 && content[0] == 0x1f && content[1] == 0x8b {
		if decoded := tryGunzipSafe(content); decoded != nil {
			return e.detectWithDepth(decoded, depth+1, deobfCount) // ✅ Increment depth
		}
	}

	// Zlib magic: 78 9c, 78 da, 78 01
	if len(content) > 2 && content[0] == 0x78 {
		if decoded := tryZlibSafe(content); decoded != nil {
			return e.detectWithDepth(decoded, depth+1, deobfCount)
		}
	}

	return nil
}

func tryGunzipSafe(data []byte) []byte {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer reader.Close()

	// ✅ Size limit
	decoded, err := io.ReadAll(io.LimitReader(reader, MaxDecodedSize))
	if err != nil {
		return nil
	}

	return decoded
}

func tryZlibSafe(data []byte) []byte {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer reader.Close()

	decoded, err := io.ReadAll(io.LimitReader(reader, MaxDecodedSize))
	if err != nil {
		return nil
	}

	return decoded
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER METHODS (FIXED)
// ═══════════════════════════════════════════════════════════════════════════════

// ✅ Work with []byte instead of string
func (e *DeobfuscationEngineV2) extractURLFromBytes(data []byte) *ObfuscatedURL {
	return e.extractURLFromBytesLowered(data, bytes.ToLower(data))
}

func (e *DeobfuscationEngineV2) extractURLFromBytesLowered(data, lower []byte) *ObfuscatedURL {
	if e.domainMatcher == nil {
		return nil
	}
	hits := e.domainMatcher.SearchBytes(lower)
	if len(hits) == 0 {
		return nil
	}

	// SearchBytes returns matches in text traversal order, whereas the old
	// loop selected the first configured domain that appeared anywhere. Keep
	// that exact selection rule so findings remain byte-for-byte stable.
	best := hits[0]
	for _, id := range hits[1:] {
		if id < best {
			best = id
		}
	}
	if best < 0 || best >= len(e.knownDomainsBytes) {
		return nil
	}
	domain := e.knownDomainsBytes[best]
	return &ObfuscatedURL{
		Decoded:    string(data),
		Domain:     string(domain),
		Confidence: 0.9,
	}
}

func (e *DeobfuscationEngineV2) containsKnownDomainBytes(data []byte) bool {
	if e.domainMatcher == nil {
		return false
	}
	return len(e.domainMatcher.SearchBytes(bytes.ToLower(data))) > 0
}

// ✅ Keep old methods for compatibility
func (e *DeobfuscationEngineV2) extractURL(data []byte) *ObfuscatedURL {
	return e.extractURLFromBytes(data)
}

func (e *DeobfuscationEngineV2) containsKnownDomain(data []byte) bool {
	return e.containsKnownDomainBytes(data)
}

// ═══════════════════════════════════════════════════════════════════════════════
// OTHER METHODS (unchanged but safe)
// ═══════════════════════════════════════════════════════════════════════════════

func (e *DeobfuscationEngineV2) detectBase64(content []byte) []ObfuscatedURL {
	var results []ObfuscatedURL

	ranges := p4ScanClassRuns(content, &p4B64Class, 32, true, 100)
	for _, r := range ranges {
		match := content[r[0]:r[1]]
		decoded, ok := decodeBase64Bytes(match)
		if !ok {
			continue
		}

		// ✅ Size check
		if len(decoded) > MaxDecodedSize {
			continue
		}

		if url := e.extractURLFromBytes(decoded); url != nil {
			url.Original = string(match)
			url.Method = string(ObfBase64)
			results = append(results, *url)
		}
	}

	return results
}

func (e *DeobfuscationEngineV2) detectBase64MultiLine(content []byte) []ObfuscatedURL {
	var results []ObfuscatedURL

	// Only the first 50 candidates are analyzed. Stop the regexp there rather
	// than scanning and allocating every remaining match in a large file.
	matches := e.reBase64Multi.FindAll(content, 50)

	for _, match := range matches {
		cleaned := bytes.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
				return -1
			}
			return r
		}, match)

		decoded, ok := decodeBase64Bytes(cleaned)
		if !ok {
			continue
		}

		if len(decoded) > MaxDecodedSize {
			continue
		}

		if url := e.extractURLFromBytes(decoded); url != nil {
			url.Original = string(match)
			url.Method = string(ObfBase64MultiLine)
			results = append(results, *url)
		}
	}

	return results
}

func (e *DeobfuscationEngineV2) detectHex(content []byte) []ObfuscatedURL {
	var results []ObfuscatedURL

	ranges := p4ScanClassRuns(content, &p4HexClass, 32, false, 100)
	for _, r := range ranges {
		match := content[r[0]:r[1]]
		decoded, err := decodeHexBytes(match)
		if err != nil {
			continue
		}

		if len(decoded) > MaxDecodedSize {
			continue
		}

		if url := e.extractURLFromBytes(decoded); url != nil {
			url.Original = string(match)
			url.Method = string(ObfHex)
			results = append(results, *url)
		}
	}

	return results
}

func (e *DeobfuscationEngineV2) detectURLEncoded(content []byte) []ObfuscatedURL {
	if !e.reURLEncoded.Match(content) {
		return nil
	}

	// Avoid decoding huge blobs; URL-encoded payloads are usually short.
	if len(content) > 64*1024 {
		return nil
	}

	decoded, err := url.QueryUnescape(string(content))
	if err != nil {
		return nil
	}

	if url := e.extractURLFromBytes([]byte(decoded)); url != nil {
		url.Original = string(content)
		url.Method = string(ObfURLEncoded)
		return []ObfuscatedURL{*url}
	}

	return nil
}

func (e *DeobfuscationEngineV2) detectROT13(content []byte) []ObfuscatedURL {
	// ✅ Limit size
	if len(content) > 10*1024 {
		return nil
	}

	decoded := rot13(string(content))

	if url := e.extractURLFromBytes([]byte(decoded)); url != nil {
		url.Original = string(content)
		url.Method = string(ObfROT13)
		return []ObfuscatedURL{*url}
	}

	return nil
}

func (e *DeobfuscationEngineV2) detectReversed(content []byte) []ObfuscatedURL {
	if len(content) > 1024 {
		return nil
	}

	reversed := reverseBytes(content)

	if url := e.extractURLFromBytes(reversed); url != nil {
		url.Original = string(content)
		url.Method = string(ObfReversed)
		return []ObfuscatedURL{*url}
	}

	return nil
}

func reverseBytes(data []byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[len(data)-1-i] = b
	}
	return result
}

func (e *DeobfuscationEngineV2) detectPunycode(content []byte) []ObfuscatedURL {
	// Punycode detection disabled to avoid golang.org/x/net/idna dependency
	return nil
}
