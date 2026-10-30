package fpfilter

import (
	"math"
	"regexp"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// SecretValidator decides whether a secret-style finding is a real, high-confidence
// credential or low-confidence noise. It combines Shannon entropy, known
// credential formats and placeholder/test heuristics. This is the cheapest and
// most effective single lever for reducing "looks like a key" false positives.
type SecretValidator struct {
	formats     []secretFormat
	placeholder *regexp.Regexp
}

type secretFormat struct {
	name       string
	re         *regexp.Regexp
	confidence float64
}

// NewSecretValidator builds a validator with the default credential formats.
func NewSecretValidator() *SecretValidator {
	return &SecretValidator{
		formats: []secretFormat{
			{"aws_access_key_id", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b`), 0.98},
			{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35,}\b`), 0.97},
			{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`), 0.95},
			{"github_token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b`), 0.98},
			{"github_fine_grained_pat", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{80,}\b`), 0.98},
			{"telegram_bot_token", regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_-]{35}\b`), 0.99},
			{"discord_webhook", regexp.MustCompile(`https://(?:discord(?:app)?\.com)/api/webhooks/\d{15,25}/[A-Za-z0-9_-]{40,}`), 0.98},
			{"openai_key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`), 0.9},
			{"anthropic_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`), 0.95},
			{"slack_token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`), 0.96},
			{"stripe_key", regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b`), 0.96},
			{"private_key_block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), 0.99},
			{"firebase_db_url", regexp.MustCompile(`https://[a-z0-9\-]+\.firebaseio\.com`), 0.7},
		},
		// Common non-secret placeholders that masquerade as keys.
		placeholder: regexp.MustCompile(`(?i)(your[_-]?api[_-]?key|example|sample|dummy|placeholder|changeme|xxx+|test[_-]?key|fake|null|none|todo|<.*>|\$\{.*\}|@string/|@android:)`),
	}
}

// SecretVerdict is the outcome of validating a secret-style finding.
type SecretVerdict struct {
	// IsReal is true when the value is a high-confidence credential.
	IsReal bool
	// Confidence in [0,1].
	Confidence float64
	// FormatName is the matched credential format, when any.
	FormatName string
	// Entropy is the Shannon entropy (bits/char) of the candidate value.
	Entropy float64
	// Reason is a short human-readable explanation.
	Reason string
}

// minSecretLen is the shortest token we consider worth scoring.
const minSecretLen = 12

// Validate inspects a match and returns a verdict about its credential-ness.
func (v *SecretValidator) Validate(match *types.Match) SecretVerdict {
	if match == nil {
		return SecretVerdict{Reason: "nil match"}
	}

	hay := match.Text
	if hay == "" {
		hay = match.Context
	}

	// 1. Known credential formats are an immediate strong confirmation,
	// regardless of entropy (some are structured, not high-entropy).
	for _, f := range v.formats {
		if f.re.MatchString(hay) {
			return SecretVerdict{
				IsReal:     true,
				Confidence: f.confidence,
				FormatName: f.name,
				Entropy:    shannonEntropy(hay),
				Reason:     "matches known credential format: " + f.name,
			}
		}
	}

	// 2. Extract the most secret-like token and score its entropy.
	candidate := bestSecretCandidate(hay)
	if len(candidate) < minSecretLen {
		return SecretVerdict{
			IsReal:     false,
			Confidence: 0.15,
			Entropy:    shannonEntropy(candidate),
			Reason:     "no sufficiently long high-entropy token",
		}
	}

	// 3. Placeholder / example / resource-reference demotion.
	if v.placeholder.MatchString(hay) {
		return SecretVerdict{
			IsReal:     false,
			Confidence: 0.1,
			Entropy:    shannonEntropy(candidate),
			Reason:     "placeholder/example/resource reference, not a real secret",
		}
	}

	ent := shannonEntropy(candidate)

	// 4. Entropy thresholds. base64/hex secrets typically sit at >= 3.5 bits/char.
	switch {
	case ent >= 4.0:
		return SecretVerdict{
			IsReal:     true,
			Confidence: 0.9,
			Entropy:    ent,
			Reason:     "high-entropy random-looking token",
		}
	case ent >= 3.5:
		return SecretVerdict{
			IsReal:     true,
			Confidence: 0.72,
			Entropy:    ent,
			Reason:     "medium-high entropy token",
		}
	default:
		return SecretVerdict{
			IsReal:     false,
			Confidence: 0.25,
			Entropy:    ent,
			Reason:     "low entropy, likely a dictionary word or constant",
		}
	}
}

// tokenRe extracts secret-shaped tokens (base64/hex/url-safe alphabets).
var tokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{8,}`)

// bestSecretCandidate returns the longest secret-shaped token in s.
func bestSecretCandidate(s string) string {
	best := ""
	for _, tok := range tokenRe.FindAllString(s, -1) {
		// Ignore tokens that are obviously file paths / package names.
		if strings.Count(tok, ".") > 2 {
			continue
		}
		if len(tok) > len(best) {
			best = tok
		}
	}
	if best == "" {
		return strings.TrimSpace(s)
	}
	return best
}

// shannonEntropy returns the Shannon entropy in bits per character of s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	n := 0
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
		n++
	}
	if n == 0 {
		return 0
	}
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}
