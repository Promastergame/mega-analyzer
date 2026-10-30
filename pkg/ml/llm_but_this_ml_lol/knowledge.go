package llmkeys

import (
	"encoding/json"
	"strings"
	"sync"
)

// Negative is one learned non-secret example from negatives.json.
type Negative struct {
	ID     string `json:"id"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// Family is a known credential family with the prefixes that identify it.
// Prefixes were taken from the families present in keys_dataset.json.
type Family struct {
	Name     string
	Prefixes []string
	// MinBodyLen is the minimum length required for the part of the value
	// AFTER the prefix. Required for every prefix <=4 chars long: those are
	// short enough to accidentally match ordinary words ("CF_WORKER_NAME",
	// "co-workerFooBar", "ddaShboardWidget", zh_workspaceConfig", …), so a
	// bare 6-char isTrivialBody check is not enough. 0 means "use the
	// package-wide default" (see minFamilyBodyLen in matchFamily).
	MinBodyLen int
}

// minFamilyBodyLen is the fallback minimum body length for any family that
// doesn't set MinBodyLen explicitly. It is deliberately generous (real
// credential bodies for these families run 20-40+ chars) so that ordinary
// English identifiers ("workspaceConfig", "deploymentHook", "AccountNumber")
// don't get accepted just because they happen to start with a short prefix.
const minFamilyBodyLen = 20

// knownFamilies maps a real credential value to the service it belongs to.
// A prefix match is a strong signal, but it is only trusted *after* the value
// survives the placeholder and triviality checks (so "AKIAXXXX..." or
// "sk-ant-example" are still rejected).
//
// Order matters: more-specific prefixes must come before shorter ambiguous
// ones (e.g. "sk-proj-" before "sk-" so OpenAI project keys are named first).
var knownFamilies = []Family{
	// --- Cryptographic keys ---
	{Name: "private_key", Prefixes: []string{"-----BEGIN", "MIIEv", "MIIEov", "MIIFDj", "AAAAB3NzaC"}},

	// --- Cloud / infra ---
	// AWS access key IDs are exactly 16 chars after the 4-letter prefix (20 total).
	{Name: "aws", Prefixes: []string{"AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA"}, MinBodyLen: 16},
	{Name: "gcp_service_account", Prefixes: []string{"-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"}},
	// "sv="/"se="/"sig=" are 3-char prefixes that show up in ordinary query
	// strings and code ("service=", "signature=…"), so require a long,
	// high-entropy-looking body instead of the package default.
	{Name: "azure_sas", Prefixes: []string{"sv=", "se=", "sig="}, MinBodyLen: 24},
	{Name: "cloudflare", Prefixes: []string{"v1.0-"}}, // "CF_" removed: not a real CF token prefix, matched any "CF_..." constant

	// --- AI providers ---
	{Name: "anthropic", Prefixes: []string{"sk-ant-"}},
	{Name: "openai", Prefixes: []string{"sk-proj-", "sk-"}},
	{Name: "google_ai", Prefixes: []string{"AIza"}},
	{Name: "huggingface", Prefixes: []string{"hf_"}},
	// "cohere" removed: Cohere keys have no "co-" prefix in the training data;
	// "co-" matched ordinary hyphenated words ("co-worker", "co-founder", …).
	{Name: "groq", Prefixes: []string{"gsk_"}},
	{Name: "perplexity", Prefixes: []string{"pplx-"}},

	// --- Source control / CI ---
	{Name: "github", Prefixes: []string{"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"}},
	{Name: "gitlab", Prefixes: []string{"glpat-", "glgat-", "gldt-", "glrt-"}},
	{Name: "circleci", Prefixes: []string{"CCIPAT_"}},
	{Name: "docker", Prefixes: []string{"dckr_pat_", "ghcr_pat_"}},

	// --- Package registries ---
	{Name: "npm", Prefixes: []string{"npm_"}},
	{Name: "pypi", Prefixes: []string{"pypi-"}},

	// --- Secrets / vault ---
	{Name: "vault_hvs", Prefixes: []string{"hvs."}},
	{Name: "doppler", Prefixes: []string{"dp.st.", "dp.pt."}},

	// --- Communication / support ---
	{Name: "slack", Prefixes: []string{"xoxb-", "xoxp-", "xapp-", "xoxe-", "xoxa-", "xoxr-"}},
	// Twilio SIDs are "SK"/"AC" + 30-32 hex chars. These 2-char prefixes
	// otherwise match any capitalized word ("SKip", "ACcount…"), so require
	// close to the full hex body length, not just 6 chars.
	{Name: "twilio", Prefixes: []string{"SK", "AC"}, MinBodyLen: 30},
	{Name: "sendgrid", Prefixes: []string{"SG."}},
	{Name: "mailgun", Prefixes: []string{"key-"}},
	{Name: "postmark", Prefixes: []string{}},                 // no stable prefix — caught by entropy
	{Name: "intercom", Prefixes: []string{"dG9rO", "dGVzd"}}, // base64("tok" / "test") prefixes
	{Name: "pagerduty", Prefixes: []string{"pdus+eyJ"}},      // PD user-scoped token
	// "zenhub" removed: "zh_" is not a documented ZenHub token prefix and
	// matched arbitrary identifiers ("zh_workspaceConfig").

	// --- Observability ---
	// "datadog" removed: Datadog API/app keys are bare 32/40-char hex with no
	// "DD_"/"dda"/"ddp" prefix — those strings matched ordinary words
	// ("ddaShboardWidget", "ddpSyncEngine…").
	{Name: "grafana", Prefixes: []string{"glc_", "glsa_"}},
	{Name: "sentry", Prefixes: []string{"sntrys_"}},

	// --- Payments ---
	{Name: "stripe", Prefixes: []string{"sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_", "sk-live_", "sk-test_", "pk-live_", "pk-test_", "rk-live_", "rk-test_", "sklive_", "sktest_", "whsec_"}},

	// --- Databases / storage ---
	// bare "dapi" (no dash) removed: matches any word starting "dapi..." with
	// no structural signal; "dapi-" is the real Databricks PAT prefix.
	{Name: "databricks", Prefixes: []string{"dapi-"}},
	{Name: "planetscale", Prefixes: []string{"pscale_tkn_", "pscale_oauth_"}},
	{Name: "turso", Prefixes: []string{"eyJhb"}}, // Turso JWT always starts with base64-encoded header
	{Name: "supabase_service", Prefixes: []string{"sbp_"}},
	{Name: "neon", Prefixes: []string{"neon_"}},

	// --- Dev tooling / hosting ---
	{Name: "netlify", Prefixes: []string{"nfp_"}},
	{Name: "render", Prefixes: []string{"rnd_"}},

	// --- Auth / identity ---
	{Name: "atlassian", Prefixes: []string{"ATATT"}},
	{Name: "notion", Prefixes: []string{"secret_ntn_", "ntn_"}},
	{Name: "shopify", Prefixes: []string{"shppa_", "shpca_", "shpat_", "shpss_", "shpua_"}},
	{Name: "linear", Prefixes: []string{"lin_api_"}},
	{Name: "pinecone", Prefixes: []string{"pcsk_"}},
	{Name: "mapbox", Prefixes: []string{"pk.eyJ", "sk.eyJ", "tk.eyJ"}},
	{Name: "google_oauth", Prefixes: []string{"ya29."}},
	{Name: "discord", Prefixes: []string{}},
	{Name: "telegram", Prefixes: []string{}},

	// --- Generic structured tokens ---
	{Name: "jwt", Prefixes: []string{"eyJ"}}, // must be last — short prefix, caught after specifics
}

type negativesFile struct {
	DB struct {
		Negatives []Negative `json:"negatives"`
	} `json:"ml_negative_database"`
}

type keysFile struct {
	DB struct {
		Metadata struct {
			TotalRecords int `json:"total_records"`
		} `json:"metadata"`
		Services map[string]json.RawMessage `json:"services"`
	} `json:"ml_training_database"`
}

// knowledge is the parsed, ready-to-query view of the embedded datasets.
type knowledge struct {
	negatives    []Negative
	negativeSet  map[string]bool // normalized value -> true
	serviceCount int
	positiveLen  int
}

var (
	kb     *knowledge
	kbOnce sync.Once
)

// normalize is the canonical form used for exact junk lookups.
func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func load() *knowledge {
	kbOnce.Do(func() {
		k := &knowledge{negativeSet: make(map[string]bool)}

		var nf negativesFile
		_ = json.Unmarshal(negativesJSON, &nf)
		k.negatives = nf.DB.Negatives
		for _, n := range k.negatives {
			k.negativeSet[normalize(n.Value)] = true
		}

		var kf keysFile
		_ = json.Unmarshal(keysDatasetJSON, &kf)
		k.serviceCount = len(kf.DB.Services)
		k.positiveLen = kf.DB.Metadata.TotalRecords

		kb = k
	})
	return kb
}

// Negatives returns the learned non-secret examples.
func Negatives() []Negative { return load().negatives }

// Families returns the known credential families.
func Families() []Family { return knownFamilies }

// Stats reports how much the classifier currently knows.
func Stats() (services, positives, negatives int) {
	k := load()
	return k.serviceCount, k.positiveLen, len(k.negatives)
}
