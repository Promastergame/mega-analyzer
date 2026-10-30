package secrets

// valueJudge, when set, is consulted for every finding produced by
// DetectProviders. It lets the host project plug in an offline value
// classifier without this package importing anything:
//
//	secrets.SetValueJudge(llmkeys.JunkJudge())
//
// A "junk" verdict (placeholder, test value, structured identifier) demotes
// the finding to low severity - it is never dropped, so scan coverage is
// preserved and nothing silently disappears from reports.
var valueJudge func(value string) bool

// SetValueJudge installs (or removes, with nil) the junk-value classifier.
// Not safe for concurrent use with running scans; set it once at startup.
func SetValueJudge(judge func(value string) bool) { valueJudge = judge }
