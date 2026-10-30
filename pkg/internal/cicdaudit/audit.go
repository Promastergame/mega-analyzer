package cicdaudit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Severity string

const (
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

type Issue struct {
	ID, Title, Description, File, Evidence, Remediation string
	Line                                                int
	Severity                                            Severity
	Confidence                                          float64
}
type Report struct {
	GeneratedAt time.Time
	Target      string
	Issues      []Issue
}

var untrustedContext = regexp.MustCompile(`\$\{\{\s*(github\.(head_ref|event\.(pull_request\.(title|body|head\.(ref|sha))|issue\.(title|body)|comment\.body|head_commit\.message))|inputs\.[A-Za-z0-9_-]+)\s*\}\}`)
var actionRef = regexp.MustCompile(`(?i)uses:\s*[^\s#]+@(main|master|develop|dev|latest|v?\d+(?:\.\d+){0,1})\s*$`)

func Analyze(root string) (*Report, error) {
	r := &Report{GeneratedAt: time.Now().UTC(), Target: root}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		slash := filepath.ToSlash(rel)
		if !(strings.Contains(slash, ".github/workflows/") || strings.HasSuffix(slash, ".gitlab-ci.yml") || strings.HasSuffix(slash, "Jenkinsfile")) {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil
		}
		r.Issues = append(r.Issues, scanWorkflow(slash, string(b))...)
		return nil
	})
	sort.SliceStable(r.Issues, func(i, j int) bool {
		if r.Issues[i].File != r.Issues[j].File {
			return r.Issues[i].File < r.Issues[j].File
		}
		return r.Issues[i].Line < r.Issues[j].Line
	})
	return r, err
}

func scanWorkflow(file, body string) []Issue {
	lines := strings.Split(body, "\n")
	lower := strings.ToLower(body)
	prTarget := strings.Contains(lower, "pull_request_target")
	writePriv := strings.Contains(lower, "contents: write") || strings.Contains(lower, "packages: write") || strings.Contains(lower, "id-token: write") || strings.Contains(lower, "deployments: write")
	secrets := strings.Contains(body, "secrets.") || strings.Contains(lower, "secrets: inherit")
	untrustedCheckout := false
	execAfterCheckout := false
	checkoutLine := 0
	var out []Issue
	for i, line := range lines {
		n := i + 1
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "run:") || strings.HasPrefix(t, "- run:") {
			if m := untrustedContext.FindString(line); m != "" {
				out = append(out, Issue{ID: "CICD-GHA-001", Title: "Untrusted GitHub context interpolated into shell", Description: "Attacker-controlled event data is expanded into a run block before the shell parses it. Quoting the expression inside YAML does not prevent command injection.", File: file, Line: n, Severity: SevCritical, Confidence: .98, Evidence: strings.TrimSpace(line), Remediation: "Bind the context to an env variable and reference it as a quoted shell variable; avoid eval and command-string construction."})
			}
			if untrustedCheckout {
				execAfterCheckout = true
			}
		}
		if strings.Contains(t, "uses: actions/checkout@") {
			checkoutLine = n
		}
		if checkoutLine > 0 && n <= checkoutLine+5 && (strings.Contains(line, "github.event.pull_request.head.sha") || strings.Contains(line, "github.event.pull_request.head.ref") || strings.Contains(line, "github.head_ref")) {
			untrustedCheckout = true
		}
		if actionRef.MatchString(t) {
			out = append(out, Issue{ID: "CICD-GHA-003", Title: "Mutable or weakly pinned workflow action", Description: "The workflow trusts a mutable branch/major tag instead of an immutable commit SHA. Upstream compromise or tag movement can execute code in the build context.", File: file, Line: n, Severity: SevHigh, Confidence: .95, Evidence: t, Remediation: "Pin third-party actions to a reviewed full commit SHA and use dependency automation to update it."})
		}
	}
	if prTarget && untrustedCheckout && execAfterCheckout {
		sev := SevHigh
		if writePriv || secrets {
			sev = SevCritical
		}
		out = append(out, Issue{ID: "CICD-GHA-002", Title: "pull_request_target executes untrusted checkout", Description: "An elevated pull_request_target workflow checks out attacker-controlled PR code and later executes repository commands.", File: file, Line: checkoutLine, Severity: sev, Confidence: .99, Evidence: fmt.Sprintf("pull_request_target + untrusted checkout; write_permissions=%v secrets=%v", writePriv, secrets), Remediation: "Never execute PR head code under pull_request_target. Use pull_request with read-only permissions, or split untrusted build and privileged follow-up workflows with verified artifacts."})
	}
	if (strings.Contains(lower, "pull_request") || strings.Contains(lower, "merge_request")) && execAfterCheckout && (writePriv || secrets) {
		out = append(out, Issue{ID: "CICD-PPE-001", Title: "Poisoned Pipeline Execution path", Description: "Untrusted contribution code reaches execution in a job with writable credentials or secrets, forming a repository-to-release compromise path.", File: file, Line: checkoutLine, Severity: SevCritical, Confidence: .92, Evidence: "untrusted trigger -> checkout -> run -> privileged token/secrets", Remediation: "Separate untrusted builds from publish/deploy jobs; use immutable artifacts, environment approval, least-privilege tokens and protected refs."})
	}
	return out
}

func RenderMarkdown(r *Report) string {
	var b strings.Builder
	b.WriteString("# CI/CD Security Audit\n\n")
	fmt.Fprintf(&b, "- **Target**: `%s`\n- **Issues**: %d\n\n", r.Target, len(r.Issues))
	b.WriteString("| Severity | ID | File:line | Finding |\n|---|---|---|---|\n")
	for _, x := range r.Issues {
		fmt.Fprintf(&b, "| %s | `%s` | `%s:%d` | %s |\n", x.Severity, x.ID, x.File, x.Line, x.Title)
	}
	return b.String()
}
