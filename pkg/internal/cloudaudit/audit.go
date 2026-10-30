package cloudaudit

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

var traversal = regexp.MustCompile(`(?i)(?:^|[/'"=:])(?:\.\.[/\\]|%2e%2e(?:%2f|%5c))`)

func Analyze(root string) (*Report, error) {
	r := &Report{GeneratedAt: time.Now().UTC(), Target: root}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		base := strings.ToLower(filepath.Base(path))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" && base != "dockerfile" {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		r.Issues = append(r.Issues, scan(filepath.ToSlash(rel), string(b))...)
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
func scan(file, body string) []Issue {
	lines := strings.Split(body, "\n")
	low := strings.ToLower(body)
	var out []Issue
	// Container escape requires concrete primitives; combinations escalate severity.
	priv := lineOf(lines, "privileged: true")
	hostPID := lineOf(lines, "hostpid: true")
	hostNet := lineOf(lines, "hostnetwork: true")
	sysAdmin := lineOfFold(lines, "sys_admin")
	socket := lineOfFold(lines, "/var/run/docker.sock")
	if socket == 0 {
		socket = lineOfFold(lines, "/run/containerd/containerd.sock")
	}
	hostRoot := 0
	for i, l := range lines {
		ll := strings.ToLower(l)
		if strings.Contains(ll, "hostpath:") && i+1 < len(lines) {
			for j := i + 1; j < len(lines) && j < i+5; j++ {
				t := strings.TrimSpace(strings.ToLower(lines[j]))
				if strings.HasPrefix(t, "path:") && (strings.TrimSpace(strings.TrimPrefix(t, "path:")) == "/" || strings.Contains(t, "/proc") || strings.Contains(t, "/sys")) {
					hostRoot = j + 1
				}
			}
		}
	}
	if priv > 0 || socket > 0 || hostRoot > 0 || sysAdmin > 0 {
		sev := SevHigh
		signals := []string{}
		for k, v := range map[string]int{"privileged": priv, "runtime socket": socket, "host root/proc/sys": hostRoot, "SYS_ADMIN": sysAdmin, "hostPID": hostPID, "hostNetwork": hostNet} {
			if v > 0 {
				signals = append(signals, fmt.Sprintf("%s@%d", k, v))
			}
		}
		if socket > 0 || hostRoot > 0 || (priv > 0 && sysAdmin > 0) {
			sev = SevCritical
		}
		line := priv
		if line == 0 {
			line = socket
		}
		if line == 0 {
			line = hostRoot
		}
		if line == 0 {
			line = sysAdmin
		}
		out = append(out, Issue{ID: "CLOUD-CONTAINER-001", Title: "Container-to-host escape primitives", Description: "The workload exposes concrete host-control primitives rather than only a generic hardening omission.", File: file, Line: line, Severity: sev, Confidence: .97, Evidence: strings.Join(signals, ", "), Remediation: "Remove privileged mode, runtime sockets and host root mounts; drop all capabilities and add only required ones; use read-only filesystems and enforced Pod Security admission."})
	}
	// Helm plugin traversal: require plugin metadata context plus the dangerous version field.
	if strings.EqualFold(filepath.Base(file), "plugin.yaml") || strings.EqualFold(filepath.Base(file), "plugin.yml") {
		for i, l := range lines {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(strings.ToLower(t), "version:") && traversal.MatchString(t) {
				out = append(out, Issue{ID: "CLOUD-K8S-002", Title: "Helm plugin version path traversal", Description: "plugin.yaml version contains a traversal sequence used in filesystem path construction by affected Helm 4 releases.", File: file, Line: i + 1, Severity: SevCritical, Confidence: .99, Evidence: t, Remediation: "Reject non-SemVer plugin versions and upgrade Helm to 4.1.4 or newer."})
			}
		}
	}
	// AWS IAM graph primitives and confused-deputy trust policy.
	if strings.Contains(low, "iam:passrole") && (strings.Contains(low, "lambda:createfunction") || strings.Contains(low, "ecs:runtask") || strings.Contains(low, "ec2:runinstances") || strings.Contains(low, "cloudformation:createstack")) {
		out = append(out, Issue{ID: "CLOUD-IAM-001", Title: "IAM PassRole privilege-escalation path", Description: "The same policy grants iam:PassRole and a compute creation/execution primitive, allowing code to run under a more privileged role when resources are broad.", File: file, Line: lineOfFold(lines, "iam:PassRole"), Severity: SevCritical, Confidence: .96, Evidence: "iam:PassRole + compute execution primitive", Remediation: "Restrict PassRole to exact low-privilege role ARNs with iam:PassedToService conditions and scope compute creation resources."})
	}
	if strings.Contains(low, "sts:assumerole") && strings.Contains(low, "principal") && !strings.Contains(low, "sts:externalid") && !strings.Contains(low, "aws:sourcearn") && !strings.Contains(low, "aws:sourceaccount") {
		out = append(out, Issue{ID: "CLOUD-IAM-002", Title: "External AssumeRole trust lacks confused-deputy binding", Description: "A role trust policy allows AssumeRole without ExternalId, SourceArn or SourceAccount tenant binding.", File: file, Line: lineOfFold(lines, "sts:AssumeRole"), Severity: SevHigh, Confidence: .88, Evidence: "AssumeRole trust without deputy-binding condition", Remediation: "Bind third-party trust with a unique ExternalId or AWS service trust with SourceArn and SourceAccount; avoid wildcard principals."})
	}
	return out
}
func lineOf(lines []string, s string) int {
	for i, l := range lines {
		if strings.Contains(l, s) {
			return i + 1
		}
	}
	return 0
}
func lineOfFold(lines []string, s string) int {
	s = strings.ToLower(s)
	for i, l := range lines {
		if strings.Contains(strings.ToLower(l), s) {
			return i + 1
		}
	}
	return 0
}
func RenderMarkdown(r *Report) string {
	var b strings.Builder
	b.WriteString("# Cloud & GitOps Security Audit\n\n")
	fmt.Fprintf(&b, "- **Target**: `%s`\n- **Issues**: %d\n\n| Severity | ID | File:line | Finding |\n|---|---|---|---|\n", r.Target, len(r.Issues))
	for _, x := range r.Issues {
		fmt.Fprintf(&b, "| %s | `%s` | `%s:%d` | %s |\n", x.Severity, x.ID, x.File, x.Line, x.Title)
	}
	return b.String()
}
