package report

import (
	"fmt"
	"html"
	"net"
	"net/url"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/networkrefs"
	"mega-analyzer/pkg/internal/types"
)

type NetworkIndicatorView struct {
	Value     string
	Kind      string
	File      string
	Recovered bool
	Role      string
}

func (b *ViewBuilder) buildNetworkIndicators() []NetworkIndicatorView {
	if b.result == nil {
		return nil
	}
	paths := make([]string, 0, len(b.result.Files))
	for path := range b.result.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	items := make(map[string]NetworkIndicatorView)
	add := func(value, file string, recovered bool) {
		value = strings.TrimSpace(value)
		host := value
		fromURL := false
		if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" && parsed.Hostname() != "" {
			value, host = parsed.Host, parsed.Hostname()
			fromURL = true
		} else if bareHost, _, err := net.SplitHostPort(value); err == nil {
			host = bareHost
		}
		if value == "" || strings.ContainsAny(value, " \t\r\n/\\@?#") || strings.Contains(value, "...") {
			return
		}
		kind := "domain"
		if ip := net.ParseIP(host); ip != nil {
			kind = "ip_address"
		} else if !strings.Contains(host, ".") || strings.Contains(host, ":") || (!fromURL && !networkrefs.IsRecoveredHostname(host)) {
			return
		}
		value = strings.ToLower(value)
		key := kind + ":" + value
		if existing, found := items[key]; found {
			if recovered {
				existing.Recovered = true
				items[key] = existing
			}
		} else {
			items[key] = NetworkIndicatorView{Value: value, Kind: kind, File: normalizePath(file), Recovered: recovered, Role: networkrefs.ResolverRole(host)}
		}
	}
	for _, path := range paths {
		file := b.result.Files[path]
		if file == nil {
			continue
		}
		for _, match := range file.Matches {
			switch match.Category {
			case types.CategoryNetworkEndpoint, types.CategorySuspiciousURL, types.CategoryHardcodedIP, types.CategoryCleartextTraffic:
				add(match.Pattern, path, false)
				add(match.Text, path, false)
				if host := match.Metadata["host"]; host != "" {
					if port := match.Metadata["port"]; port != "" {
						host = net.JoinHostPort(host, port)
					}
					add(host, path, false)
				}
			}
		}
		for _, artifact := range file.RecoveredArtifacts {
			switch artifact.Kind {
			case "url", "domain", "ip_address":
				add(artifact.Preview, path, true)
			}
		}
	}
	result := make([]NetworkIndicatorView, 0, len(items))
	for _, item := range items {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Value < result[j].Value })
	return result
}

func (r *MarkdownRenderer) renderNetworkIndicators(items []NetworkIndicatorView) {
	if len(items) == 0 {
		return
	}
	r.sb.WriteString("## Recovered Network Indicators\n\n")
	r.sb.WriteString("Static host/address references, including decoded constants. Their presence does not prove a connection or identify a C2 server.\n\n")
	r.sb.WriteString("| Host/address | Kind | Role | Recovered | Source |\n|---|---|---|---|---|\n")
	for i, item := range items {
		if i >= 100 {
			break
		}
		fmt.Fprintf(r.sb, "| `%s` | %s | %s | %t | `%s` |\n", mdCell(item.Value), item.Kind, mdCell(item.Role), item.Recovered, mdCell(item.File))
	}
	if len(items) > 100 {
		fmt.Fprintf(r.sb, "\n%d additional network references are available in analysis.json.\n", len(items)-100)
	}
	r.sb.WriteString("\n---\n\n")
}

func (r *HTMLReporter) buildNetworkIndicators(sb htmlWriter, items []NetworkIndicatorView) {
	if len(items) == 0 {
		return
	}
	sb.WriteString(`<section class="section" id="network-indicators"><h2 class="section-title">Recovered Network Indicators</h2><p class="section-desc">Static host/address references; connection and C2 attribution require separate evidence.</p><table><thead><tr><th>Host/address</th><th>Kind</th><th>Role</th><th>Recovered</th><th>Source</th></tr></thead><tbody>`)
	for i, item := range items {
		if i >= 100 {
			break
		}
		fmt.Fprintf(sb, "<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%t</td><td><code>%s</code></td></tr>",
			html.EscapeString(item.Value), item.Kind, html.EscapeString(item.Role), item.Recovered, html.EscapeString(item.File))
	}
	sb.WriteString(`</tbody></table></section>`)
}
