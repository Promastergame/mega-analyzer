package main

import (
	"time"

	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/ncer"
)

// sensorIDSandboxAuthority identifies this file's events as coming from the
// live sandbox run, distinct from ncer's own sensorIDCorrelationEngine.
const sensorIDSandboxAuthority = "sandbox.authority"

// feedNcerAuthority converts a finished sandbox Report's declared Android
// permissions and observed network actions into NCER authority events (see
// ncer.FromAuthorityContextGranular) and attaches them to collector, so
// Reconcile can compute d_authority/d_capability alongside the HTTP-derived
// d_causal. A no-op when the report has no AndroidProfile (e.g. non-Android
// targets, or Android analysis that couldn't parse the manifest).
func feedNcerAuthority(collector *ncer.Collector, report *sandbox.Report) {
	if report == nil || report.AndroidProfile == nil {
		return
	}
	profile := report.AndroidProfile
	subjectID := profile.PackageName
	if subjectID == "" {
		return
	}

	ctx := ncer.AuthorityContext{
		Subject: ncer.Subject{ID: subjectID, Kind: "app", Name: firstNonEmpty(profile.AppLabel, subjectID)},
		Identity: ncer.Identity{
			Principal: "package:" + subjectID,
			Issuer:    "android",
		},
	}
	for _, p := range profile.Permissions {
		ctx.Granted = append(ctx.Granted, ncer.GrantedPermission{
			Name:   p.Name,
			Scope:  firstNonEmpty(p.Risk, "normal"),
			Source: "AndroidManifest.xml",
		})
	}

	base := report.StartedAt
	observedAtMs := func(t time.Time) int64 {
		if t.IsZero() {
			t = base
		}
		return t.UnixMilli()
	}

	if report.NetworkCapture != nil {
		for _, c := range report.NetworkCapture.Connections {
			ctx.Observed = append(ctx.Observed, ncer.ObservedAction{
				Action:      "network_connect",
				Target:      c.RemoteAddr,
				TimestampMs: observedAtMs(c.Timestamp),
			})
		}
		for _, d := range report.NetworkCapture.DNSQueries {
			ctx.Observed = append(ctx.Observed, ncer.ObservedAction{
				Action:      "dns_query",
				Target:      d.QueryName,
				TimestampMs: observedAtMs(d.Timestamp),
			})
		}
		for _, tconn := range report.NetworkCapture.TLSMetadata {
			ctx.Observed = append(ctx.Observed, ncer.ObservedAction{
				Action:      "tls_connect",
				Target:      tconn.SNI,
				TimestampMs: observedAtMs(tconn.Timestamp),
			})
		}
	} else {
		for _, c := range report.Connections {
			ctx.Observed = append(ctx.Observed, ncer.ObservedAction{
				Action:      "network_connect",
				Target:      c.RemoteAddr,
				TimestampMs: observedAtMs(c.FirstSeen),
			})
		}
	}

	if len(ctx.Granted) == 0 && len(ctx.Observed) == 0 {
		return
	}
	collector.ObserveAuthority(ncer.FromAuthorityContextGranular(ctx, sensorIDSandboxAuthority, observedAtMs(base)))
}
