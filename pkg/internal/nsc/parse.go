package nsc

import (
	"encoding/xml"
	"strings"
)

// rawConfig mirrors the on-disk XML schema closely; we then reduce
// it to the shape consumers care about.
type rawConfig struct {
	XMLName        xml.Name        `xml:"network-security-config"`
	BaseConfig     *rawBaseConfig  `xml:"base-config"`
	DomainConfigs  []rawDomainConf `xml:"domain-config"`
	DebugOverrides *rawBaseConfig  `xml:"debug-overrides"`
}

type rawBaseConfig struct {
	CleartextTrafficPermitted *bool            `xml:"cleartextTrafficPermitted,attr"`
	TrustAnchors              *rawTrustAnchors `xml:"trust-anchors"`
	PinSet                    *rawPinSet       `xml:"pin-set"`
}

type rawDomainConf struct {
	rawBaseConfig
	Domains []rawDomain `xml:"domain"`
}

type rawDomain struct {
	IncludeSubdomains bool   `xml:"includeSubdomains,attr"`
	Value             string `xml:",chardata"`
}

type rawTrustAnchors struct {
	Certificates []rawCertificates `xml:"certificates"`
}

type rawCertificates struct {
	Src          string `xml:"src,attr"`
	OverridePins bool   `xml:"overridePins,attr"`
}

type rawPinSet struct {
	Expiration string   `xml:"expiration,attr"`
	Pins       []rawPin `xml:"pin"`
}

type rawPin struct {
	Digest string `xml:"digest,attr"`
	Value  string `xml:",chardata"`
}

// parse decodes raw XML bytes into our domain-level Report.
// Returns an error only when the XML is fundamentally malformed.
// Missing / partial fields are tolerated and surfaced via Issues.
func parse(target, source string, data []byte) (*Report, error) {
	var raw rawConfig
	if err := xml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	r := &Report{
		Target:  target,
		Source:  source,
		Present: true,
	}

	// Base config
	if raw.BaseConfig != nil {
		r.BaseCleartextPermitted = raw.BaseConfig.CleartextTrafficPermitted != nil &&
			*raw.BaseConfig.CleartextTrafficPermitted
		flags := analyzeTrustAnchors(raw.BaseConfig.TrustAnchors)
		r.BaseHasUserTrustAnchor = flags.user
		r.BaseHasCustomTrustAnchor = flags.custom
		r.BaseHasCertificatePinning = raw.BaseConfig.PinSet != nil && len(raw.BaseConfig.PinSet.Pins) > 0
	}

	// Debug overrides
	if raw.DebugOverrides != nil {
		r.HasDebugOverrides = true
		flags := analyzeTrustAnchors(raw.DebugOverrides.TrustAnchors)
		r.DebugOverridesUserTrust = flags.user
	}

	// Domain configs
	for _, dc := range raw.DomainConfigs {
		hosts := make([]string, 0, len(dc.Domains))
		includeSub := false
		for _, d := range dc.Domains {
			h := strings.TrimSpace(d.Value)
			if h == "" {
				continue
			}
			hosts = append(hosts, h)
			if d.IncludeSubdomains {
				includeSub = true
			}
		}
		flags := analyzeTrustAnchors(dc.TrustAnchors)
		dom := Domain{
			Hosts:                hosts,
			IncludeSubdomains:    includeSub,
			HasUserTrustAnchor:   flags.user,
			HasCustomTrustAnchor: flags.custom,
			HasSystemTrustAnchor: flags.system || (!flags.user && !flags.custom),
			OverridePinsForLocal: flags.overridePins,
		}
		if dc.CleartextTrafficPermitted != nil {
			v := *dc.CleartextTrafficPermitted
			dom.CleartextPermitted = &v
			if v {
				r.DomainsCleartextPermitted = append(r.DomainsCleartextPermitted, hosts...)
			}
		}
		if dc.PinSet != nil && len(dc.PinSet.Pins) > 0 {
			dom.HasCertificatePinning = true
			dom.PinExpirationISO = strings.TrimSpace(dc.PinSet.Expiration)
			dom.PinCount = len(dc.PinSet.Pins)
			for _, p := range dc.PinSet.Pins {
				dom.PinDigests = append(dom.PinDigests, strings.TrimSpace(p.Digest))
			}
			r.DomainsWithPinning = append(r.DomainsWithPinning, hosts...)
		}
		if dom.HasUserTrustAnchor {
			r.DomainsWithUserTrust = append(r.DomainsWithUserTrust, hosts...)
		}
		r.Domains = append(r.Domains, dom)
	}
	return r, nil
}

type trustFlags struct {
	user, system, custom, overridePins bool
}

func analyzeTrustAnchors(ta *rawTrustAnchors) trustFlags {
	if ta == nil {
		return trustFlags{}
	}
	out := trustFlags{}
	for _, c := range ta.Certificates {
		src := strings.ToLower(strings.TrimSpace(c.Src))
		switch src {
		case "user":
			out.user = true
		case "system":
			out.system = true
		default:
			// raw resource, e.g. "@raw/my_ca" — counts as custom anchor
			out.custom = true
		}
		if c.OverridePins {
			out.overridePins = true
		}
	}
	return out
}
