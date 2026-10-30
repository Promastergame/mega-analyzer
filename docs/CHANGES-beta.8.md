# Mega Analyzer - v1.0.0-beta.8

## New detector: Staging / pre-production endpoint exposure (`staging_endpoint`)
- Flags hostnames that belong to non-production environments (staging / pre-prod / UAT)
  but are shipped inside a production release build.
- Why it matters: such endpoints widen the attack surface and leak internal
  infrastructure (CWE-200); inside App Links they also dilute deep-link verification.
- Detection: DNS-label-aware scan over manifest / XML / JSON / properties / text and
  app-code smali. The env token must be a COMPLETE DNS label in an `env.<domain>.<tld>`
  shape (preceded by a delimiter, followed by another label) to keep false positives low.
  Deduplicated per host, capped per file.
- Severity: LOW (informational / attack-surface).

## Findings on the analyzed app (Claude, com.anthropic.claude)
- staging_endpoint: `staging.claudeusercontent.com`, `frame.staging.claudeusercontent.com`
  (and more) are shipped in the release build.
- The manifest additionally verifies `claude-ai.staging.ant.dev` next to the production
  `claude.ai` App Links host.
- Context (reported, not new detectors): OAuth/SSO deep-link callbacks are SECURE
  (autoVerify App Links, https, host claude.ai); backup & data-extraction rules include
  the whole `sharedpref` domain (potential token exposure, CWE-312/538); FileProvider
  paths are well scoped; the manifest Google API key is already flagged by Hardcoded Secret.

## Hardening: HTML report is now guaranteed emoji-free
- Added a final `stripResidualEmoji` pass at the HTML build choke point
  (`BuildHTML` / `Generate`), so REPORT.html is SVG-only regardless of which categories
  appear. This removes emoji leaks that came from a few category-icon render sites that
  were not wired to the per-string sanitizer.
