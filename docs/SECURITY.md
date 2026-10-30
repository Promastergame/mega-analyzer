# Security policy

[Русский](SECURITY.ru.md)

**Do not open a public issue for a security vulnerability.**

Open a private advisory instead:

> [**Report a vulnerability →**](https://github.com/Promastergame/mega-analyzer/security/advisories/new)

(GitHub: repository → **Security** → **Advisories** → **Report a vulnerability**.)

## What to include

- Version / commit you tested (`analyzer -version`)
- Your OS and architecture
- Minimal reproduction — a tiny sample file or command line
- What you expected vs. what happened, and the impact
- Any crash output, stack trace, or log

If you have a proof-of-concept, attach it to the advisory — not anywhere public.

## In scope

- Memory-safety or crash bugs in the parsers and loaders (APK/DEX/PE/ELF/Mach-O), including denial-of-service on crafted input.
- A malicious sample that escapes analysis and executes on the host, or reaches the network when offline mode is expected.
- Any built-in proxy, DNS, or HTTP server binding to something other than `localhost`.
- Path traversal or arbitrary file write when unpacking an archive or writing a report.
- Hardcoded credentials, accidental telemetry, or any uninvited outbound connection.

## Out of scope

- The intentionally vulnerable [`demo/`](../demo/) target.
- Findings from scanning third-party apps.
- Theoretical issues with no realistic exploit, or anything requiring an already-compromised host.

## Supported versions

| Version | Supported |
| :--- | :---: |
| Latest release / `main` | ✅ |
| Older pre-releases | ❌ |

## Disclosure

Give a reasonable window to ship a fix before any public write-up. There is no bug-bounty program, but genuine reporters are credited in release notes if they want to be.
