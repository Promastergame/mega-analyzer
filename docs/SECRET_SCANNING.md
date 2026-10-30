# Secret scanning

CI and releases run Gitleaks 8.30.1 on all fetched Git refs. The default rules
apply to documentation, tests, examples and source code alike.

The analyzer deliberately contains synthetic credentials as detector inputs.
Each exception in `.gitleaks.toml` is scoped with `targetRules` and requires
**both** an exact reviewed file path and an exact matched value. Gitleaks 8.30.1
can skip files matching global path allowlists before evaluating their value
conditions in directory mode; rule-scoped exceptions avoid that shortcut.
Historical examples are retained where needed to
scan old commits. The two APK-signing matches are resource/type identifiers,
not service credentials. Vendored CPU/hash identifiers are also explicit.

Do not exclude whole directories or all tests/Markdown. Review a new finding
before adding an exception; a real credential must be revoked and removed from
the published history. Never turn an unreviewed scan report into a baseline.

Run locally from the repository root:

```sh
gitleaks git --redact --no-banner --log-opts=--all .
python scripts/test_gitleaks_policy.py
```

The policy test creates nonfunctional random token-shaped strings in temporary
README, documentation, test and fixture paths and checks that all are detected.
It also verifies that the original reviewed fixture still passes, with paths
relative to the scan root.
It performs no service authentication or outbound requests.

The Git scan covers commits. Before publishing a source export, change into
its directory and run `gitleaks dir --redact --config .gitleaks.toml .`.
Exact fixture paths are relative to the scan's working directory. This includes
new source files that have not yet been committed. Verify the source manifest
before scanning, as described in [public source exports](PUBLIC_SOURCE.md).
