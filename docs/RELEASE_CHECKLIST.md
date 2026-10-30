# Public core release checklist

For the first public publication, start with the reviewed
[source export](PUBLIC_SOURCE.md) so private development history is not copied.

1. Finish the intended changes and record the release commit. Changes to tests,
   checks or CI configuration do not require a version bump. Run
   `bump_version.py` with the chosen version only when deliberately preparing a
   new release identity. Release notes and the active checklist are updated;
   historical changelog names are retained.
2. Run `go vet ./...` and `go test ./...`. CI additionally runs the race detector,
   fuzz smoke, coverage collection and the detection quality gate on that SHA.
3. Build with `python scripts/release.py build --output dist/core`, then run
   `python scripts/release.py verify --output dist/core`. It tests the unpacked
   archive, including the documented demo command, reports, API Host protection,
   metadata, local documentation assets and every packaged Markdown file's
   relative links. The native APK example must be available offline.
4. Review `docs/RELEASE_NOTES.md` and the release archive checks on Linux, Windows
   and macOS (`amd64`). The reusable core smoke job covers Linux only; the release
   workflow downloads and verifies the actual built artifacts on all three OSes.
   ARM64 archives are cross-compiled, without runtime coverage. While Actions quota
   is unavailable, attach local results and list pending platforms; complete the
   release gates after quota returns before publishing. Update the
   [validation record](RELEASE_VALIDATION.md) with the checked commit and results.
   Inspect coverage/test evidence attached to that CI run; static badges are
   not release evidence.
   Confirm `MINISIGN_SECRET_KEY` matches `minisign.pub`; public releases require
   a verified signature. Compare a representative pair of
   [analysis reports](REPORT_COMPARISON.md) when changing detectors.
5. Ensure the proposed tag matches VERSION and is not already in use. The local
   repository already contains the historical `beta.1` tag. This does not require
   changing the version while updating tests. Changing VERSION does not replace historical tags.
   Check the target repository's own tags before publishing;
   do not force-push or silently overwrite an existing release.
6. After publication, verify checksums/signature and the attached archives.

The old `RELEASE_CHECKLIST_beta.10.md` is historical. Its missing gnnprobe build
constraint and placeholder LICENSE have already been corrected.

Runtime configuration: `MEGA_ANALYZER_SCAN_CONCURRENCY` controls active Web UI
scans (default 2); `MEGA_ANALYZER_WEB_QUEUE_SIZE` controls waiting capacity
(default 8). A full queue returns HTTP 429 and Retry-After. Results remain on disk.
For a network-bound REST API behind a named reverse proxy, set
`MEGA_ANALYZER_API_HOSTS` to a comma-separated hostname allowlist in addition to
the required `MEGA_ANALYZER_API_TOKEN`. Preserve the API port in the forwarded Host.
