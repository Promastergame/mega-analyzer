# Releasing

[Русский](RELEASING.ru.md)

Releases are fully automated by [`.github/workflows/release.yml`](../.github/workflows/release.yml).

See [the current release checklist](RELEASE_CHECKLIST.md) before creating a tag.
Changes to tests, checks or CI configuration do not require a version bump.
Changing VERSION never replaces existing tags. The historical `beta.1` tag is
already used in this development repository; check the intended release tag
when actually preparing a publication.

## Cutting a release

Review the diff, run the checklist and commit the intended changes. Change the
release identity with `bump_version.py` only when deliberately choosing a new
release version. For the current VERSION, inspect the proposed tag:

```bash
release_tag="v$(cat VERSION)"
git diff
git tag --list "$release_tag"
```

The tag lookup must be empty. After committing, confirm the worktree is clean
and signing is configured, then create and push the matching tag:

```bash
git status --short
git tag "$release_tag"
git push origin "$release_tag"
```

In a new repository created from a source export, check its own tags before
choosing a release number. Never force-update a historical tag.

The workflow then:

1. Cross-compiles the pure-Go **core** analyzer (one `analyzer` executable; use
   `analyzer --api` for the REST server) for
   Linux, Windows and macOS on both `amd64` and `arm64` (CGO disabled).
2. Packages each target as a `.tar.gz` (`.zip` on Windows) bundled with
   `LICENSE`, `COPYING`, `NOTICE.txt`, third-party license texts, English/Russian
   instructions, the demo, the native APK example and `minisign.pub`.
3. Downloads the built `amd64` archives on Linux (`ubuntu-latest`), Windows
   (`windows-latest`) and macOS (`macos-15-intel`) and smoke-tests their unpacked
   contents without rebuilding. Any failure stops publication.
4. Generates `SHA256SUMS.txt` over all archives.
5. Signs `SHA256SUMS.txt` with minisign and verifies the signature against
   the repository's public key. A missing or mismatched key stops publication.
6. Publishes a GitHub Release using `docs/RELEASE_NOTES.md` with all artifacts attached.

> Prebuilt artifacts are the **core** build only. The optional native engines
> (OmniSec/Zig/GNN) are not distributed as binaries — build them yourself per
> [docs/BUILD.md](BUILD.md).

## Signing setup (one-time)

Public release signing is required. Local build and verification commands work
without a signing key. Configure signing before pushing a release tag:

1. Generate a **password-less** minisign key (CI cannot type a password):
   ```bash
   minisign -G -W -p minisign.pub -s minisign.key
   ```
   The repo already tracks a `minisign.pub`; replace it with this one (commit it)
   if you generate a fresh key.
2. Add the **private** key as a repository secret named `MINISIGN_SECRET_KEY`
   (Settings → Secrets and variables → Actions). Paste the full contents of
   `minisign.key`.
3. Keep `minisign.key` offline. Never commit it.

## Verifying a download (for users)

```bash
# Verify the checksum file's signature against the bundled public key
minisign -Vm SHA256SUMS.txt -p minisign.pub

# Then verify your archive's hash is listed
sha256sum -c SHA256SUMS.txt --ignore-missing
```


Core archives are built by `scripts/release.py`. The reusable `core.yml` smoke job
currently runs only on Linux; the three-platform checks above belong to the
tag-triggered release workflow. ARM64 targets are cross-compiled and have no
runtime smoke coverage. Evidence is uploaded as `release-smoke-evidence-*`.
While Actions quota is unavailable, record local results and pending platforms;
cross-compilation alone does not prove an archive runs. Complete all release
gates after quota returns before publishing. Prerelease tags are marked as
prereleases and use `docs/RELEASE_NOTES.md`.
