# Preparing a public source snapshot

The development repository may contain private historical lab material, local
analysis output and work in progress. `.gitignore` does not remove tracked files
or their older versions. Prepare the public repository from a reviewed export,
without copying the development `.git` directory or pushing its existing refs.

From the development repository root, choose a fresh output directory:

```sh
python scripts/public_source.py --output dist/public-source
python scripts/public_source.py --verify dist/public-source
cd dist/public-source
gitleaks dir --redact --no-banner --config .gitleaks.toml .
```

Python 3.12+ is required. The export includes tracked sources and new nonignored
files, with current edits. It excludes the private BSD lab, the separate APK
editor, local toolchains, agent data, credential files and local audit reports.
Case-colliding filenames and symlink/junction source paths are rejected. The
original worktree, index and history are not changed.

Run the directory secret scan **from inside the export**, as shown above: the
reviewed fixture exceptions use exact paths relative to that root.

Review the resulting directory and ZIP. `SOURCE_MANIFEST.json` records every
included file hash and a combined tree checksum. The ZIP has a separate SHA-256
sidecar. Verification checks file contents, missing files, extra files and the
manifest checksum; it ignores generated build/cache directories. Integrity
checks do not certify that a file is safe to publish. Review the included
sources, synthetic fixtures and third-party notices, and run the secret scan.

Verify the actual exported sources, not just the development checkout:

```sh
# Continue from the exported directory above.
python scripts/check_docs.py
python scripts/check_bundled_tools.py
go build -buildvcs=false ./pkg/cmd/analyzer ./cmd/decompiler
python scripts/release.py build --output dist/core
python scripts/release.py verify --output dist/core
```

An unversioned build from the export records `source-<tree-sha256>-unversioned`.
The release helper verifies the source manifest before using that identity;
modified sources must be re-exported, or committed in the new repository before
a versioned build. Normal direct `go build` remains available for local work.

Once reviewed, initialize the intended public repository from the exported
directory and commit its contents as a new history. Configure the GitHub
destination, private vulnerability reporting, required CI checks and the
`MINISIGN_SECRET_KEY` release secret there. Publishing the repository and creating
a release tag are separate actions; the export script performs neither.

The exported project is dual-licensed under [BSD-3-Clause](../LICENSE) OR
[GPLv2](../COPYING), at your option. Third-party components retain their own
licenses; unrelated lab samples are excluded from the export and are not covered
by this license choice. Both .env.example and .env.example_ru are included;
real .env files and private keys remain excluded.
See [release instructions](RELEASING.md), [the checklist](RELEASE_CHECKLIST.md)
and [secret scanning](SECRET_SCANNING.md).
