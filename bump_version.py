#!/usr/bin/env python3
"""Update the current release identity without rewriting historical changelogs.

Usage: python bump_version.py NEW_VERSION
Only local files are edited; git tags and published releases are never changed.
"""
import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ACTIVE_FILES = [
    "README.md", "README.ru.md", "QUICKSTART.md", "FlagiFiles.md",
    "Dockerfile", "build.ps1", "build.sh", "pkg/cmd/analyzer/main.go",
    "docs/BUILD.md", "docs/BUILD.ru.md", "docs/RELEASING.md", "docs/RELEASING.ru.md",
    "docs/RELEASE_NOTES.md", "docs/RELEASE_CHECKLIST.md",
    "docs/ARCHITECTURE.md", "docs/ARCHITECTURE.ru.md",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    args = parser.parse_args()
    version = args.version.removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)?", version):
        parser.error("expected a version such as 1.0.0-beta.1")
    current = (ROOT / "VERSION").read_text().strip()
    for rel in ACTIVE_FILES:
        path = ROOT / rel
        if not path.exists():
            continue
        old = path.read_text(encoding="utf-8")
        updated = re.sub(re.escape(current) + r"(?![.\d])", version, old)
        if updated != old:
            path.write_text(updated, encoding="utf-8", newline="\n")
            print(rel)
    identity = ROOT / "pkg/buildinfo/version.go"
    text = identity.read_text(encoding="utf-8")
    text, count = re.subn(r'(Version\s*=\s*")[^"]+(".*)', lambda m: m[1] + version + m[2], text, count=1)
    if count != 1:
        raise SystemExit("Cannot find the buildinfo version declaration")
    identity.write_text(text, encoding="utf-8", newline="\n")
    (ROOT / "VERSION").write_text(version + "\n", encoding="utf-8", newline="\n")
    print("Current version:", version)

if __name__ == "__main__":
    main()
