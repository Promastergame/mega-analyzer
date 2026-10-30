#!/usr/bin/env python3
"""Export the current publishable sources without the private Git history."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = ("labs/bsd_emu/", "zig/apk_editor/", "docs/validation/",
            "docs/review-jar-minecraft/", "docs/review-jar-workspace/")
LOCAL_FILES = {"README.me.md", "APK_REPORT.md", "time_control.txt", "time_control.md", "SOURCE_MANIFEST.json",
               ".github/dependabot.yml",
               "docs/ML_CURRENCY_SEARCH_AUDIT_2026-09-27.ru.md",
               "WEB_STATIC_UPGRADE.ru.md", "docs/PETYA_DECRYPTOR_REVIEW.ru.md",
               "docs/RELEASE_VALIDATION.md", "docs/RELEASE_CHECKLIST_beta.10.md",
               "docs/SMART_PATCHER_OVERHAUL.md", "docs/SMART_PATCHER_OVERHAUL.ru.md",
               "docs/network-interception-overhaul.md", "docs/pe-analysis-improvements.ru.md",
               "docs/sandbox-overhaul.md", "pkg/internal/sandbox/IMPLEMENTATION_STATUS.md",
               "pkg/internal/ipaloader/CHANGES.md", "pkg/ml/security_report.md",
               "rust/crates/omnisec-scan-native/IMPROVEMENTS.md", "testkit/REPORT.md",
               "labs/servers/labkit/EXPLAINER.md", "pkg/internal/report/report_cover",
               "examples/native-apk/project/build/R.txt", "examples/native-apk/project/classes.dex"}
PRIVATE_DIRS = {".git", ".memory", ".claude", ".codex", ".agents", ".aws", ".ssh", ".azure", ".kube"}
GENERATED_DIRS = {"dist", "target", "__pycache__", ".test-go-cache", ".test-tmp", ".tmp"}


def repository_files(root=ROOT):
    """Include staged/unstaged source edits and new nonignored files."""
    result = subprocess.run(
        ["git", "-c", "core.excludesFile=", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root, check=True, capture_output=True,
    )
    return sorted(set(result.stdout.decode("utf-8").split("\0")) - {""})


def publishable(name):
    path = PurePosixPath(name)
    # Git paths use '/', including on Windows. Reject aliases, drive paths,
    # NTFS streams and names whose meaning changes when unpacked on Windows.
    if not name or "\\" in name or ":" in name or "\0" in name:
        return False
    if path.is_absolute() or any(p in {"", ".", ".."} or p.endswith((" ", ".")) for p in name.split("/")):
        return False
    lower = name.casefold()
    if lower.startswith(tuple(p.casefold() for p in EXCLUDED)) or lower in {p.casefold() for p in LOCAL_FILES}:
        return False
    if path.suffix.lower() == ".md" and re.search(r"(^|[_.-])audit([_.-]|$)", path.name, re.IGNORECASE):
        return False
    if re.fullmatch(r"\.mega-analyzer-(build|decode)-cache\.json", path.name, re.IGNORECASE):
        return False
    if path.name.lower().startswith(".env") and path.name.lower() not in {".env.example", ".env.example_ru"}:
        return False
    if path.suffix.lower() in {".key", ".pem", ".p12", ".pfx", ".keystore", ".jks"}:
        return False
    if lower.startswith("tools/") and not lower.startswith("tools/webui-split/"):
        return False
    if lower == "tools/webui-split/split_report.txt":
        return False
    return not any(part.casefold() in PRIVATE_DIRS | GENERATED_DIRS or part.casefold().startswith(".dai-") for part in path.parts)


def file_hash(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def tree_hash(hashes):
    return hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def ordinary_source(root, name):
    source = root / name
    if not source.resolve().is_relative_to(root.resolve()) or not source.is_file():
        raise ValueError("Export requires ordinary in-repository files: " + name)
    cursor = source
    while cursor != root:
        if cursor.is_symlink() or cursor.is_junction():
            raise ValueError("Export refuses linked source paths: " + name)
        cursor = cursor.parent
    return source


def verify_export(root):
    """Verify declared sources and reject extra files, without trusting a tree ID.

    Build/cache directories are ignored so the check can also precede a rebuild.
    This verifies integrity, not authenticity; secret scanning is a separate gate.
    """
    root = Path(root).resolve()
    manifest = json.loads((root / "SOURCE_MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest.get("files")
    if manifest.get("format") == 2 and isinstance(entries, list):
        if not all(isinstance(entry, dict) and set(entry) == {"path", "sha256"} and isinstance(entry["path"], str) for entry in entries):
            raise ValueError("Invalid source manifest entries")
        hashes = {entry["path"]: entry["sha256"] for entry in entries}
        if len(hashes) != len(entries):
            raise ValueError("Duplicate source manifest entry")
    elif manifest.get("format") == 1 and isinstance(entries, dict):
        hashes = entries
    else:
        raise ValueError("Invalid source manifest format")
    if manifest.get("history_included") is not False or not hashes:
        raise ValueError("Invalid source manifest")
    if tree_hash(hashes) != manifest.get("tree_sha256"):
        raise ValueError("Source manifest tree checksum mismatch")
    seen = set()
    for name, digest in hashes.items():
        if not publishable(name) or name.casefold() in seen or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("Invalid source manifest entry: " + name)
        seen.add(name.casefold())
        if file_hash(ordinary_source(root, name)) != digest:
            raise ValueError("Source checksum mismatch: " + name)
    for directory, dirs, files in os.walk(root, followlinks=False):
        # Do not walk build outputs; they can contain copied source trees.
        dirs[:] = [d for d in dirs if d not in GENERATED_DIRS and d != ".git"]
        for d in dirs:
            path = Path(directory) / d
            if path.is_symlink() or path.is_junction():
                raise ValueError("Unexpected linked directory: " + path.relative_to(root).as_posix())
        for filename in files:
            name = (Path(directory) / filename).relative_to(root).as_posix()
            if name != "SOURCE_MANIFEST.json" and name not in hashes:
                raise ValueError("Unmanifested source file: " + name)
    return manifest["tree_sha256"]


def export(output, root=None):
    root = Path(root or ROOT).resolve()
    output = Path(output).resolve()
    if not output.is_relative_to(root) or not output.is_relative_to((root / "dist").resolve()) or output == (root / "dist").resolve():
        raise ValueError("Choose a new directory under dist/")
    archive = output.with_suffix(".zip")
    checksum = archive.with_suffix(archive.suffix + ".sha256")
    if output.exists() or archive.exists() or checksum.exists():
        raise ValueError("Output already exists; choose a new directory name")
    entries = []
    seen = set()
    for name in repository_files(root):
        if not publishable(name):
            continue
        source = root / name
        if not source.exists():  # Deleted from the working tree, not yet staged.
            continue
        source = ordinary_source(root, name)
        if name.casefold() in seen:
            raise ValueError("Source names collide on case-insensitive systems: " + name)
        seen.add(name.casefold())
        entries.append((name, source))
    if not entries:
        raise ValueError("No sources to export")
    output.mkdir(parents=True)
    hashes = {}
    for name, source in entries:
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        hashes[name] = file_hash(target)
    tree = tree_hash(hashes)
    # Keep paths separate from hash keys: names such as api_key_test.go must
    # not make a generic secret detector mistake a checksum for a credential.
    manifest = {"format": 2, "tree_sha256": tree,
                "files": [{"path": name, "sha256": digest} for name, digest in hashes.items()],
                "history_included": False}
    (output / "SOURCE_MANIFEST.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    verify_export(output)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
        for name in [*hashes, "SOURCE_MANIFEST.json"]:
            handle.write(output / name, output.name + "/" + name)
    digest = file_hash(archive)
    checksum.write_text(digest + "  " + archive.name + "\n", encoding="ascii")
    print(json.dumps({"directory": str(output), "archive": str(archive), "files": len(hashes), "tree_sha256": tree}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(ROOT / "dist/public-source"))
    parser.add_argument("--verify", metavar="DIRECTORY", help="Verify an existing export against its manifest")
    args = parser.parse_args()
    if args.verify:
        print("Verified source tree: " + verify_export(args.verify))
    else:
        export(args.output)
