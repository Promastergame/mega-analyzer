#!/usr/bin/env python3
"""Verify the checked-in tool binaries against the reviewed manifest."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "pkg/internal/apkloader/embedtools"


def verify():
    manifest = json.loads((DIRECTORY / "PROVENANCE.json").read_text(encoding="utf-8"))
    for entry in manifest["tools"]:
        path = DIRECTORY / entry["file"]
        if not path.resolve().is_relative_to(DIRECTORY.resolve()):
            raise ValueError("Tool path escapes manifest directory")
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("Bundled tool checksum mismatch: " + entry["file"])
        for license_file in entry["licenses"]:
            license_path = (ROOT / license_file).resolve()
            if not license_path.is_relative_to(ROOT) or not license_path.is_file():
                raise ValueError("Missing license: " + license_file)
    print("Bundled tool checksums and license files passed")


if __name__ == "__main__":
    verify()
