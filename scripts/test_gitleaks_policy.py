#!/usr/bin/env python3
"""Ensure fixture exceptions still detect new credentials in the same paths."""
import argparse
import json
from pathlib import Path
import secrets
import shutil
import string
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def verify(executable):
    executable = shutil.which(str(executable)) or str(Path(executable).resolve())
    with tempfile.TemporaryDirectory(prefix="gitleaks-policy-") as directory:
        root = Path(directory)
        names = ["docs/example.md", "README.md", "pkg/internal/secrets/generic_test.go", "demo/vulnerable-app/assets/config.properties"]
        fixture = names[-1]
        original_fixture = (ROOT / fixture).read_text(encoding="utf-8")
        for name in names:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            # Sample without replacement so detector entropy thresholds cannot
            # make this positive control fail randomly.
            token = "ghp_" + "".join(secrets.SystemRandom().sample(string.ascii_letters + string.digits, 36))
            prefix = original_fixture.rstrip() + "\n" if name == fixture else ""
            target.write_text(prefix + 'token = "' + token + '"\n', encoding="utf-8")
        report = root.parent / (root.name + ".json")
        try:
            result = subprocess.run([str(executable), "dir", "--no-banner", "--redact", "--config", str(ROOT / ".gitleaks.toml"), "--report-format", "json", "--report-path", str(report), "."], cwd=root, capture_output=True, text=True)
            if result.returncode != 1:
                raise AssertionError("Expected new credentials to fail the scan: " + result.stderr)
            findings = json.loads(report.read_text())
            found = {Path(row["File"]).as_posix() for row in findings}
            for row in findings:
                if Path(row["File"]).as_posix() == fixture and row["StartLine"] <= len(original_fixture.rstrip().splitlines()):
                    raise AssertionError("Reviewed fixture exception stopped matching; scan from the source root")
            for name in names:
                if not any(path == name or path.endswith("/" + name) for path in found):
                    raise AssertionError("Policy skipped a new credential in " + name + "; scanned matches: " + repr(sorted(found)) + "; " + result.stderr)
        finally:
            report.unlink(missing_ok=True)
    print("New credentials detected in docs, README, tests and an allowlisted fixture path")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", default="gitleaks")
    verify(parser.parse_args().gitleaks)
