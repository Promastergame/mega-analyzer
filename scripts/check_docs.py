#!/usr/bin/env python3
"""Check local Markdown links, including the layout of release templates."""
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from public_source import ROOT, publishable, repository_files

LINK = re.compile(r'!?\[[^\]\n]*\]\((<[^>]+>|[^\s)]+)(?:\s+"[^"]*")?\)')
TEMPLATES = {"docs/README_CORE.md", "docs/README_CORE.ru.md"}
PACKAGE_FILES = {"README.md", "README.ru.md", "QUICKSTART.md", "FlagiFiles.md", "LICENSE", "COPYING", "NOTICE.txt"}


def check(root, names):
    failures = []
    for name in names:
        path = root / name
        if not publishable(name) or path.suffix.lower() != ".md" or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        # Keep line numbers while discarding code fences and inline code.
        text = re.sub(r"(?ms)^\s*(`{3,}|~{3,}).*?^\s*\1\s*$", lambda m: "\n" * m[0].count("\n"), text)
        text = re.sub(r"`[^`\n]*`", "", text)
        for match in LINK.finditer(text):
            target = match[1].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            local = unquote(parsed.path)
            if name in TEMPLATES and local in PACKAGE_FILES:
                continue
            resolved = root / local.lstrip("/") if local.startswith("/") else path.parent / local
            inside = resolved.resolve().is_relative_to(root.resolve())
            excluded = inside and resolved.is_file() and not publishable(resolved.resolve().relative_to(root.resolve()).as_posix())
            if not resolved.exists() or not inside or excluded:
                failures.append(f"{name}:{text.count(chr(10), 0, match.start()) + 1}: missing local target {target}")
    return failures


if __name__ == "__main__":
    names = repository_files() if (ROOT / ".git").exists() else [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*.md")]
    failures = check(ROOT, names)
    print("\n".join(failures) if failures else "Local documentation links passed")
    raise SystemExit(bool(failures))
