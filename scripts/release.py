#!/usr/bin/env python3
"""Build a core release archive or smoke-test its actual unpacked contents."""
import argparse
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

from public_source import verify_export
from check_docs import check as check_doc_links

ROOT = Path(__file__).resolve().parents[1]
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

def command(args, **kwargs):
    return subprocess.run(args, check=True, creationflags=NO_WINDOW, **kwargs)

def source_revision(root, tag=None):
    """Reject dirty tag builds, including staged changes and untracked files."""
    if not (root / ".git").exists():
        if tag:
            raise ValueError("Tagged releases require a Git checkout")
        return "source-" + verify_export(root) + "-unversioned"
    commit = command(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True).stdout.strip()
    status = command(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root, capture_output=True, text=True).stdout
    if tag:
        if status:
            raise ValueError("Tagged releases require a clean worktree and index, including untracked files")
        tagged = command(["git", "rev-parse", "--verify", "refs/tags/" + tag + "^{commit}"], cwd=root, capture_output=True, text=True).stdout.strip()
        if tagged != commit:
            raise ValueError("Release tag does not point to HEAD")
    return commit + ("-dirty" if status else "")

def verify_package_docs(stage):
    """Check every Markdown document against the actual package contents."""
    names = sorted(path.relative_to(stage).as_posix() for path in stage.rglob("*.md"))
    failures = check_doc_links(stage, names)
    if failures:
        raise ValueError("Broken package documentation links:\n" + "\n".join(failures))

def build(args):
    version = (ROOT / "VERSION").read_text().strip()
    declared = re.search(r'Version\s*=\s*"([^"]+)"', (ROOT / "pkg/buildinfo/version.go").read_text()).group(1)
    if declared != version:
        raise ValueError("VERSION and pkg/buildinfo/version.go differ; run bump_version.py")
    if args.tag and args.tag != "v" + version:
        raise ValueError("Release tag must match VERSION exactly: v" + version)
    commit = source_revision(ROOT, args.tag)
    host = command(["go", "env", "GOOS", "GOARCH"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    goos, arch = args.goos or host[0], args.goarch or host[1]
    if goos not in ("windows", "linux", "darwin") or arch not in ("amd64", "arm64"):
        raise ValueError("Unsupported release target")
    output = Path(args.output).resolve(); output.mkdir(parents=True, exist_ok=True)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    binary = "analyzer.exe" if goos == "windows" else "analyzer"
    name = f"mega-analyzer-v{version}-{goos}-{arch}"
    with tempfile.TemporaryDirectory(prefix="package-", dir=output) as temp:
        stage = Path(temp).resolve()
        assert stage.is_relative_to(output)
        env = dict(os.environ, CGO_ENABLED="0", GOOS=goos, GOARCH=arch)
        flags = f"-s -w -X main.Version={version} -X main.BuildDate={date} -X main.CommitHash={commit}"
        command(["go", "build", "-trimpath", "-ldflags", flags, "-o", str(stage / binary), "./pkg/cmd/analyzer"], cwd=ROOT, env=env)
        decompiler = "decompiler.exe" if goos == "windows" else "decompiler"
        biflags = f"-s -w -X mega-analyzer/pkg/buildinfo.Version={version} -X mega-analyzer/pkg/buildinfo.BuildDate={date} -X mega-analyzer/pkg/buildinfo.CommitHash={commit}"
        command(["go", "build", "-trimpath", "-ldflags", biflags, "-o", str(stage / decompiler), "./cmd/decompiler"], cwd=ROOT, env=env)
        for filename in ("LICENSE", "COPYING", "NOTICE.txt", "minisign.pub"):
            shutil.copy2(ROOT / filename, stage / filename)
        shutil.copytree(ROOT / "third-party/licenses", stage / "licenses")
        shutil.copy2(ROOT / "pkg/internal/apkloader/embedtools/PROVENANCE.json", stage / "BUNDLED_TOOLS.json")
        for source, target in (("docs/README_CORE.md", "README.md"), ("docs/README_CORE.ru.md", "README.ru.md"), ("QUICKSTART.md", "QUICKSTART.md"), ("FlagiFiles.md", "FlagiFiles.md")):
            text = (ROOT / source).read_text(encoding="utf-8").replace("@VERSION@", version)
            # Binary packages link to online extended docs, not missing files.
            text = re.sub(r'\]\((docs/[^)#]+)(#[^)]*)?\)', lambda m: "](https://github.com/Promastergame/mega-analyzer/blob/main/" + m[1] + (m[2] or "") + ")", text)
            (stage / target).write_text(text, encoding="utf-8")
        shutil.copytree(ROOT / "demo/vulnerable-app", stage / "demo/vulnerable-app")
        shutil.copytree(ROOT / "examples/native-apk", stage / "examples/native-apk")
        verify_package_docs(stage)
        meta = dict(version=version, commit=commit, build_date=date, goos=goos, goarch=arch, build="core", cgo=False)
        (stage / "BUILD.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        archive = output / (name + (".zip" if goos == "windows" else ".tar.gz"))
        if goos == "windows":
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
                for path in sorted(stage.rglob("*")):
                    if path.is_file(): handle.write(path, path.relative_to(stage).as_posix())
        else:
            with tarfile.open(archive, "w:gz") as handle:
                for path in sorted(stage.iterdir()): handle.add(path, arcname=path.name)
    print(archive)

class AssetLinks(HTMLParser):
    def __init__(self): super().__init__(); self.paths = []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and attrs.get("src"): self.paths.append(attrs["src"])
        if tag == "link" and attrs.get("rel") == "stylesheet": self.paths.append(attrs["href"])

def verify(args):
    output = Path(args.output).resolve(); output.mkdir(parents=True, exist_ok=True)
    candidates = [Path(args.archive).resolve()] if args.archive else sorted(output.glob("mega-analyzer-*.zip")) + sorted(output.glob("mega-analyzer-*.tar.gz"))
    if len(candidates) != 1: raise ValueError("Choose one archive with --archive")
    archive = candidates[0]
    with tempfile.TemporaryDirectory(prefix="verify-", dir=output) as temp:
        stage = Path(temp).resolve(); assert stage.is_relative_to(output)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as handle:
                for item in handle.infolist():
                    if not (stage / item.filename).resolve().is_relative_to(stage): raise ValueError("Unsafe archive path")
                handle.extractall(stage)
        else:
            with tarfile.open(archive) as handle: handle.extractall(stage, filter="data")
        meta = json.loads((stage / "BUILD.json").read_text())
        verify_package_docs(stage)
        binary = stage / ("analyzer.exe" if os.name == "nt" else "analyzer")
        env = dict(os.environ, MEGA_ANALYZER_CONFIG_DIR=str(stage), MEGA_ANALYZER_WORKSPACE=str(stage / "workspace"), MEGA_ANALYZER_JOB_ROOT=str(stage / "jobs"), MEGA_ANALYZER_SCAN_ROOT=str(stage), MEGA_ANALYZER_API_BIND="127.0.0.1", MEGA_ANALYZER_API_TOKEN="", MEGA_ANALYZER_CORS_ORIGINS="", NO_COLOR="1")
        for label, cli in (("version", ["--version"]), ("help", ["--help"]), ("demo", ["-t", "demo/vulnerable-app", "-report", "all", "-sarif", "-no-profile"])):
            with (output / (label + ".log")).open("wb") as log:
                command([str(binary), *cli], cwd=stage, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=180)
        version_text = (output / "version.log").read_text(encoding="utf-8")
        assert " v" + meta["version"] in version_text and " vv" not in version_text, version_text
        assert meta["commit"] in version_text and meta["build_date"] in version_text
        for name in ("analysis.json", "analysis.sarif"):
            json.loads((stage / "analysis_output" / name).read_text(encoding="utf-8"))
        analysis = json.loads((stage / "analysis_output/analysis.json").read_text(encoding="utf-8"))
        assert analysis["report_metadata"]["analyzer_version"] == meta["version"]
        assert analysis["report_metadata"]["commit"] == meta["commit"]
        assert isinstance(analysis["findings"], list) and analysis["findings"], "Demo lost its typed findings"
        assert "coverage" in analysis and "data_flow_stats" in analysis, "Report lost completeness metadata"
        assert analysis["run"]["core_settings"] and analysis["run"]["status"] in ("complete", "incomplete")
        sarif = json.loads((stage / "analysis_output/analysis.sarif").read_text(encoding="utf-8"))
        assert sarif["runs"][0]["tool"]["driver"]["version"] == meta["version"]
        assert (stage / "analysis_output/REPORT.html").stat().st_size > 0
        with socket.socket() as sock: sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base = "http://127.0.0.1:" + str(port)
        with (output / "api.log").open("wb") as log:
            proc = subprocess.Popen([str(binary), "--api", "--api-port", str(port), "-no-profile"], cwd=stage, env=env, stdout=log, stderr=subprocess.STDOUT, creationflags=NO_WINDOW)
            try:
                deadline = time.monotonic() + 30
                while True:
                    try:
                        with opener.open(base + "/api/v1/status", timeout=2) as response: info = json.load(response)
                        break
                    except OSError:
                        if proc.poll() is not None or time.monotonic() > deadline: raise RuntimeError("API did not start; see api.log")
                        time.sleep(.2)
                for key in ("version", "commit", "build_date"): assert info[key] == meta[key], (key, info[key], meta[key])
                for method, path in (("GET", "/api/v1/status"), ("GET", "/api/v1/mitm/packets"), ("POST", "/api/v1/rules/web")):
                    req = urllib.request.Request(base + path, method=method, headers={"Host":"audit.invalid:" + str(port), "Sec-Fetch-Site":"same-origin"})
                    try: opener.open(req, timeout=5)
                    except urllib.error.HTTPError as error: assert error.code == 403
                    else: raise AssertionError("Foreign Host was accepted")
                with opener.open(base + "/api/docs", timeout=5) as response: html = response.read().decode()
                assets = AssetLinks(); assets.feed(html); assert assets.paths
                for path in assets.paths:
                    assert path.startswith("/api/docs/assets/") and not path.startswith("//"), path
                    with opener.open(base + path, timeout=5) as response: assert response.read()
                with opener.open(base + "/api/v1/swagger.json", timeout=5) as response: spec = json.load(response)
                assert spec["info"]["version"] == meta["version"] and spec["servers"][0]["url"] == "/"
            finally:
                proc.terminate()
                try: proc.wait(timeout=10)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=10)
        meta["verified"] = ["version", "help", "demo", "html", "json", "sarif", "api", "host-guard", "offline-doc-assets", "package-doc-links"]
        (output / "verification.json").write_text(json.dumps(meta, indent=2) + "\n")
        print(json.dumps(meta, indent=2))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["build", "verify"])
    parser.add_argument("--output", default=str(ROOT / "dist/core"))
    parser.add_argument("--goos"); parser.add_argument("--goarch")
    parser.add_argument("--tag"); parser.add_argument("--archive")
    args = parser.parse_args()
    (build if args.action == "build" else verify)(args)

if __name__ == "__main__": main()
