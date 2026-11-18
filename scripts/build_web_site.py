"""Export the --web interface with the Go CLI running inside a Web Worker."""
import argparse
import hashlib
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "pkg/cmd/analyzer/web/assets"

def source_fingerprint(env: dict) -> str:
    # Hash the actual js/wasm dependency inputs, including embedded assets.
    listing = subprocess.check_output(["go", "list", "-deps", "-json", "./pkg/cmd/analyzer"], cwd=ROOT, env=env, text=True)
    decoder, cursor, inputs = json.JSONDecoder(), 0, set()
    while cursor < len(listing):
        while cursor < len(listing) and listing[cursor].isspace(): cursor += 1
        if cursor == len(listing): break
        package, cursor = decoder.raw_decode(listing, cursor)
        directory = Path(package["Dir"])
        if not directory.is_relative_to(ROOT): continue
        for kind in ("GoFiles", "CgoFiles", "EmbedFiles", "SFiles", "HFiles"):
            inputs.update(directory / name for name in package.get(kind, []))
    digest = hashlib.sha256()
    for source in sorted(inputs):
        digest.update(source.relative_to(ROOT).as_posix().encode() + b"\0")
        digest.update(source.read_bytes())
    return digest.hexdigest()

def build(output: Path, prebuilt: Path | None = None) -> None:
    output.mkdir(parents=True, exist_ok=True)
    static = output / "static"
    static.mkdir(exist_ok=True)
    wasm = static / "analyzer.wasm"
    env = dict(os.environ, GOOS="js", GOARCH="wasm", CGO_ENABLED="0")
    source_hash = source_fingerprint(env)
    git_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    version = (ROOT / "VERSION").read_text().strip()
    build_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    link_flags = f"-s -w -X main.Version={version} -X main.BuildDate={build_date} -X main.CommitHash={git_commit}"
    if prebuilt:
        if not wasm.exists() or hashlib.sha256(prebuilt.read_bytes()).digest() != hashlib.sha256(wasm.read_bytes()).digest():
            shutil.copyfile(prebuilt, wasm)
    else:
        subprocess.run(["go", "build", "-trimpath", "-ldflags", link_flags, "-o", str(wasm), "./pkg/cmd/analyzer"], cwd=ROOT, env=env, check=True)
    rust_wasm = static / "gnn.wasm"
    weights = static / "gnn_weights.json"
    if prebuilt:
        shutil.copyfile(prebuilt.parent / "gnn.wasm", rust_wasm)
        shutil.copyfile(prebuilt.parent / "gnn_weights.json", weights)
    else:
        rust_env = dict(os.environ, RUSTFLAGS="-C target-feature=+simd128 -C panic=abort -C link-arg=--strip-all")
        subprocess.run(["cargo", "build", "--manifest-path", "rust/Cargo.toml", "-p", "omnisec-ml-gnn", "--lib", "--target", "wasm32-unknown-unknown", "--release"], cwd=ROOT, env=rust_env, check=True)
        shutil.copyfile(ROOT / "rust/target/wasm32-unknown-unknown/release/omnisec_ml_gnn.wasm", rust_wasm)
        shutil.copyfile(ROOT / "rust/gnn_weights.json", weights)
    (static / "gnn.wasm.gz").write_bytes(gzip.compress(rust_wasm.read_bytes(), compresslevel=9, mtime=0))
    goroot = Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())
    compressed = gzip.compress(wasm.read_bytes(), compresslevel=9, mtime=0)
    (static / "analyzer.wasm.gz").write_bytes(compressed)
    shutil.copyfile(goroot / "lib/wasm/wasm_exec.js", static / "wasm_exec.js")
    shutil.copyfile(goroot / "LICENSE", static / "Go-LICENSE.txt")
    shutil.copyfile(ROOT / "LICENSE", output / "LICENSE")
    shutil.copyfile(ROOT / "third-party/iced-x86/LICENSE.txt", static / "iced-x86-LICENSE.txt")
    shutil.copyfile(ROOT / "pkg/internal/apkloader/hermes_spec/LICENSE", static / "Hermes-LICENSE.txt")
    for name in ("app.css", "app.js", "workspace.css", "workspace.js", "workspace-preview.js",
                 "favicon.ico", "favicon-32.png", "apple-touch-icon.png"):
        shutil.copyfile(ASSETS / name, static / name)
    # Browsers request /favicon.ico at the site root; the SPA _redirects rule
    # would otherwise answer with index.html and no icon would ever appear.
    shutil.copyfile(ASSETS / "favicon.ico", output / "favicon.ico")
    page = (ASSETS / "index.html").read_text(encoding="utf-8")
    page = page.replace('<body>', '<body>\n' + (ROOT / "web/wasm/notice.html").read_text(encoding="utf-8"), 1)
    for source, target in (("bridge.js", "wasm-bridge.js"), ("worker.js", "wasm-worker.js"), ("pool.js", "wasm-pool.js"), ("notice.js", "wasm-notice.js"), ("memfs.js", "memfs.js"), ("gnn.js", "gnn.js")):
        shutil.copyfile(ROOT / "web/wasm" / source, static / target)
    page = page.replace('<script src="/static/app.js" defer>', '<script src="/static/wasm-bridge.js" defer></script>\n<script src="/static/wasm-notice.js" defer></script>\n<script src="/static/app.js" defer>', 1)
    (output / "index.html").write_text(page, encoding="utf-8")
    (output / "_redirects").write_text("/api/* /not-found.txt 404!\n/* /index.html 200\n", encoding="utf-8")
    (output / "not-found.txt").write_text("Analysis runs locally in your browser. There is no server API.\n", encoding="utf-8")
    (output / "_headers").write_text("""/*
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  X-Frame-Options: DENY
  Content-Security-Policy: default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; connect-src 'self'; worker-src 'self'; frame-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'
  Permissions-Policy: camera=(), microphone=(), geolocation=()
/static/analyzer.wasm
  Content-Type: application/wasm
  Cache-Control: public, max-age=0, must-revalidate
/static/analyzer.wasm.gz
  Content-Type: application/wasm
  Content-Encoding: gzip
  Cache-Control: public, max-age=0, must-revalidate
/static/gnn.wasm
  Content-Type: application/wasm
  Cache-Control: public, max-age=0, must-revalidate
/static/gnn.wasm.gz
  Content-Type: application/wasm
  Content-Encoding: gzip
  Cache-Control: public, max-age=0, must-revalidate
/static/gnn_weights.json
  Cache-Control: public, max-age=0, must-revalidate
""", encoding="utf-8")
    (output / "robots.txt").write_text("User-agent: *\nDisallow: /api/\n", encoding="utf-8")
    manifest = {"go": subprocess.check_output(["go", "version"], text=True).strip(), "wasm_sha256": hashlib.sha256(wasm.read_bytes()).hexdigest(), "wasm_bytes": wasm.stat().st_size,
                "source_commit": git_commit, "source_modified": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()),
                "source_sha256": source_hash if not prebuilt else None, "built_at": datetime.now(timezone.utc).isoformat(),
                "target": "js/wasm", "cgo": False, "optimizations": "Go default optimization and inlining; -trimpath; -ldflags=-s -w",
                "prebuilt": bool(prebuilt)}
    if prebuilt:
        provenance = prebuilt.parent.parent / "build-info.json"
        if provenance.is_file():
            previous = json.loads(provenance.read_text(encoding="utf-8"))
            if previous.get("wasm_sha256") == manifest["wasm_sha256"]:
                if previous.get("go") != manifest["go"]:
                    raise ValueError("Prebuilt WASM and installed Go runtime use different toolchains")
                manifest = previous
    manifest["wasm_gzip_bytes"] = len(compressed)
    for name, asset in (("gnn_wasm_sha256", rust_wasm), ("gnn_weights_sha256", weights)):
        actual = hashlib.sha256(asset.read_bytes()).hexdigest()
        if prebuilt and manifest.get(name) not in (None, actual):
            raise ValueError(f"Prebuilt {asset.name} does not match its build provenance")
    manifest["gnn_wasm_sha256"] = hashlib.sha256(rust_wasm.read_bytes()).hexdigest()
    manifest["gnn_weights_sha256"] = hashlib.sha256(weights.read_bytes()).hexdigest()
    manifest.setdefault("rust", subprocess.check_output(["rustc", "--version"], text=True).strip())
    manifest.setdefault("gnn_optimizations", "Rust release, LTO, simd128, panic=abort, strip-all")
    asset_digest = hashlib.sha256()
    for asset in sorted([output / "index.html", *static.glob("*.js"), *static.glob("*.css")]):
        asset_digest.update(asset.relative_to(output).as_posix().encode() + b"\0" + asset.read_bytes().replace(b"\r\n", b"\n"))
    manifest["browser_assets_sha256"] = asset_digest.hexdigest()
    manifest["browser_assets_hash_format"] = "UTF-8 text with LF line endings"
    (output / "build-info.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (output / "netlify.toml").write_text('[build]\n  publish = "."\n', encoding="utf-8")
    (output / "README.md").write_text("""# Mega Analyzer in the browser

Static deployment of the existing `analyzer --web` interface with the Go CLI
compiled to WebAssembly. Netlify serves this repository with `publish = "."`
and no build command. Connect the `main` branch for automatic deployments.

Analysis runs in 1–4 browser workers (default 2) for full/Minecraft scans.
The coordinator owns global analysis; helpers scan individual files. Input
files are never uploaded. Results
remain in tab memory: download them before closing or reloading the page.
Maximum input size: 512 MiB. Timeout accepts 0–3600 seconds (default 300);
0 disables it. A dismissible startup dialog can remember “Don't show again”.
Worker count and timeout are remembered in this browser. Device/VM
execution, native subprocesses and network proxy tools require the desktop
application. Native binary inspection uses the Go engine.
The trained GNN runs in a separate Rust WASM module within the coordinator,
using the same weight JSON and classification gates as the desktop analyzer.
Building from source requires Rust with the wasm32-unknown-unknown target.

To update this repository, run `python scripts/build_web_site.py --output
<this-checkout>` in the Mega Analyzer source checkout with the required Go
toolchain installed. Commit the regenerated static files. `build-info.json`
records the compiler version and WASM SHA-256. The Go runtime JavaScript must
always match the compiler that produced `static/analyzer.wasm`.
""", encoding="utf-8")
    print(f"Browser WASM site built in {output} ({wasm.stat().st_size:,} bytes)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wasm", type=Path, help="Already-built WASM from the installed Go toolchain")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/web")
    args = parser.parse_args()
    build(args.output.resolve(), args.wasm)
