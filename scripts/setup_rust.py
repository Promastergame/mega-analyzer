#!/usr/bin/env python3
"""Install the same Rust toolchain for native CI and Elixir NIF builds."""
import os
from pathlib import Path
import subprocess
import tomllib

root = Path(__file__).resolve().parents[1]
toolchain = tomllib.loads((root / "rust/rust-toolchain.toml").read_text())["toolchain"]
version = toolchain["channel"]
subprocess.run(["rustup", "toolchain", "install", version, "--profile", "minimal", "--component", ",".join(toolchain["components"])], check=True)
if os.environ.get("GITHUB_ENV"):
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as handle:
        handle.write("RUSTUP_TOOLCHAIN=" + version + "\n")
