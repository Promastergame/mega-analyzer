#!/usr/bin/env python3
"""Build a native Docker image and check its CLI, API and health probe."""
import json
from pathlib import Path
import secrets
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def docker(*args):
    return subprocess.run(["docker", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def main():
    name = "mega-analyzer-smoke-" + secrets.token_hex(4)
    token = secrets.token_hex(32)
    subprocess.run(["docker", "build", "--pull", "-t", name, "."], cwd=ROOT, check=True)
    try:
        assert "Mega" in docker("run", "--rm", name, "--version")
        docker("run", "-d", "--name", name, "-p", "127.0.0.1::5000", "-e", "MEGA_ANALYZER_API_BIND=0.0.0.0", "-e", "MEGA_ANALYZER_API_TOKEN=" + token, name)
        address = docker("port", name, "5000/tcp").splitlines()[0]
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request = urllib.request.Request("http://" + address + "/api/v1/status", headers={"Authorization": "Bearer " + token})
        deadline = time.monotonic() + 90
        while True:
            try:
                with opener.open(request, timeout=3) as response:
                    assert json.load(response)["version"]
                if docker("inspect", "--format", "{{.State.Health.Status}}", name) == "healthy":
                    break
            except (OSError, subprocess.CalledProcessError):
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("Container API/health probe did not become ready")
            time.sleep(1)
        print("Docker CLI, authenticated API and health probe passed")
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        subprocess.run(["docker", "image", "rm", name], capture_output=True)


if __name__ == "__main__":
    main()
