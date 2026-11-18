#!/usr/bin/env python3
"""Ping opencode-hosted teacher (e.g. Jev 1.13 Free) without hardcoding any key.

Reads OPENCODE_API_KEY from env. Tries a few candidate OpenAI-compatible base URLs
and model ids until /models or a tiny chat completion succeeds. Stdlib only.

  OPENCODE_API_KEY=... python3 ping_opencode.py
"""
import json, os, sys, urllib.request, urllib.error

KEY = os.environ.get("OPENCODE_API_KEY") or os.environ.get("TEACHER_API_KEY") or ""
BASES = [
    "https://opencode.ai/inference/systemone/v1",
    "https://opencode.ai/inference/v1",
    "https://opencode.ai/v1",
]
MODELS = ["systemone", "jev-1.13-free", "jev-1.13"]


def try_get(base, path):
    req = urllib.request.Request(
        base.rstrip("/") + path,
        headers={"Authorization": "Bearer " + KEY},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status, json.load(r)


def try_chat(base, model):
    body = json.dumps({
        "model": model,
        "max_tokens": 8,
        "messages": [{"role": "user", "content": "say ok"}],
    }).encode()
    req = urllib.request.Request(
        base.rstrip("/") + "/chat/completions",
        body,
        {"Content-Type": "application/json", "Authorization": "Bearer " + KEY},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    text = data["choices"][0]["message"]["content"]
    return text


def main():
    if not KEY:
        print("NO KEY: set OPENCODE_API_KEY in your environment first.")
        print("In PowerShell:  [Environment]::SetEnvironmentVariable('OPENCODE_API_KEY','<NEW_KEY>','User')")
        sys.exit(1)
    print(f"key loaded (len={len(KEY)}), probing...")
    for base in BASES:
        try:
            status, data = try_get(base, "/models")
            ids = [m.get("id") for m in data.get("data", [])]
            print(f"OK GET {base}/models -> {status}, models={ids[:20]}")
            for m in ids or MODELS:
                try:
                    text = try_chat(base, m)
                    print(f"OK CHAT {base} model={m!r} reply={text!r}")
                    print("USE THIS:")
                    print(f"  TEACHER_BASE_URL={base} TEACHER_API_KEY=... python scripts/teacher/label.py ... --models {m}")
                    return
                except urllib.error.HTTPError as e:
                    print(f"   chat {m}: HTTP {e.code} {e.read().decode()[:120]}")
                except Exception as e:
                    print(f"   chat {m}: {e}")
        except urllib.error.HTTPError as e:
            print(f"HTTP {e.code} at {base}/models: {e.read().decode()[:120]}")
        except Exception as e:
            print(f"fail {base}/models: {e}")
    print("Nothing worked. Check the base URL in opencode settings (provider options.baseURL).")
    sys.exit(2)


if __name__ == "__main__":
    main()
