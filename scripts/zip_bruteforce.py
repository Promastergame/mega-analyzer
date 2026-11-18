"""Brute-force a ZipCrypto-protected member of a zip archive.

Ordered attack, cheap candidates first:
  1. hand-picked simple/keyboard passwords
  2. digits, lengths 1-5
  3. lowercase a-z, lengths 1-4
  4. lowercase+digits, lengths 1-4
  5. lowercase a-z, length 5 (large, run last)
Prints the password and extracts the member on success.
"""
import itertools
import string
import sys
import time
import zipfile

ZIP = "xeno.zip"
MEMBER = "xenomorph.apk"
OUT = "outputs/xeno-sample/xenomorph.apk"


def candidates():
    simple = [
        "qwe", "asd", "zxc", "qaz", "wsx", "edc", "abc", "aaa", "zzz", "qqq",
        "www", "111", "000", "123", "321", "999", "555", "777", "222", "666",
        "888", "101", "100", "007", "69", "13", "77777", "123456", "qwert",
        "qweasd", "zxcvbn", "q1w2e3", "1q2w3e", "qwerty", "zxc123", "asd123",
        "qwe123", "123qwe", "1a2b3c", "apka", "apk", "zip", "xeno", "virus",
        "hack", "haker", "crack", "pass", "parol", "kot", "kit", "dom", "mir",
    ]
    for p in simple:
        yield p.encode()
    for n in range(1, 6):
        for t in itertools.product("0123456789", repeat=n):
            yield "".join(t).encode()
    for n in range(1, 5):
        for t in itertools.product(string.ascii_lowercase, repeat=n):
            yield "".join(t).encode()
    alnum = string.ascii_lowercase + "0123456789"
    for n in range(1, 5):
        for t in itertools.product(alnum, repeat=n):
            yield "".join(t).encode()
    for t in itertools.product(string.ascii_lowercase, repeat=5):
        yield "".join(t).encode()


def main():
    z = zipfile.ZipFile(ZIP)
    start = time.time()
    tried = 0
    for pwd in candidates():
        tried += 1
        if tried % 500000 == 0:
            rate = tried / max(time.time() - start, 1e-6)
            print(f"  ...{tried} tried, {rate:,.0f}/s", flush=True)
        try:
            data = z.read(MEMBER, pwd=pwd)
        except RuntimeError:
            continue
        print(f"PASSWORD FOUND: {pwd.decode()!r} after {tried} tries, "
              f"{time.time() - start:.1f}s", flush=True)
        with open(OUT, "wb") as f:
            f.write(data)
        print(f"extracted {len(data)} bytes -> {OUT}", flush=True)
        return 0
    print(f"NOT FOUND after {tried} tries, {time.time() - start:.1f}s", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
