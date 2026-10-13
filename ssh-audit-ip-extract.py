#!/usr/bin/env python3
"""Sort hosts from the ssh-audit batch output (out.txt) into Weak / Pass."""

import re
import sys

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
HEADER = re.compile(r"\[(\d+)/(\d+)\]\s+(\S+):(\d+)")
SUMMARY = re.compile(r"SUMMARY \(\d+/\d+ hosts scanned\)")
# One algorithm entry: from its (kex)/(key)/(enc)/(mac) tag up to the next tag
ENTRY = re.compile(
    r"\((kex|key|enc|mac)\)(.*?)(?=\((?:kex|key|enc|mac|gen|fin|rec|nfo)\)|\Z)",
    re.S,
)


def is_weak(block):
    """Weak if any kex/key/enc/mac algorithm is marked [fail] (the red ones)."""
    return any("[fail]" in m.group(2) for m in ENTRY.finditer(block))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "out.txt"
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        sys.exit(f"[!] Cannot read {path}: {e}")

    text = ANSI.sub("", text)

    # Drop the batch script's own summary table so it isn't read as scan output
    s = SUMMARY.search(text)
    if s:
        text = text[:s.start()]

    headers = list(HEADER.finditer(text))
    if not headers:
        sys.exit("[!] No '[n/total] ip:port' headers found in the file.")

    status = {}  # ip -> True if weak; insertion order is kept
    for i, h in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        ip = h.group(3)
        weak = is_weak(text[h.end():end])
        status[ip] = status.get(ip, False) or weak

    weak_ips = [ip for ip, w in status.items() if w]
    pass_ips = [ip for ip, w in status.items() if not w]

    print("Weak cipher ips")
    print("\n".join(weak_ips))
    print("\nPass ips")
    print("\n".join(pass_ips))


if __name__ == "__main__":
    main()