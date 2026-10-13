#!/usr/bin/env python3
"""Find hosts whose SSH banner discloses detailed version info (patch/OS), not just the bare version."""

import re
import sys

HEADER = re.compile(r"\[(\d+)/(\d+)\]\s+(\S+):(\d+)")

# Bare version only, e.g. "SSH-2.0-OpenSSH_9.9" -- nothing else on the line
BARE_SSH_BANNER = re.compile(r"^SSH-2\.0-OpenSSH_\d+\.\d+$")

# Any SSH banner line at all
SSH_BANNER = re.compile(r"^SSH-2\.0-OpenSSH_\S+")


def has_detailed_disclosure(block):
    for line in block.splitlines():
        line = line.strip()
        if SSH_BANNER.match(line) and not BARE_SSH_BANNER.match(line):
            return True
    return False


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "out.txt"
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        sys.exit(f"[!] Cannot read {path}: {e}")

    headers = list(HEADER.finditer(text))
    if not headers:
        sys.exit("[!] No '[n/total] ip:port' headers found in the file.")

    disclosed = []
    for i, h in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        ip = h.group(3)
        if has_detailed_disclosure(text[h.end():end]):
            if ip not in disclosed:
                disclosed.append(ip)

    print("Version disclosure hosts")
    print("\n".join(disclosed))


if __name__ == "__main__":
    main()
    
