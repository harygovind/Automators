#!/usr/bin/env python3
"""Find hosts that leaked a service banner/version in telnet_scan.py output."""

import re
import sys

HEADER = re.compile(r"\[(\d+)/(\d+)\]\s+(\S+):(\d+)")

# telnet's own fixed lines, ignored when deciding if a banner was disclosed
NOISE = re.compile(
    r"^(Trying .+\.\.\.|Connected to .+\.|Escape character is .+|"
    r"telnet: .+|\(no output\))$"
)


def has_banner(block):
    for line in block.splitlines():
        line = line.strip()
        if line and not NOISE.match(line):
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
        if has_banner(text[h.end():end]):
            if ip not in disclosed:
                disclosed.append(ip)

    print("Version disclosure hosts")
    print("\n".join(disclosed))


if __name__ == "__main__":
    main()