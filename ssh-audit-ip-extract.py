#!/usr/bin/env python3
"""Sort hosts from ssh-audit -T -l fail output into Weak / Pass / Non-reachable."""

import re
import sys

TARGET = re.compile(r"^\(gen\)\s+target:\s+(\S+)", re.M)
EXCEPTION_NO_TARGET = re.compile(r"^\[exception\]\s+cannot connect to (\S+)", re.M)
EXCEPTION_IN_BLOCK = re.compile(r"\[exception\]")

ENTRY = re.compile(
    r"\((kex|key|enc|mac)\)(.*?)(?=\((?:kex|key|enc|mac|gen|fin|rec|nfo)\)|\Z)",
    re.S,
)


def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def is_weak(block):
    return any("[fail]" in m.group(2) for m in ENTRY.finditer(block))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "out.txt"
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        sys.exit(f"[!] Cannot read {path}: {e}")

    # Strip ANSI color codes before parsing
    text = strip_ansi(text)

    blocks = re.split(r"-{10,}", text)

    weak_ips, pass_ips, unreachable_ips = [], [], []

    for block in blocks:
        t = TARGET.search(block)
        if t:
            ip = t.group(1)
            if EXCEPTION_IN_BLOCK.search(block):
                if ip not in unreachable_ips:
                    unreachable_ips.append(ip)
            elif is_weak(block):
                if ip not in weak_ips:
                    weak_ips.append(ip)
            else:
                if ip not in pass_ips:
                    pass_ips.append(ip)
            continue

        e = EXCEPTION_NO_TARGET.search(block)
        if e:
            ip = e.group(1)
            if ip not in unreachable_ips:
                unreachable_ips.append(ip)

    print("Weak cipher IPs")
    print("\n".join(weak_ips) if weak_ips else "(none)")

    print("\nPass IPs")
    print("\n".join(pass_ips) if pass_ips else "(none)")

    print("\nNon-reachable IPs")
    print("\n".join(unreachable_ips) if unreachable_ips else "(none)")

    total = len(weak_ips) + len(pass_ips) + len(unreachable_ips)
    print(
        f"\n[weak={len(weak_ips)} pass={len(pass_ips)} "
        f"unreachable={len(unreachable_ips)} total={total}]",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
