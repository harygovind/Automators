#!/usr/bin/env python3
"""Sort hosts from ssh-audit -T -l fail output into Weak / Pass / Non-reachable."""

import re
import sys
import argparse

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


def parse_args():
    parser = argparse.ArgumentParser(
        prog="ssh-audit-ip-extract",
        description=(
            "Parse ssh-audit output and categorize hosts into:\n"
            "  Weak    - hosts with [fail] algorithms (broken ciphers, SHA-1, NIST curves, etc.)\n"
            "  Pass    - hosts with no [fail] findings\n"
            "  Unreachable - hosts that could not be reached or dropped the connection\n\n"
            "Supports output files containing ANSI color codes (strips them automatically).\n"
            "Tip: use 'ssh-audit --no-colors' to avoid color codes in output files."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s out.txt\n"
            "  %(prog)s out.txt --weak-only\n"
            "  %(prog)s out.txt --output results.txt\n"
            "  ssh-audit --no-colors -T targets.txt | tee out.txt | %(prog)s /dev/stdin\n"
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="out.txt",
        metavar="FILE",
        help="ssh-audit output file to parse (default: out.txt)",
    )
    parser.add_argument(
        "--weak-only",
        action="store_true",
        help="print only weak IPs, one per line (useful for piping)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="write results to FILE instead of stdout",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        with open(args.input, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        sys.exit(f"[!] Cannot read {args.input}: {e}")

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

    # Build output
    if args.weak_only:
        output = "\n".join(weak_ips)
    else:
        lines = [
            "Weak cipher IPs",
            "\n".join(weak_ips) if weak_ips else "(none)",
            "\nPass IPs",
            "\n".join(pass_ips) if pass_ips else "(none)",
            "\nNon-reachable IPs",
            "\n".join(unreachable_ips) if unreachable_ips else "(none)",
        ]
        output = "\n".join(lines)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output + "\n")
            print(f"[*] Results written to {args.output}")
        except OSError as e:
            sys.exit(f"[!] Cannot write to {args.output}: {e}")
    else:
        print(output)

    total = len(weak_ips) + len(pass_ips) + len(unreachable_ips)
    print(
        f"\n[weak={len(weak_ips)} pass={len(pass_ips)} "
        f"unreachable={len(unreachable_ips)} total={total}]",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
