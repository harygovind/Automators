#!/usr/bin/env python3
"""Run ssh-audit against every host in a list, one after another."""

import argparse
import subprocess
import sys
from pathlib import Path

SSH_AUDIT = Path(__file__).resolve().parent / "ssh-audit.py"

EXIT_MEANING = {
    0: "GOOD",
    1: "WARNING",
    2: "FAILURE",
    3: "CONNECTION_ERROR",
    4: "UNKNOWN_ERROR",
}


def read_hosts(path):
    hosts = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    return hosts


def main():
    parser = argparse.ArgumentParser(
        description="Run ssh-audit on each host in a list (sequential).",
        epilog="Any other flags are passed straight to ssh-audit, e.g. --timeout 5",
        allow_abbrev=False,
    )
    parser.add_argument("-l", "--list", required=True,
                        help="file with one IP/hostname per line")
    parser.add_argument("-p", "--port", default="22",
                        help="SSH port for every host (default: 22)")
    args, extra = parser.parse_known_args()

    if not SSH_AUDIT.exists():
        sys.exit(f"[!] ssh-audit.py not found next to this script: {SSH_AUDIT}")

    try:
        hosts = read_hosts(args.list)
    except OSError as e:
        sys.exit(f"[!] Cannot read list: {e}")

    if not hosts:
        sys.exit("[!] No hosts found in the list.")

    results = []
    total = len(hosts)

    try:
        for i, host in enumerate(hosts, 1):
            print("\n" + "=" * 70)
            print(f"[{i}/{total}] {host}:{args.port}")
            print("=" * 70, flush=True)

            cmd = [sys.executable, str(SSH_AUDIT), "-p", args.port, *extra, host]

            # stdout/stderr are inherited (not captured) so ssh-audit
            # keeps its colored output in the terminal.
            rc = subprocess.run(cmd).returncode
            results.append((host, rc))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user, showing summary so far.")

    print("\n" + "=" * 70)
    print(f"SUMMARY ({len(results)}/{total} hosts scanned)")
    print("=" * 70)
    for host, rc in results:
        print(f"{host:<40} {EXIT_MEANING.get(rc, f'EXIT {rc}')}")


if __name__ == "__main__":
    main()