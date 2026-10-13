#!/usr/bin/env python3
"""Run 'telnet <ip> <port>' for every host in a list, 2 seconds each."""

import argparse
import os
import select
import shutil
import subprocess
import sys
import time


def read_hosts(path):
    hosts = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    return hosts


def run_telnet(host, port, timeout):
    proc = subprocess.Popen(
        ["telnet", host, port],
        stdin=subprocess.PIPE,      # held open so telnet doesn't quit on EOF
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    buf = b""
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([proc.stdout], [], [], remaining)
            if not ready:
                break
            data = os.read(proc.stdout.fileno(), 4096)
            if not data:            # telnet exited on its own (e.g. refused)
                break
            buf += data
    finally:
        proc.kill()
        proc.wait()
        proc.stdin.close()
        proc.stdout.close()
    return buf.decode(errors="replace").replace("\r", "").strip()


def main():
    parser = argparse.ArgumentParser(
        description="Run telnet against each host in a list, one after another."
    )
    parser.add_argument("-l", "--list", required=True,
                        help="file with one IP/hostname per line")
    parser.add_argument("port", help="port to connect to")
    parser.add_argument("-t", "--timeout", type=float, default=2,
                        help="seconds to wait per host (default: 2)")
    args = parser.parse_args()

    if not args.port.isdigit() or not 1 <= int(args.port) <= 65535:
        sys.exit(f"[!] Invalid port: {args.port}")
    if shutil.which("telnet") is None:
        sys.exit("[!] 'telnet' command not found. Install it first "
                 "(e.g. sudo apt install telnet).")

    try:
        hosts = read_hosts(args.list)
    except OSError as e:
        sys.exit(f"[!] Cannot read list: {e}")
    if not hosts:
        sys.exit("[!] No hosts found in the list.")

    total = len(hosts)
    try:
        for i, host in enumerate(hosts, 1):
            print("\n" + "=" * 70)
            print(f"[{i}/{total}] {host}:{args.port}")
            print("=" * 70, flush=True)
            output = run_telnet(host, args.port, args.timeout)
            print(output if output else "(no output)")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")


if __name__ == "__main__":
    main()