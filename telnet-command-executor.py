#!/usr/bin/env python3
import socket
import sys
import time
import argparse
import os

def parse_args():
    parser = argparse.ArgumentParser(
        prog="telnet-command-executor.py",
        description="Connect to a list of hosts on given ports, send 'help', and print the response.",
        epilog="Example: python telnet-command-executor.py -i targets.txt"
    )
    parser.add_argument(
        "-i", "--input",
        dest="targets",
        help="Path to a file containing 'IP PORT' on each line, or a comma-separated string (e.g. '10.0.0.1 80, 10.0.0.2')."
    )
    parser.add_argument(
        "-p", "--default-port",
        dest="default_port",
        type=int,
        default=23,
        help="Default port to use if only an IP is provided (default: 23)",
    )
    parser.add_argument(
        "-c", "--command",
        dest="command",
        default="help",
        help="Command to send after connecting (default: help)",
    )
    parser.add_argument(
        "-t", "--timeout",
        dest="timeout",
        type=float,
        default=3.0,
        help="Connection timeout in seconds (default: 3.0)",
    )
    return parser.parse_args()


def resolve_targets(cli_value, default_port):
    """
    Parse targets from a file or string.
    Expected format per entry: 'IP PORT' or 'IP'.
    """
    if cli_value:
        raw = cli_value.strip()
    else:
        raw = input("Enter the path to your target file (or comma-separated targets): ").strip()

    if not raw:
        print("Error: input cannot be empty.")
        sys.exit(1)

    targets = []

    # Check if it's a file
    if os.path.isfile(raw):
        with open(raw, 'r') as f:
            lines = f.readlines()
    else:
        # Treat as comma-separated string
        lines = raw.split(',')

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Split by whitespace (handles space or tab)
        parts = line.split()
        ip = parts[0]
        port = default_port

        if len(parts) > 1:
            try:
                port = int(parts[1])
            except ValueError:
                print(f"Warning: Invalid port '{parts[1]}' for IP {ip}. Falling back to default port {default_port}.")

        targets.append((ip, port))

    if not targets:
        print("Error: No valid targets found.")
        sys.exit(1)

    return targets


def scan_host(ip_address, port, command, timeout):
    print(f"[*] Command: telnet {ip_address} {port}")
    print(f"Trying {ip_address}...")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip_address, port))

            print(f"Connected to {ip_address}.")
            print("Escape character is '^]'.")

            try:
                s.settimeout(1.0)
                banner = s.recv(4096).decode('utf-8', errors='ignore')
                if banner:
                    print(banner, end='')
            except socket.timeout:
                pass

            print(command)
            s.sendall(command.encode() + b"\r\n")

            time.sleep(1)

            try:
                s.settimeout(timeout)
                response = s.recv(4096).decode('utf-8', errors='ignore')
                if response:
                    print(response, end='')
            except socket.timeout:
                pass

            print("exit")
            s.sendall(b"exit\r\n")
            print("Connection closed by foreign host.")

    except ConnectionRefusedError:
        print("telnet: Unable to connect to remote host: Connection refused")
    except socket.timeout:
        print("telnet: Unable to connect to remote host: Connection timed out")
    except Exception as e:
        print(f"telnet: Unable to connect to remote host: {e}")

    print("-" * 50)


def main():
    args = parse_args()

    # Resolve the targets into a list of (ip, port) tuples
    target_list = resolve_targets(args.targets, args.default_port)

    print("-" * 50)
    for ip_address, port in target_list:
        scan_host(ip_address, port, args.command, args.timeout)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
