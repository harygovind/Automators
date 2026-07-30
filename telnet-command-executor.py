#!/usr/bin/env python3
import socket
import sys
import time
import argparse
import os


def parse_args():
    parser = argparse.ArgumentParser(
        prog="telnet-command-executor.py",
        description="Connect to a list of hosts on given ports, send 'help', and print the response (telnet-style output).",
        epilog="Example: python telnet-command-executor.py -i 10.0.0.1,10.0.0.2 -p 22,23",
    )
    parser.add_argument(
        "-i", "--ip",
        dest="ips",
        help="Comma-separated list of IPs/hostnames, OR a path to a file containing "
             "one IP per line (or comma-separated) (e.g. 10.0.0.1,10.0.0.2 or ips.txt)",
    )
    parser.add_argument(
        "-p", "--ports",
        dest="ports",
        help="Comma-separated list of ports to scan (e.g. 80,443,22)",
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


def get_list(prompt_text, cli_value):
    """Use CLI value if provided, otherwise prompt interactively."""
    if cli_value:
        raw = cli_value
    else:
        raw = input(prompt_text).strip()
    if not raw:
        print("Error: input cannot be empty.")
        sys.exit(1)
    return [item.strip() for item in raw.split(',') if item.strip()]


def resolve_ips(cli_value):
    """
    Resolve the -i/--ip value (or interactive prompt) into a list of IPs.
    Accepts either:
      - a comma-separated string of IPs/hostnames, or
      - a path to a file containing IPs (one per line, and/or comma-separated)
    """
    if cli_value:
        raw = cli_value.strip()
    else:
        raw = input("Enter the IP address(es) to scan, or a path to a file: ").strip()

    if not raw:
        print("Error: input cannot be empty.")
        sys.exit(1)

    # If it's a path to an existing file, read IPs from it
    if os.path.isfile(raw):
        ips = []
        with open(raw, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # support comma-separated entries within a line too
                ips.extend(part.strip() for part in line.split(',') if part.strip())
        if not ips:
            print(f"Error: no IPs found in file '{raw}'.")
            sys.exit(1)
        return ips

    # Otherwise treat it as a comma-separated list
    return [item.strip() for item in raw.split(',') if item.strip()]


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

    ip_list = resolve_ips(args.ips)

    ports_raw = get_list("Enter the ports required (comma-separated, e.g., 80,443,22): ", args.ports)
    try:
        port_list = [int(p) for p in ports_raw]
    except ValueError:
        print("Error: Invalid port format. Please enter numbers separated by commas.")
        sys.exit(1)

    print("-" * 50)

    for ip_address in ip_list:
        for port in port_list:
            scan_host(ip_address, port, args.command, args.timeout)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
