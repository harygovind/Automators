# Telnet Command Executor

![Python](https://img.shields.io/badge/python-3.x-blue)
A small Python utility that connects to one or more hosts over TCP, mimics native `telnet` output, sends a command (default: `help`), and prints the response. Useful for quickly fingerprinting/interacting with plaintext services across a list of hosts and ports during recon.

---

## Table of Contents

- [Requirements](#requirements)
- [Usage](#usage)
  - [Options](#options)
  - [Examples](#examples)
- [Sample Output](#sample-output)
- [Notes](#notes)

## Requirements

- Python 3.x (standard library only — no external dependencies)

## Usage

```bash
python telnet-command-executor.py [-h] [-i IPS] [-p PORTS] [-c COMMAND] [-t TIMEOUT]
```

### Options

| Flag | Long form | Description | Default |
|------|-----------|--------------|---------|
| `-h` | `--help` | Show help message and exit | — |
| `-i` | `--ip` | Comma-separated list of IPs/hostnames | prompts if omitted |
| `-p` | `--ports` | Comma-separated list of ports | prompts if omitted |
| `-c` | `--command` | Command to send after connecting | `help` |
| `-t` | `--timeout` | Connection/response timeout (seconds) | `3.0` |

### Examples

Scan a single host on one port:
```bash
python telnet-command-executor.py -i 10.0.139.139 -p 22
```

Scan multiple hosts on multiple ports:
```bash
python telnet-command-executor.py -i 10.0.139.139,10.0.175.32,10.0.14.13 -p 22,23,80
```

Send a custom command instead of `help`:
```bash
python telnet-command-executor.py -i 10.0.0.5 -p 23 -c "version"
```

Run interactively (no flags — it will prompt you):
```bash
python telnet-command-executor.py
```

## Sample Output

```console
[*] Command: telnet 10.0.139.139 22
Trying 10.0.139.139...
Connected to 10.0.139.139.
Escape character is '^]'.
help
<server response here>
exit
Connection closed by foreign host.
--------------------------------------------------
```

## Notes

> **⚠️ Disclaimer:** Only use this tool against hosts and networks you are authorized to test.

- The tool has a 3-second default connect timeout and a 1-second banner-grab wait; adjust with `-t` for slower/unstable links.
- If a host is unreachable, refuses the connection, or times out, the tool prints a `telnet:`-style error and moves on to the next target/port.

---
