# Automators

![Python](https://img.shields.io/badge/python-3.x-blue)

A small collection of Python recon/automation utilities for working through a **list** of hosts, ports, or URLs instead of one target at a time — telnet banner grabbing, SSH exposure triage, and web recon scanning (`nuclei` / `dirsearch` / `curl`) across a scope file.

---

## Table of Contents

- [Telnet Command Executor](#telnet-command-executor)
- [Telnet Automator](#telnet-automator)
- [Telnet Extract IPs — SSH Banner Disclosure](#telnet-extract-ips--ssh-banner-disclosure)
- [SSH Audit IP Extract](#ssh-audit-ip-extract)
- [DNC Automator (Dirsearch / Nuclei / Curl)](#dnc-automator-dirsearch--nuclei--curl)

---

## Telnet Command Executor

`telnet-command-executor.py`

A small Python utility that connects to one or more hosts over TCP, mimics native `telnet` output, sends a command (default: `help`), and prints the response. Useful for quickly fingerprinting/interacting with plaintext services across a list of hosts and ports during recon.

### Requirements

- Python 3.x (standard library only — no external dependencies)

### Usage

```bash
python3 telnet-command-executor.py [-h] [-i IPS] [-p PORTS] [-c COMMAND] [-t TIMEOUT]
```

#### Options

| Flag | Long form | Description | Default |
|------|-----------|--------------|---------|
| `-h` | `--help` | Show help message and exit | — |
| `-i` | `--ip` | Comma-separated list of IPs/hostnames | prompts if omitted |
| `-p` | `--ports` | Comma-separated list of ports | prompts if omitted |
| `-c` | `--command` | Command to send after connecting | `help` |
| `-t` | `--timeout` | Connection/response timeout (seconds) | `3.0` |

#### Examples

Scan a single host on one port:
```bash
python3 telnet-command-executor.py -i 10.0.139.139 -p 22
```

Scan multiple hosts on multiple ports:
```bash
python3 telnet-command-executor.py -i 10.0.139.139,10.0.175.32,10.0.14.13 -p 22,23,80
```

Send a custom command instead of `help`:
```bash
python3 telnet-command-executor.py -i 10.0.0.5 -p 23 -c "version"
```

Run interactively (no flags — it will prompt you):
```bash
python3 telnet-command-executor.py
```

### Sample Output

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

### Notes

- The tool has a 3-second default connect timeout and a 1-second banner-grab wait; adjust with `-t` for slower/unstable links.
- If a host is unreachable, refuses the connection, or times out, the tool prints a `telnet:`-style error and moves on to the next target/port.

---

## Telnet Automator

`telnet-automator.py`

Runs the real system `telnet` binary against a **single port** across every host in a list file, captures whatever the service prints within a timeout window, then kills the connection and moves to the next host. Handy for a quick first pass across a scope — e.g. grabbing SSH banners on port 22 for every host before deeper analysis.

### Requirements

- Python 3.x (standard library only)
- The system `telnet` client installed and on `PATH` (e.g. `sudo apt install telnet`)

### Usage

```bash
python3 telnet-automator.py [-h] -l LIST [-t TIMEOUT] [-s SAVE] port
```

#### Options

| Flag | Long form | Description | Default |
|------|-----------|--------------|---------|
| `-h` | `--help` | Show help message and exit | — |
| (positional) | `port` | Port to connect to (1–65535) | required |
| `-l` | `--list` | File with one IP/hostname per line | required |
| `-t` | `--timeout` | Seconds to wait for output per host | `2` |
| `-s` | `--save` | Also write all output to this file | not saved |

#### Examples

Scan port 23 against every host in a list, 2 seconds per host (default):
```bash
python3 telnet-automator.py -l hosts.txt 23
```

Grab SSH banners (port 22), wait 3 seconds per host, and save the transcript:
```bash
python3 telnet-automator.py -l hosts.txt 22 -t 3 -s results.txt
```

### Sample Output

```console
======================================================================
[2/5] 10.0.0.2:23
======================================================================
<telnet output, or (no output) if nothing was received>
```

On completion with `-s`: `[+] Output saved to results.txt`
On Ctrl+C: `[!] Interrupted by user.`

### Notes

- `hosts.txt` takes one IP/hostname per line; blank lines and `#`-prefixed lines are ignored.
- Each host gets a fixed `-t` seconds window, then `telnet` is killed regardless of whether the connection is still open — this is a fixed per-host wait, not a smart "done when quiet" detector.
- The script exits early with an error if the port is invalid, `telnet` isn't installed, or the list file can't be read / is empty.
- The `[n/total] ip:port` header format in its output is what [Telnet Extract IPs](#telnet-extract-ips--ssh-banner-disclosure) below expects as input.

---

## Telnet Extract IPs — SSH Banner Disclosure

`telnet-extract-ips.py`

Post-processing companion to [Telnet Automator](#telnet-automator). Reads a saved transcript and flags hosts whose SSH banner discloses more than the bare OpenSSH version — e.g. a patch suffix or OS string — which can hand an attacker exact version/OS info for CVE matching.

### Requirements

- Python 3.x (standard library only)
- An input file in the `[n/total] ip:port` block format that Telnet Automator's `-s` option produces

### Usage

```bash
python3 telnet-extract-ips.py [path]
```

| Argument | Description | Default |
|----------|--------------|---------|
| `path` (positional, optional) | File to analyze | `out.txt` |

There are no flags — just one optional positional path.

#### Examples

Analyze the default `out.txt`:
```bash
python3 telnet-extract-ips.py
```

Typical pipeline — scan SSH banners, save, then analyze:
```bash
python3 telnet-automator.py -l hosts.txt 22 -s out.txt
python3 telnet-extract-ips.py out.txt
```

### Sample Output

```console
Version disclosure hosts
10.0.0.5
10.0.0.9
```

### Notes

- A banner only counts as a disclosure if it goes beyond the bare `SSH-2.0-OpenSSH_<major>.<minor>` pattern — e.g. `SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7` would be flagged, `SSH-2.0-OpenSSH_7.4` would not.
- If the file can't be read, or no `[n/total] ip:port` headers are found in it, the script exits with a `[!]` error instead of printing results.
- Output IPs are de-duplicated.

---

## SSH Audit IP Extract

`ssh-audit-ip-extract.py`

Sorts hosts from [`ssh-audit`](https://github.com/jtesta/ssh-audit)'s output into three buckets — **weak** (at least one failing cipher/kex/key/mac), **pass** (clean), and **non-reachable** — so you can triage a large SSH footprint at a glance instead of reading every host's full report.

### Requirements

- Python 3.x (standard library only)
- An input file containing output from `ssh-audit -T <targets file> -l fail` (or similar), run separately — `ssh-audit` itself is not bundled in this repo

### Usage

```bash
python3 ssh-audit-ip-extract.py [path]
```

| Argument | Description | Default |
|----------|--------------|---------|
| `path` (positional, optional) | File to analyze | `out.txt` |

There are no flags — just one optional positional path.

#### Examples

Run `ssh-audit` across a target list, save its output, then sort it:
```bash
ssh-audit -T hosts.txt -l fail > ssh-audit-results.txt
python3 ssh-audit-ip-extract.py ssh-audit-results.txt
```

Analyze the default `out.txt`:
```bash
python3 ssh-audit-ip-extract.py
```

### Sample Output

```console
Weak cipher ips
10.0.0.3
10.0.0.7

Pass ips
10.0.0.1
10.0.0.4

Non-reachable ips
10.0.0.9
```

A one-line summary is printed to stderr: `[weak=2 pass=2 unreachable=1 total=5]`

### Notes

- Expects `ssh-audit`'s block format: target blocks separated by dashed-line rules, a `(gen) target: <ip>` line per block, algorithm entries tagged `(kex)`/`(key)`/`(enc)`/`(mac)`, and unreachable hosts marked `[exception] cannot connect to <ip>`.
- A host is marked **weak** if any algorithm entry in its block contains `[fail]`.
- If the file can't be read, the script exits with a `[!] Cannot read <path>: <reason>` error.

---

## DNC Automator (Dirsearch / Nuclei / Curl)

`dnc-automator.py`

Runs `nuclei`, `dirsearch`, or `curl` against every target in a scope file, one target at a time, streaming each run's live output (progress bars included) and optionally saving a clean transcript. Built so you can bring your own flags for the underlying tool straight through the same command line.

### Requirements

- Python 3.x (standard library only for the wrapper itself)
- Whichever underlying tool you invoke must be installed and on `PATH`: [`nuclei`](https://github.com/projectdiscovery/nuclei), [`dirsearch`](https://github.com/maurosoria/dirsearch), or `curl`
- A real interactive terminal (POSIX pty) to get live-updating progress bars and the Ctrl+C/Ctrl+E controls below — it still runs without one, just without those extras

### Usage

```bash
python3 dnc-automator.py {nuclei,dirsearch,curl} -l SCOPE_FILE [-s SAVE_FILE] [-t TIMEOUT] [extra tool flags...]
```

#### Options

| Flag | Long form | Description | Default |
|------|-----------|--------------|---------|
| `-l` | `--list` | Scope file — one target per line, `#` comments and blank lines ignored, commas within a line also split, duplicates removed | required |
| `-s` | `--save` | Tee a clean transcript (progress-bar frames collapsed, ANSI codes stripped) to this file | not saved |
| `-t` | `--timeout` | Kill a single target's run after N seconds and move on | no timeout |

Anything else on the command line is **passed straight through** to `nuclei` / `dirsearch` / `curl` for every target, in the order given — e.g. `-x 400,401,402` for dirsearch, or `-I` for curl.

Target placement in the underlying command:

| Tool | Command built |
|------|----------------|
| `nuclei` | `nuclei -u <target> <extra flags>` |
| `dirsearch` | `dirsearch -u <target> <extra flags>` |
| `curl` | `curl <extra flags> <target>` |

#### Examples

```bash
python3 dnc-automator.py nuclei -l scope.txt
python3 dnc-automator.py dirsearch -l scope.txt -x 400,401,402,403,404,405
python3 dnc-automator.py curl -l scope.txt -I
python3 dnc-automator.py nuclei -l scope.txt -s results.txt -severity critical,high
```

### Sample Output

```console
[*] Tool: dirsearch
[*] Scope file: scope.txt (3 unique target(s))
[*] Ctrl+C = skip current target, Ctrl+E = stop everything

--------------------------------------------------
dirsearch target: https://example.com
[*] Command: dirsearch -u https://example.com
--------------------------------------------------
<live progress bar, then results>
<completed>
--------------------------------------------------
```

### Notes

- **Controls while a run is in progress:** `Ctrl+C` kills only the current target's command and moves on to the next one; `Ctrl+E` kills the current command and stops the whole run immediately, leaving the rest of the scope list untouched. Both only work when stdin is a real terminal.
- Each command runs inside a pseudo-terminal so tools render their normal progress bars instead of spamming carriage-return updates as separate lines.
- `-s`/`--save` is reserved by the wrapper and intercepted before it reaches the underlying tool — note that this shadows curl's own `-s` (silent mode); use curl's long form `--silent` if you need that instead.
- If the chosen tool isn't installed, the script says so up front rather than failing partway through the scope list.
