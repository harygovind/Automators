#!/usr/bin/env python3
"""
automator.py - Run nuclei / dirsearch / curl against every target in a scope file.

Usage:
    python3 automator.py nuclei    -l scope.txt [extra nuclei flags...]
    python3 automator.py dirsearch -l scope.txt [extra dirsearch flags...]
    python3 automator.py curl      -l scope.txt [extra curl flags...]

Examples:
    python3 automator.py nuclei -l scope.txt
    python3 automator.py dirsearch -l scope.txt -x 400,401,402,403,404,405
    python3 automator.py curl -l scope.txt -I
    python3 automator.py nuclei -l scope.txt -s results.txt -severity critical,high

Reserved automator flags (consumed here, never forwarded to the underlying tool):
    -l, --list <file>    scope file (required) - one target per line, "#" comments
                         and blank lines ignored, commas within a line also split.
    -s, --save <file>    tee all output to this file as well as the terminal.
    -t, --timeout <sec>  kill a single target's run after N seconds and move on
                         (default: no timeout).

Everything else on the command line (order preserved) is passed straight through
to nuclei / dirsearch / curl for each target, e.g. "-I" or "-x 400,401".

Target placement in the underlying command:
    nuclei:    nuclei -u <target> <extra flags>
    dirsearch: dirsearch -u <target> <extra flags>
    curl:      curl <extra flags> <target>

Controls while a scope run is in progress (interactive terminal only):
    Ctrl+C  - stop ONLY the current target's command, then move on to the next.
    Ctrl+E  - stop everything right now: kills the current command and ends the
              whole run without touching the rest of the scope list.
"""

import os
import sys
import shutil
import subprocess
import threading
import time
import select

try:
    import pty
    import tty
    import termios
    HAVE_PTY = True
except ImportError:  # pragma: no cover - POSIX only (pty/tty/termios)
    HAVE_PTY = False

TOOLS = {
    "nuclei":    {"bin": "nuclei",    "target_style": "u_flag"},
    "dirsearch": {"bin": "dirsearch", "target_style": "u_flag"},
    "curl":      {"bin": "curl",      "target_style": "trailing"},
}

RESERVED_WITH_VALUE = {
    "-l": "scope_file",
    "--list": "scope_file",
    "-s": "save_file",
    "--save": "save_file",
    "-t": "timeout",
    "--timeout": "timeout",
}

CTRL_C = b"\x03"
CTRL_E = b"\x05"


def usage_error(msg):
    print(f"Error: {msg}\n")
    print(__doc__)
    sys.exit(1)


def parse_cli(argv):
    if not argv:
        usage_error("no tool specified.")

    tool = argv[0]
    if tool not in TOOLS:
        usage_error(f"unknown tool '{tool}'. Expected one of: {', '.join(TOOLS)}")

    scope_file = None
    save_file = None
    timeout = None
    passthrough = []

    rest = argv[1:]
    i = 0
    while i < len(rest):
        token = rest[i]
        if token in RESERVED_WITH_VALUE:
            field = RESERVED_WITH_VALUE[token]
            if i + 1 >= len(rest):
                usage_error(f"'{token}' requires a value.")
            value = rest[i + 1]
            if field == "scope_file":
                scope_file = value
            elif field == "save_file":
                save_file = value
            elif field == "timeout":
                try:
                    timeout = float(value)
                except ValueError:
                    usage_error(f"'{token}' value must be a number of seconds, got '{value}'.")
            i += 2
            continue
        passthrough.append(token)
        i += 1

    if not scope_file:
        usage_error("scope file is required, e.g. -l scope.txt")

    return tool, scope_file, save_file, timeout, passthrough


def read_targets(scope_file):
    if not os.path.isfile(scope_file):
        usage_error(f"scope file '{scope_file}' not found.")

    targets = []
    seen = set()
    with open(scope_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for piece in line.split(","):
                piece = piece.strip()
                if piece and piece not in seen:
                    seen.add(piece)
                    targets.append(piece)

    if not targets:
        usage_error(f"no targets found in '{scope_file}'.")
    return targets


def build_command(tool, target, passthrough):
    binary = TOOLS[tool]["bin"]
    style = TOOLS[tool]["target_style"]
    if style == "u_flag":
        return [binary, "-u", target, *passthrough]
    else:  # trailing
        return [binary, *passthrough, target]


class KeyListener:
    """
    Puts our own stdin into cbreak mode and watches for single keystrokes in a
    background thread, so Ctrl+C (skip current target) and Ctrl+E (abort
    everything) can be told apart instead of both raising the same SIGINT.

    Only active when stdin is a real interactive terminal; otherwise this is a
    no-op and the script falls back to Python's default Ctrl+C handling.
    """

    def __init__(self):
        self.skip_event = threading.Event()
        self.abort_event = threading.Event()
        self._stop = threading.Event()
        self._old_settings = None
        self._thread = None
        self.active = HAVE_PTY and sys.stdin.isatty()

    def start(self):
        if not self.active:
            return
        fd = sys.stdin.fileno()
        self._old_settings = termios.tcgetattr(fd)
        new_settings = termios.tcgetattr(fd)
        new_settings[3] = new_settings[3] & ~(termios.ICANON | termios.ECHO | termios.ISIG)
        new_settings[6][termios.VMIN] = 1
        new_settings[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSANOW, new_settings)
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()

    def _listen(self):
        fd = sys.stdin.fileno()
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([fd], [], [], 0.2)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            ch = os.read(fd, 1)
            if ch == CTRL_C:
                self.skip_event.set()
            elif ch == CTRL_E:
                self.abort_event.set()
                self.skip_event.set()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        if self.active and self._old_settings is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._old_settings)


class OutputSink:
    """
    Relays raw bytes from a subprocess straight to the real terminal (so
    progress bars and ANSI colors work identically to running the tool
    directly) and, optionally, writes a clean deduplicated transcript to a
    save file by emulating terminal line discipline (\r, \n, and ANSI CSI
    line-erase / cursor-positioning codes like \x1b[2K and \x1b[1G that
    dirsearch uses to redraw its progress bar in place).
    """

    def __init__(self, save_fp):
        self.save_fp = save_fp
        self._line_buf = []
        self._col = 0
        self._esc_state = "normal"  # normal -> esc -> csi -> normal
        self._csi_params = []

    def write_text(self, text):
        """For our own plain-text banners (no \r in these)."""
        sys.stdout.write(text)
        sys.stdout.flush()
        if self.save_fp:
            self.save_fp.write(text)
            self.save_fp.flush()

    def _handle_csi(self, final_char, params_str):
        """
        Emulate cursor positioning and line erasure used by tools like
        dirsearch (\x1b[2K to clear line, \x1b[1G to return to column 1)
        so progress bar redraws overwrite the buffer instead of appending.
        """
        if final_char == "K":
            # EL - Erase in Line:
            # 0 (or empty) = clear from cursor to end of line
            # 1 = clear from start of line to cursor
            # 2 = clear entire line
            mode = int(params_str) if params_str.isdigit() else 0
            if mode == 2:
                self._line_buf = []
                self._col = 0
            elif mode == 0:
                del self._line_buf[self._col:]
            elif mode == 1:
                for i in range(min(self._col + 1, len(self._line_buf))):
                    self._line_buf[i] = " "
        elif final_char in ("G", "`"):
            # CHA - Cursor Horizontal Absolute (1-based column index)
            col = int(params_str) if params_str.isdigit() else 1
            self._col = max(0, col - 1)
        elif final_char == "D":
            # CUB - Cursor Back
            n = int(params_str) if params_str.isdigit() else 1
            self._col = max(0, self._col - n)
        elif final_char == "C":
            # CUF - Cursor Forward
            n = int(params_str) if params_str.isdigit() else 1
            self._col += n
        elif final_char in ("H", "f"):
            # CUP - Cursor Position (row;col)
            parts = params_str.split(";")
            if len(parts) == 2 and parts[1].isdigit():
                self._col = max(0, int(parts[1]) - 1)
            else:
                self._col = 0
        elif final_char == "F":
            # CPL - Cursor Previous Line (resets column to 0)
            self._col = 0

    def feed_bytes(self, data):
        # 1. Full raw passthrough to the real terminal, ANSI colors and
        #    live progress bar animations intact.
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

        if not self.save_fp:
            return

        # 2. Decode UTF-8 safely and emulate line discipline for the save file.
        text = data.decode("utf-8", errors="replace")
        for c in text:
            if self._esc_state == "esc":
                if c == "[":
                    self._esc_state = "csi"
                    self._csi_params = []
                else:
                    self._esc_state = "normal"
                continue

            if self._esc_state == "csi":
                if "@" <= c <= "~":  # final byte of the CSI sequence
                    params_str = "".join(self._csi_params)
                    self._handle_csi(c, params_str)
                    self._esc_state = "normal"
                else:
                    self._csi_params.append(c)
                continue

            if c == "\x1b":
                self._esc_state = "esc"
            elif c == "\r":
                self._col = 0
            elif c == "\b":
                self._col = max(0, self._col - 1)
            elif c == "\n":
                line = "".join(self._line_buf).rstrip()
                self.save_fp.write(line + "\n")
                self.save_fp.flush()
                self._line_buf = []
                self._col = 0
            else:
                while len(self._line_buf) <= self._col:
                    self._line_buf.append(" ")
                self._line_buf[self._col] = c
                self._col += 1

    def flush_pending_line(self):
        if self.save_fp and self._line_buf:
            line = "".join(self._line_buf).rstrip()
            if line:
                self.save_fp.write(line + "\n")
                self.save_fp.flush()
            self._line_buf = []
            self._col = 0


def run_one(tool, target, passthrough, timeout, sink, listener):
    cmd = build_command(tool, target, passthrough)

    banner = "-" * 50
    sink.write_text(f"{banner}\n")
    sink.write_text(f"{tool} target: {target}\n")
    sink.write_text(f"[*] Command: {' '.join(cmd)}\n")
    sink.write_text(f"{banner}\n")

    use_pty = HAVE_PTY
    master_fd = slave_fd = None
    if use_pty:
        master_fd, slave_fd = pty.openpty()
        # Copy real terminal window size to the PTY slave so tools like
        # dirsearch know the exact column width and don't wrap prematurely.
        if sys.stdout.isatty():
            try:
                import fcntl
                import struct
                winsize = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, b"\x00" * 8)
                fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)
            except OSError:
                pass

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=slave_fd if use_pty else subprocess.DEVNULL,
            stdout=slave_fd if use_pty else subprocess.PIPE,
            stderr=slave_fd if use_pty else subprocess.STDOUT,
            close_fds=True,
        )
    except FileNotFoundError:
        if slave_fd is not None:
            os.close(slave_fd)
        if master_fd is not None:
            os.close(master_fd)
        sink.write_text(f"[!] '{TOOLS[tool]['bin']}' not found on PATH. Aborting run.\n")
        sys.exit(1)

    if use_pty:
        os.close(slave_fd)

    listener.skip_event.clear()
    start_time = time.time()
    timed_out = False
    skipped = False
    aborted = False

    read_fd = master_fd if use_pty else proc.stdout.fileno()

    while True:
        if timeout and (time.time() - start_time) > timeout:
            timed_out = True
            proc.kill()
            break
        if listener.skip_event.is_set():
            skipped = True
            aborted = listener.abort_event.is_set()
            proc.kill()
            listener.skip_event.clear()
            break
        try:
            ready, _, _ = select.select([read_fd], [], [], 0.2)
        except OSError:
            break
        if ready:
            try:
                data = os.read(read_fd, 4096)
            except OSError:
                data = b""
            if not data:
                break
            sink.feed_bytes(data)
        if proc.poll() is not None and not ready:
            break

    sink.flush_pending_line()
    if use_pty:
        try:
            os.close(master_fd)
        except OSError:
            pass
    proc.wait()

    if timed_out:
        sink.write_text(f"<timed out after {timeout}s>\n")
    elif skipped:
        sink.write_text("<skipped by user (Ctrl+C)>\n" if not aborted else "<stopped by user (Ctrl+E)>\n")
    elif proc.returncode not in (0, None):
        sink.write_text(f"<completed - exit code {proc.returncode}>\n")
    else:
        sink.write_text("<completed>\n")
    sink.write_text("-" * 50 + "\n\n")

    return aborted


def main():
    tool, scope_file, save_file, timeout, passthrough = parse_cli(sys.argv[1:])

    if shutil.which(TOOLS[tool]["bin"]) is None:
        usage_error(
            f"'{TOOLS[tool]['bin']}' is not installed or not on PATH. "
            f"Install it before running this automator."
        )

    targets = read_targets(scope_file)

    save_fp = open(save_file, "a") if save_file else None
    sink = OutputSink(save_fp)

    print(f"[*] Tool: {tool}")
    print(f"[*] Scope file: {scope_file} ({len(targets)} unique target(s))")
    if passthrough:
        print(f"[*] Extra flags passed through: {' '.join(passthrough)}")
    if save_file:
        print(f"[*] Saving output to: {save_file}")
    listener = KeyListener()
    if listener.active:
        print("[*] Ctrl+C = skip current target, Ctrl+E = stop everything")
    print()

    listener.start()
    try:
        for idx, target in enumerate(targets, start=1):
            try:
                aborted = run_one(tool, target, passthrough, timeout, sink, listener)
            except KeyboardInterrupt:
                print(f"[!] Interrupted on target {idx}/{len(targets)} - continuing to next target.")
                aborted = False
            if aborted:
                print(f"[!] Ctrl+E pressed - stopping after target {idx}/{len(targets)}.")
                break
    finally:
        listener.stop()
        if save_fp:
            save_fp.close()

    print("[*] Scope complete.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
        
