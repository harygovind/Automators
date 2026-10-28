#!/usr/bin/env python3
"""
ffuf_automator.py - Run ffuf directory enumeration against every target in a scope file.

Usage:
    python3 ffuf_automator.py -l scope.txt [extra ffuf flags...]

Examples:
    python3 ffuf_automator.py -l scope.txt
    python3 ffuf_automator.py -l scope.txt -fc 400,401,402,403,404,405
    python3 ffuf_automator.py -l scope.txt -s ffuf-out.txt -mc 200,301,302
    python3 ffuf_automator.py -l scope.txt -e php,bak,txt -s ffuf-out.txt
    python3 ffuf_automator.py -l scope.txt -w /usr/share/wordlists/common.txt

Reserved automator flags (consumed here, never forwarded to ffuf):
    -l, --list <file>    scope file (required) - one target per line, "#" comments
                         and blank lines ignored, commas within a line also split.
    -s, --save <file>    tee clean output (banner + findings) to this file.
    -t, --timeout <sec>  kill a single target's run after N seconds and move on
                         (default: no timeout).

Wordlist & %EXT% handling (dirsearch parity):
    * Defaults to: /usr/lib/python3/dist-packages/dirsearch/db/dicc.txt
      (override with -w <wordlist>).
    * Any "%EXT%" placeholder in the wordlist is expanded into separate entries
      using default extensions: php, aspx, jsp, html, js (11,460 words total,
      matching dirsearch).
    * Pass "-e ext1,ext2" to override the extensions used for "%EXT%" expansion.

Target formatting:
    * http://example.com      -> http://example.com/FUZZ
    * http://example.com/     -> http://example.com/FUZZ
    * http://example.com/FUZZ -> http://example.com/FUZZ

Controls while a scope run is in progress (interactive terminal only):
    Ctrl+C  - stop ONLY the current target's command, then move on to the next.
    Ctrl+E  - stop everything right now: kills the current command and ends the
              whole run without touching the rest of the scope list.
"""

import os
import sys
import shutil
import subprocess
import tempfile
import threading
import time
import select

try:
    import pty
    import tty
    import termios
    HAVE_PTY = True
except ImportError:  # pragma: no cover - POSIX only
    HAVE_PTY = False

FFUF_BIN = "ffuf"
DEFAULT_WORDLIST = "/usr/lib/python3/dist-packages/dirsearch/db/dicc.txt"
DEFAULT_EXTENSIONS = ["php", "aspx", "jsp", "html", "js"]

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
        usage_error("no arguments specified.")

    # Allow optional "ffuf" subcommand in case user invokes:
    # python3 ffuf_automator.py ffuf -l scope.txt
    if argv[0] == "ffuf":
        argv = argv[1:]

    scope_file = None
    save_file = None
    timeout = None
    custom_wordlist = None
    custom_extensions = None
    passthrough = []

    i = 0
    while i < len(argv):
        token = argv[i]
        if token in RESERVED_WITH_VALUE:
            field = RESERVED_WITH_VALUE[token]
            if i + 1 >= len(argv):
                usage_error(f"'{token}' requires a value.")
            value = argv[i + 1]
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

        # Capture -w / --wordlist so we can expand %EXT% if present
        if token in ("-w", "--wordlist"):
            if i + 1 >= len(argv):
                usage_error(f"'{token}' requires a wordlist path.")
            custom_wordlist = argv[i + 1]
            i += 2
            continue
        if token.startswith("-w="):
            custom_wordlist = token.split("=", 1)[1]
            i += 1
            continue

        # Capture -e so it drives %EXT% expansion like dirsearch
        if token == "-e":
            if i + 1 >= len(argv):
                usage_error("'-e' requires a comma-separated list of extensions.")
            custom_extensions = [
                ext.strip().lstrip(".")
                for ext in argv[i + 1].split(",")
                if ext.strip().lstrip(".")
            ]
            i += 2
            continue
        if token.startswith("-e="):
            raw_exts = token.split("=", 1)[1]
            custom_extensions = [
                ext.strip().lstrip(".")
                for ext in raw_exts.split(",")
                if ext.strip().lstrip(".")
            ]
            i += 1
            continue

        passthrough.append(token)
        i += 1

    if not scope_file:
        usage_error("scope file is required, e.g. -l scope.txt")

    return scope_file, save_file, timeout, custom_wordlist, custom_extensions, passthrough


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


def format_ffuf_target(target):
    """
    Ensure the target URL ends with /FUZZ for directory enumeration:
    - http://example.com      -> http://example.com/FUZZ
    - http://example.com/     -> http://example.com/FUZZ
    - http://example.com/FUZZ -> http://example.com/FUZZ
    """
    if "FUZZ" in target:
        return target
    if target.endswith("/"):
        return f"{target}FUZZ"
    return f"{target}/FUZZ"


def build_expanded_wordlist(wordlist_path, extensions):
    """
    Reads the wordlist and expands any line containing '%EXT%' (case-insensitive)
    across all configured extensions, matching dirsearch's exact behavior.
    Returns (effective_wordlist_path, is_temp_file, word_count, had_ext_placeholder).
    """
    # Support ffuf's "path:KEYWORD" syntax if user passed -w path:FUZZ
    raw_path = wordlist_path
    keyword_suffix = ""
    if ":" in wordlist_path and not os.path.exists(wordlist_path):
        candidate_path, candidate_kw = wordlist_path.rsplit(":", 1)
        if os.path.isfile(candidate_path):
            raw_path = candidate_path
            keyword_suffix = f":{candidate_kw}"

    if not os.path.isfile(raw_path):
        usage_error(f"wordlist file '{raw_path}' not found.")

    expanded = []
    seen = set()
    had_ext = False

    with open(raw_path, "r", errors="ignore") as f:
        for line in f:
            word = line.rstrip("\r\n")
            if not word:
                continue
            if "%EXT%" in word or "%ext%" in word:
                had_ext = True
                for ext in extensions:
                    replaced = word.replace("%EXT%", ext).replace("%ext%", ext)
                    if replaced not in seen:
                        seen.add(replaced)
                        expanded.append(replaced)
            else:
                if word not in seen:
                    seen.add(word)
                    expanded.append(word)

    if not had_ext:
        return wordlist_path, False, len(expanded), False

    tmp = tempfile.NamedTemporaryFile(
        mode="w", prefix="ffuf_dicc_expanded_", suffix=".txt", delete=False
    )
    tmp.write("\n".join(expanded) + "\n")
    tmp.close()
    return f"{tmp.name}{keyword_suffix}", True, len(expanded), True


class KeyListener:
    """
    Puts our own stdin into cbreak mode and watches for single keystrokes in a
    background thread, so Ctrl+C (skip current target) and Ctrl+E (abort
    everything) can be told apart instead of both raising the same SIGINT.
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
    Relays raw bytes from ffuf straight to the real terminal (keeping live
    :: Progress: [...] :: updates and ANSI colors intact) while writing a
    clean, ANSI-stripped transcript without progress bar noise to save_fp.
    """

    def __init__(self, save_fp):
        self.save_fp = save_fp
        self._line_buf = []
        self._col = 0
        self._esc_state = "normal"  # normal -> esc -> csi -> normal
        self._csi_params = []

    def write_text(self, text):
        sys.stdout.write(text)
        sys.stdout.flush()
        if self.save_fp:
            self.save_fp.write(text)
            self.save_fp.flush()

    def _handle_csi(self, final_char, params_str):
        """
        Emulate ANSI line-erase and cursor-positioning sequences (\x1b[2K,
        \x1b[0K, \x1b[G, etc.) used by ffuf to redraw its status bar.
        """
        if final_char == "K":
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
            col = int(params_str) if params_str.isdigit() else 1
            self._col = max(0, col - 1)
        elif final_char == "D":
            n = int(params_str) if params_str.isdigit() else 1
            self._col = max(0, self._col - n)
        elif final_char == "C":
            n = int(params_str) if params_str.isdigit() else 1
            self._col += n
        elif final_char in ("H", "f"):
            parts = params_str.split(";")
            if len(parts) == 2 and parts[1].isdigit():
                self._col = max(0, int(parts[1]) - 1)
            else:
                self._col = 0
        elif final_char == "F":
            self._col = 0

    @staticmethod
    def _is_progress_frame(line):
        stripped = line.strip()
        if stripped.startswith(":: Progress: ["):
            return True
        return False

    def feed_bytes(self, data):
        # 1. Raw passthrough to terminal for live progress bar & colors
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

        if not self.save_fp:
            return

        # 2. Clean terminal emulation for the saved file
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
                if "@" <= c <= "~":
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
                if not self._is_progress_frame(line):
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
            if line and not self._is_progress_frame(line):
                self.save_fp.write(line + "\n")
                self.save_fp.flush()
            self._line_buf = []
            self._col = 0


def run_one(target, effective_wl, display_wl, passthrough, timeout, sink, listener):
    fuzz_target = format_ffuf_target(target)
    cmd = [FFUF_BIN, "-u", fuzz_target, "-w", effective_wl, *passthrough]
    display_cmd = [FFUF_BIN, "-u", fuzz_target, "-w", display_wl, *passthrough]

    banner = "-" * 50
    sink.write_text(f"{banner}\n")
    sink.write_text(f"ffuf target: {fuzz_target}\n")
    sink.write_text(f"[*] Command: {' '.join(display_cmd)}\n")
    sink.write_text(f"{banner}\n")

    use_pty = HAVE_PTY
    master_fd = slave_fd = None
    if use_pty:
        master_fd, slave_fd = pty.openpty()
        if sys.stdout.isatty():
            try:
                import fcntl
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
        sink.write_text(f"[!] '{FFUF_BIN}' not found on PATH. Aborting run.\n")
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
    (
        scope_file,
        save_file,
        timeout,
        custom_wordlist,
        custom_extensions,
        passthrough,
    ) = parse_cli(sys.argv[1:])

    if shutil.which(FFUF_BIN) is None:
        usage_error(f"'{FFUF_BIN}' is not installed or not on PATH. Install it before running.")

    targets = read_targets(scope_file)

    source_wordlist = custom_wordlist if custom_wordlist else DEFAULT_WORDLIST
    extensions = custom_extensions if custom_extensions else DEFAULT_EXTENSIONS

    effective_wl, is_temp_wl, word_count, had_ext = build_expanded_wordlist(
        source_wordlist, extensions
    )

    # If the user passed -e and the wordlist did NOT contain %EXT% placeholders,
    # forward -e to ffuf natively so standard wordlists still get extensions appended.
    if custom_extensions and not had_ext:
        passthrough = ["-e", ",".join(f".{e}" for e in custom_extensions), *passthrough]

    save_fp = open(save_file, "a") if save_file else None
    sink = OutputSink(save_fp)

    print(f"[*] Tool: ffuf")
    print(f"[*] Scope file: {scope_file} ({len(targets)} unique target(s))")
    print(f"[*] Wordlist: {source_wordlist} ({word_count} entries)")
    if had_ext:
        print(f"[*] Expanded %EXT% with: {', '.join(extensions)}")
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
                aborted = run_one(
                    target,
                    effective_wl,
                    source_wordlist,
                    passthrough,
                    timeout,
                    sink,
                    listener,
                )
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
        if is_temp_wl:
            tmp_file = effective_wl.split(":", 1)[0]
            if os.path.exists(tmp_file):
                try:
                    os.remove(tmp_file)
                except OSError:
                    pass

    print("[*] Scope complete.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
