#!/usr/bin/env python3
"""Read-only status TUI for Aether on Termux.

Starts one aether process that serves two local SOCKS5 proxies:

    127.0.0.1:10889  WARP over MASQUE (HTTP/3)
    127.0.0.1:10890  psiphon carried inside that WARP tunnel

and shows their live state: whether each port actually passes traffic (checked
with Cloudflare's /cdn-cgi/trace through the proxy), the exit address, traffic
counters, and aether's log. Standard library only. Press q to quit, which also
stops aether; r re-runs the health checks now.
"""

import argparse
import collections
import curses
import os
import re
import signal
import socket
import ssl
import struct
import subprocess
import threading
import time

WARP_PORT = 10889
PSIPHON_PORT = 10890
CHECK_SECS = 20        # between checks while both ports are up
RETRY_SECS = 5         # while either is down, e.g. still connecting
CHECK_TIMEOUT = 12
STATS_SECS = 2
TRACE_HOST = "www.cloudflare.com"

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# env_logger prefix: [2026-09-28T12:00:00.000Z INFO  aether::socks] message
LOG_PREFIX = re.compile(r"^\[\S+\s+(\w+)\s*[^\]]*\]\s?")
STATS = re.compile(r"\[=\] up (\S+ \S+) down (\S+ \S+) uptime (\S+(?: \S+)?)")
UNITS = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}

# Log fragments that move the headline phase, checked in order.
PHASES = [
    ("psiphon lost its tunnel", "psiphon reconnecting"),
    ("psiphon is ready", "psiphon ready"),
    ("starting psiphon", "starting psiphon"),
    ("socks5 server listening", "tunnel up"),
    ("MASQUE transport:", "tunnel established"),
    ("hunting for", "scanning for a gateway"),
    ("verifying cached", "checking saved gateway"),
    ("retrying last known-good", "checking saved gateway"),
    ("provisioning", "registering device"),
    ("identity ready", "identity ready"),
    ("loaded existing", "identity loaded"),
]


def parse_size(text):
    value, _, unit = text.partition(" ")
    try:
        return float(value) * UNITS.get(unit, 1)
    except ValueError:
        return 0.0


def fmt_rate(bps):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if bps < 1024 or unit == "GiB":
            return f"{bps:.0f} {unit}/s" if unit == "B" else f"{bps:.1f} {unit}/s"
        bps /= 1024


class State:
    """Everything the screen shows, shared between the reader, checker and UI."""

    def __init__(self):
        self.lock = threading.Lock()
        self.logs = collections.deque(maxlen=400)
        self.phase = "starting"
        self.exit_code = None
        self.up = self.down = "-"
        self.uptime = "-"
        self.rate_up = self.rate_down = 0.0
        self._last_stats = None
        self.psiphon_server = None
        self.checks = {WARP_PORT: None, PSIPHON_PORT: None}
        self.checking = set()

    def add_line(self, raw):
        line = ANSI.sub("", raw).rstrip()
        if not line:
            return
        level = "INFO"
        m = LOG_PREFIX.match(line)
        if m:
            level = m.group(1).upper()
            line = line[m.end():]
        with self.lock:
            s = STATS.search(line)
            if s:
                self._stats(*s.groups())
                return  # counters go in the header, not the log
            for needle, phase in PHASES:
                if needle in line:
                    self.phase = phase
                    break
            if "psiphon reached a server at" in line:
                self.psiphon_server = line.rsplit(" ", 1)[-1]
            self.logs.append((time.strftime("%H:%M:%S"), level, line))

    def _stats(self, up, down, uptime):
        now = time.monotonic()
        u, d = parse_size(up), parse_size(down)
        if self._last_stats:
            t0, u0, d0 = self._last_stats
            dt = max(now - t0, 0.001)
            self.rate_up = max(u - u0, 0) / dt
            self.rate_down = max(d - d0, 0) / dt
        self._last_stats = (now, u, d)
        self.up, self.down, self.uptime = up, down, uptime


# ---------------------------------------------------------------- health check

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("proxy closed the connection")
        buf += chunk
    return buf


def socks_trace(port):
    """GET /cdn-cgi/trace through the SOCKS5 proxy on port; returns (fields, rtt)."""
    start = time.monotonic()
    sock = socket.create_connection(("127.0.0.1", port), timeout=CHECK_TIMEOUT)
    try:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise ConnectionError("proxy refused the handshake")
        host = TRACE_HOST.encode()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", 443))
        _, rep, _, atyp = recv_exact(sock, 4)
        if rep != 0:
            raise ConnectionError(f"proxy connect failed (code {rep})")
        skip = {1: 4, 4: 16}.get(atyp)
        if skip is None:
            skip = recv_exact(sock, 1)[0]
        recv_exact(sock, skip + 2)

        tls = ssl.create_default_context().wrap_socket(sock, server_hostname=TRACE_HOST)
        sock = tls
        tls.sendall(
            f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {TRACE_HOST}\r\n"
            "User-Agent: aether-tui\r\nConnection: close\r\n\r\n".encode()
        )
        data = b""
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
        rtt = time.monotonic() - start
    finally:
        sock.close()

    head, _, body = data.decode(errors="replace").partition("\r\n\r\n")
    if " 200 " not in head.split("\r\n", 1)[0]:
        raise ConnectionError(head.split("\r\n", 1)[0] or "empty reply")
    fields = dict(l.split("=", 1) for l in body.splitlines() if "=" in l)
    return fields, rtt


def checker(state, wake, stop):
    while not stop.is_set():
        for port in (WARP_PORT, PSIPHON_PORT):
            with state.lock:
                state.checking.add(port)
            try:
                fields, rtt = socks_trace(port)
                result = {"ok": True, "rtt": rtt, **fields}
            except (OSError, ValueError) as e:
                result = {"ok": False, "error": str(e) or e.__class__.__name__}
            result["at"] = time.strftime("%H:%M:%S")
            with state.lock:
                state.checks[port] = result
                state.checking.discard(port)
            if stop.is_set():
                return
        with state.lock:
            healthy = all(c and c["ok"] for c in state.checks.values())
        wake.wait(CHECK_SECS if healthy else RETRY_SECS)
        wake.clear()


# ---------------------------------------------------------------------- aether

def start_aether(args, state):
    os.makedirs(args.data_dir, exist_ok=True)
    cmd = [
        args.aether,
        "--masque", "--h3",
        "--bind", f"127.0.0.1:{WARP_PORT}",
        "--psiphon", "--psiphon-bind", f"127.0.0.1:{PSIPHON_PORT}",
        "--config", os.path.join(args.data_dir, "aether.toml"),
    ]
    env = dict(os.environ, AETHER_STATS="1", AETHER_STATS_SECS=str(STATS_SECS))
    state.add_line("[*] running: " + " ".join(cmd))
    # stdin is not a terminal, so aether asks nothing and uses the flags as given.
    # Its own session lets us stop psiphon-tunnel-core along with it.
    proc = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=env, start_new_session=True, bufsize=1, text=True, errors="replace",
    )

    def reader():
        for line in proc.stdout:
            state.add_line(line)
        code = proc.wait()
        with state.lock:
            state.exit_code = code
            state.phase = f"aether exited ({code})"

    threading.Thread(target=reader, daemon=True).start()
    return proc


def stop_aether(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


# -------------------------------------------------------------------------- UI

def draw(scr, state, colors):
    scr.erase()
    h, w = scr.getmaxyx()
    row = 0

    def put(text, attr=0):
        nonlocal row
        if row < h:
            try:
                scr.addnstr(row, 0, text, w - 1, attr)
            except curses.error:
                pass
        row += 1

    with state.lock:
        phase_attr = colors["bad"] if state.exit_code is not None else colors["accent"]
        put(" aether-tui ", curses.A_REVERSE | curses.A_BOLD)
        put(f" state   {state.phase}", phase_attr | curses.A_BOLD)
        put(f" uptime  {state.uptime}")
        put(f" up      {state.up:<12} {fmt_rate(state.rate_up)}")
        put(f" down    {state.down:<12} {fmt_rate(state.rate_down)}")
        put("")

        for port, name in ((WARP_PORT, "WARP  masque/h3"), (PSIPHON_PORT, "PSIPHON via warp")):
            c = state.checks[port]
            busy = " …" if port in state.checking else ""
            if c is None:
                put(f" :{port} {name}  waiting for first check{busy}", colors["dim"])
            elif c["ok"]:
                put(f" :{port} {name}  UP  {c['rtt'] * 1000:.0f} ms{busy}", colors["good"] | curses.A_BOLD)
                put(f"     ip {c.get('ip', '?')}")
                put(f"     loc {c.get('loc', '?')}  colo {c.get('colo', '?')}  warp={c.get('warp', '?')}")
                put(f"     checked {c['at']}", colors["dim"])
            else:
                put(f" :{port} {name}  DOWN{busy}", colors["bad"] | curses.A_BOLD)
                put(f"     {c['error']}", colors["bad"])
                put(f"     checked {c['at']}", colors["dim"])
        if state.psiphon_server:
            put(f"     psiphon server {state.psiphon_server}", colors["dim"])
        put("")

        put(" log ".ljust(w - 1, "─"), colors["dim"])
        space = h - row - 1
        lines = list(state.logs)[-space:] if space > 0 else []

    for stamp, level, text in lines:
        attr = 0
        if level == "ERROR" or text.startswith(("[-]", "Error")):
            attr = colors["bad"]
        elif level == "WARN" or text.startswith("[!]"):
            attr = colors["warn"]
        elif text.startswith("[+]"):
            attr = colors["good"]
        put(f"{stamp} {text}", attr)

    row = h - 1
    put(" q quit (stops aether)   r recheck ", curses.A_REVERSE)
    scr.refresh()


def ui(scr, state, wake):
    curses.curs_set(0)
    scr.timeout(500)
    colors = {k: 0 for k in ("good", "bad", "warn", "accent", "dim")}
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        for i, (name, fg) in enumerate(
            [("good", curses.COLOR_GREEN), ("bad", curses.COLOR_RED),
             ("warn", curses.COLOR_YELLOW), ("accent", curses.COLOR_CYAN)], start=1):
            curses.init_pair(i, fg, -1)
            colors[name] = curses.color_pair(i)
    colors["dim"] = curses.A_DIM

    while True:
        draw(scr, state, colors)
        key = scr.getch()
        if key in (ord("q"), ord("Q")):
            return
        if key in (ord("r"), ord("R")):
            wake.set()


def main():
    home = os.path.expanduser("~")
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--aether", default="aether", help="aether binary (default: aether on PATH)")
    p.add_argument("--data-dir", default=os.path.join(home, ".aether-tui"),
                   help="where aether keeps its identity files (default: ~/.aether-tui)")
    p.add_argument("--no-spawn", action="store_true",
                   help="do not start aether; only watch the two ports")
    args = p.parse_args()

    state = State()
    proc = None
    if args.no_spawn:
        state.phase = "watching (aether not started here)"
    else:
        try:
            proc = start_aether(args, state)
        except FileNotFoundError:
            raise SystemExit(f"cannot find '{args.aether}'. install it with aether.sh, "
                             "or pass --aether /path/to/aether")

    stop, wake = threading.Event(), threading.Event()
    threading.Thread(target=checker, args=(state, wake, stop), daemon=True).start()
    try:
        curses.wrapper(ui, state, wake)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        wake.set()
        stop_aether(proc)


if __name__ == "__main__":
    main()
