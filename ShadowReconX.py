#!/usr/bin/env python3
"""
ShadowReconX — Interactive Host Recon Toolkit
------------------------------------------------
Enhanced, fully interactive recon tool. Just run it:

    python3 shadowreconx.py

and answer the prompts — no CLI flags required. Supports multiple
targets in one run, remembers your preferred settings, and saves
JSON + CSV + per-status folders + an optional HTML report.

Modules:
  1. Domain status   - resolve, HTTP(S) status, ping, OS guess (TTL)
  2. TLS certificate  - issuer, expiry, SANs (for HTTPS targets)
  3. Security headers - CSP, HSTS, X-Frame-Options, etc.
  4. Port scan        - pluggable engine: built-in / masscan / rustscan / naabu
                         + service, version/banner, firewall hint
  5. Path probe       - quick check of common sensitive paths
                         (robots.txt, .env, .git, admin, etc.)

Scan engines (Nmap is intentionally NOT used anywhere):
  builtin  - pure-Python TCP connect scan (no dependencies, no root)
  masscan  - very fast async scanner (needs root/admin + masscan installed)
  rustscan - fast connect scanner (Nmap hand-off disabled: --scripts none)
  naabu    - ProjectDiscovery scanner (connect mode, no root required)
  auto     - first installed external engine for big scans, else builtin

IMPORTANT: Only run this against hosts/domains you are explicitly
authorized to test. Read-only / unauthenticated checks only — no
exploitation, no credential bruteforce.
"""

import csv
import errno
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

CONFIG_PATH = os.path.expanduser("~/.shadowreconx.json")
HISTORY_PATH = os.path.expanduser("~/.shadowreconx_history.log")


# --------------------------------------------------------------------------
# Terminal colors / styling
# --------------------------------------------------------------------------

class C:
    _enabled = sys.stdout.isatty()
    RESET = "\033[0m" if _enabled else ""
    BOLD = "\033[1m" if _enabled else ""
    GREY = "\033[90m" if _enabled else ""
    RED = "\033[31m" if _enabled else ""
    GREEN = "\033[32m" if _enabled else ""
    YELLOW = "\033[33m" if _enabled else ""
    BLUE = "\033[34m" if _enabled else ""
    MAGENTA = "\033[35m" if _enabled else ""
    CYAN = "\033[36m" if _enabled else ""


def term_width(default=78):
    try:
        return shutil.get_terminal_size((default, 20)).columns
    except Exception:
        return default


def hr(char="-"):
    print(C.GREY + char * min(term_width(), 78) + C.RESET)


def section(title, step_no=None, total_steps=5):
    hr()
    tag = f"[{step_no}/{total_steps}] " if step_no else ""
    print(f"{C.BOLD}{C.BLUE}{tag}{title}{C.RESET}")
    hr()


_FONT = {
    "S": [" ####", "#    ", " ### ", "    #", "#### "],
    "H": ["#   #", "#   #", "#####", "#   #", "#   #"],
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "D": ["#### ", "#   #", "#   #", "#   #", "#### "],
    "O": [" ### ", "#   #", "#   #", "#   #", " ### "],
    "W": ["#   #", "#   #", "# # #", "## ##", "#   #"],
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #"],
    "E": ["#####", "#    ", "###  ", "#    ", "#####"],
    "C": [" ####", "#    ", "#    ", "#    ", " ####"],
    "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"],
    "X": ["#   #", " # # ", "  #  ", " # # ", "#   #"],
}


def _render_word(word, gap=1):
    rows = ["" for _ in range(5)]
    for letter in word.upper():
        glyph = _FONT.get(letter, ["     "] * 5)
        for r in range(5):
            rows[r] += glyph[r] + " " * gap
    return rows


def banner():
    for row in _render_word("SHADOWRECONX"):
        print(C.CYAN + C.BOLD + row + C.RESET)
    print()
    print(C.GREY + "  Interactive recon: status, TLS, headers, ports, paths" + C.RESET)
    print(C.YELLOW + "  \u26a0  Only scan hosts you are explicitly authorized to test." + C.RESET)
    hr("=")


def make_table(headers, rows):
    ansi_re = re.compile(r"\033\[[0-9;]*m")

    def vlen(s):
        return len(ansi_re.sub("", str(s)))

    widths = [vlen(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], vlen(cell))

    def pad(cell, w):
        return str(cell) + " " * max(w - vlen(cell), 0)

    def sep(l, m, r, fill="─"):
        return l + m.join(fill * (w + 2) for w in widths) + r

    lines = [sep("┌", "┬", "┐")]
    lines.append("│ " + " │ ".join(f"{C.BOLD}{pad(h, widths[i])}{C.RESET}" for i, h in enumerate(headers)) + " │")
    lines.append(sep("├", "┼", "┤"))
    for row in rows:
        lines.append("│ " + " │ ".join(pad(c, widths[i]) for i, c in enumerate(row)) + " │")
    lines.append(sep("└", "┴", "┘"))
    return "\n".join(lines)


def progress_bar(current, total, start_time, label="", bar_len=30):
    total = max(total, 1)
    fraction = min(current / total, 1.0)
    filled = int(bar_len * fraction)
    bar = "#" * filled + "-" * (bar_len - filled)
    elapsed = time.time() - start_time
    rate = current / elapsed if elapsed > 0 else 0
    remaining = (total - current) / rate if rate > 0 else 0
    eta = f"{remaining:4.0f}s" if current < total else "  0s"
    line = (f"\r  {C.CYAN}[{bar}]{C.RESET} {C.BOLD}{fraction*100:5.1f}%{C.RESET} "
            f"({current}/{total})  ETA {eta}   {C.GREY}{label:<30}{C.RESET}")
    line = line[: term_width() + 20]
    sys.stdout.write(line)
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")


# --------------------------------------------------------------------------
# Config (remembers your preferred defaults between runs)
# --------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "threads": 100,
    "timeout": 1.0,
    "port_mode": "common",   # common | full | custom
    "custom_ports": "1-1024",
    "delay": 0.0,
    "save_html": True,
    "probe_paths": True,
    "engine": "auto",        # auto | builtin | masscan | rustscan | naabu
    "rate": 1000,            # packets/sec for external engines
}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    return cfg


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


def log_history(targets, elapsed):
    try:
        with open(HISTORY_PATH, "a", encoding="utf-8") as f:
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            f.write(f"{ts}  targets={','.join(targets)}  duration={elapsed:.1f}s\n")
    except Exception:
        pass


# --------------------------------------------------------------------------
# Input helpers
# --------------------------------------------------------------------------

def ask(prompt, default=None):
    suffix = f" {C.GREY}[{default}]{C.RESET}" if default is not None else ""
    val = input(f"{C.CYAN}?{C.RESET} {prompt}{suffix}: ").strip()
    return val if val else default


def ask_yes_no(prompt, default="n"):
    return ask(prompt + " (y/n)", default).lower().startswith("y")


def ask_choice(prompt, options, default_index=0):
    print(f"{C.CYAN}?{C.RESET} {prompt}")
    for i, (key, label) in enumerate(options, start=1):
        marker = C.GREEN + "*" + C.RESET if (i - 1) == default_index else " "
        print(f"    {marker} {i}) {label}")
    raw = input(f"  Choose [1-{len(options)}] {C.GREY}[{default_index+1}]{C.RESET}: ").strip()
    if not raw:
        return options[default_index][0]
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(options):
            return options[idx][0]
    except ValueError:
        pass
    return options[default_index][0]


def clean_target(raw):
    return raw.replace("http://", "").replace("https://", "").strip().strip("/")


def ask_targets():
    """Accepts comma-separated targets, or a path to a file with one
    target per line (multi-target support)."""
    while True:
        raw = ask("Enter target(s): comma-separated, or a path to a file (one per line)")
        if not raw:
            print(f"  {C.RED}At least one target is required.{C.RESET}")
            continue
        if os.path.isfile(raw):
            with open(raw, "r", encoding="utf-8", errors="ignore") as f:
                targets = [clean_target(l) for l in f if l.strip()]
        else:
            targets = [clean_target(t) for t in raw.split(",") if t.strip()]
        targets = [t for t in targets if t]
        if targets:
            return targets
        print(f"  {C.RED}No valid targets found.{C.RESET}")


# --------------------------------------------------------------------------
# Module 1: Domain status / ping / OS detection
# --------------------------------------------------------------------------

def resolve(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def http_status(target, timeout):
    results = {}
    for scheme in ("http", "https"):
        url = f"{scheme}://{target}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                results[scheme] = r.status
        except urllib.error.HTTPError as e:
            results[scheme] = e.code
        except Exception as e:
            results[scheme] = f"error ({type(e).__name__})"
    return results


def ping(target):
    is_windows = platform.system().lower() == "windows"
    cmd = ["ping", "-n" if is_windows else "-c", "2", target]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return False, None
    match = re.search(r"ttl[=:](\d+)", out, re.IGNORECASE)
    ttl = int(match.group(1)) if match else None
    return ttl is not None, ttl


def guess_os(ttl):
    if ttl is None:
        return "Unknown (no ping reply - ICMP may be blocked)"
    if ttl <= 64:
        return "Linux / Unix / macOS (TTL ~64)"
    if ttl <= 128:
        return "Windows (TTL ~128)"
    return "Network device / Solaris (TTL ~255)"


def module_domain_status(target, timeout):
    section(f"Domain status - {target}", 1)
    ip = resolve(target)
    if not ip:
        print(f"  {C.RED}DNS resolution failed. Domain may not exist.{C.RESET}")
        return None

    status = http_status(target, timeout)
    up, ttl = ping(target)
    os_guess = guess_os(ttl)

    rows = [
        ["Resolved IP", ip],
        ["HTTP status", str(status.get("http"))],
        ["HTTPS status", str(status.get("https"))],
        ["Ping", f"{C.GREEN}UP{C.RESET}" if up else f"{C.RED}DOWN / ICMP blocked{C.RESET}"],
        ["TTL", str(ttl)],
        ["OS guess", os_guess],
    ]
    print(make_table(["Check", "Result"], rows))
    return {"ip": ip, "http_status": status, "ping_up": up, "ttl": ttl, "os_guess": os_guess}


# --------------------------------------------------------------------------
# Module 2: TLS certificate check
# --------------------------------------------------------------------------

def module_tls_cert(target, timeout):
    section(f"TLS certificate - {target}", 2)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((target, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        print(f"  {C.YELLOW}Could not retrieve certificate: {type(e).__name__}{C.RESET}")
        return None

    def name_from(tup):
        return dict(x[0] for x in tup if x)

    subject = name_from(cert.get("subject", ()))
    issuer = name_from(cert.get("issuer", ()))
    not_after = cert.get("notAfter")
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

    days_left = None
    expired = False
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
            expired = days_left < 0
        except Exception:
            pass

    expiry_display = f"{not_after}"
    if days_left is not None:
        color = C.RED if expired else (C.YELLOW if days_left < 30 else C.GREEN)
        expiry_display += f"  {color}({days_left} days left){C.RESET}"

    rows = [
        ["Subject CN", subject.get("commonName", "-")],
        ["Issuer", issuer.get("organizationName", issuer.get("commonName", "-"))],
        ["Valid until", expiry_display],
        ["SANs", ", ".join(sans[:6]) + (" ..." if len(sans) > 6 else "") if sans else "-"],
    ]
    print(make_table(["Field", "Value"], rows))
    return {"subject": subject, "issuer": issuer, "not_after": not_after,
            "days_left": days_left, "expired": expired, "sans": sans}


# --------------------------------------------------------------------------
# Module 3: HTTP security headers check
# --------------------------------------------------------------------------

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def module_security_headers(target, scheme, timeout):
    section(f"Security headers - {scheme}://{target}", 3)
    url = f"{scheme}://{target}/"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            headers = dict(r.getheaders())
    except urllib.error.HTTPError as e:
        headers = dict(e.headers) if e.headers else {}
    except Exception as e:
        print(f"  {C.YELLOW}Could not fetch headers: {type(e).__name__}{C.RESET}")
        return None

    rows = []
    found = {}
    for h in SECURITY_HEADERS:
        val = headers.get(h)
        found[h] = val
        if val:
            rows.append([h, f"{C.GREEN}present{C.RESET}", val[:60]])
        else:
            rows.append([h, f"{C.RED}missing{C.RESET}", "-"])
    print(make_table(["Header", "Status", "Value"], rows))
    server = headers.get("Server")
    if server:
        print(f"\n  {C.GREY}Server header reveals: {server}{C.RESET}")
    return {"headers_found": found, "server": server}


# --------------------------------------------------------------------------
# Module 4: Port scanning (pluggable engines), service + banner detection
# --------------------------------------------------------------------------

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
TLS_PORTS = {443, 465, 993, 995, 8443}
HTTP_PORTS = {80, 8000, 8080, 8888, 443, 8443}

# Engines: key -> (label, binary name or None, needs_root)
ENGINES = {
    "builtin":  ("Built-in Python connect scan (no dependencies)", None, False),
    "masscan":  ("masscan  - fastest, async (needs root + masscan)", "masscan", True),
    "rustscan": ("RustScan - fast connect scan (Nmap hand-off disabled)", "rustscan", False),
    "naabu":    ("naabu    - ProjectDiscovery, connect mode", "naabu", False),
}
EXTERNAL_PRIORITY = ["rustscan", "naabu", "masscan"]  # order used by 'auto'
AUTO_EXTERNAL_THRESHOLD = 1024  # use an external engine above this many ports


def is_root():
    if platform.system().lower() == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def engine_available(key):
    if key == "builtin":
        return True
    binary = ENGINES[key][1]
    return bool(binary and shutil.which(binary))


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def ports_to_spec(ports):
    """Compress [1,2,3,5,80] -> '1-3,5,80' for external engines."""
    ports = sorted(set(ports))
    if not ports:
        return ""
    parts, start, prev = [], ports[0], ports[0]
    for p in ports[1:]:
        if p == prev + 1:
            prev = p
            continue
        parts.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = p
    parts.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(parts)


def _run_engine(cmd, ports, rate):
    """Run an external engine; return (stdout, stderr) or raise."""
    est = len(ports) / max(rate, 1)
    limit = max(120, int(est * 3) + 60)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=limit)
    return proc.stdout or "", proc.stderr or "", proc.returncode


def scan_with_masscan(ip, ports, rate, timeout):
    if not is_root():
        print(f"  {C.YELLOW}masscan needs root/admin (raw sockets) - falling back.{C.RESET}")
        return None
    tmp = tempfile.NamedTemporaryFile(suffix=".lst", delete=False)
    tmp.close()
    try:
        cmd = ["masscan", ip, "-p", ports_to_spec(ports), "--rate", str(rate),
               "--wait", "3", "-oL", tmp.name]
        _, err, rc = _run_engine(cmd, ports, rate)
        if rc != 0:
            print(f"  {C.YELLOW}masscan exited with code {rc}: {err.strip()[:120]}{C.RESET}")
            return None
        open_ports = set()
        with open(tmp.name, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                # format: open tcp 80 1.2.3.4 1700000000
                if len(parts) >= 4 and parts[0] == "open" and parts[1] == "tcp":
                    open_ports.add(int(parts[2]))
        return open_ports
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def scan_with_rustscan(ip, ports, rate, timeout):
    # '--scripts none' stops RustScan from handing results to Nmap.
    cmd = ["rustscan", "-a", ip, "-p", ports_to_spec(ports), "-g",
           "--scripts", "none", "-t", str(int(max(timeout, 0.5) * 1000)),
           "-b", str(min(max(rate // 10, 100), 5000)), "--ulimit", "5000"]
    out, err, rc = _run_engine(cmd, ports, rate)
    if rc != 0 and not out.strip():
        print(f"  {C.YELLOW}rustscan failed: {err.strip()[:120]}{C.RESET}")
        return None
    open_ports = set()
    for m in re.finditer(r"\[([0-9,\s]*)\]", out):
        for p in m.group(1).split(","):
            p = p.strip()
            if p.isdigit():
                open_ports.add(int(p))
    return open_ports


def scan_with_naabu(ip, ports, rate, timeout):
    cmd = ["naabu", "-host", ip, "-p", ports_to_spec(ports), "-rate", str(rate),
           "-timeout", str(int(max(timeout, 0.5) * 1000)), "-s", "c",
           "-silent", "-Pn"]
    out, err, rc = _run_engine(cmd, ports, rate)
    if rc != 0 and not out.strip():
        print(f"  {C.YELLOW}naabu failed: {err.strip()[:120]}{C.RESET}")
        return None
    open_ports = set()
    for line in out.splitlines():
        m = re.search(r":(\d{1,5})\s*$", line.strip())
        if m:
            open_ports.add(int(m.group(1)))
    return open_ports


EXTERNAL_SCANNERS = {
    "masscan": scan_with_masscan,
    "rustscan": scan_with_rustscan,
    "naabu": scan_with_naabu,
}


def choose_engine(requested, ports):
    """Resolve 'auto' / unavailable engines to something that can run."""
    if requested == "auto":
        if len(ports) > AUTO_EXTERNAL_THRESHOLD:
            for key in EXTERNAL_PRIORITY:
                if engine_available(key) and (key != "masscan" or is_root()):
                    return key
        return "builtin"
    if not engine_available(requested):
        print(f"  {C.YELLOW}Engine '{requested}' not installed - using built-in scanner.{C.RESET}")
        return "builtin"
    return requested


def grab_banner(ip, port, timeout):
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        data = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        if not data:
            return ""
        if data.upper().startswith("HTTP"):
            for line in data.splitlines():
                if line.lower().startswith("server:"):
                    return line.strip()
            return data.splitlines()[0]
        return data.splitlines()[0][:100]
    except Exception:
        return ""


def scan_port(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((ip, port))
        if code == 0:
            return port, "open"
        if code in (errno.ECONNREFUSED, 10061):
            return port, "closed"
        return port, "filtered"
    except socket.timeout:
        return port, "filtered"
    except Exception:
        return port, "filtered"
    finally:
        s.close()


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def firewall_hint(states):
    total = len(states)
    if total == 0:
        return "n/a"
    filtered = sum(1 for s in states.values() if s == "filtered")
    closed = sum(1 for s in states.values() if s == "closed")
    opened = sum(1 for s in states.values() if s == "open")
    if filtered / total > 0.8:
        return f"{C.RED}Firewall likely ACTIVE{C.RESET} (most ports silently dropped)"
    if filtered > 0:
        return f"{C.YELLOW}Partial filtering detected{C.RESET}"
    if closed + opened == total:
        return f"{C.GREEN}No firewall detected{C.RESET} on scanned ports"
    return "Inconclusive"


def builtin_scan(ip, ports, threads, timeout, delay):
    states = {}
    start = time.time()
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_port, ip, p, timeout): p for p in ports}
        done = 0
        for f in as_completed(futures):
            port, state = f.result()
            states[port] = state
            done += 1
            progress_bar(done, len(ports), start, label=f"port {port}")
            if delay:
                time.sleep(delay)
    return states


def module_port_scan(ip, ports, threads, timeout, delay=0.0, engine="auto", rate=1000):
    section(f"Port scan ({len(ports)} ports) on {ip}", 4)
    engine = choose_engine(engine, ports)
    states = None
    used = engine

    if engine != "builtin":
        print(f"  Engine: {C.BOLD}{engine}{C.RESET} (rate {rate}/s) - scanning, please wait...")
        try:
            open_set = EXTERNAL_SCANNERS[engine](ip, ports, rate, timeout)
        except subprocess.TimeoutExpired:
            print(f"  {C.YELLOW}{engine} timed out - falling back.{C.RESET}")
            open_set = None
        except Exception as e:
            print(f"  {C.YELLOW}{engine} error ({type(e).__name__}) - falling back.{C.RESET}")
            open_set = None
        if open_set is not None:
            states = {p: "open" for p in sorted(open_set)}  # external engines report open only
        else:
            used = "builtin"

    if states is None:
        print(f"  Engine: {C.BOLD}builtin{C.RESET} ({threads} threads, {timeout}s timeout)")
        states = builtin_scan(ip, ports, threads, timeout, delay)
        used = "builtin"

    open_ports = sorted(p for p, s in states.items() if s == "open")
    banners = {}
    rows = []
    if open_ports:
        print(f"\n  Grabbing banners on {len(open_ports)} open port(s)...")
        for p in open_ports:
            b = grab_banner(ip, p, timeout + 1)
            banners[p] = b
            rows.append([str(p), "open", service_name(p), b or "-"])
        print(make_table(["Port", "State", "Service", "Version / Banner"], rows))
    else:
        print(f"\n  {C.YELLOW}No open ports found.{C.RESET}")

    if used == "builtin":
        closed = sum(1 for s in states.values() if s == "closed")
        filtered = sum(1 for s in states.values() if s == "filtered")
        print(f"\n  Summary: {C.GREEN}{len(open_ports)} open{C.RESET}, "
              f"{closed} closed, {filtered} filtered")
        print(f"  Firewall hint : {firewall_hint(states)}")
    else:
        print(f"\n  Summary: {C.GREEN}{len(open_ports)} open{C.RESET} "
              f"{C.GREY}({used} reports open ports only; no closed/filtered data){C.RESET}")
    return states, banners, used


# --------------------------------------------------------------------------
# Module 5: Lightweight path probing
# --------------------------------------------------------------------------

DEFAULT_PROBE_PATHS = [
    "robots.txt", ".git/config", ".env", ".svn/entries", ".htaccess",
    "wp-config.php", "admin", "login", "api", "config", "backup",
    "sitemap.xml", "health", "status", ".well-known/security.txt",
]


def module_path_probe(target, scheme, timeout):
    section(f"Path probe - {scheme}://{target}", 5)
    results = []
    start = time.time()
    for i, path in enumerate(DEFAULT_PROBE_PATHS, start=1):
        url = f"{scheme}://{target}/{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception:
            code = 0
        results.append({"path": path, "status": code})
        progress_bar(i, len(DEFAULT_PROBE_PATHS), start, label=path)

    print()
    interesting = [r for r in results if r["status"] in (200, 301, 302, 401, 403)]
    if interesting:
        rows = [[r["path"], str(r["status"])] for r in interesting]
        print(make_table(["Path", "Status"], rows))
    else:
        print(f"  {C.GREY}Nothing interesting found among default paths.{C.RESET}")
    return results


# --------------------------------------------------------------------------
# Saving results: JSON + CSV + per-status folders + HTML
# --------------------------------------------------------------------------

def save_results(target, domain_info, tls_info, headers_info, port_states, banners,
                 path_results, engine_used="builtin"):
    target_dir = target
    os.makedirs(target_dir, exist_ok=True)

    json_dir = os.path.join(target_dir, "JSON")
    os.makedirs(json_dir, exist_ok=True)
    with open(os.path.join(json_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump({
            "target": target,
            "scan_engine": engine_used,
            "domain_status": domain_info,
            "tls": tls_info,
            "security_headers": headers_info,
            "ports": {str(p): {"state": s, "banner": banners.get(p, "")}
                      for p, s in port_states.items()},
            "paths": path_results,
        }, f, indent=2, default=str)

    csv_dir = os.path.join(target_dir, "CSV")
    os.makedirs(csv_dir, exist_ok=True)
    with open(os.path.join(csv_dir, "ports.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["port", "state", "service", "banner"])
        for p, s in sorted(port_states.items()):
            w.writerow([p, s, service_name(p), banners.get(p, "")])

    ports_dir = os.path.join(target_dir, "Ports")
    grouped = defaultdict(list)
    for p, s in port_states.items():
        line = f"{p}  {s}"
        if banners.get(p):
            line += f"  {banners[p]}"
        grouped[s].append(line)
    for state, entries in grouped.items():
        folder = os.path.join(ports_dir, state)
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "results.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(entries)) + "\n")

    print(f"\n{C.GREEN}Results saved under {target_dir}/{C.RESET}")
    print(f"  {C.GREY}{json_dir}/results.json{C.RESET}")
    print(f"  {C.GREY}{csv_dir}/ports.csv{C.RESET}")
    print(f"  {C.GREY}{ports_dir}/<open|closed|filtered>/results.txt{C.RESET}")
    return target_dir


def generate_html_report(target, domain_info, tls_info, headers_info,
                          port_states, banners, path_results, out_path, engine_used="builtin"):
    def badge_class(state):
        return {"open": "st-ok", "closed": "st-warn", "filtered": "st-error",
                "present": "st-ok", "missing": "st-error"}.get(state, "st-none")

    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    port_rows = ""
    for p in sorted(port_states):
        s = port_states[p]
        port_rows += f"""
        <tr><td class="mono">{p}</td><td><span class="badge {badge_class(s)}">{s}</span></td>
        <td class="mono">{service_name(p)}</td>
        <td class="note">{esc(banners.get(p) or '-')}</td></tr>"""

    header_rows = ""
    if headers_info:
        for h, v in headers_info.get("headers_found", {}).items():
            state = "present" if v else "missing"
            header_rows += f"""
            <tr><td class="mono">{h}</td><td><span class="badge {badge_class(state)}">{state}</span></td>
            <td class="note">{esc((v or '-')[:80])}</td></tr>"""

    path_rows = ""
    for r in path_results or []:
        if r["status"] in (200, 301, 302, 401, 403):
            path_rows += f"""
            <tr><td class="mono">/{r['path']}</td><td>{r['status']}</td></tr>"""

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    ip = domain_info.get("ip", "N/A") if domain_info else "N/A"
    http_s = domain_info.get("http_status", {}).get("http", "N/A") if domain_info else "N/A"
    https_s = domain_info.get("http_status", {}).get("https", "N/A") if domain_info else "N/A"
    os_guess = domain_info.get("os_guess", "N/A") if domain_info else "N/A"
    up = ("UP" if domain_info.get("ping_up") else "DOWN") if domain_info else "N/A"
    tls_line = "N/A"
    if tls_info:
        tls_line = f"{tls_info.get('issuer', {}).get('organizationName', '-')} ({tls_info.get('days_left','?')}d left)"

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShadowReconX Report — {target}</title>
<style>
 :root{{--bg:#0b0f14;--panel:#10161d;--panel2:#141c25;--border:#223041;--text:#dbe6f0;
 --dim:#7f92a3;--accent:#22d3ee;--ok:#34d399;--warn:#fbbf24;--error:#f87171;--none:#64748b;}}
 *{{box-sizing:border-box}}
 body{{margin:0;background:radial-gradient(1200px 600px at 10% -10%, #14202b 0%, var(--bg) 60%);
 color:var(--text);font-family:ui-monospace,Consolas,monospace;padding:32px 20px 60px;}}
 .wrap{{max-width:940px;margin:0 auto}}
 header{{display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px;
 border-bottom:1px solid var(--border);padding-bottom:20px;margin-bottom:28px}}
 .logo{{font-size:26px;font-weight:700;background:linear-gradient(90deg,var(--accent),#a78bfa);
 -webkit-background-clip:text;background-clip:text;color:transparent}}
 .meta{{text-align:right;color:var(--dim);font-size:12px}}
 .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:32px}}
 .card{{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px 18px}}
 .card .label{{color:var(--dim);font-size:11px;text-transform:uppercase}}
 .card .value{{font-size:20px;font-weight:700;margin-top:6px;color:var(--accent)}}
 h2{{font-size:14px;text-transform:uppercase;letter-spacing:1.5px;color:var(--accent);margin:0 0 14px}}
 .table-wrap{{background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:32px}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 thead th{{text-align:left;background:var(--panel2);color:var(--dim);font-size:11px;
 text-transform:uppercase;padding:12px 16px;border-bottom:1px solid var(--border)}}
 tbody td{{padding:10px 16px;border-bottom:1px solid var(--border)}}
 tbody tr:last-child td{{border-bottom:none}}
 .badge{{display:inline-block;min-width:60px;text-align:center;padding:3px 8px;border-radius:6px;
 font-weight:700;font-size:12px;border:1px solid transparent}}
 .st-ok{{color:var(--ok);background:rgba(52,211,153,.12);border-color:rgba(52,211,153,.35)}}
 .st-warn{{color:var(--warn);background:rgba(251,191,36,.12);border-color:rgba(251,191,36,.35)}}
 .st-error{{color:var(--error);background:rgba(248,113,113,.12);border-color:rgba(248,113,113,.35)}}
 footer{{margin-top:40px;padding-top:18px;border-top:1px solid var(--border);color:var(--dim);
 font-size:11px;text-align:center}}
 footer .warn{{color:var(--warn)}}
</style></head><body><div class="wrap">
 <header>
   <div><div class="logo">ShadowReconX</div>
   <div style="color:var(--dim);font-size:13px;margin-top:4px">Full host recon report</div></div>
   <div class="meta"><div style="color:var(--text);font-size:15px;font-weight:600">{target}</div>
   <div>Generated {timestamp}</div></div>
 </header>
 <div class="cards">
   <div class="card"><div class="label">Resolved IP</div><div class="value">{ip}</div></div>
   <div class="card"><div class="label">Ping</div><div class="value">{up}</div></div>
   <div class="card"><div class="label">HTTP / HTTPS</div><div class="value">{http_s} / {https_s}</div></div>
   <div class="card"><div class="label">OS Guess</div><div class="value" style="font-size:13px">{os_guess}</div></div>
   <div class="card"><div class="label">TLS Issuer</div><div class="value" style="font-size:13px">{tls_line}</div></div>
   <div class="card"><div class="label">Scan Engine</div><div class="value" style="font-size:16px">{engine_used}</div></div>
 </div>

 <h2>Open / Closed / Filtered Ports</h2>
 <div class="table-wrap">
   <table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version / Banner</th></tr></thead>
   <tbody>{port_rows if port_rows else '<tr><td colspan=4 style="padding:20px;color:var(--dim)">No ports found open.</td></tr>'}</tbody></table>
 </div>

 <h2>Security Headers</h2>
 <div class="table-wrap">
   <table><thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead>
   <tbody>{header_rows if header_rows else '<tr><td colspan=3 style="padding:20px;color:var(--dim)">Not checked.</td></tr>'}</tbody></table>
 </div>

 <h2>Interesting Paths</h2>
 <div class="table-wrap">
   <table><thead><tr><th>Path</th><th>Status</th></tr></thead>
   <tbody>{path_rows if path_rows else '<tr><td colspan=2 style="padding:20px;color:var(--dim)">Nothing found / not checked.</td></tr>'}</tbody></table>
 </div>

 <footer>Generated by ShadowReconX — read-only checks only.<br>
 <span class="warn">Only test hosts you are explicitly authorized to assess.</span></footer>
</div></body></html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


# --------------------------------------------------------------------------
# Per-target orchestration
# --------------------------------------------------------------------------

def run_target(target, ports, cfg):
    print(f"\n{C.CYAN}{C.BOLD}=== Target: {target} ==={C.RESET}\n")

    domain_info = module_domain_status(target, timeout=max(cfg["timeout"], 5))
    if not domain_info:
        return None
    ip = domain_info["ip"]

    tls_info = module_tls_cert(target, timeout=max(cfg["timeout"], 5))
    scheme = "https" if tls_info else "http"
    headers_info = module_security_headers(target, scheme, timeout=max(cfg["timeout"], 5))

    port_states, banners, engine_used = module_port_scan(
        ip, ports, cfg["threads"], cfg["timeout"], cfg["delay"],
        engine=cfg["engine"], rate=cfg["rate"])

    path_results = []
    if cfg["probe_paths"]:
        path_results = module_path_probe(target, scheme, timeout=max(cfg["timeout"], 5))

    target_dir = save_results(target, domain_info, tls_info, headers_info,
                               port_states, banners, path_results, engine_used)

    if cfg["save_html"]:
        html_dir = os.path.join(target_dir, "HTML")
        os.makedirs(html_dir, exist_ok=True)
        html_path = os.path.join(html_dir, f"{target}_report.html")
        generate_html_report(target, domain_info, tls_info, headers_info,
                              port_states, banners, path_results, html_path, engine_used)
        print(f"{C.GREEN}HTML report saved to {html_path}{C.RESET}")

    return target_dir


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    banner()
    cfg = load_config()

    targets = ask_targets()

    port_choice = ask_choice(
        "Which ports do you want to scan?",
        [("common", f"Common ports ({len(COMMON_PORTS)} well-known ports) - fast"),
         ("full", "Full range 1-65535 - slow, thorough"),
         ("custom", "Custom range / list (e.g. 22,80,1-1024)")],
        default_index={"common": 0, "full": 1, "custom": 2}[cfg["port_mode"]],
    )
    if port_choice == "common":
        ports = COMMON_PORTS
    elif port_choice == "full":
        ports = list(range(1, 65536))
    else:
        spec = ask("Enter ports (e.g. 22,80,443 or 1-1024)", cfg["custom_ports"])
        ports = parse_ports(spec)
        cfg["custom_ports"] = spec
    cfg["port_mode"] = port_choice

    # Scan engine selection (shows what is installed on this machine)
    engine_options = [("auto", "Auto - best installed engine for the scan size")]
    for key, (label, _binary, needs_root) in ENGINES.items():
        status = "installed" if engine_available(key) else "not installed"
        if key == "builtin":
            status = "always available"
        note = f"{label} [{status}]"
        if key == "masscan" and engine_available(key) and not is_root():
            note += " (not running as root)"
        engine_options.append((key, note))
    keys = [k for k, _ in engine_options]
    default_idx = keys.index(cfg["engine"]) if cfg["engine"] in keys else 0
    cfg["engine"] = ask_choice("Which port-scan engine?", engine_options, default_idx)

    if cfg["engine"] in ("auto", "masscan", "rustscan", "naabu"):
        try:
            cfg["rate"] = int(ask("Packet rate for external engines (packets/sec; keep low)",
                                  str(cfg["rate"])))
        except (TypeError, ValueError):
            pass

    if ask_yes_no("Customize threads/timeout/delay? (defaults shown are your saved settings)", "n"):
        cfg["threads"] = int(ask("Number of threads (builtin engine)", str(cfg["threads"])))
        cfg["timeout"] = float(ask("Per-port timeout in seconds", str(cfg["timeout"])))
        cfg["delay"] = float(ask("Delay between port probes in seconds (builtin only)", str(cfg["delay"])))

    cfg["probe_paths"] = ask_yes_no("Probe common sensitive paths (.env, .git, admin, etc.)?",
                                     "y" if cfg["probe_paths"] else "n")
    cfg["save_html"] = ask_yes_no("Save an HTML report per target?",
                                   "y" if cfg["save_html"] else "n")

    if ask_yes_no("Save these as your new defaults for next time?", "y"):
        save_config(cfg)

    start = time.time()
    results_dirs = []
    for t in targets:
        d = run_target(t, ports, cfg)
        if d:
            results_dirs.append(d)
    elapsed = time.time() - start
    log_history(targets, elapsed)

    hr("=")
    print(f"{C.GREEN}{C.BOLD}All done!{C.RESET} Scanned {len(targets)} target(s) in {elapsed:.1f}s.")
    for d in results_dirs:
        print(f"  {C.CYAN}{d}/{C.RESET}")
    print(f"  {C.GREY}History log: {HISTORY_PATH}{C.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}Interrupted by user (Ctrl+C).{C.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{C.RED}Unexpected error: {e}{C.RESET}")
        sys.exit(1)
