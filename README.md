# ShadowReconX 🕶️

**Interactive host recon toolkit** — built for teaching the basics of host-level
reconnaissance methodology (DNS resolution, HTTP status checks, TLS certificate
inspection, security-header review, port scanning, and common-path probing).

Run it, answer a few prompts, and ShadowReconX walks through the full recon
workflow automatically, showing progress live and producing clean table output
plus JSON, CSV, and HTML reports.

---

## ⚠️ Authorized Use Only

This tool performs **read-only, unauthenticated** checks only — no credential
bruteforce, no exploitation, no destructive actions. Even so:

> **Only run ShadowReconX against domains/hosts you own or are explicitly
> authorized to test.** Unauthorized scanning of systems you don't have
> permission to test may be illegal in your jurisdiction, regardless of intent.

Safe targets to practice on:
- `example.com` (IANA-reserved, safe to resolve/probe)
- `testphp.vulnweb.com` (Acunetix's public vulnerable test site)
- `demo.testfire.net` (IBM's intentionally vulnerable demo bank)
- `scanme.nmap.org` (explicitly provided for scan practice; be polite with rate)
- Your own domains/servers, or in-scope bug bounty targets you've verified

---

## What it does

ShadowReconX replicates a 5-step manual recon methodology:

| Step | What happens |
|------|--------------|
| 1 | **Domain status** — resolves the hostname, checks HTTP/HTTPS status, pings the host, and guesses the OS from the TTL |
| 2 | **TLS certificate** — retrieves issuer, subject, expiry (with days left), and SANs |
| 3 | **Security headers** — checks HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| 4 | **Port scan** — open/closed/filtered detection, service name, version/banner grab, and a firewall hint |
| 5 | **Path probe** — checks common sensitive paths (`robots.txt`, `.git/config`, `.env`, `/admin`, `/api`, etc.) |

## Features

- ✅ **Fully interactive** — just run it and answer the prompts, no CLI flags required
- ✅ **Multi-target support** — comma-separated targets, or a file with one target per line
- ✅ **Pluggable scan engines** — built-in, `masscan`, `rustscan`, `naabu`, or `auto`
- ✅ **Automatic fallback** — if an engine is missing or fails, it falls back to the built-in scanner
- ✅ **Banner grabbing** — HTTP and TLS-aware (HEAD request over TLS for 443/8443 etc.)
- ✅ **Remembers your settings** between runs (`~/.shadowreconx.json`)
- ✅ **ASCII banner**, live progress bars with ETA, and color-coded Unicode tables
- ✅ **JSON + CSV export**, per-state port folders, and a modern dark **HTML report**
- ✅ **Run history log** (`~/.shadowreconx_history.log`)
- ✅ Graceful `Ctrl+C` handling — no raw tracebacks
- ✅ **No Python dependencies** — pure standard library
- ✅ **No Nmap required** — and none is ever invoked

## Requirements

- Python 3.8+
- Internet access (DNS, HTTP, TLS, and the target itself)
- No `pip install` needed
- *Optional* external scan engines (only if you want faster scans of large port ranges):

| Engine | Notes |
|--------|-------|
| [`masscan`](https://github.com/robertdavidgraham/masscan) | Fastest. Needs **root/admin** (raw sockets). IPv4 only. |
| [`rustscan`](https://github.com/RustScan/RustScan) | Fast connect scan. Run with `--scripts none`, so no Nmap hand-off. |
| [`naabu`](https://github.com/projectdiscovery/naabu) | ProjectDiscovery scanner, run in connect mode (no root needed). |

## Usage

```bash
git clone https://github.com/Zeeshan2374/ShadowReconX.git
cd ShadowReconX
python3 shadowreconx.py
```

To use `masscan`, run with elevated privileges:

```bash
sudo python3 shadowreconx.py
```

You'll be prompted step by step, e.g.:

```
? Enter target(s): comma-separated, or a path to a file (one per line): testphp.vulnweb.com
? Which ports do you want to scan?
    * 1) Common ports (24 well-known ports) - fast
      2) Full range 1-65535 - slow, thorough
      3) Custom range / list (e.g. 22,80,1-1024)
  Choose [1-3] [1]:
? Which port-scan engine?
    * 1) Auto - best installed engine for the scan size
      2) Built-in Python connect scan (no dependencies) [always available]
      3) masscan  - fastest, async (needs root + masscan) [not installed]
      4) RustScan - fast connect scan (Nmap hand-off disabled) [not installed]
      5) naabu    - ProjectDiscovery, connect mode [not installed]
  Choose [1-5] [1]:
```

Press Enter to accept defaults and let it run.

### Scan engines

| Engine | Needs root | Reports closed/filtered | Best for |
|--------|:----------:|:-----------------------:|----------|
| `builtin` | No | ✅ Yes | Small scans, no dependencies, firewall hint |
| `masscan` | **Yes** | No (open only) | Very large ranges, fast |
| `rustscan` | No | No (open only) | Full-range scans without root |
| `naabu` | No | No (open only) | Full-range scans, clean output |
| `auto` | Depends | Depends | Picks `rustscan` → `naabu` → `masscan` for scans over 1024 ports, otherwise `builtin` |

> **Note:** External engines report open ports only, so the closed/filtered
> counts and firewall hint are available only with the `builtin` engine.
> Banner grabbing runs on all open ports regardless of engine.

> **Be considerate with rate:** the default external-engine rate is 1000
> packets/sec. Keep it low unless you have explicit authorization, since high
> rates can overwhelm small hosts and trip IDS/WAF alerts.

### Port modes

- **Common** — 24 well-known ports (FTP, SSH, SMTP, HTTP(S), SMB, RDP, MySQL, Postgres, Redis, etc.)
- **Full** — all ports 1–65535
- **Custom** — any list or range, e.g. `22,80,443` or `1-1024`

### Settings

If you answer "y" to customize settings you can change threads, per-port
timeout, and delay between probes (built-in engine only). Choices are saved to
`~/.shadowreconx.json` if you accept "Save these as your new defaults."

## Output

Everything from a scan is saved under **one folder per target**, right next to
`shadowreconx.py`:

```
<target>/
  JSON/
    results.json            ← full structured results (status, TLS, headers, ports, paths, engine used)
  CSV/
    ports.csv               ← port, state, service, banner
  Ports/
    open/results.txt        ← "port  state  banner" — one per line
    closed/results.txt      ← (builtin engine only)
    filtered/results.txt    ← (builtin engine only)
  HTML/
    <target>_report.html    ← optional: modern dark-themed HTML report
```

Example, scanning `example.com`:

```
example.com/
  JSON/results.json
  CSV/ports.csv
  Ports/open/results.txt
  HTML/example.com_report.html
```

Each `results.txt` is plain text, grouped by port state — handy for quick
grepping or feeding the open-port list into another tool.

## For instructors / classroom use

This project is designed as a teaching tool for an intro recon/pentesting
module. Suggested exercises:

1. Run it against `testphp.vulnweb.com` and interpret each section of the output
2. Compare the same scan using the `builtin` engine versus `rustscan`/`naabu`,
   and discuss why the results (and available detail) differ
3. Explain why a blocked path like `.git/config` or `.env` may return `403`
   from a WAF rather than `404` from the origin
4. Discuss why TTL-based OS guessing is only a rough heuristic, and how ICMP
   filtering affects it
5. Add a new module (e.g. subdomain enumeration via certificate transparency)
   as a homework extension

## Disclaimer

This project is provided for **educational purposes**. The author and
contributors are not responsible for misuse. By using this tool you agree to
only test systems you own or are explicitly authorized to assess.

## License

MIT — see [LICENSE](LICENSE).
