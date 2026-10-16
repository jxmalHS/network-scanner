# Tamer

A network vulnerability scanner: a command line tool that scans a target host for common security vulnerabilities.

## What it checks

- **Open ports** — identifies which ports are accepting connections and grabs service banners to identify running software and versions
- **HTTP security headers** — checks for missing headers that leave users exposed to common attacks. For HSTS it also flags a short max-age, a header that doesn't cover subdomains (`[INFO]`, no `includeSubDomains`), and a `preload` request whose header doesn't meet the preload list's header rules, `includeSubDomains` and a max-age of at least 1 year (`[WARNING]`; the list's other rules aren't checked). Only the target's own header is read; no preload list is ever looked up.
- **Open redirects** — tests whether the server blindly follows external redirect parameters
- **SSL/TLS certificate** — checks whether HTTPS is enabled, validates the certificate expiry date, and flags expired or domain-mismatched certificates

## Installation

Clone the repository and install dependencies:

```powershell
git clone https://github.com/jxmalHS/network-scanner.git
cd network-scanner
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Requirements

- **Python 3.14 (recommended).** It's the only version the scanner is tested on. Its HTML parser
  has a `scripting=True` option that reads `<noscript>` the way a browser with JavaScript on does,
  which the open redirect check uses. Python's parser is still not a full browser parser, so very
  unusual HTML can be read differently on any version.
- **Python 3.11 to 3.13 should also work, but aren't tested.** The code needs at least 3.11, and
  its libraries (`requests`, `urllib3`, `pytest`) need at least 3.10. On these versions a fallback
  handles `<noscript>`, but unusual HTML is more likely to be read differently, because Python's
  built-in HTML parser has changed between versions.
- **Python 3.10 and older won't run it.**

Check your version with `python --version`.

## Usage

Basic scan using common ports:

```powershell
python main.py <host>
```

Scan specific ports:

```powershell
python main.py <host> --ports 80 443 22
```

Check more ports at the same time (default 20, max 200). Keep this low on hosts you don't own:

```powershell
python main.py <host> --workers 50
```

For a slower, gentler scan, use fewer workers (only ever on hosts you're allowed to scan):

```powershell
python main.py scanme.nmap.org --workers 2
```

If the scanner reports an internal error (a bug), run it again with `--debug` to also print the
full Python error details (traceback) for a bug report:

```powershell
python main.py localhost --debug
```

The details can contain text sent by the scanned host, so read them before sharing.

**IPv4 vs IPv6:** when a host name has both an IPv4 and an IPv6 address, the port scan uses the
IPv4 one (the report shows which, e.g. `Target: localhost (127.0.0.1)`). Add `--ipv6` to port-scan
its IPv6 address instead:

```powershell
python main.py localhost --ipv6
```

If the name has no IPv6 address, the scan stops with exit code 1 rather than quietly using IPv4.
`--ipv6` with an IPv4 address (e.g. `python main.py 127.0.0.1 --ipv6`) is refused (exit code 2).
Your own machine needs working IPv6 too: without it every port fails to connect and looks closed.

To port-scan **both** addresses, use `--dual-stack`. Open ports are listed per address in the
report, which shows when a firewall treats IPv4 and IPv6 differently:

```powershell
python main.py scanme.nmap.org --dual-stack
```

It sends twice as many connection attempts (each port is tried on both addresses), so it's off by
default. It needs a host name with both an IPv4 and an IPv6 address (otherwise exit code 1), and it
can't be combined with `--ipv6` or used with an IP address (exit code 2). Only scan names you're
allowed to test: in rare setups a name's IPv6 address is a different machine (e.g. a CDN).

The header, redirect and certificate checks always connect by name, so your operating system picks
which address they use, with or without `--ipv6`; the report says so when `--ipv6` is used. To make
every check use one address, pass the address itself, e.g. `python main.py ::1`. The certificate's
name check will then report a mismatch, because certificates are issued for names, not raw addresses.

Link-local IPv6 addresses (`fe80::...`) aren't supported: passing one is refused, and a host
name's link-local addresses are skipped. If a name has no other address (common for `.local`
printers and similar devices), the scan stops with exit code 1.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan finished and the report was written (also `--help`, which scans nothing) |
| 1 | The host name could not be resolved, or it has no address that can be scanned, or `--ipv6`/`--dual-stack` was used and it lacks the address needed (no report written) |
| 2 | Bad arguments, e.g. an invalid host, port or `--workers` value, or `--ipv6` with `--dual-stack` (nothing scanned) |
| 3 | Internal error: a bug in the scanner stopped one or more checks. The report was still written, but those sections are incomplete. Run again with `--debug` to see the full error |
| 4 | The report could not be saved (for example the folder isn't writable or the disk is full). The results were only shown on screen |
| 5 | Scanner bug outside the checks: the scan stopped. The console says what went wrong and whether a report was saved; please report it. Also used, silently, if the console output itself breaks (e.g. the output was piped into a command that stopped reading early) |
| 130 | Stopped with Ctrl+C (`[!] Scan interrupted by keyboard input (Ctrl+C) — stopped early, no report was written`). If you press Ctrl+C just after the report was saved, the message says so and names the file |

## Example

```powershell
python main.py scanme.nmap.org
```

## How the open redirect check behaves

- It sends 32 probes (4 pages × 8 parameters) that point at a reserved `.invalid` address, and
  **never follows a redirect** — it only reads where the server says to go. Only the target
  host is ever contacted.
- Probes go out one at a time with a 0.2 s pause between them, through one connection client
  that stores no cookies (so every probe is independent).
- If plain HTTP redirects to HTTPS (or can't be reached), the probes are sent to `https://`
  instead; this is decided by the first answered probe among the first 4.
- One failed connection only skips that probe; the check stops after 2 failed connections in a
  row, or at once on a TLS/certificate problem.
- A page that isn't a redirect can still redirect a browser. The check also looks at a
  `Refresh:` response header and, for HTML pages only, a `<meta http-equiv="refresh">` tag in
  the first 64 KB of the page. Neither is ever followed.
- This applies to any page a browser would show, error pages included (401, 403, 404, 500…),
  a 3xx answer without a `Location`, and a 300 even with one. Only 301/302/303/307/308 with a
  `Location` count as redirects, and 204/205/304 answers (no page to show) are never judged; an invalid Content-Type such as `text` counts as no type.
- Refresh values are read with the same rules browsers use (so `0url=…` or a delay written in
  non-ASCII digits is ignored, as a browser would), and UTF-16 pages (marked by a byte order
  mark or a `charset=utf-16` in `Content-Type`) are decoded correctly.
- A meta refresh inside `<noscript>` or `<template>` is ignored, as browsers with JavaScript on
  ignore it (so a refresh meant only for visitors with JavaScript off is not reported).
- A page counts as HTML if its `Content-Type` says so, or, when it has no usable type (missing,
  empty or "unknown") and doesn't send `X-Content-Type-Options: nosniff`, if its first bytes
  look like HTML the way a browser guesses. Any other stated type (JSON, images,
  `application/octet-stream`…) is never read.
- On sites with many error pages or untyped pages the check can take longer, since more pages
  are read — still capped at 64 KB and 5 s per page and 36 requests in total.
- **JavaScript redirects are not detected.** Spotting them reliably would mean running the
  page's scripts like a browser does; just searching the page for the test address would flag
  every page that merely echoes the parameter back, giving false alarms.
- **Worst case:** at most 36 requests (up to 4 over HTTP, then 32 over HTTPS), about 0.2 s
  apart — roughly 7 s plus network time (each probe waits at most 5 s for an answer), and up
  to 64 KB read from each HTML page, for at most 5 s more per page however slowly it arrives.
- If the check could not finish, or some probes got no usable answer, the console prints
  `[!] Redirect check incomplete — see the report for details`.

## Project Structure

- `scanner.py` — TCP port scanning with service banner grabbing
- `headers.py` — HTTP security header checks
- `redirects.py` — open redirect detection
- `textsafe.py` — makes server-controlled text safe to print (one printable line)
- `urltools.py` — shared URL helpers (real host of a URL, IPv6 brackets)
- `ssl_checker.py` — SSL/TLS certificate checks (expiry, issuer, domain match)
- `reporter.py` — generates timestamped report files
- `main.py` — CLI interface

## Legal

Only scan hosts you have permission to scan. This tool was tested against scanme.nmap.org, a server maintained by the nmap project for legal scanning practice.
