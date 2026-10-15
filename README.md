# Network Vulnerability Scanner

A command line tool that scans a target host for common security vulnerabilities.

## What it checks

- **Open ports** — identifies which ports are accepting connections and grabs service banners to identify running software and versions
- **HTTP security headers** — checks for missing headers that leave users exposed to common attacks
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
- A normal page (status 200, no redirect) can still redirect a browser. The check also looks at
  a `Refresh:` response header and, for HTML pages only, a `<meta http-equiv="refresh">` tag in
  the first 64 KB of the page. Neither is ever followed.
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
- `ssl_checker.py` — SSL/TLS certificate checks (expiry, issuer, domain match)
- `reporter.py` — generates timestamped report files
- `main.py` — CLI interface

## Legal

Only scan hosts you have permission to scan. This tool was tested against scanme.nmap.org, a server maintained by the nmap project for legal scanning practice.
