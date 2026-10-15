import argparse
import ipaddress
import os
import re
import signal
import sys
import traceback
from scanner import DEFAULT_WORKERS, HostResolutionError, resolve_host, scan_ports
from headers import check_headers
from reporter import generate_report
from redirects import check_open_redirect
from ssl_checker import check_ssl
from textsafe import clean_text

COMMON_PORTS = [21,22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 8080, 8443]


def valid_host(value: str) -> str:
    """Accept a plain hostname or IP address; reject anything that could point elsewhere."""
    if "%" in value:                           # IPv6 zone IDs (fe80::1%eth0) break URLs
        raise argparse.ArgumentTypeError(f"IPv6 zone IDs (%...) are not supported: {value!r}")
    try:
        ip = ipaddress.ip_address(value)       # IPv4 or IPv6 address
    except ValueError:
        ip = None
    if ip is not None:
        # Link-local IPv6 (fe80::/10), any multicast (IPv4 224.0.0.0/4, IPv6 ff00::/8) and the
        # IPv4 broadcast address aren't single hosts you can port-scan.
        if ((ip.version == 6 and ip.is_link_local) or ip.is_multicast
                or ip == ipaddress.ip_address("255.255.255.255")):
            raise argparse.ArgumentTypeError(
                f"link-local, multicast and broadcast addresses (fe80::..., ff..::..., "
                f"224-239.x.x.x, 255.255.255.255) aren't supported: they aren't a single host you "
                f"can port-scan, so every port would wrongly look closed: {value!r}")
        return value
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value):
        raise argparse.ArgumentTypeError(f"not a plain hostname or IP address: {value!r}")
    return value


MAX_WORKERS = 200
MAX_PORT = 65535


def port_number(value: str) -> int:
    """Accept a whole-number port between 1 and MAX_PORT."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {value!r}")
    if not 1 <= number <= MAX_PORT:
        raise argparse.ArgumentTypeError(f"port must be between 1 and {MAX_PORT}, got {number}")
    return number


def worker_count(value: str) -> int:
    """Accept a whole number of worker threads between 1 and MAX_WORKERS."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {value!r}")
    if not 1 <= number <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_WORKERS}, got {number}")
    return number


def _safe_console() -> None:
    """Show characters the console can't encode as '?' instead of crashing.

    E.g. with output redirected to a file on Windows (cp1252), a banner with Vietnamese
    accents would otherwise raise UnicodeEncodeError. The saved report stays full UTF-8.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)   # StringIO and some wrappers lack it
        if reconfigure is not None:
            reconfigure(errors="replace")


def _interrupt_once(signum: int, frame: object) -> None:
    """Ctrl+C handler: the first press stops the scan; later presses are ignored.

    Switching to "ignore" here, at the very first press, also covers the cleanup that runs
    while the scan unwinds (the last port scans finishing, temp files being removed), so a
    second press can't interrupt that cleanup and make Python print shutdown noise.
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise KeyboardInterrupt


def main() -> None:
    _safe_console()
    signal.signal(signal.SIGINT, _interrupt_once)
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("host", type=valid_host, help="Target host or IP address")
    parser.add_argument("--ports", nargs="+", type=port_number, default=COMMON_PORTS, help="Ports to scan")
    parser.add_argument("--workers", type=worker_count, default=DEFAULT_WORKERS,
                        help=f"Ports to check at the same time (1-{MAX_WORKERS}, default {DEFAULT_WORKERS})")
    args = parser.parse_args()

    try:
        had_internal_errors = run_scan(args)
    except KeyboardInterrupt:
        print("\n[!] Scan aborted")   # \n: the terminal echoes ^C on the current line
        sys.exit(130)                  # 128 + 2 (SIGINT): the usual "stopped by Ctrl+C" code
    except HostResolutionError as e:
        print(f"\n[!] Could not resolve host: {e}")   # no report: there is nothing to assess
        sys.exit(1)
    if had_internal_errors:
        sys.exit(1)                    # the report was written, but some checks didn't run


def _run_check(label: str, key: str, errors: dict[str, str], func, *args):
    """Run one check; if it crashes because of a bug in the scanner, say so loudly and go on.

    The other checks still run and the report is still written, but the bug is shown on the
    console, in that report section, and through exit code 1. Ctrl+C and "host not found"
    are not bugs, so they pass straight through.
    """
    try:
        return func(*args)
    except HostResolutionError:
        raise
    except Exception as e:                  # Exception, not BaseException: Ctrl+C passes through
        frame = traceback.extract_tb(e.__traceback__)[-1]
        detail = (f"{type(e).__name__}: {clean_text(str(e))} "
                  f"({os.path.basename(frame.filename)} line {frame.lineno})")
        print(f"[!] Internal error in {label}: {detail} — this is a bug in the scanner, "
              f"please report it")
        errors[key] = detail
        return None


def run_scan(args: argparse.Namespace) -> bool:
    """Run every check in order and write the report. True if any check hit an internal error."""
    host = args.host
    ports = args.ports
    errors: dict[str, str] = {}

    # Look the name up once (raises HostResolutionError), so the port scan and the report
    # both use the same address. The other checks keep the name: TLS needs it.
    _, address = resolve_host(host)
    target = host if address == host else f"{host} ({address})"

    print(f"\n[*] Starting scan on {target}")

    print(f"[*] Scanning {len(ports)} ports ({args.workers} at a time)...")
    open_ports = _run_check("the port scan", "ports", errors, scan_ports, address, ports, args.workers)
    for entry in open_ports or []:
        if entry["banner"]:
            print(f"[+] Port {entry['port']} open — {entry['banner'][:50]}")
        elif entry["banner"] == "":
            print(f"[+] Port {entry['port']} open — (non-printable reply)")
        else:
            print(f"[+] Port {entry['port']} open — no banner")

    print("[*] Checking security headers...")
    header_results = _run_check("the header check", "headers", errors, check_headers, host)

    print("[*] Checking for open redirects...")
    redirect_results = _run_check("the redirect check", "redirects", errors, check_open_redirect, host)
    if redirect_results is not None and (
            not redirect_results["complete"] or redirect_results["probes_skipped"] > 0):
        print("[!] Redirect check incomplete — see the report for details")

    print("[*] Checking SSL/TLS certificate...")
    ssl_results = _run_check("the SSL/TLS check", "ssl", errors, check_ssl, host)

    print("[*] Generating report...")
    filename = generate_report(host, open_ports, header_results, redirect_results, ssl_results,
                               address=address, internal_errors=errors)
    print(f"[+] Report saved to {filename}\n")
    if errors:
        print(f"[!] {len(errors)} check(s) hit an internal error; their report sections are incomplete")
    return bool(errors)

if __name__ == "__main__":
    main()