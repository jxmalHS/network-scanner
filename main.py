import argparse
import ipaddress
import re
import sys
from scanner import DEFAULT_WORKERS, HostResolutionError, resolve_host, scan_ports
from headers import check_headers
from reporter import generate_report
from redirects import check_open_redirect
from ssl_checker import check_ssl

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
        if ip.version == 6 and ip.is_link_local:   # fe80::/10
            raise argparse.ArgumentTypeError(
                f"link-local IPv6 addresses (fe80::...) aren't supported: they only work with a "
                f"zone ID naming the network card, and without one every port would wrongly "
                f"look closed: {value!r}")
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


def main() -> None:
    _safe_console()
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("host", type=valid_host, help="Target host or IP address")
    parser.add_argument("--ports", nargs="+", type=port_number, default=COMMON_PORTS, help="Ports to scan")
    parser.add_argument("--workers", type=worker_count, default=DEFAULT_WORKERS,
                        help=f"Ports to check at the same time (1-{MAX_WORKERS}, default {DEFAULT_WORKERS})")
    args = parser.parse_args()

    try:
        run_scan(args)
    except KeyboardInterrupt:
        print("\n[!] Scan aborted")   # \n: the terminal echoes ^C on the current line
        sys.exit(130)                  # 128 + 2 (SIGINT): the usual "stopped by Ctrl+C" code
    except HostResolutionError as e:
        print(f"\n[!] Could not resolve host: {e}")   # no report: there is nothing to assess
        sys.exit(1)


def run_scan(args: argparse.Namespace) -> None:
    """Run every check in order and write the report."""
    host = args.host
    ports = args.ports

    # Look the name up once (raises HostResolutionError), so the port scan and the report
    # both use the same address. The other checks keep the name: TLS needs it.
    _, address = resolve_host(host)
    target = host if address == host else f"{host} ({address})"

    print(f"\n[*] Starting scan on {target}")

    print(f"[*] Scanning {len(ports)} ports ({args.workers} at a time)...")
    open_ports = scan_ports(address, ports, args.workers)
    for entry in open_ports:
        if entry["banner"]:
            print(f"[+] Port {entry['port']} open — {entry['banner'][:50]}")
        elif entry["banner"] == "":
            print(f"[+] Port {entry['port']} open — (non-printable reply)")
        else:
            print(f"[+] Port {entry['port']} open — no banner")

    print("[*] Checking security headers...")
    header_results = check_headers(host)

    print("[*] Checking for open redirects...")
    redirect_results = check_open_redirect(host)
    if not redirect_results["complete"] or redirect_results["probes_skipped"] > 0:
        print("[!] Redirect check incomplete — see the report for details")

    print("[*] Checking SSL/TLS certificate...")
    ssl_results = check_ssl(host)
    
    print("[*] Generating report...")
    filename = generate_report(host, open_ports, header_results, redirect_results, ssl_results,
                               address=address)
    print(f"[+] Report saved to {filename}\n")

if __name__ == "__main__":
    main()