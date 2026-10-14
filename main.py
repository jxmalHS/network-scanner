import argparse
import ipaddress
import re
import sys
from scanner import DEFAULT_WORKERS, scan_ports
from headers import check_headers
from reporter import generate_report
from redirects import check_open_redirect
from ssl_checker import check_ssl

COMMON_PORTS = [21,22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 8080, 8443]


def valid_host(value: str) -> str:
    """Accept a plain hostname or IP address; reject anything that could point elsewhere."""
    try:
        ipaddress.ip_address(value)            # IPv4 or IPv6 address
        return value
    except ValueError:
        pass
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value):
        raise argparse.ArgumentTypeError(f"not a plain hostname or IP address: {value!r}")
    return value


MAX_WORKERS = 200


def worker_count(value: str) -> int:
    """Accept a whole number of worker threads between 1 and MAX_WORKERS."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {value!r}")
    if not 1 <= number <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_WORKERS}, got {number}")
    return number


def main() -> None:
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("host", type=valid_host, help="Target host or IP address")
    parser.add_argument("--ports", nargs="+", type=int, default=COMMON_PORTS, help="Ports to scan")
    parser.add_argument("--workers", type=worker_count, default=DEFAULT_WORKERS,
                        help=f"Ports to check at the same time (1-{MAX_WORKERS}, default {DEFAULT_WORKERS})")
    args = parser.parse_args()

    try:
        run_scan(args)
    except KeyboardInterrupt:
        print("\n[!] Scan aborted")   # \n: the terminal echoes ^C on the current line
        sys.exit(130)                  # 128 + 2 (SIGINT): the usual "stopped by Ctrl+C" code


def run_scan(args: argparse.Namespace) -> None:
    """Run every check in order and write the report."""
    host = args.host
    ports = args.ports

    print(f"\n[*] Starting scan on {host}")

    print(f"[*] Scanning {len(ports)} ports ({args.workers} at a time)...")
    open_ports = scan_ports(host, ports, args.workers)
    for entry in open_ports:
        if entry["banner"]:
            print(f"[+] Port {entry['port']} open — {entry['banner'][:50]}")
        else:
            print(f"[+] Port {entry['port']} open — no banner")

    print("[*] Checking security headers...")
    header_results = check_headers(host)

    print("[*] Checking for open redirects...")
    redirect_results = check_open_redirect(host)

    print("[*] Checking SSL/TLS certificate...")
    ssl_results = check_ssl(host)
    
    print("[*] Generating report...")
    filename = generate_report(host, open_ports, header_results, redirect_results, ssl_results)
    print(f"[+] Report saved to {filename}\n")

if __name__ == "__main__":
    main()