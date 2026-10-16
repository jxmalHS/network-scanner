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


class ReportSaveError(Exception):
    """The report file could not be written (folder not writable, disk full, file locked)."""


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
    parser = argparse.ArgumentParser(description="Tamer: network vulnerability scanner")
    parser.add_argument("host", type=valid_host, help="Target host or IP address")
    parser.add_argument("--ports", nargs="+", type=port_number, default=COMMON_PORTS, help="Ports to scan")
    parser.add_argument("--workers", type=worker_count, default=DEFAULT_WORKERS,
                        help=f"Ports to check at the same time (1-{MAX_WORKERS}, default {DEFAULT_WORKERS})")
    parser.add_argument("--debug", action="store_true",
                        help="On an internal error, also print the full Python traceback (for bug reports)")
    args = parser.parse_args()

    saved: dict[str, str] = {}          # run_scan fills in "report" once the file is on disk
    try:
        had_internal_errors = run_scan(args, saved)
    except KeyboardInterrupt:
        # \n: the terminal echoes ^C on the current line
        if "report" in saved:
            print(f"\n[!] Scan interrupted by keyboard input (Ctrl+C) — the report was already "
                  f"saved: {saved['report']}")
        else:
            print("\n[!] Scan interrupted by keyboard input (Ctrl+C) — stopped early, no report was written")
        sys.exit(130)                  # 128 + 2 (SIGINT): the usual "stopped by Ctrl+C" code
    except HostResolutionError as e:
        print(f"\n[!] Could not resolve host: {e}")   # no report: there is nothing to assess
        sys.exit(1)
    except ReportSaveError as e:
        print(f"\n[!] Could not save the report: {e}. Check that this folder is writable "
              f"and the disk isn't full. The results above were not saved.")
        sys.exit(4)
    except Exception as e:             # not BaseException: Ctrl+C and SystemExit pass through
        report = (f", but the report was already saved: {saved['report']}" if "report" in saved
                  else "; no report was written")
        print(f"\n[!] Internal error: {_bug_detail(e)} — this is a bug in the scanner, "
              f"please report it. The scan stopped{report}.")
        if args.debug:
            _print_traceback(e)
        sys.exit(5)
    if had_internal_errors:
        sys.exit(3)                    # report written, but some checks hit a bug (see README table)


def _print_traceback(e: BaseException) -> None:
    """The full traceback on stderr, one cleaned line at a time, each starting with "[debug] ".

    Error messages can carry text from the scanned host, so every line goes through clean_text
    (its indentation is put back afterwards), and the prefix stops any line posing as a result.
    """
    for line in "".join(traceback.format_exception(e)).splitlines():
        indent = len(line) - len(line.lstrip(" "))
        print(f"[debug] {' ' * indent}{clean_text(line)}", file=sys.stderr)


def _bug_detail(e: Exception) -> str:
    """'Type: message (file line N)' for a bug, with the message made safe to print."""
    frame = traceback.extract_tb(e.__traceback__)[-1]
    return (f"{type(e).__name__}: {clean_text(str(e))} "
            f"({os.path.basename(frame.filename)} line {frame.lineno})")


def _run_check(label: str, key: str, errors: dict[str, str], func, *args, debug: bool = False):
    """Run one check; if it crashes because of a bug in the scanner, say so loudly and go on.

    The other checks still run and the report is still written, but the bug is shown on the
    console, in that report section, and through exit code 3. Ctrl+C and "host not found"
    are not bugs, so they pass straight through.
    """
    try:
        return func(*args)
    except HostResolutionError:
        raise
    except Exception as e:                  # Exception, not BaseException: Ctrl+C passes through
        detail = _bug_detail(e)
        print(f"[!] Internal error in {label}: {detail} — this is a bug in the scanner, "
              f"please report it")
        if debug:
            _print_traceback(e)
        errors[key] = detail
        return None


def run_scan(args: argparse.Namespace, saved: dict[str, str]) -> bool:
    """Run every check in order and write the report. True if any check hit an internal error.

    Puts the report's filename in saved["report"] as soon as it is written, so main() can say
    so if Ctrl+C or a bug stops things after that point.
    """
    host = args.host
    ports = args.ports
    errors: dict[str, str] = {}

    # Look the name up once (raises HostResolutionError), so the port scan and the report
    # both use the same address. The other checks keep the name: TLS needs it.
    _, address = resolve_host(host)
    target = host if address == host else f"{host} ({address})"

    print(f"\n[*] Starting scan on {target}")

    print(f"[*] Scanning {len(ports)} ports ({args.workers} at a time)...")
    open_ports = _run_check("the port scan", "ports", errors, scan_ports, address, ports, args.workers,
                            debug=args.debug)
    for entry in open_ports or []:
        if entry["banner"]:
            print(f"[+] Port {entry['port']} open — {entry['banner'][:50]}")
        elif entry["banner"] == "":
            print(f"[+] Port {entry['port']} open — (non-printable reply)")
        else:
            print(f"[+] Port {entry['port']} open — no banner")

    print("[*] Checking security headers...")
    header_results = _run_check("the header check", "headers", errors, check_headers, host,
                                debug=args.debug)

    print("[*] Checking for open redirects...")
    redirect_results = _run_check("the redirect check", "redirects", errors, check_open_redirect, host,
                                  debug=args.debug)
    if redirect_results is not None and (
            not redirect_results["complete"] or redirect_results["probes_skipped"] > 0):
        print("[!] Redirect check incomplete — see the report for details")

    print("[*] Checking SSL/TLS certificate...")
    ssl_results = _run_check("the SSL/TLS check", "ssl", errors, check_ssl, host,
                             debug=args.debug)

    print("[*] Generating report...")
    try:
        filename = generate_report(host, open_ports, header_results, redirect_results, ssl_results,
                                   address=address, internal_errors=errors)
    except OSError as e:               # PermissionError after the retries, disk full, ...
        raise ReportSaveError(clean_text(str(e))) from e
    saved["report"] = filename         # before any print: Ctrl+C can land from here on
    print(f"[+] Report saved to {filename}\n")
    if errors:
        print(f"[!] {len(errors)} check(s) hit an internal error; their report sections are incomplete")
    return bool(errors)

if __name__ == "__main__":
    main()