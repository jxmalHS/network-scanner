import contextlib
import os
import re
import time
from datetime import datetime

from textsafe import clean_text

# Plain-English reason for each cert_problem word from ssl_checker.
CERT_PROBLEM_TEXT = {
    "hostname_mismatch": "name does not match the host",
    "expired": "has expired",
    "not_yet_valid": "is not valid yet",
    "untrusted": "is not from a trusted issuer (self-signed or unknown)",
    "invalid": "failed verification",
}

def _https_failure_kind(header_results: dict) -> str:
    """Plain words for why the HTTPS header check failed."""
    if header_results.get("https_tls_problem"):
        return "TLS problem"
    if header_results.get("https_too_many_redirects"):
        return "too many redirects"
    return "could not connect"


def _hsts_missing_reason(header: str, header_results: dict) -> str:
    """Extra text for a [MISSING] HSTS line when the header was sent but doesn't count."""
    if header != "Strict-Transport-Security" or "hsts_max_age" not in header_results:
        return ""
    if header_results["hsts_max_age"] == 0:
        return " (sent with max-age=0, which switches HSTS off)"
    return " (sent, but max-age is missing or unreadable, so browsers ignore it)"


def generate_report(host, open_ports, header_results, redirect_results, ssl_results, address=None,
                    internal_errors=None):
    """Write the report and return its filename. The file appears complete or not at all."""
    # e.g. "::1" -> "__1" (":" is illegal in Windows filenames); [:100] keeps long names under
    # Windows' 255-character filename limit.
    safe_host = re.sub(r"[^A-Za-z0-9.-]", "_", host)[:100]
    filename = f"report_{safe_host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    tmp = filename + ".tmp"
    try:
        _write_report(tmp, host, open_ports, header_results, redirect_results, ssl_results, address,
                      internal_errors or {})
        _replace_with_retry(tmp, filename)   # one atomic rename: never a half-written report
    except BaseException:              # includes Ctrl+C; always re-raised after cleaning up
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise
    return filename


RENAME_ATTEMPTS = 5


def _replace_with_retry(tmp: str, filename: str) -> None:
    """os.replace, retried briefly if Windows says the file is busy.

    Antivirus or a search indexer can hold a just-written file open for a moment, which
    makes the rename fail with PermissionError; waiting a little usually clears it.
    """
    for attempt in range(RENAME_ATTEMPTS):
        try:
            os.replace(tmp, filename)
            return
        except PermissionError:
            if attempt == RENAME_ATTEMPTS - 1:
                raise
            time.sleep(0.1)


def _internal_error_line(detail: str) -> str:
    """The report line for a check that crashed because of a bug in the scanner itself."""
    return (f"[INTERNAL ERROR] Check did not run: {clean_text(detail)}. This is a bug in the "
            "scanner, not a finding about the target — please report it.\n")


def _write_report(path, host, open_ports, header_results, redirect_results, ssl_results, address,
                  internal_errors):
    """Write every report section to path."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("Tamer - Network Vulnerability Scan Report\n")
        target = host if address in (None, host) else f"{host} ({address})"
        f.write(f"Target: {target}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")

        f.write("OPEN PORTS\n")
        f.write("-" * 20 + "\n")
        if "ports" in internal_errors:
            f.write(_internal_error_line(internal_errors["ports"]))
        else:
            if open_ports:
                for entry in open_ports:
                    if entry["banner"]:
                        f.write(f"[OPEN] Port {entry['port']} — {entry['banner'][:100]}\n")
                    elif entry["banner"] == "":
                        f.write(f"[OPEN] Port {entry['port']} — (non-printable reply)\n")
                    else:
                        f.write(f"[OPEN] Port {entry['port']} — no banner\n")
            else:
                f.write("No open ports found.\n")

        f.write("\nHTTP SECURITY HEADERS\n")
        f.write("-" * 20 + "\n")
        if "headers" in internal_errors:
            f.write(_internal_error_line(internal_errors["headers"]))
        else:
            if "error" in header_results and "https_error" in header_results:
                f.write("Error fetching headers: HTTPS and HTTP both failed\n")
                f.write(f"HTTPS ({_https_failure_kind(header_results)}): "
                        f"{clean_text(header_results['https_error'])}\n")
                f.write(f"HTTP: {clean_text(header_results['error'])}\n")
            elif "error" in header_results:
                f.write(f"Error fetching headers: {clean_text(header_results['error'])}\n")
            else:
                if "url" in header_results:
                    f.write(f"Checked: {clean_text(header_results['url'])}\n")
                if "https_error" in header_results:
                    kind = _https_failure_kind(header_results)
                    f.write(f"[WARNING] HTTPS attempt failed ({kind}) — fell back to http://\n")
                    f.write(f"Details: {clean_text(header_results['https_error'])}\n")
                if "downgraded_from" in header_results:
                    f.write(f"[WARNING] HTTPS redirected to plain HTTP "
                            f"({clean_text(header_results['downgraded_from'])} -> {clean_text(header_results['url'])})\n")
                if "offsite_redirect" in header_results:
                    f.write(f"[INFO] Redirect to another host not followed: {clean_text(header_results['offsite_redirect'])}\n")
                max_age = header_results.get("hsts_max_age")
                for header in header_results["present"]:
                    f.write(f"[PRESENT] {header}\n")
                if header_results.get("hsts_short"):    # headers.py decides what counts as too short
                    if isinstance(max_age, int) and not isinstance(max_age, bool):
                        days = f" (about {max_age // 86400} days)" if max_age >= 86400 else ""
                        f.write(f"[WARNING] HSTS max-age is only {max_age} seconds{days}; "
                                f"6 months or more is recommended\n")
                    else:   # flag set without a usable number: still warn, don't crash
                        f.write("[WARNING] HSTS max-age is shorter than recommended (6 months or more)\n")
                for header in header_results["missing"]:
                    f.write(f"[MISSING] {header}{_hsts_missing_reason(header, header_results)}\n")
                for header in header_results.get("not_applicable", []):
                    f.write(f"[N/A] {header} (only counts over HTTPS)\n")

        f.write("\nOPEN REDIRECT CHECK\n")
        f.write("-" * 20 + "\n")
        if "redirects" in internal_errors:
            f.write(_internal_error_line(internal_errors["redirects"]))
        else:
            r = redirect_results
            http_url = r["base_url"].replace("https://", "http://", 1)
            http_sent = r.get("http_probes_sent") or 0
            earlier = (f" (plus {http_sent} earlier probe{'' if http_sent == 1 else 's'} over HTTP)"
                       if http_sent else "")
            if r.get("switch_reason") == "redirect":
                f.write(f"[INFO] {http_url} redirects to HTTPS; probes were sent to {r['base_url']} "
                        f"instead{earlier}\n")
            elif r.get("switch_reason") == "no_http":
                f.write(f"[INFO] {http_url} could not be reached; probes were sent to {r['base_url']} "
                        f"instead{earlier}\n")
            if r.get("offsite_redirect"):
                f.write(f"[INFO] {r['base_url']} redirects to another host "
                        f"({clean_text(r['offsite_redirect'])}); that host was not tested\n")
            for url in r["vulnerable"]:
                if url in r.get("vulnerable_meta_refresh", []):
                    how = " (via <meta refresh> in the page)"
                elif url in r.get("vulnerable_refresh_header", []):
                    how = " (via a Refresh header)"
                else:
                    how = ""
                f.write(f"[VULNERABLE] {clean_text(url)}{how}\n")
            # Probes that really got an answer: the one the check stopped on never did.
            answered = r["probes_sent"] - r["probes_skipped"] - (0 if r["complete"] else 1)
            if not r["complete"]:
                if r.get("stop_reason") == "tls":
                    where = ("; no probes were answered" if answered == 0 else
                             f" at probe {r['probes_sent']} of {r['probes_total']}; the rest were not sent")
                    f.write(f"[WARNING] Check incomplete: TLS/certificate problem with {r['base_url']}{where}\n")
                elif answered == 0:
                    f.write(f"[WARNING] Check incomplete: could not connect to {r['base_url']}; "
                            f"no probes were answered\n")
                else:
                    f.write(f"[WARNING] Check incomplete: host stopped answering at probe "
                            f"{r['probes_sent']} of {r['probes_total']}; the rest were not sent\n")
            if r["probes_skipped"]:
                f.write(f"[INFO] {r['probes_skipped']} of {r['probes_total']} probes got no usable "
                        f"answer (timeout, dropped connection or unreadable reply) and were skipped\n")
            if not r["vulnerable"]:
                # Only claim a clean result for probes that actually got an answer.
                if answered == 0:
                    f.write("[WARNING] No probe got a usable answer; the redirect check could not run.\n")
                elif r["complete"] and not r["probes_skipped"]:
                    f.write("No open redirects found.\n")
                else:
                    probes = "probe" if answered == 1 else "probes"
                    f.write(f"No open redirects found in the {answered} {probes} that got an answer.\n")

        f.write("\nSSL/TLS CERTIFICATE\n")
        f.write("-" * 20 + "\n")
        if "ssl" in internal_errors:
            f.write(_internal_error_line(internal_errors["ssl"]))
        else:
            if "cert_problem" in ssl_results:
                reason = CERT_PROBLEM_TEXT.get(ssl_results['cert_problem'], CERT_PROBLEM_TEXT["invalid"])
                f.write(f"[CRITICAL] Certificate rejected: {reason}\n")
                f.write(f"Details: {clean_text(ssl_results.get('error', 'no details'))}\n")
            elif "error" in ssl_results:
                if ssl_results.get("error_kind") == "refused":
                    f.write("[CRITICAL] Port 443 is closed — HTTPS is not enabled on this server\n")
                else:
                    f.write(f"Error checking SSL: {clean_text(ssl_results['error'])}\n")
            else:
                f.write(f"Issued to: {clean_text(ssl_results['issued_to'])}\n")
                f.write(f"Issued by: {clean_text(ssl_results['issued_by'])}\n")
                f.write(f"Expires: {ssl_results['expire_date']} ({ssl_results['days_remaining']} days remaining)\n")
                if ssl_results['expired']:
                    f.write("[CRITICAL] Certificate has expired\n")
                elif ssl_results['expiring_soon']:
                    f.write("[WARNING] Certificate expiring within 30 days\n")
                else:
                    f.write("[OK] Certificate is valid\n")
                if not ssl_results['domain_match']:
                    f.write("[CRITICAL] Certificate domain does not match target\n")
                else:
                    f.write("[OK] Domain matches certificate\n")
