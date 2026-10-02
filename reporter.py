from datetime import datetime

# Plain-English reason for each cert_problem word from ssl_checker.
CERT_PROBLEM_TEXT = {
    "hostname_mismatch": "name does not match the host",
    "expired": "has expired",
    "not_yet_valid": "is not valid yet",
    "untrusted": "is not from a trusted issuer (self-signed or unknown)",
    "invalid": "failed verification",
}

def generate_report(host, open_ports, header_results, redirect_results, ssl_results):

    filename = f"report_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, "w") as f:
        f.write(f"Network Vulnerability Scan Report\n")
        f.write(f"Target: {host}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")

        f.write("OPEN PORTS\n")
        f.write("-" * 20 + "\n")
        if open_ports:
            for entry in open_ports:
                if entry["banner"]:
                    f.write(f"[OPEN] Port {entry['port']} — {entry['banner'][:100]}\n")
                else:
                    f.write(f"[OPEN] Port {entry['port']} — no banner\n")
        else:
            f.write("No open ports found.\n")

        f.write("\nHTTP SECURITY HEADERS\n")
        f.write("-" * 20 + "\n")
        if "error" in header_results:
            f.write(f"Error fetching headers: {header_results['error']}\n")
        else:
            for header in header_results["present"]:
                f.write(f"[PRESENT] {header}\n")
            for header in header_results["missing"]:
                f.write(f"[MISSING] {header}\n")

        f.write("\nOPEN REDIRECT CHECK\n")
        f.write("-" * 20 + "\n")
        if redirect_results:
            for url in redirect_results:
                f.write(f"[VULNERABLE] {url}\n")
        else:
            f.write("No open redirects found.\n")

        f.write("\nSSL/TLS CERTIFICATE\n")
        f.write("-" * 20 + "\n")
        if "cert_problem" in ssl_results:
            reason = CERT_PROBLEM_TEXT.get(ssl_results['cert_problem'], CERT_PROBLEM_TEXT["invalid"])
            f.write(f"[CRITICAL] Certificate rejected: {reason}\n")
            f.write(f"Details: {ssl_results.get('error', 'no details')}\n")
        elif "error" in ssl_results:
            if "10061" in str(ssl_results['error']) or "refused" in str(ssl_results['error']).lower():
                f.write("[CRITICAL] Port 443 is closed — HTTPS is not enabled on this server\n")
            else:
                f.write(f"Error checking SSL: {ssl_results['error']}\n")
        else:
            f.write(f"Issued to: {ssl_results['issued_to']}\n")
            f.write(f"Issued by: {ssl_results['issued_by']}\n")
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

    return filename