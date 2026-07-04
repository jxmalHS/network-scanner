from datetime import datetime

def generate_report(host, open_ports, header_results, redirect_results):
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

    return filename