import argparse
from scanner import scan_ports
from headers import check_headers
from reporter import generate_report
from redirects import check_open_redirect

COMMON_PORTS = [21,22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 8080, 8443]

def main():
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("host", help ="Target host or IP address")
    parser.add_argument("--ports", nargs="+", type=int, default=COMMON_PORTS, help="Ports to scan")
    args = parser.parse_args()

    host = args.host
    ports = args.ports

    print(f"\n[*] Starting scan on {host}")
    
    print(f"[*] Scanning ports...")
    open_ports = scan_ports(host, ports)
    for entry in open_ports:
        if entry["banner"]:
            print(f"[+] Port {entry['port']} open — {entry['banner'][:50]}")
        else:
            print(f"[+] Port {entry['port']} open — no banner")

    print("[*] Checking HTTP security headers...")
    header_results = check_headers(f"http://{host}")

    print("[*] Checking for open redirects...")
    redirect_results = check_open_redirect(host)
    
    print("[*] Generating report...")
    filename = generate_report(host, open_ports, header_results, redirect_results)
    print(f"[+] Report saved to {filename}\n")

if __name__ == "__main__":
    main()