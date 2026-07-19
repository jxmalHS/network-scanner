import ssl
import socket
from datetime import datetime


def check_ssl(host):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

                subject = dict(x[0] for x in cert["subject"])
                issued_to = subject.get("commonName", "Unknown")

                issuer = dict(x[0] for x in cert["issuer"])
                issued_by = issuer.get("organizationName", "Unknown")

                expire_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_remaining = (expire_date - datetime.utcnow()).days

                expired = days_remaining < 0
                expiring_soon = 0 <= days_remaining <= 30

                domain_match = issued_to == host or issued_to.startswith("*.")

                return {
                    "issued_to": issued_to,
                    "issued_by": issued_by,
                    "expire_date": expire_date.strftime("%Y-%m-%d"),
                    "days_remaining": days_remaining,
                    "expired": expired,
                    "expiring_soon": expiring_soon,
                    "domain_match": domain_match
                }
    except Exception as e:
        return {"error": str(e)}