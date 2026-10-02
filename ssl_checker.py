import ipaddress
import ssl
import socket
from datetime import datetime, timezone


def _name_matches(pattern: str, host: str) -> bool:
    """True if one certificate name (maybe a wildcard) covers the host."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]                      # "*.example.com" -> ".example.com"
        if suffix.count(".") < 2:                 # refuse "*.com"
            return False
        if not host.endswith(suffix):
            return False
        label = host[: -len(suffix)]              # "www.example.com" -> "www"
        return label != "" and "." not in label   # exactly one extra part
    return pattern == host


def _as_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The text as an IP address, or None if it isn't one."""
    try:
        return ipaddress.ip_address(text.strip())
    except ValueError:
        return None


def _domain_matches(cert: dict, host: str, issued_to: str) -> bool:
    """Check the SAN list; fall back to the CN only if there is no SAN list."""
    sans = cert.get("subjectAltName", ())
    host_ip = _as_ip(host)
    if host_ip is not None:
        # An IP target only matches the certificate's "IP Address" entries.
        return any(kind == "IP Address" and _as_ip(value) == host_ip for kind, value in sans)
    names = [value for kind, value in sans if kind == "DNS"] or [issued_to]
    return any(_name_matches(name, host) for name in names)


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

                expire_date = datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                days_remaining = (expire_date - datetime.now(timezone.utc)).days

                expired = days_remaining < 0
                expiring_soon = 0 <= days_remaining <= 30

                domain_match = _domain_matches(cert, host, issued_to)

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