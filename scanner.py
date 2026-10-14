import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from textsafe import clean_text

DEFAULT_WORKERS = 20


class HostResolutionError(Exception):
    """The target name could not be turned into an IP address."""


def resolve_host(host: str) -> tuple[int, str]:
    """Return (address family, IP) for host. IP addresses skip the DNS lookup."""
    try:
        ip = ipaddress.ip_address(host)
        return (socket.AF_INET6 if ip.version == 6 else socket.AF_INET), str(ip)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as e:   # gaierror is an OSError; an over-long label gives UnicodeError
        raise HostResolutionError(f"{host} ({e})") from e
    # Prefer IPv4 when the name has one: many services (e.g. lab apps on localhost) listen
    # only on 127.0.0.1, and Windows lists ::1 first. IPv6 is used only if there is no IPv4.
    ipv4 = [info for info in infos if info[0] == socket.AF_INET]
    family, _, _, _, sockaddr = (ipv4 or infos)[0]
    return family, sockaddr[0]


def scan_port(host, port, family=socket.AF_INET):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        banner = None
        if result == 0:
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                # clean_text: the banner comes from a possibly hostile server; make it one
                # printable line so it can't fake report lines or send terminal escape codes.
                banner = clean_text(sock.recv(1024).decode("utf-8", errors="ignore"))
            except OSError:
                pass
    return result == 0, banner


def scan_ports(host: str, ports: list[int], workers: int = DEFAULT_WORKERS) -> list[dict]:
    """Scan ports `workers` at a time; results come back in the original port order.

    Raises HostResolutionError if the host name can't be looked up.
    """
    family, address = resolve_host(host)     # once, before any worker starts
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        results = list(pool.map(lambda port: scan_port(address, port, family), ports))
    finally:
        # cancel_futures=True: on Ctrl+C or an error, drop the ports still waiting in the
        # queue instead of scanning them all before stopping.
        pool.shutdown(wait=True, cancel_futures=True)
    return [{"port": port, "banner": banner}
            for port, (is_open, banner) in zip(ports, results) if is_open]
