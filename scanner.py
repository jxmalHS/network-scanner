import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from textsafe import clean_text

DEFAULT_WORKERS = 20


class HostResolutionError(Exception):
    """The target name gave no address that can be scanned. The message is a full sentence."""


def is_unscannable(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Link-local IPv6 (needs a zone ID), multicast, or IPv4 broadcast: not one host you can port-scan."""
    return ((ip.version == 6 and ip.is_link_local) or ip.is_multicast
            or ip == ipaddress.IPv4Address("255.255.255.255"))


def _usable_addresses(host: str) -> list[tuple[int, str]]:
    """(family, IP) pairs for host in lookup order, minus ones that can't be scanned. IPs skip DNS."""
    try:
        ip = ipaddress.ip_address(host)
        return [((socket.AF_INET6 if ip.version == 6 else socket.AF_INET), str(ip))]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as e:   # gaierror is an OSError; an over-long label gives UnicodeError
        raise HostResolutionError(f"Could not resolve host: {host} ({e})") from e
    if not infos:
        raise HostResolutionError(f"Could not resolve host: {host} (the lookup returned no addresses)")
    usable = [(info[0], info[4][0]) for info in infos
              if not is_unscannable(ipaddress.ip_address(info[4][0]))]
    if not usable:
        raise HostResolutionError(
            f"Can't scan {host}: it only has link-local IPv6 (fe80::...), multicast or broadcast "
            f"addresses, which aren't a single host you can port-scan")
    return usable


def resolve_dual(host: str) -> list[tuple[int, str]]:
    """[(AF_INET, IPv4), (AF_INET6, IPv6)] from one lookup; an error names a missing kind."""
    addresses = _usable_addresses(host)
    pair = []
    for family, name in ((socket.AF_INET, "IPv4"), (socket.AF_INET6, "IPv6")):
        found = [a for a in addresses if a[0] == family]
        if not found:
            raise HostResolutionError(
                f"Can't scan {host} over both IPv4 and IPv6: it has no {name} address that can be scanned")
        pair.append(found[0])
    return pair


def resolve_host(host: str, ipv6: bool = False) -> tuple[int, str]:
    """Return (address family, IP) for host. IP addresses skip the DNS lookup.

    With ipv6=True, the first usable IPv6 address, or an error if there is none (never IPv4).
    """
    addresses = _usable_addresses(host)
    if ipv6:
        found = [a for a in addresses if a[0] == socket.AF_INET6]
        if not found:
            raise HostResolutionError(f"Can't scan {host} over IPv6: it has no IPv6 address that can be scanned")
        return found[0]
    # Prefer IPv4 when the name has one: many services (e.g. lab apps on localhost) listen
    # only on 127.0.0.1, and Windows lists ::1 first. IPv6 is used only if there is no IPv4.
    ipv4 = [a for a in addresses if a[0] == socket.AF_INET]
    return (ipv4 or addresses)[0]


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
                # None = nothing received; "" = bytes arrived but none were printable.
                data = sock.recv(1024)
                banner = clean_text(data.decode("utf-8", errors="ignore")) if data else None
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
