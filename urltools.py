import requests
from urllib3.util import parse_url


def url_host(host: str) -> str:
    """The host as it must appear in a URL (IPv6 addresses need [brackets])."""
    return f"[{host}]" if ":" in host else host


def host_of(url: str) -> str | None:
    """The host requests will really connect to (same parser requests uses)."""
    prepared = requests.Request("GET", url).prepare().url
    host = parse_url(prepared).host
    return host.lower().rstrip(".") if host else None
