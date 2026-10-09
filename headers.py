from urllib.parse import urljoin, urlsplit

import requests
from urllib3.util import parse_url

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy"
]

# HSTS only means something when it arrives over HTTPS.
HTTPS_ONLY_HEADERS = ["Strict-Transport-Security"]

MAX_REDIRECTS = 5


def _url_host(host: str) -> str:
    """The host as it must appear in a URL (IPv6 addresses need [brackets])."""
    return f"[{host}]" if ":" in host else host


def _host_of(url: str) -> str | None:
    """The host requests will really connect to (same parser requests uses)."""
    prepared = requests.Request("GET", url).prepare().url
    host = parse_url(prepared).host
    return host.lower().rstrip(".") if host else None


def _scheme(url: str) -> str:
    """'http' or 'https', always lower-case."""
    return urlsplit(url).scheme


def _fetch(url: str) -> dict:
    """GET one URL, following redirects only on the same host, and sort its security headers."""
    notes: dict = {}
    try:
        target_host = _host_of(url)
        for _ in range(MAX_REDIRECTS + 1):
            # stream=True + with: read only the headers, never the page body, then close.
            with requests.get(url, timeout=5, allow_redirects=False, stream=True) as response:
                headers = response.headers
                if not response.is_redirect:
                    break
                next_url = urljoin(url, response.headers["Location"])
            if _host_of(next_url) != target_host:
                notes["offsite_redirect"] = next_url   # note it, never follow it
                break
            if _scheme(url) == "https" and _scheme(next_url) == "http":
                notes["downgraded_from"] = url
            url = next_url
        else:
            return {"error": f"more than {MAX_REDIRECTS} redirects"}
    except requests.exceptions.SSLError as e:
        return {"error": str(e), "tls_problem": True}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    over_https = _scheme(url) == "https"
    present, missing, not_applicable = [], [], []
    for header in SECURITY_HEADERS:
        if not over_https and header in HTTPS_ONLY_HEADERS:
            not_applicable.append(header)
        elif header in headers:
            present.append(header)
        else:
            missing.append(header)
    return {**notes, "url": url, "present": present, "missing": missing,
            "not_applicable": not_applicable}


def check_headers(host: str) -> dict:
    """Check headers over HTTPS; if HTTPS doesn't work, fall back to plain HTTP."""
    netloc = _url_host(host)
    result = _fetch(f"https://{netloc}")
    if "error" not in result:
        return result
    fallback = _fetch(f"http://{netloc}")
    fallback["https_error"] = result["error"]
    if result.get("tls_problem"):
        fallback["https_tls_problem"] = True
    return fallback
