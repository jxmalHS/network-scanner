from urllib.parse import urljoin, urlsplit

import requests

from urltools import host_of, url_host

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

# HSTS shorter than about 6 months (Mozilla Observatory's bar) gets a warning.
HSTS_MIN_MAX_AGE = 15_768_000


def _hsts_max_age(value: str) -> int | None:
    """The max-age (seconds) of an HSTS header, or None if it's missing or unreadable.

    Browsers only use the first HSTS header; requests joins repeated headers with ", ",
    so only the part before the first comma counts (RFC 6797 section 8.1).
    """
    first = value.split(",", 1)[0]
    names, ages = [], []
    for part in first.split(";"):
        if not part.strip():
            continue
        name, _, raw = part.strip().partition("=")
        name = name.strip().lower()
        names.append(name)
        if name == "max-age":
            raw = raw.strip()
            if len(raw) >= 2 and raw[0] == raw[-1] == '"':   # one matching pair of quotes only
                raw = raw[1:-1]
            ages.append(raw)
    if len(names) != len(set(names)):   # any directive repeated: the whole header is invalid
        return None
    if len(ages) != 1:                  # no max-age at all
        return None
    age = ages[0]
    if not (age.isascii() and age.isdigit()):
        return None
    try:
        return int(age)
    except ValueError:              # absurdly long number
        return None


def _scheme(url: str) -> str:
    """'http' or 'https', always lower-case."""
    return urlsplit(url).scheme


def _fetch(url: str) -> dict:
    """GET one URL, following redirects only on the same host, and sort its security headers."""
    notes: dict = {}
    try:
        target_host = host_of(url)
        for _ in range(MAX_REDIRECTS + 1):
            # stream=True + with: read only the headers, never the page body, then close.
            with requests.get(url, timeout=5, allow_redirects=False, stream=True) as response:
                headers = response.headers
                if not response.is_redirect:
                    break
                next_url = urljoin(url, response.headers["Location"])
            if host_of(next_url) != target_host:
                notes["offsite_redirect"] = next_url   # note it, never follow it
                break
            if _scheme(url) == "https" and _scheme(next_url) == "http":
                notes["downgraded_from"] = url
            url = next_url
        else:
            return {"error": f"more than {MAX_REDIRECTS} redirects", "too_many_redirects": True}
    except requests.exceptions.SSLError as e:
        return {"error": str(e), "tls_problem": True}
    except (requests.exceptions.RequestException, ValueError) as e:   # ValueError: garbled Location
        return {"error": str(e)}

    over_https = _scheme(url) == "https"
    present, missing, not_applicable = [], [], []
    for header in SECURITY_HEADERS:
        if not over_https and header in HTTPS_ONLY_HEADERS:
            not_applicable.append(header)
        elif header == "Strict-Transport-Security" and header in headers:
            # max-age=0 switches HSTS off and an unreadable one is ignored by browsers,
            # so only a real, positive max-age counts as present.
            max_age = _hsts_max_age(headers[header])
            notes["hsts_max_age"] = max_age
            (present if max_age else missing).append(header)
        elif header in headers:
            present.append(header)
        else:
            missing.append(header)
    return {**notes, "url": url, "present": present, "missing": missing,
            "not_applicable": not_applicable}


def check_headers(host: str) -> dict:
    """Check headers over HTTPS; if HTTPS doesn't work, fall back to plain HTTP."""
    netloc = url_host(host)
    result = _fetch(f"https://{netloc}")
    if "error" not in result:
        return result
    fallback = _fetch(f"http://{netloc}")
    fallback["https_error"] = result["error"]
    if result.get("tls_problem"):
        fallback["https_tls_problem"] = True
    if result.get("too_many_redirects"):
        fallback["https_too_many_redirects"] = True
    return fallback
