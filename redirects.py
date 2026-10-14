import re
from typing import Literal, TypedDict
from urllib.parse import urljoin, urlsplit

import requests

from urltools import host_of, url_host

REDIRECT_PARAMS = ["next", "url", "redirect", "return", "goto", "dest", "destination", "redir"]
REDIRECT_PATHS = ["/", "/login", "/logout", "/redirect"]

# ".invalid" names are reserved (RFC 2606) and can never be a real site,
# so even a mistake can't make the scanner contact a third party.
CANARY_HOST = "redirect-canary.invalid"
CANARY_URL = f"http://{CANARY_HOST}/"


def _browser_target(base: str, location: str) -> str:
    """Where a browser would go: backslash counts as slash, extra leading slashes are ignored.

    Only used to judge the Location header; the scanner never requests this address.
    """
    loc = location.strip().replace("\\", "/")
    loc = re.sub(r"^(?i:(https?:))?/{2,}", lambda m: (m.group(1) or "") + "//", loc)
    return urljoin(base, loc)


class RedirectResults(TypedDict):
    base_url: str              # where the probes were sent: "http://host" or "https://host"
    vulnerable: list[str]      # probe URLs whose Location points to the canary
    probes_total: int          # how many probes a full check sends
    probes_sent: int           # probes attempted, including one that failed to connect
    probes_skipped: int        # probes that got no usable answer (slow page, unreadable reply)
    complete: bool             # False when the host stopped answering and the rest weren't sent
    switch_reason: Literal["redirect", "no_http"] | None  # why probes went to https:// instead: "redirect", "no_http" or None


def _is_https_upgrade(test: str, location: str) -> bool:
    """True if Location sends us to HTTPS on the same host (port 443): the real site is HTTPS."""
    target = urljoin(test, location)
    parts = urlsplit(target)
    return parts.scheme == "https" and host_of(target) == host_of(test) and parts.port in (None, 443)


def _probe_all(base: str, detect_https: bool) -> tuple[RedirectResults, Literal["redirect", "no_http"] | None]:
    """Send every probe to base. With detect_https, stop at probe 1 if the site is really HTTPS."""
    result: RedirectResults = {
        "base_url": base, "vulnerable": [],
        "probes_total": len(REDIRECT_PATHS) * len(REDIRECT_PARAMS),
        "probes_sent": 0, "probes_skipped": 0, "complete": True, "switch_reason": None,
    }
    for path in REDIRECT_PATHS:
        for param in REDIRECT_PARAMS:
            test = f"{base}{path}?{param}={CANARY_URL}"
            result["probes_sent"] += 1
            first_probe = result["probes_sent"] == 1
            try:
                with requests.get(test, timeout=5, allow_redirects=False, stream=True) as response:
                    location = response.headers.get("Location") if response.is_redirect else None
                points_to_canary = (location is not None
                                    and host_of(_browser_target(test, location)) == CANARY_HOST)
                upgrade = (detect_https and first_probe and location is not None
                           and not points_to_canary and _is_https_upgrade(test, location))
            except requests.exceptions.ConnectionError:      # includes "connect timed out" and TLS errors
                result["complete"] = False  # host can't be reached at all: stop instead of waiting 32 x 5 s
                return result, ("no_http" if detect_https and first_probe else None)
            except (requests.exceptions.RequestException, ValueError):
                result["probes_skipped"] += 1   # slow page, garbled Location or other odd failure
                continue
            if upgrade:
                return result, "redirect"
            if points_to_canary:
                result["vulnerable"].append(test)
    return result, None


def check_open_redirect(host: str) -> RedirectResults:
    """Probe common pages and parameters; never follow a redirect, only read where it points.

    If plain HTTP redirects to HTTPS on the same host, or can't be reached at all, the probes
    are sent to https://<host> instead, so HTTPS-only sites are really tested.
    """
    netloc = url_host(host)
    result, reason = _probe_all(f"http://{netloc}", detect_https=True)
    if reason is None:
        return result
    result, _ = _probe_all(f"https://{netloc}", detect_https=False)
    result["switch_reason"] = reason
    return result
