import re
from typing import TypedDict
from urllib.parse import urljoin

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
    base_url: str          # where the probes were sent, e.g. "http://host"
    vulnerable: list[str]  # probe URLs whose Location points to the canary
    probes_total: int      # how many probes a full check sends
    probes_sent: int       # probes attempted, including one that failed to connect
    probes_skipped: int    # probes that got no usable answer (slow page, unreadable reply)
    complete: bool         # False when the host stopped answering and the rest weren't sent


def check_open_redirect(host: str) -> RedirectResults:
    """Probe common pages and parameters; never follow a redirect, only read where it points."""
    base = f"http://{url_host(host)}"
    result: RedirectResults = {
        "base_url": base, "vulnerable": [],
        "probes_total": len(REDIRECT_PATHS) * len(REDIRECT_PARAMS),
        "probes_sent": 0, "probes_skipped": 0, "complete": True,
    }
    for path in REDIRECT_PATHS:
        for param in REDIRECT_PARAMS:
            test = f"{base}{path}?{param}={CANARY_URL}"
            result["probes_sent"] += 1
            try:
                with requests.get(test, timeout=5, allow_redirects=False, stream=True) as response:
                    location = response.headers.get("Location") if response.is_redirect else None
                points_to_canary = (location is not None
                                    and host_of(_browser_target(test, location)) == CANARY_HOST)
            except requests.exceptions.ConnectionError:      # includes "connect timed out"
                result["complete"] = False  # host can't be reached at all: stop instead of waiting 32 x 5 s
                return result
            except (requests.exceptions.RequestException, ValueError):
                result["probes_skipped"] += 1   # slow page, garbled Location or other odd failure
                continue
            if points_to_canary:
                result["vulnerable"].append(test)
    return result
