import re
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


def check_open_redirect(host: str) -> list[str]:
    """Probe common pages and parameters; never follow a redirect, only read where it points."""
    vulnerable = []
    base = f"http://{url_host(host)}"
    for path in REDIRECT_PATHS:
        for param in REDIRECT_PARAMS:
            test = f"{base}{path}?{param}={CANARY_URL}"
            try:
                with requests.get(test, timeout=5, allow_redirects=False, stream=True) as response:
                    location = response.headers.get("Location") if response.is_redirect else None
                points_to_canary = (location is not None
                                    and host_of(_browser_target(test, location)) == CANARY_HOST)
            except requests.exceptions.ConnectionError:      # includes "connect timed out"
                return vulnerable          # host can't be reached at all: stop instead of waiting 32 x 5 s
            except (requests.exceptions.RequestException, ValueError):
                continue                   # slow page, garbled Location or other odd failure: next probe
            if points_to_canary:
                vulnerable.append(test)
    return vulnerable
