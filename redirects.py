import re
import time
from http.cookiejar import DefaultCookiePolicy
from typing import Literal, NotRequired, TypedDict
from urllib.parse import urljoin, urlsplit

import requests

from urltools import host_of, url_host

REDIRECT_PARAMS = ["next", "url", "redirect", "return", "goto", "dest", "destination", "redir"]
REDIRECT_PATHS = ["/", "/login", "/logout", "/redirect"]

# ".invalid" names are reserved (RFC 2606) and can never be a real site,
# so even a mistake can't make the scanner contact a third party.
CANARY_HOST = "redirect-canary.invalid"
CANARY_URL = f"http://{CANARY_HOST}/"

PROBE_TIMEOUT = 5        # seconds to wait for each probe
PROBE_DELAY = 0.2        # pause between probes (seconds), so the target is never flooded
SWITCH_WINDOW = 4        # the HTTPS switch is decided within the first 4 HTTP probes
FAILURES_TO_STOP = 2     # give up after this many failed connections in a row


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
    probes_sent: int           # probes attempted, including the one the check stopped on
    probes_skipped: int        # probes that got no usable answer (slow page, dropped connection, unreadable reply)
    complete: bool             # False when the host stopped answering and the rest weren't sent
    switch_reason: Literal["redirect", "no_http"] | None  # why probes went to https:// instead: "redirect", "no_http" or None
    # Optional so hand-built results (old tests) still work; check_open_redirect always fills them.
    http_probes_sent: NotRequired[int]   # probes sent over plain HTTP before switching to https:// (0 = no switch)
    stop_reason: NotRequired[Literal["connection", "tls"] | None]  # why an incomplete check stopped
    offsite_redirect: NotRequired[str | None]  # another host the first answered probe redirected to (never requested)


def _new_session() -> requests.Session:
    """One client for the whole check. Cookies are switched off so every probe stays independent."""
    session = requests.Session()
    session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))   # accept cookies from no site
    return session


def _is_https_upgrade(test: str, location: str) -> bool:
    """True if Location sends us to HTTPS on the same host (port 443): the real site is HTTPS."""
    target = urljoin(test, location)
    parts = urlsplit(target)
    return parts.scheme == "https" and host_of(target) == host_of(test) and parts.port in (None, 443)


def _offsite_target(test: str, location: str) -> str | None:
    """The address Location points to if it is on another host (not the canary), else None."""
    target = _browser_target(test, location)
    host = host_of(target)
    if host is None or host in (host_of(test), CANARY_HOST):
        return None
    return target


def _probe_all(
    session: requests.Session, base: str, detect_https: bool, sent_before: int,
) -> tuple[RedirectResults, Literal["redirect", "no_http"] | None]:
    """Send every probe to base. With detect_https, stop early if the site is really HTTPS.

    sent_before is how many requests this check already sent (they decide the first pause).
    """
    result: RedirectResults = {
        "base_url": base, "vulnerable": [],
        "probes_total": len(REDIRECT_PATHS) * len(REDIRECT_PARAMS),
        "probes_sent": 0, "probes_skipped": 0, "complete": True, "switch_reason": None,
        "http_probes_sent": 0, "stop_reason": None, "offsite_redirect": None,
    }
    deciding = detect_https     # still waiting for the first answered probe to decide the switch
    answered_yet = False
    failures_in_a_row = 0

    def stop(reason: Literal["connection", "tls"]) -> tuple[RedirectResults, Literal["no_http"] | None]:
        result["complete"] = False
        result["stop_reason"] = reason
        return result, ("no_http" if deciding else None)

    for path in REDIRECT_PATHS:
        for param in REDIRECT_PARAMS:
            test = f"{base}{path}?{param}={CANARY_URL}"
            if sent_before or result["probes_sent"]:
                time.sleep(PROBE_DELAY)     # never before the very first request of a check
            result["probes_sent"] += 1
            try:
                with session.get(test, timeout=PROBE_TIMEOUT, allow_redirects=False,
                                 stream=True) as response:
                    location = response.headers.get("Location") if response.is_redirect else None
                points_to_canary = (location is not None
                                    and host_of(_browser_target(test, location)) == CANARY_HOST)
                upgrade = (location is not None and not points_to_canary
                           and _is_https_upgrade(test, location))
                offsite = (_offsite_target(test, location)
                           if location is not None and not points_to_canary and not upgrade else None)
            except requests.exceptions.SSLError:
                return stop("tls")          # certificate problems don't go away: stop at once
            except requests.exceptions.ConnectionError:     # includes "connect timed out"
                failures_in_a_row += 1
                if failures_in_a_row >= FAILURES_TO_STOP:
                    return stop("connection")   # host really gone: don't wait 32 x 5 s
                result["probes_skipped"] += 1   # one dropped connection: skip it and go on
                deciding = deciding and result["probes_sent"] < SWITCH_WINDOW
                continue
            except (requests.exceptions.RequestException, ValueError):
                failures_in_a_row = 0           # it connected, the reply was just unusable
                result["probes_skipped"] += 1   # slow page, garbled Location or other odd failure
                deciding = deciding and result["probes_sent"] < SWITCH_WINDOW
                continue
            failures_in_a_row = 0
            if not answered_yet:
                answered_yet = True
                if deciding and upgrade:
                    return result, "redirect"
                result["offsite_redirect"] = offsite
            deciding = False
            if points_to_canary:
                result["vulnerable"].append(test)
    return result, None


def check_open_redirect(host: str) -> RedirectResults:
    """Probe common pages and parameters; never follow a redirect, only read where it points.

    If plain HTTP redirects to HTTPS on the same host, or can't be reached at all, the probes
    are sent to https://<host> instead, so HTTPS-only sites are really tested.
    """
    netloc = url_host(host)
    with _new_session() as session:
        result, reason = _probe_all(session, f"http://{netloc}", detect_https=True, sent_before=0)
        if reason is None:
            return result
        http_sent = result["probes_sent"]
        result, _ = _probe_all(session, f"https://{netloc}", detect_https=False, sent_before=http_sent)
    result["switch_reason"] = reason
    result["http_probes_sent"] = http_sent
    return result
