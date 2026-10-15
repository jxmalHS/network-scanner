import re
import time
from html.parser import HTMLParser
from http.cookiejar import DefaultCookiePolicy
from typing import Literal, NotRequired, TypedDict
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

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
MAX_BODY_BYTES = 64 * 1024   # read at most 64 KB of a page when looking for <meta refresh>
MAX_BODY_SECONDS = 5         # and spend at most 5 s reading it, however slowly it arrives


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
    vulnerable_meta_refresh: NotRequired[list[str]]    # probe URLs (also in vulnerable) caught by <meta refresh>
    vulnerable_refresh_header: NotRequired[list[str]]  # probe URLs (also in vulnerable) caught by a Refresh header


class _MetaRefreshFinder(HTMLParser):
    """Remembers the content="..." of the first <meta http-equiv="refresh"> tag."""

    def __init__(self) -> None:
        super().__init__()
        self.content: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "meta" or self.content is not None:
            return
        values = {name: value or "" for name, value in attrs}   # names come lower-cased, &amp; decoded
        if values.get("http-equiv", "").strip().lower() == "refresh" and "content" in values:
            self.content = values["content"]


def _refresh_url(content: str | None) -> str | None:
    """The URL in a refresh value like '0; url=http://x/' (Refresh header or <meta refresh>).

    Follows the HTML rules loosely: a delay, then ';' or ',', then an optional 'url=' and an
    optional quote. None when there is no URL (a refresh of the same page) or it is unreadable.
    """
    if content is None:
        return None
    match = re.match(r"\s*[\d.]+\s*[;,]?\s*(?:url\s*=\s*)?(.*)", content, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    url = match.group(1).strip()
    if url[:1] in ("'", '"'):
        url = url[1:].split(url[0], 1)[0]
    return url.strip() or None


def _read_capped(response: requests.Response) -> bytes:
    """At most MAX_BODY_BYTES of the body, read for at most MAX_BODY_SECONDS in total.

    read1 returns as soon as *some* bytes arrive, so a server that drips one byte every few
    seconds can't keep a probe busy for hours (the 5 s timeout only limits each single wait).
    A body that breaks off halfway gives what arrived.
    """
    data = bytearray()
    deadline = time.monotonic() + MAX_BODY_SECONDS
    try:
        while len(data) < MAX_BODY_BYTES and time.monotonic() < deadline:
            chunk = response.raw.read1(8192, decode_content=True)
            if not chunk:
                break
            data += chunk
    except (requests.exceptions.RequestException, urllib3.exceptions.HTTPError, OSError):
        pass
    return bytes(data[:MAX_BODY_BYTES])


def _meta_refresh_url(body: bytes) -> str | None:
    """The URL of the first <meta http-equiv="refresh"> in an HTML page, or None."""
    finder = _MetaRefreshFinder()
    try:
        finder.feed(body.decode("utf-8", errors="replace"))
        finder.close()
    except (AssertionError, ValueError):     # html.parser's ways of giving up on broken markup
        return None                          # treated as "no meta refresh found"
    return _refresh_url(finder.content)


def _points_to_canary(test: str, url: str | None) -> bool:
    """True if a browser at `test` sent to `url` would land on the canary host."""
    if url is None:
        return False
    try:
        return host_of(_browser_target(test, url)) == CANARY_HOST
    except (requests.exceptions.RequestException, ValueError):
        return False        # garbled refresh URL: a browser wouldn't go anywhere useful either


def _new_session() -> requests.Session:
    """One client for the whole check. Cookies are switched off so every probe stays independent."""
    session = requests.Session()
    session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))   # accept cookies from no site
    return session


def _refresh_finding(test: str, response: requests.Response) -> Literal["header", "meta"] | None:
    """How a 200 page without a redirect still sends browsers to the canary, if it does.

    Checks the Refresh header first (no body needed), then, for HTML pages only, a
    <meta http-equiv="refresh"> in the first MAX_BODY_BYTES. JavaScript redirects are not
    detected: that would need running the page's scripts.
    """
    if response.status_code != 200:
        return None
    if _points_to_canary(test, _refresh_url(response.headers.get("Refresh"))):
        return "header"
    if "html" not in response.headers.get("Content-Type", "").lower():
        return None
    if _points_to_canary(test, _meta_refresh_url(_read_capped(response))):
        return "meta"
    return None


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
        "vulnerable_meta_refresh": [], "vulnerable_refresh_header": [],
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
                    refresh = _refresh_finding(test, response) if location is None else None
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
            if points_to_canary or refresh:
                result["vulnerable"].append(test)
            if refresh == "header":
                result["vulnerable_refresh_header"].append(test)
            elif refresh == "meta":
                result["vulnerable_meta_refresh"].append(test)
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
