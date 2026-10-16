import contextlib
import re
import threading
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
NO_PAGE_STATUSES = (204, 205, 304)   # No Content / Reset Content / Not Modified: no page to show

_now = time.monotonic        # (a module-level name tests can patch without touching the time module)


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
    stop_reason: NotRequired[Literal["connection", "tls", "timeout"] | None]  # why an incomplete check stopped
    offsite_redirect: NotRequired[str | None]  # another host the first answered probe redirected to (never requested)
    vulnerable_meta_refresh: NotRequired[list[str]]    # probe URLs (also in vulnerable) caught by <meta refresh>
    vulnerable_refresh_header: NotRequired[list[str]]  # probe URLs (also in vulnerable) caught by a Refresh header


class _MetaRefreshFinder(HTMLParser):
    """Remembers the content="..." of the first <meta http-equiv="refresh"> a browser would obey.

    Reads the page like a browser with JavaScript on: <noscript> content is plain text, and
    anything inside <template> is inert, so a meta refresh in either is ignored.
    Inside <svg>/<math> a "/" does close a tag, so <svg><title/></svg> doesn't hide the page.
    """

    # Tags whose content a browser reads as text, even when written as <tag/> (the "/" is ignored).
    TEXT_ELEMENTS = frozenset({"script", "style", "title", "textarea", "xmp", "iframe", "noembed",
                               "noframes", "plaintext", "noscript"})
    # HTML tags that end an open <svg>/<math> in a browser (meta is one of them).
    BREAKOUT_TAGS = frozenset({"b", "big", "blockquote", "body", "br", "center", "code", "dd", "div",
                               "dl", "dt", "em", "embed", "h1", "h2", "h3", "h4", "h5", "h6", "head",
                               "hr", "i", "img", "li", "listing", "menu", "meta", "nobr", "ol", "p",
                               "pre", "ruby", "s", "small", "span", "strong", "strike", "sub", "sup",
                               "table", "tt", "u", "ul", "var"})

    def __init__(self) -> None:
        try:
            super().__init__(scripting=True)    # Python 3.14+: <noscript> content read as text
        except TypeError:                       # older Python: handle_starttag below does the job
            super().__init__()
        self.content: str | None = None
        self.template_depth = 0                 # how many <template> elements we're inside
        self.foreign_depth = 0                  # how many <svg>/<math> elements we're inside

    def _breaks_out(self, tag: str, attrs: list[tuple[str, str | None]]) -> bool:
        """True if this start tag ends <svg>/<math> content and is read as HTML again."""
        return tag in self.BREAKOUT_TAGS or (
            tag == "font" and any(name in ("color", "face", "size") for name, _ in attrs))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("svg", "math"):
            self.foreign_depth += 1
            return
        if self.foreign_depth and self._breaks_out(tag, attrs):
            self.foreign_depth = 0
        if tag == "template":
            self.template_depth += 1
            return
        if tag in self.TEXT_ELEMENTS:
            # Everything up to the closing tag is plain text in a browser (noscript: with JavaScript
            # on; plaintext: the whole rest of the page). html.parser misses <script/>, <noscript/>
            # etc. and, on older Python, several of these tags, so it is switched on here as well.
            self.set_cdata_mode(tag)
            return
        if tag != "meta" or self.content is not None or self.template_depth:
            return
        values = {name: value or "" for name, value in attrs}   # names come lower-cased, &amp; decoded
        if values.get("http-equiv", "").strip().lower() == "refresh" and "content" in values:
            self.content = values["content"]

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Browsers ignore the "/" in <template/>, <script/> etc.: they still open as usual.
        # But <svg/>, <math/> and tags inside them (<svg><title/>) really are empty.
        if tag in ("svg", "math") or (self.foreign_depth and not self._breaks_out(tag, attrs)):
            return
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "template" and self.template_depth:
            self.template_depth -= 1            # a stray </template> is ignored, as in browsers
        elif tag in ("svg", "math") and self.foreign_depth:
            self.foreign_depth -= 1


ASCII_WHITESPACE = "\t\n\x0c\r "     # the only "whitespace" in the HTML refresh rules (not NBSP etc.)


def _refresh_url(content: str | None) -> str | None:
    """The URL in a refresh value like '0; url=http://x/' (Refresh header or <meta refresh>).

    Follows the HTML standard's "shared declarative refresh steps": a delay made of ASCII
    digits and dots, then whitespace, ';' or ',' (so '0url=x' is ignored), then an optional
    'url =' and an optional quote. Without '=' the whole rest is the URL ('0; url x' -> 'url x').
    None when there is no URL (a refresh of the same page) or the value is invalid.
    """
    if content is None:
        return None
    pos = 0
    end = len(content)

    def skip_whitespace() -> None:
        nonlocal pos
        while pos < end and content[pos] in ASCII_WHITESPACE:
            pos += 1

    skip_whitespace()
    delay_start = pos
    while pos < end and content[pos] in "0123456789":    # not str.isdigit(): that accepts Arabic-Indic digits too
        pos += 1
    if pos == delay_start and content[pos:pos + 1] != ".":
        return None                                       # no delay number: browsers ignore it
    while pos < end and content[pos] in "0123456789.":
        pos += 1
    if pos < end:
        if content[pos] not in ASCII_WHITESPACE + ";,":
            return None
        skip_whitespace()
        if content[pos:pos + 1] in (";", ","):
            pos += 1
        skip_whitespace()
    if pos >= end:
        return None
    url_start = pos
    if content[pos:pos + 3].lower() == "url":
        pos += 3
        skip_whitespace()
        if content[pos:pos + 1] == "=":
            pos += 1
            skip_whitespace()
        else:
            pos = url_start                                # no '=': 'url' is part of the URL itself
    quote = content[pos:pos + 1] if content[pos:pos + 1] in ("'", '"') else ""
    url = content[pos + len(quote):]
    if quote:
        url = url.split(quote, 1)[0]
    return url.strip(ASCII_WHITESPACE) or None


def _stop_reading(raw) -> None:
    """Watchdog action: shut the connection so a stuck read fails at once.

    If the read already finished and the connection was closed or handed back, urllib3
    raises; that's the harmless outcome of the race, so it's ignored instead of printing
    an "Exception in thread" message.
    """
    with contextlib.suppress(ValueError, RuntimeError, OSError):
        raw.shutdown()


def _read_capped(response: requests.Response, *, sniff: bool = False) -> bytes:
    """At most MAX_BODY_BYTES of the body, read for at most MAX_BODY_SECONDS in total.

    The 5 s socket timeout only limits each single wait, and one read1 call can keep waiting
    (e.g. a gzip header or chunk-size line dripped a byte at a time never produces output).
    So a watchdog timer shuts the connection down when time is up, which makes any stuck
    read fail at once. A body that breaks off halfway gives what arrived.
    With sniff=True the first SNIFF_BYTES are read on their own and judged once they have all
    arrived; a page that doesn't look like HTML is not read any further.
    """
    data = bytearray()
    deadline = _now() + MAX_BODY_SECONDS
    watchdog = threading.Timer(MAX_BODY_SECONDS, _stop_reading, args=(response.raw,))
    watchdog.daemon = True
    watchdog.start()
    judging = sniff                     # still waiting for the first SNIFF_BYTES
    try:
        while len(data) < MAX_BODY_BYTES and _now() < deadline:
            amount = (SNIFF_BYTES if judging else MAX_BODY_BYTES) - len(data)   # what the cap leaves
            amount = min(amount, 8192)                                          # in 8 KB chunks at most
            chunk = response.raw.read1(amount, decode_content=True)
            if not chunk:
                break
            data += chunk
            if judging and len(data) >= SNIFF_BYTES:
                judging = False
                if not _sniffs_as_html(bytes(data)):
                    break               # a browser wouldn't show it as HTML: stop here
    except (requests.exceptions.RequestException, urllib3.exceptions.HTTPError, OSError):
        pass
    finally:
        watchdog.cancel()
    return bytes(data[:MAX_BODY_BYTES])


BOMS = (                          # byte order marks, which decide the encoding before anything else
    (b"\xef\xbb\xbf", "utf-8"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xff\xfe", "utf-16-le"),
)
# WHATWG Encoding Standard labels for UTF-16 (any other charset is read as UTF-8, see _decode_body).
UTF16_LABELS = {
    "utf-16be": "utf-16-be", "unicodefffe": "utf-16-be",
    "utf-16": "utf-16-le", "utf-16le": "utf-16-le", "unicode": "utf-16-le", "unicodefeff": "utf-16-le",
    "ucs-2": "utf-16-le", "iso-10646-ucs-2": "utf-16-le", "csunicode": "utf-16-le",
}


def _charset(content_type: str) -> str:
    """The charset= value of a Content-Type header, lower-cased ('' if there is none)."""
    for param in content_type.split(";")[1:]:
        name, _, value = param.partition("=")
        if name.strip(ASCII_WHITESPACE).lower() == "charset":
            return value.strip(ASCII_WHITESPACE).strip("\"'").strip(ASCII_WHITESPACE).lower()
    return ""


def _decode_body(body: bytes, content_type: str) -> str:
    """The page text, decoded the way a browser picks the encoding.

    A byte order mark wins (and is removed); otherwise a UTF-16 charset in Content-Type is used;
    otherwise UTF-8. Every other browser encoding keeps plain ASCII as the same bytes, and the
    canary address is plain ASCII, so reading those pages as UTF-8 finds the same tag.
    Accepted gap: the rare "replacement" charsets (e.g. iso-2022-kr) make a browser show nothing,
    so a meta refresh on such a page could be a false alarm.
    """
    for bom, encoding in BOMS:
        if body.startswith(bom):
            return body[len(bom):].decode(encoding, errors="replace")
    encoding = UTF16_LABELS.get(_charset(content_type), "utf-8")
    return body.decode(encoding, errors="replace")


def _meta_refresh_url(body: bytes, content_type: str = "") -> str | None:
    """The URL of the first <meta http-equiv="refresh"> in an HTML page, or None."""
    finder = _MetaRefreshFinder()
    try:
        finder.feed(_decode_body(body, content_type))
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
    """How a page without a redirect still sends browsers to the canary, if it does.

    Browsers show (and obey refreshes on) any answer that isn't a redirect, error pages
    included: 401, 403, 404, 500, a 3xx without Location, and a 300 even with Location.
    Only 204, 205 and 304 have no page to show, so they are never judged.
    Checks the Refresh header first (no body needed), then, for HTML pages only, a
    <meta http-equiv="refresh"> in the first MAX_BODY_BYTES. A page counts as HTML if its
    Content-Type says so, or if it has no usable type and its first bytes look like HTML
    to a browser's sniffing (see _browser_sniffs). JavaScript redirects are not
    detected: that would need running the page's scripts.
    """
    if response.status_code in NO_PAGE_STATUSES:
        return None
    if _points_to_canary(test, _refresh_url(response.headers.get("Refresh"))):
        return "header"
    content_type = response.headers.get("Content-Type", "")
    if _mime_essence(content_type) in HTML_TYPES:
        body = _read_capped(response)
    elif _browser_sniffs(response):
        body = _read_capped(response, sniff=True)
        if not _sniffs_as_html(body):
            return None
    else:
        return None                     # a stated non-HTML type (JSON, image, octet-stream...)
    if _points_to_canary(test, _meta_refresh_url(body, content_type)):
        return "meta"
    return None


# Content-Types that tell a browser nothing, so it guesses from the bytes (WHATWG MIME Sniffing).
UNKNOWN_TYPES = {"", "unknown/unknown", "application/unknown", "*/*"}
HTML_TYPES = {"text/html", "application/xhtml+xml"}   # types a browser renders as HTML
SNIFF_BYTES = 1445                  # browsers only look at this much of the page to guess
HTML_SIGNATURES = (                 # upper-cased; matched case-insensitively after leading whitespace,
                                    # and only when followed by a space or '>' (so not "<htmlx", "<abbr>")
    b"<!DOCTYPE HTML", b"<HTML", b"<HEAD", b"<SCRIPT", b"<IFRAME", b"<H1", b"<DIV", b"<FONT",
    b"<TABLE", b"<A", b"<STYLE", b"<TITLE", b"<B", b"<BODY", b"<BR", b"<P", b"<!--",
)


def _browser_sniffs(response: requests.Response) -> bool:
    """True if a browser would guess this page's type from its bytes.

    Only when Content-Type is missing, empty or one of the "unknown" values, and the server
    didn't forbid guessing with X-Content-Type-Options: nosniff. Any other type, even one the
    scanner doesn't know (application/octet-stream, image/png...), is taken at its word.
    """
    first_option = response.headers.get("X-Content-Type-Options", "").split(",", 1)[0]
    if first_option.strip(ASCII_WHITESPACE).lower() == "nosniff":
        return False
    return _mime_essence(response.headers.get("Content-Type", "")) in UNKNOWN_TYPES


_MIME_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"


def _mime_essence(content_type: str) -> str:
    """The "type/subtype" a browser would take from a Content-Type header, lower-case.

    Like a browser's "extract a MIME type": repeated headers arrive joined by commas and
    the last valid one wins; a value that isn't a valid type/subtype (e.g. "text", "html",
    "text/ html") counts as no type at all, which gives "" (and the page gets sniffed).
    """
    essence = ""
    for part in content_type.split(","):
        candidate = part.split(";", 1)[0].strip(ASCII_WHITESPACE)
        if re.fullmatch(f"{_MIME_TOKEN}/{_MIME_TOKEN}", candidate):
            essence = candidate.lower()
    return essence


def _sniffs_as_html(body: bytes) -> bool:
    """True if a browser's sniffing would call this page HTML (first SNIFF_BYTES only)."""
    head = body[:SNIFF_BYTES].lstrip(ASCII_WHITESPACE.encode()).upper()
    for signature in HTML_SIGNATURES:
        if head.startswith(signature) and head[len(signature):len(signature) + 1] in (b" ", b">"):
            return True
    return False


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

    def stop(reason: Literal["connection", "tls", "timeout"]) -> tuple[RedirectResults, Literal["no_http"] | None]:
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
                    # is_redirect is True only for 301/302/303/307/308 with a Location: the
                    # statuses browsers follow (Fetch's "redirect statuses"). A 300 with a
                    # Location, or any 3xx without one, is shown as a page, so its refresh is judged.
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
            except requests.exceptions.ConnectionError as e:    # includes "connect timed out"
                failures_in_a_row += 1
                if failures_in_a_row >= FAILURES_TO_STOP:      # host really gone: don't wait 32 x 5 s
                    return stop("timeout" if isinstance(e, requests.exceptions.ConnectTimeout)
                                else "connection")
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
