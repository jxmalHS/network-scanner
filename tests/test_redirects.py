"""Tests for redirects.py - open redirect check (requests.Session mocked, nothing is ever sent)."""
import email.message
import threading
from collections.abc import Iterator
from http.cookiejar import DefaultCookiePolicy
from unittest.mock import MagicMock, call, patch
from urllib.parse import urlparse

import pytest
import requests
import urllib3
from requests.cookies import MockRequest, MockResponse
from requests.structures import CaseInsensitiveDict

import redirects
from urltools import host_of

TOTAL_PROBES = len(redirects.REDIRECT_PATHS) * len(redirects.REDIRECT_PARAMS)
LOGIN_NEXT = f"http://example.com/login?next={redirects.CANARY_URL}"
FIRST_HTTP = f"http://example.com/?next={redirects.CANARY_URL}"
REFUSED = requests.exceptions.ConnectionError("refused")


@pytest.fixture(autouse=True)
def fake_sleep() -> Iterator[MagicMock]:
    """Never really pause between probes in tests; the mock records each pause instead."""
    with patch("redirects.time.sleep") as sleep:
        yield sleep


def _response(location: str | None = None) -> MagicMock:
    """Fake response usable in `with`: a 3xx pointing at `location`, or a plain 200 if None."""
    response = MagicMock()
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    response.is_redirect = location is not None
    response.status_code = 302 if location is not None else 200
    headers = CaseInsensitiveDict()
    if location is not None:
        headers["Location"] = location
    response.headers = headers
    response.raw.read1.return_value = b""     # an empty body (a page with no Content-Type is read)
    return response


def _session(fake_get: MagicMock) -> MagicMock:
    """Fake requests.Session whose .get is fake_get, also when used in a `with` block."""
    session = MagicMock()
    session.__enter__.return_value = session
    session.__exit__.return_value = False
    session.get = fake_get
    return session


def _run(fake_get: MagicMock, host: str = "example.com") -> redirects.RedirectResults:
    """Run the check with every request going to fake_get."""
    with patch("redirects.requests.Session", return_value=_session(fake_get)):
        return redirects.check_open_redirect(host)


def _urls(fake_get: MagicMock) -> list[str]:
    return [c.args[0] for c in fake_get.call_args_list]


def _answers(*responses: object) -> MagicMock:
    """Fake get that answers probe 1, 2, ... with the given responses/exceptions, then plain 200s."""
    queue = list(responses)

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        item = queue.pop(0) if queue else _response()
        if isinstance(item, BaseException):
            raise item
        return item

    return MagicMock(side_effect=fake_get)


def _flagged_with_location(location: str) -> list[str]:
    """Run the check where every probe redirects to `location`; return the flagged probe URLs."""
    return _run(MagicMock(return_value=_response(location)))["vulnerable"]


def test_check_open_redirect_returns_empty_list_when_nothing_redirects() -> None:
    """No probe gets a redirect, so nothing is vulnerable."""
    assert _run(MagicMock(return_value=_response()))["vulnerable"] == []


def test_check_open_redirect_complete_run_counts_every_probe() -> None:
    """A normal run: all 32 sent, none skipped, marked complete, base_url recorded."""
    result = _run(MagicMock(return_value=_response()))
    assert result == {
        "base_url": "http://example.com", "vulnerable": [], "probes_total": TOTAL_PROBES,
        "probes_sent": TOTAL_PROBES, "probes_skipped": 0, "complete": True,
        "switch_reason": None, "http_probes_sent": 0, "stop_reason": None,
        "offsite_redirect": None, "vulnerable_meta_refresh": [], "vulnerable_refresh_header": [],
    }
    assert TOTAL_PROBES == 32


def test_check_open_redirect_probes_every_path_and_param() -> None:
    """One request per path x param (32), covering every path, not just the root (backlog #6)."""
    fake_get = MagicMock(return_value=_response())
    _run(fake_get)
    assert fake_get.call_count == TOTAL_PROBES
    assert {urlparse(u).path for u in _urls(fake_get)} == set(redirects.REDIRECT_PATHS)


def test_check_open_redirect_never_follows_redirects() -> None:
    """Every request uses a 5 s timeout, allow_redirects=False and stream=True."""
    fake_get = MagicMock(return_value=_response())
    _run(fake_get)
    for c in fake_get.call_args_list:
        assert c.kwargs == {"timeout": 5, "allow_redirects": False, "stream": True}


# --- One Session per check, cookies off, a pause between probes ----------------


def test_check_open_redirect_uses_one_session_and_never_plain_requests_get() -> None:
    """Even with an HTTPS switch, one Session sends every probe; requests.get is never used."""
    fake_get = _answers(_response("https://example.com/"))
    with (
        patch("redirects.requests.Session", return_value=_session(fake_get)) as session_class,
        patch("redirects.requests.get") as plain_get,
    ):
        redirects.check_open_redirect("example.com")
    session_class.assert_called_once_with()
    plain_get.assert_not_called()
    assert fake_get.call_count == TOTAL_PROBES + 1


def test_check_open_redirect_closes_the_session() -> None:
    """The session is used in a `with` block, so its connections are closed at the end."""
    session = _session(MagicMock(return_value=_response()))
    with patch("redirects.requests.Session", return_value=session):
        redirects.check_open_redirect("example.com")
    session.__exit__.assert_called_once()


def test_check_open_redirect_never_disables_certificate_checks() -> None:
    """No probe ever passes verify=False (or any verify setting at all)."""
    fake_get = _answers(_response("https://example.com/"))
    _run(fake_get)
    assert all("verify" not in c.kwargs for c in fake_get.call_args_list)


def _store_set_cookie(jar: requests.cookies.RequestsCookieJar) -> None:
    """Feed the jar a 'Set-Cookie: sid=abc' reply from http://example.com/ (nothing is sent)."""
    headers = email.message.Message()
    headers["Set-Cookie"] = "sid=abc; Path=/"
    request = requests.Request("GET", "http://example.com/").prepare()
    jar.extract_cookies(MockResponse(headers), MockRequest(request))


def test_new_session_refuses_all_cookies() -> None:
    """A real session from _new_session() stores no cookie the server sets: probes stay independent."""
    session = redirects._new_session()
    try:
        policy = session.cookies.get_policy()
        assert isinstance(policy, DefaultCookiePolicy)
        assert tuple(policy.allowed_domains()) == ()
        _store_set_cookie(session.cookies)
        assert len(session.cookies) == 0
        assert session.verify is True
    finally:
        session.close()


def test_plain_session_would_store_the_cookie() -> None:
    """Control for the test above: without the policy, the same reply does store a cookie."""
    session = requests.Session()
    try:
        _store_set_cookie(session.cookies)
        assert len(session.cookies) == 1
    finally:
        session.close()


def test_new_session_sets_cookie_policy_on_the_session() -> None:
    """With the Session mocked, _new_session still installs the no-cookies policy."""
    with patch("redirects.requests.Session"):
        session = redirects._new_session()
    policy = session.cookies.set_policy.call_args.args[0]
    assert tuple(policy.allowed_domains()) == ()


def test_clean_run_pauses_31_times_never_before_first_probe(fake_sleep: MagicMock) -> None:
    """32 probes -> 31 pauses of PROBE_DELAY, and the very first request goes out without one."""
    events: list[str] = []
    fake_sleep.side_effect = lambda seconds: events.append("sleep")

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        events.append("get")
        return _response()

    _run(MagicMock(side_effect=fake_get))
    assert events[0] == "get"
    assert events.count("get") == TOTAL_PROBES
    assert events.count("sleep") == TOTAL_PROBES - 1
    assert "sleep sleep" not in " ".join(events)    # one pause between two requests, no more
    assert fake_sleep.call_args_list == [call(redirects.PROBE_DELAY)] * (TOTAL_PROBES - 1)


def test_switched_run_pauses_before_every_https_probe(fake_sleep: MagicMock) -> None:
    """1 HTTP probe + 32 HTTPS probes = 33 requests -> 32 pauses (also before the first HTTPS one)."""
    _run(_answers(_response("https://example.com/")))
    assert fake_sleep.call_count == TOTAL_PROBES


def test_probe_delay_is_small_and_positive() -> None:
    """The pause keeps the check polite (at most 5 requests a second) without making it slow."""
    assert redirects.PROBE_DELAY == 0.2


# --- Judging the Location header ---------------------------------------------


def test_check_open_redirect_flags_location_pointing_to_canary() -> None:
    """A redirect to the canary host is reported as the exact test URL that caused it."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        return _response(redirects.CANARY_URL) if url == LOGIN_NEXT else _response()

    assert _run(MagicMock(side_effect=fake_get))["vulnerable"] == [LOGIN_NEXT]


def test_check_open_redirect_flags_only_the_matching_probe() -> None:
    """Other probes redirect too, but only to the site itself, so only one is flagged."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        return _response(redirects.CANARY_URL) if url == LOGIN_NEXT else _response("/home")

    assert _run(MagicMock(side_effect=fake_get))["vulnerable"] == [LOGIN_NEXT]


def test_check_open_redirect_ignores_relative_location() -> None:
    """A relative Location like /home stays on the target site."""
    assert _flagged_with_location("/home") == []


def test_check_open_redirect_ignores_relative_same_site_redirect_carrying_canary() -> None:
    """/login?next=<canary> mentions the canary but never leaves the site (backlog #13)."""
    assert _flagged_with_location(f"/login?next={redirects.CANARY_URL}") == []


def test_check_open_redirect_ignores_absolute_same_site_redirect_carrying_canary() -> None:
    """Same as above with an absolute same-host URL: only the host matters, not the query."""
    assert _flagged_with_location(f"http://example.com/login?next={redirects.CANARY_URL}") == []


def test_check_open_redirect_flags_upper_case_canary_location() -> None:
    """Host names are case-insensitive, so HTTP://REDIRECT-CANARY.INVALID/ still counts."""
    assert len(_flagged_with_location("HTTP://REDIRECT-CANARY.INVALID/")) == TOTAL_PROBES


def test_check_open_redirect_backslash_before_at_sign_uses_real_host() -> None:
    r"""http://redirect-canary.invalid\@example.com/ - browsers read the backslash as a slash,
    so the real host is the canary (the '@example.com' part becomes part of the path)."""
    location = r"http://redirect-canary.invalid\@example.com/"
    assert host_of(redirects._browser_target(LOGIN_NEXT, location)) == redirects.CANARY_HOST
    assert len(_flagged_with_location(location)) == TOTAL_PROBES


def test_check_open_redirect_backslash_trick_stays_on_site() -> None:
    r"""http://example.com\@redirect-canary.invalid/ - a browser turns the backslash into a slash,
    so the host is example.com and '@redirect-canary.invalid/' is just path. Not flagged."""
    location = r"http://example.com\@redirect-canary.invalid/"
    assert host_of(redirects._browser_target(LOGIN_NEXT, location)) == "example.com"
    assert _flagged_with_location(location) == []


def test_check_open_redirect_ignores_location_header_on_non_redirect() -> None:
    """A 200 response that happens to carry a Location header is not a redirect."""
    response = _response()
    response.headers["Location"] = redirects.CANARY_URL
    assert _run(MagicMock(return_value=response))["vulnerable"] == []


@pytest.mark.parametrize(
    "location",
    [
        r"/\redirect-canary.invalid",
        r"\\redirect-canary.invalid",
        r"http:\\redirect-canary.invalid",
        "///redirect-canary.invalid",
        "  //redirect-canary.invalid  ",
    ],
)
def test_check_open_redirect_flags_browser_style_canary_location(location: str) -> None:
    """Odd-looking Locations that a browser still sends to the canary host are flagged."""
    assert len(_flagged_with_location(location)) == TOTAL_PROBES


@pytest.mark.parametrize(
    "location",
    [
        "/home",
        "/login?next=http://redirect-canary.invalid/",
        r"http://example.com\@redirect-canary.invalid/",
    ],
)
def test_check_open_redirect_does_not_flag_same_site_location(location: str) -> None:
    """Locations that stay on example.com are not flagged, even if they mention the canary."""
    assert _flagged_with_location(location) == []


def test_browser_target_backslashes_become_protocol_relative() -> None:
    r"""'\\host' is read by browsers as '//host' (a protocol-relative URL): same scheme, new host."""
    assert redirects._browser_target(LOGIN_NEXT, r"\\redirect-canary.invalid") == (
        "http://redirect-canary.invalid"
    )


def test_browser_target_collapses_extra_slashes_after_scheme() -> None:
    """'https:///host' is treated like 'https://host'."""
    assert redirects._browser_target(LOGIN_NEXT, "https:///redirect-canary.invalid/x") == (
        "https://redirect-canary.invalid/x"
    )


def test_browser_target_keeps_relative_path_on_same_site() -> None:
    """A plain relative path is joined onto the probed URL, like urljoin."""
    assert redirects._browser_target(LOGIN_NEXT, "/home") == "http://example.com/home"


def test_browser_target_strips_surrounding_whitespace() -> None:
    """Spaces around the Location are ignored."""
    assert redirects._browser_target(LOGIN_NEXT, "  /home  ") == "http://example.com/home"


def test_check_open_redirect_brackets_ipv6_host() -> None:
    """An IPv6 address must be wrapped in [brackets] inside a URL."""
    fake_get = MagicMock(return_value=_response())
    result = _run(fake_get, host="::1")
    assert _urls(fake_get)[0].startswith("http://[::1]/")
    assert result["base_url"] == "http://[::1]"


def test_canary_host_is_reserved_invalid_name() -> None:
    """The canary must be a .invalid name, which can never resolve to a real third-party site."""
    assert redirects.CANARY_HOST.endswith(".invalid")
    assert redirects.CANARY_URL == f"http://{redirects.CANARY_HOST}/"


# --- Failures: skipped probes, and stopping after 2 failed connections in a row ---


def test_check_open_redirect_stops_on_connection_error() -> None:
    """Refused twice over HTTP, then twice over HTTPS: give up after 4 requests in total."""
    fake_get = MagicMock(side_effect=REFUSED)
    result = _run(fake_get)
    urls = _urls(fake_get)
    assert fake_get.call_count == 4
    assert all(u.startswith("http://example.com/") for u in urls[:2])
    assert all(u.startswith("https://example.com/") for u in urls[2:])
    assert result["vulnerable"] == []
    assert result["base_url"] == "https://example.com"
    assert result["switch_reason"] == "no_http"
    assert result["http_probes_sent"] == 2
    assert result["complete"] is False
    assert result["stop_reason"] == "connection"


def test_check_open_redirect_connection_error_marks_incomplete() -> None:
    """Refused twice: incomplete; the 1st failure counts as skipped, the 2nd is where it stopped."""
    result = _run(MagicMock(side_effect=REFUSED))
    assert result["complete"] is False
    assert result["probes_sent"] == 2
    assert result["probes_skipped"] == 1
    assert result["probes_total"] == TOTAL_PROBES


def test_one_dropped_connection_only_skips_that_probe() -> None:
    """A single ConnectionError mid-run is skipped; the check goes on and stays complete."""
    fake_get = _answers(_response(), _response(), REFUSED)
    result = _run(fake_get)
    assert fake_get.call_count == TOTAL_PROBES
    assert result["complete"] is True
    assert result["probes_skipped"] == 1
    assert result["stop_reason"] is None


def test_two_dropped_connections_in_a_row_stop_the_check() -> None:
    """Probes 3 and 4 both fail to connect: stop at probe 4 with stop_reason 'connection'."""
    fake_get = _answers(_response(), _response(), REFUSED, REFUSED)
    result = _run(fake_get)
    assert fake_get.call_count == 4
    assert result["complete"] is False
    assert result["probes_sent"] == 4
    assert result["probes_skipped"] == 1
    assert result["stop_reason"] == "connection"
    assert result["switch_reason"] is None
    assert result["base_url"] == "http://example.com"


def test_failure_count_resets_after_an_answered_probe() -> None:
    """fail, answer, fail, answer, ...: never two in a row, so the check runs to the end."""
    fake_get = _answers(*([REFUSED, _response()] * (TOTAL_PROBES // 2)))
    result = _run(fake_get)
    assert fake_get.call_count == TOTAL_PROBES
    assert result["complete"] is True
    assert result["probes_skipped"] == TOTAL_PROBES // 2


def test_check_open_redirect_keeps_findings_when_connect_timeout_stops_scan() -> None:
    """Probe 1 is vulnerable, then two connect timeouts in a row: keep the find and stop."""
    timeout = requests.exceptions.ConnectTimeout("no answer")
    fake_get = _answers(_response(redirects.CANARY_URL), timeout, timeout)
    result = _run(fake_get)
    assert result["vulnerable"] == [FIRST_HTTP]
    assert result["probes_sent"] == 3
    assert result["complete"] is False
    assert fake_get.call_count == 3


def test_check_open_redirect_read_timeout_skips_only_that_probe() -> None:
    """The first probe connects but the page is slow (ReadTimeout): skip it, keep scanning,
    and still report a vulnerable probe that comes later."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        if url == FIRST_HTTP:
            raise requests.exceptions.ReadTimeout("slow page")
        return _response(redirects.CANARY_URL) if url == LOGIN_NEXT else _response()

    mock_get = MagicMock(side_effect=fake_get)
    result = _run(mock_get)
    assert result["vulnerable"] == [LOGIN_NEXT]
    assert result["complete"] is True
    assert result["probes_skipped"] == 1
    assert result["probes_sent"] == TOTAL_PROBES
    assert mock_get.call_count == TOTAL_PROBES


def test_check_open_redirect_garbled_location_does_not_crash() -> None:
    """Location 'http://[oops' makes urljoin raise ValueError; each probe is skipped, none crash."""
    mock_get = MagicMock(return_value=_response("http://[oops"))
    result = _run(mock_get)
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == TOTAL_PROBES
    assert result["complete"] is True
    assert mock_get.call_count == TOTAL_PROBES


def test_check_open_redirect_skips_probe_on_other_request_error() -> None:
    """An odd error (InvalidURL) skips only that probe; the other 31 still run."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        if url == LOGIN_NEXT:
            raise requests.exceptions.InvalidURL("bad")
        return _response()

    mock_get = MagicMock(side_effect=fake_get)
    result = _run(mock_get)
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == 1
    assert mock_get.call_count == TOTAL_PROBES


def test_ssl_error_stops_at_once_with_tls_reason() -> None:
    """A certificate failure won't go away by retrying: stop on the first SSLError."""
    fake_get = _answers(_response("https://example.com/"), _response(),
                        requests.exceptions.SSLError("certificate verify failed"))
    result = _run(fake_get)
    assert fake_get.call_count == 3
    assert result["complete"] is False
    assert result["stop_reason"] == "tls"
    assert result["probes_sent"] == 2
    assert result["probes_skipped"] == 0


# --- Switching to https:// when plain HTTP redirects there or can't be reached ---


def _upgrade_on_first_probe(location: str) -> MagicMock:
    """Fake get: only the very first HTTP probe redirects to `location`; all else is 200."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        return _response(location) if url == FIRST_HTTP else _response()

    return MagicMock(side_effect=fake_get)


def test_check_open_redirect_switches_to_https_on_upgrade_redirect() -> None:
    """HTTP probe 1 redirects to https://example.com/: one HTTP call, then all 32 probes over HTTPS."""
    fake_get = _upgrade_on_first_probe("https://example.com/")
    result = _run(fake_get)
    urls = _urls(fake_get)
    assert len(urls) == TOTAL_PROBES + 1
    assert urls[0].startswith("http://")
    assert all(u.startswith("https://example.com/") for u in urls[1:])
    assert result["base_url"] == "https://example.com"
    assert result["switch_reason"] == "redirect"
    assert result["http_probes_sent"] == 1
    assert result["complete"] is True
    assert result["probes_sent"] == TOTAL_PROBES
    assert result["vulnerable"] == []


@pytest.mark.parametrize("location", [
    "https://example.com/login?x=1",
    "https://example.com:443/",
    "HTTPS://EXAMPLE.COM/",
])
def test_check_open_redirect_https_upgrade_variants_switch(location: str) -> None:
    """Any path/query, an explicit :443, or upper-case scheme/host still count as an upgrade."""
    fake_get = _upgrade_on_first_probe(location)
    result = _run(fake_get)
    assert result["switch_reason"] == "redirect"
    assert result["base_url"] == "https://example.com"
    assert fake_get.call_count == TOTAL_PROBES + 1


@pytest.mark.parametrize("location", [
    "/home",
    "http://example.com/other",
    "https://example.com:8443/",
])
def test_check_open_redirect_non_upgrade_location_does_not_switch(location: str) -> None:
    """Relative paths, plain-HTTP redirects and HTTPS on another port are not an upgrade."""
    fake_get = _upgrade_on_first_probe(location)
    result = _run(fake_get)
    assert result["switch_reason"] is None
    assert result["base_url"] == "http://example.com"
    assert result["http_probes_sent"] == 0
    assert fake_get.call_count == TOTAL_PROBES


def test_check_open_redirect_upgrade_to_other_host_never_contacts_it() -> None:
    """https://www.example.com/ is a different host: no switch, and www.example.com is never requested."""
    fake_get = _upgrade_on_first_probe("https://www.example.com/")
    result = _run(fake_get)
    assert result["switch_reason"] is None
    assert fake_get.call_count == TOTAL_PROBES
    assert not any("www.example.com" in u for u in _urls(fake_get))


def test_check_open_redirect_switches_when_http_unreachable() -> None:
    """HTTP refuses twice, HTTPS answers: all 32 probes run over HTTPS, reason no_http."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        if url.startswith("http://"):
            raise REFUSED
        return _response()

    mock_get = MagicMock(side_effect=fake_get)
    result = _run(mock_get)
    assert result["switch_reason"] == "no_http"
    assert result["base_url"] == "https://example.com"
    assert result["complete"] is True
    assert result["probes_sent"] == TOTAL_PROBES
    assert result["http_probes_sent"] == 2
    assert mock_get.call_count == TOTAL_PROBES + 2


def test_check_open_redirect_https_ssl_error_after_switch_never_disables_verification() -> None:
    """HTTPS fails with an SSLError after the switch: incomplete (tls), and verify=False is never used."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        if url.startswith("http://"):
            return _response("https://example.com/")
        raise requests.exceptions.SSLError("certificate verify failed")

    mock_get = MagicMock(side_effect=fake_get)
    result = _run(mock_get)
    assert mock_get.call_count == 2
    assert result["complete"] is False
    assert result["stop_reason"] == "tls"
    assert result["switch_reason"] == "redirect"
    assert all(c.kwargs.get("verify", True) is not False for c in mock_get.call_args_list)


def test_check_open_redirect_upgrade_on_later_probe_is_ignored() -> None:
    """Probe 1 was answered, so it decided: an HTTPS upgrade on probe 2+ is neither a switch nor a finding."""
    mock_get = _answers(_response(), *[_response("https://example.com/")] * (TOTAL_PROBES - 1))
    result = _run(mock_get)
    assert result["switch_reason"] is None
    assert result["vulnerable"] == []
    assert mock_get.call_count == TOTAL_PROBES
    assert all(u.startswith("http://") for u in _urls(mock_get))


def test_check_open_redirect_switches_only_once() -> None:
    """HTTPS probes that also redirect to https://example.com/ don't trigger a second switch: 33 calls."""
    mock_get = MagicMock(return_value=_response("https://example.com/"))
    result = _run(mock_get)
    assert mock_get.call_count == TOTAL_PROBES + 1
    assert result["switch_reason"] == "redirect"
    assert result["complete"] is True


def test_check_open_redirect_canary_on_first_probe_is_flagged_not_switched() -> None:
    """A canary Location on probe 1 is a finding, not an HTTPS upgrade."""
    fake_get = _upgrade_on_first_probe(redirects.CANARY_URL)
    result = _run(fake_get)
    assert result["vulnerable"] == [FIRST_HTTP]
    assert result["switch_reason"] is None
    assert fake_get.call_count == TOTAL_PROBES


def test_check_open_redirect_ipv6_switch_keeps_brackets() -> None:
    """When ::1 switches to HTTPS, the new base is https://[::1]."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        if url.startswith("http://"):
            raise REFUSED
        return _response()

    result = _run(MagicMock(side_effect=fake_get), host="::1")
    assert result["base_url"] == "https://[::1]"
    assert result["switch_reason"] == "no_http"


# --- The first ANSWERED probe (within the first 4) decides the switch ----------

SLOW = requests.exceptions.ReadTimeout("slow page")
UPGRADE = "https://example.com/"


def test_skipped_first_probe_lets_second_probe_decide_switch() -> None:
    """Probe 1 times out, probe 2 redirects to HTTPS: switch, after 2 HTTP requests."""
    fake_get = _answers(SLOW, _response(UPGRADE))
    result = _run(fake_get)
    assert result["switch_reason"] == "redirect"
    assert result["http_probes_sent"] == 2
    assert fake_get.call_count == TOTAL_PROBES + 2


def test_upgrade_on_fourth_probe_after_three_skips_still_switches() -> None:
    """Probes 1-3 get no usable answer; probe 4 (the last in the window) can still decide."""
    fake_get = _answers(SLOW, SLOW, SLOW, _response(UPGRADE))
    result = _run(fake_get)
    assert result["switch_reason"] == "redirect"
    assert result["http_probes_sent"] == 4


def test_upgrade_after_switch_window_is_ignored() -> None:
    """Probes 1-4 skipped: the window is over, so an upgrade on probe 5 doesn't switch."""
    fake_get = _answers(SLOW, SLOW, SLOW, SLOW, _response(UPGRADE))
    result = _run(fake_get)
    assert result["switch_reason"] is None
    assert result["base_url"] == "http://example.com"
    assert fake_get.call_count == TOTAL_PROBES


def test_one_refused_then_answered_does_not_switch() -> None:
    """HTTP refuses once, then answers normally: no switch, that one probe is skipped."""
    result = _run(_answers(REFUSED, _response()))
    assert result["switch_reason"] is None
    assert result["base_url"] == "http://example.com"
    assert result["probes_skipped"] == 1
    assert result["complete"] is True


def test_skip_then_two_refusals_while_deciding_switches_no_http() -> None:
    """Timeout, then refused twice in a row, all before any answer: HTTP is unreachable -> no_http."""
    fake_get = _answers(SLOW, REFUSED, REFUSED)
    result = _run(fake_get)
    assert result["switch_reason"] == "no_http"
    assert result["http_probes_sent"] == 3
    assert result["base_url"] == "https://example.com"
    assert fake_get.call_count == TOTAL_PROBES + 3


def test_two_refusals_after_an_answer_do_not_switch() -> None:
    """HTTP answered probe 1, so a later double refusal just stops the check (no switch)."""
    fake_get = _answers(_response(), REFUSED, REFUSED)
    result = _run(fake_get)
    assert result["switch_reason"] is None
    assert result["complete"] is False
    assert fake_get.call_count == 3


def test_most_http_requests_before_switch_is_switch_window() -> None:
    """Worst case: 3 skips then an upgrade -> 4 HTTP + 32 HTTPS = 36 requests in total."""
    fake_get = _answers(SLOW, SLOW, SLOW, _response(UPGRADE))
    _run(fake_get)
    assert fake_get.call_count == redirects.SWITCH_WINDOW + TOTAL_PROBES == 36


# --- Off-site redirect on the first answered probe: recorded, never requested ---


def test_offsite_redirect_on_first_probe_is_recorded_not_requested() -> None:
    """Probe 1 redirects to https://www.example.com/: noted in offsite_redirect, www never requested."""
    fake_get = _upgrade_on_first_probe("https://www.example.com/")
    result = _run(fake_get)
    assert result["offsite_redirect"] == "https://www.example.com/"
    assert result["vulnerable"] == []
    assert not any("www.example.com" in u for u in _urls(fake_get))


def test_offsite_redirect_is_judged_like_a_browser() -> None:
    """A protocol-relative //www.example.com is resolved against the probe URL."""
    result = _run(_upgrade_on_first_probe("//www.example.com/home"))
    assert result["offsite_redirect"] == "http://www.example.com/home"


@pytest.mark.parametrize("location", [
    redirects.CANARY_URL,        # a finding, not an off-site note
    "/home",                     # same site
    "http://example.com:8080/",  # same host, other port
])
def test_no_offsite_redirect_for_canary_or_same_host(location: str) -> None:
    """The canary and the target host itself are never reported as 'another host'."""
    assert _run(_upgrade_on_first_probe(location))["offsite_redirect"] is None


def test_no_offsite_redirect_for_https_upgrade() -> None:
    """The HTTPS upgrade is a switch, not an off-site redirect."""
    assert _run(_upgrade_on_first_probe(UPGRADE))["offsite_redirect"] is None


def test_offsite_redirect_on_later_probe_is_not_recorded() -> None:
    """Only the first answered probe is looked at for an off-site redirect."""
    result = _run(_answers(_response(), _response("https://www.example.com/")))
    assert result["offsite_redirect"] is None


def test_offsite_redirect_after_skipped_probe_is_recorded() -> None:
    """Probe 1 skipped: probe 2 is the first answered one, so its off-site redirect is noted."""
    result = _run(_answers(SLOW, _response("https://www.example.com/")))
    assert result["offsite_redirect"] == "https://www.example.com/"


def test_offsite_redirect_after_https_switch_is_recorded() -> None:
    """After switching, the first HTTPS probe redirecting to www is noted (and never requested)."""
    fake_get = _answers(_response(UPGRADE), _response("https://www.example.com/"))
    result = _run(fake_get)
    assert result["switch_reason"] == "redirect"
    assert result["offsite_redirect"] == "https://www.example.com/"
    assert not any("www.example.com" in u for u in _urls(fake_get))


# --- Redirects inside a 200 page: <meta http-equiv="refresh"> and the Refresh header ---


def _page(body: bytes = b"", content_type: str | None = "text/html; charset=utf-8",
          refresh: str | None = None, status: int = 200) -> MagicMock:
    """Fake non-redirect response whose body raw.read1 hands out in chunks."""
    response = _response()
    response.status_code = status
    if content_type is not None:
        response.headers["Content-Type"] = content_type
    if refresh is not None:
        response.headers["Refresh"] = refresh

    pieces = [body[i:i + 8192] for i in range(0, len(body), 8192)]
    state = {"chunks": iter(pieces)}

    def enter() -> MagicMock:             # every probe that opens this response reads it from the start
        state["chunks"] = iter(pieces)
        return response

    response.__enter__.side_effect = enter
    response.raw.read1.side_effect = lambda amt=8192, **kwargs: next(state["chunks"], b"")
    return response


def _meta(content: str) -> bytes:
    return f'<html><head><meta http-equiv="refresh" content="{content}"></head></html>'.encode()


def _first_probe_flagged(response: MagicMock) -> redirects.RedirectResults:
    """Run with probe 1 answered by `response` (all others plain 200s)."""
    return _run(_answers(response))


@pytest.mark.parametrize("body", [
    _meta("0; url=http://redirect-canary.invalid/"),
    _meta("0;URL=http://redirect-canary.invalid/"),
    _meta("5; url='http://redirect-canary.invalid/'"),
    _meta("0;url=&quot;http://redirect-canary.invalid/&quot;"),
    _meta("0, http://redirect-canary.invalid/"),
    _meta("0;url=//redirect-canary.invalid/"),
    _meta(r"0;url=\\redirect-canary.invalid"),
    _meta("0;url=http://redirect-canary.invalid/?a=1&amp;b=2"),
    b'<META HTTP-EQUIV="REFRESH" CONTENT="0;URL=HTTP://REDIRECT-CANARY.INVALID/">',
    b"<meta http-equiv='Refresh' content='0;url=http://redirect-canary.invalid/' />",
    b"\xc3\x28\xff broken bytes " + _meta("0;url=http://redirect-canary.invalid/"),
])
def test_meta_refresh_to_canary_is_flagged(body: bytes) -> None:
    """Every spelling of a meta refresh that sends browsers to the canary is a finding."""
    result = _first_probe_flagged(_page(body))
    assert result["vulnerable"] == [FIRST_HTTP]
    assert result["vulnerable_meta_refresh"] == [FIRST_HTTP]
    assert result["vulnerable_refresh_header"] == []


@pytest.mark.parametrize("body", [
    _meta("0;url=/login?next=http://redirect-canary.invalid/"),   # same site, canary only in query
    _meta("0;url=http://example.com/?next=http://redirect-canary.invalid/"),
    _meta("5"),                                                   # refreshes the same page
    _meta("0;url=http://[oops"),                                  # garbled: no crash, no finding
    b'<a href="http://redirect-canary.invalid/">echoed link</a>',  # page only echoes the parameter
    b'<meta name="description" content="0;url=http://redirect-canary.invalid/">',
    b"",
])
def test_meta_refresh_not_flagged(body: bytes) -> None:
    """Same-site refreshes, no URL, garbled URLs and plain echoes are not findings or skips."""
    result = _first_probe_flagged(_page(body))
    assert result["vulnerable"] == []
    assert result["vulnerable_meta_refresh"] == []
    assert result["probes_skipped"] == 0
    assert result["complete"] is True


def test_meta_refresh_garbled_url_with_control_chars_does_not_crash() -> None:
    """A hostile refresh URL full of escape codes is judged safely (host is the canary: flagged)."""
    body = _meta("0;url=http://redirect-canary.invalid/\x1b[2J\u202e\n[OK] fake")
    result = _first_probe_flagged(_page(body))
    assert result["vulnerable"] == [FIRST_HTTP]


CANARY_META = _meta("0;url=http://redirect-canary.invalid/")


@pytest.mark.parametrize("content_type", [
    "application/json", "text/plain", "image/png", "application/octet-stream",
    "application/octet-stream; charset=utf-8", "text/css",
])
def test_body_not_read_for_a_stated_non_html_type(content_type: str) -> None:
    """A page whose Content-Type names any non-HTML type is taken at its word and never read."""
    response = _page(CANARY_META, content_type=content_type)
    result = _first_probe_flagged(response)
    assert result["vulnerable"] == []
    response.raw.read1.assert_not_called()


# --- Pages without a usable Content-Type: guessed from their first bytes, like a browser ---


@pytest.mark.parametrize("content_type", [
    None, "", "  ", "unknown/unknown", "application/unknown", "*/*", "UNKNOWN/UNKNOWN; x=1",
])
def test_untyped_html_page_is_sniffed_and_flagged(content_type: str | None) -> None:
    """No Content-Type (or an 'unknown' one): a browser sniffs <html> and obeys the meta refresh."""
    result = _first_probe_flagged(_page(CANARY_META, content_type=content_type))
    assert result["vulnerable_meta_refresh"] == [FIRST_HTTP]


@pytest.mark.parametrize("prefix", [
    b"<!DOCTYPE html>",
    b" \t\r\n\x0c<!doctype HTML>",
    b"<p>hello</p>",
    b"<!-- comment -->",
    b"<HtMl>",
    b"<head>",
    b"<script>x=1</script>",
    b"<b>bold</b>",
])
def test_sniffing_recognises_html_starts(prefix: bytes) -> None:
    """The browser's HTML signatures, case-insensitive, after leading whitespace."""
    body = prefix + b'<meta http-equiv="refresh" content="0;url=http://redirect-canary.invalid/">'
    result = _first_probe_flagged(_page(body, content_type=None))
    assert result["vulnerable_meta_refresh"] == [FIRST_HTTP]


@pytest.mark.parametrize("body", [
    b"<htmlx>" + CANARY_META,                     # tag name must end with a space or '>'
    b"<abbr>" + CANARY_META,                      # <a must be followed by space or '>'
    b"hello " + CANARY_META,                      # plain text first
    b"\xef\xbb\xbf" + CANARY_META,                # a BOM is not whitespace: sniffed as text
    b"\xff\xfe" + CANARY_META.decode().encode("utf-16-le"),
    b" " * redirects.SNIFF_BYTES + CANARY_META,   # the HTML start is past what browsers look at
    b"\xa0" + CANARY_META,                        # NBSP is not skipped as whitespace
])
def test_untyped_page_not_sniffed_as_html_is_not_flagged(body: bytes) -> None:
    """Untyped pages a browser would show as text are not judged for a meta refresh."""
    result = _first_probe_flagged(_page(body, content_type=None))
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == 0


@pytest.mark.parametrize("option", ["nosniff", "NoSniff ", "nosniff, nosniff"])
def test_nosniff_untyped_page_is_not_read(option: str) -> None:
    """X-Content-Type-Options: nosniff forbids guessing, so an untyped page is never read."""
    response = _page(CANARY_META, content_type=None)
    response.headers["X-Content-Type-Options"] = option
    result = _first_probe_flagged(response)
    assert result["vulnerable"] == []
    response.raw.read1.assert_not_called()


def test_nosniff_does_not_stop_a_typed_html_page() -> None:
    """nosniff only stops guessing; a page that says text/html is still read."""
    response = _page(CANARY_META)
    response.headers["X-Content-Type-Options"] = "nosniff"
    assert _first_probe_flagged(response)["vulnerable_meta_refresh"] == [FIRST_HTTP]


def test_octet_stream_page_with_meta_refresh_is_not_read() -> None:
    """application/octet-stream is a stated type (a download), not 'unknown': never sniffed."""
    response = _page(b"<html>" + CANARY_META, content_type="application/octet-stream")
    result = _first_probe_flagged(response)
    assert result["vulnerable"] == []
    response.raw.read1.assert_not_called()


def test_untyped_body_read_is_still_capped_at_64_kb() -> None:
    """An endless page with no Content-Type: at most 64 KB is pulled, then it's closed."""
    response = _page(content_type=None)
    pulled: list[int] = []

    def endless(amt: int = 8192, **kwargs: object) -> bytes:
        pulled.append(amt)
        return b"<html>" + b"a" * (amt - 6)

    response.raw.read1.side_effect = endless
    result = _first_probe_flagged(response)
    assert 0 < sum(pulled) <= redirects.MAX_BODY_BYTES
    assert result["vulnerable"] == []
    assert response.__exit__.call_count == response.__enter__.call_count == 1


def test_untyped_body_read_stops_at_the_time_limit() -> None:
    """A slow-drip untyped page is cut off at MAX_BODY_SECONDS just like an HTML one."""
    response = _page(content_type=None)
    response.raw.read1.side_effect = lambda amt=8192, **kwargs: b"a"
    clock = iter(range(0, 10_000, 2))
    with patch("redirects._now", side_effect=lambda: next(clock)):
        result = _first_probe_flagged(response)
    assert response.raw.read1.call_count <= 3
    assert result["probes_skipped"] == 0


def test_untyped_meta_page_on_every_probe_never_requests_the_canary() -> None:
    """Sniffed pages are flagged, but still only 32 requests, all to example.com."""
    fake_get = MagicMock(return_value=_page(CANARY_META, content_type=None, status=404))
    result = _run(fake_get)
    assert len(result["vulnerable_meta_refresh"]) == TOTAL_PROBES
    assert fake_get.call_count == TOTAL_PROBES
    assert all(host_of(u) == "example.com" for u in _urls(fake_get))


@pytest.mark.parametrize("status", [200, 300, 302, 401, 403, 404, 500])
def test_meta_refresh_judged_on_any_page_a_browser_shows(status: int) -> None:
    """Error pages and 3xx answers without a Location are shown by browsers, so they count."""
    result = _first_probe_flagged(_page(CANARY_META, status=status))
    assert result["vulnerable"] == [FIRST_HTTP]
    assert result["vulnerable_meta_refresh"] == [FIRST_HTTP]


def test_300_with_location_is_judged_as_a_page() -> None:
    """300 Multiple Choices is not one of the statuses browsers follow, even with a Location."""
    response = _page(CANARY_META, status=300, refresh="0;url=http://redirect-canary.invalid/")
    response.headers["Location"] = "/home"
    real = requests.Response()                      # what requests itself says about such a reply
    real.status_code = 300
    real.headers["Location"] = "/home"
    response.is_redirect = real.is_redirect
    assert response.is_redirect is False
    result = _first_probe_flagged(response)
    assert result["vulnerable"] == [FIRST_HTTP]
    assert result["vulnerable_refresh_header"] == [FIRST_HTTP]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_refresh_not_judged_on_a_real_redirect(status: int) -> None:
    """301/302/303/307/308 with a Location: the browser follows it, so the refresh never matters."""
    response = _page(CANARY_META, status=status, refresh="0;url=http://redirect-canary.invalid/")
    response.headers["Location"] = "/home"
    real = requests.Response()
    real.status_code = status
    real.headers["Location"] = "/home"
    response.is_redirect = real.is_redirect
    assert response.is_redirect is True
    result = _first_probe_flagged(response)
    assert result["vulnerable"] == []
    response.raw.read1.assert_not_called()


@pytest.mark.parametrize("status", [204, 205])
def test_no_content_answers_are_never_judged(status: int) -> None:
    """204/205 have no page to show: neither the Refresh header nor the body is looked at."""
    response = _page(CANARY_META, status=status, refresh="0;url=http://redirect-canary.invalid/")
    result = _first_probe_flagged(response)
    assert result["vulnerable"] == []
    response.raw.read1.assert_not_called()


def test_404_meta_page_on_every_probe_never_requests_the_canary() -> None:
    """Error pages with a meta refresh are flagged, but still only 32 requests, all to example.com."""
    fake_get = MagicMock(return_value=_page(CANARY_META, status=404))
    result = _run(fake_get)
    assert len(result["vulnerable_meta_refresh"]) == TOTAL_PROBES
    assert fake_get.call_count == TOTAL_PROBES
    assert all(host_of(u) == "example.com" for u in _urls(fake_get))


def test_body_not_read_for_redirect_response() -> None:
    """A 302 is judged by its Location only; its body is never read."""
    response = _response("/home")
    response.headers["Content-Type"] = "text/html"
    _first_probe_flagged(response)
    response.raw.read1.assert_not_called()


def test_body_read_is_capped_at_64_kb_and_response_closed() -> None:
    """An endless page: at most 64 KB is pulled, and the response is still closed afterwards."""
    response = _page()
    pulled: list[int] = []

    def endless(amt: int = 8192, **kwargs: object) -> bytes:
        pulled.append(amt)
        return b"a" * amt

    response.raw.read1.side_effect = endless
    result = _first_probe_flagged(response)
    assert sum(pulled) <= redirects.MAX_BODY_BYTES
    assert redirects.MAX_BODY_BYTES == 64 * 1024
    assert result["vulnerable"] == []
    response.__exit__.assert_called()
    exit_calls = response.__exit__.call_count
    assert exit_calls == response.__enter__.call_count == 1


def test_meta_refresh_after_64_kb_is_not_seen() -> None:
    """Only the first 64 KB is searched: a meta refresh further down is ignored."""
    body = b"<html>" + b" " * redirects.MAX_BODY_BYTES + _meta("0;url=http://redirect-canary.invalid/")
    assert _first_probe_flagged(_page(body))["vulnerable"] == []


def test_body_that_breaks_off_uses_what_arrived() -> None:
    """The connection drops after the meta tag: the finding still counts, and nothing is skipped."""
    response = _page()

    response.raw.read1.side_effect = [
        _meta("0;url=http://redirect-canary.invalid/"),
        urllib3.exceptions.ProtocolError("connection broken"),
    ]
    result = _first_probe_flagged(response)
    assert result["vulnerable"] == [FIRST_HTTP]
    assert result["probes_skipped"] == 0


def test_parser_error_means_no_meta_refresh_found() -> None:
    """If html.parser gives up on hostile markup, the page simply has no meta refresh."""
    with patch.object(redirects._MetaRefreshFinder, "feed", side_effect=AssertionError("bad markup")):
        result = _first_probe_flagged(_page(_meta("0;url=http://redirect-canary.invalid/")))
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == 0


@pytest.mark.parametrize("refresh", [
    "0; url=http://redirect-canary.invalid/",
    "0;URL='http://redirect-canary.invalid/'",
    "3,//redirect-canary.invalid/",
])
def test_refresh_header_to_canary_is_flagged_without_reading_body(refresh: str) -> None:
    """A Refresh: header pointing at the canary is a finding; the body is not needed."""
    response = _page(content_type=None, refresh=refresh)
    result = _first_probe_flagged(response)
    assert result["vulnerable"] == [FIRST_HTTP]
    assert result["vulnerable_refresh_header"] == [FIRST_HTTP]
    assert result["vulnerable_meta_refresh"] == []
    response.raw.read1.assert_not_called()


@pytest.mark.parametrize("refresh", [
    "0; url=/home",
    "0; url=/login?next=http://redirect-canary.invalid/",
    "10",
    "0;url=http://[oops",
])
def test_refresh_header_not_flagged(refresh: str) -> None:
    """Same-site, URL-less or garbled Refresh headers are not findings."""
    result = _first_probe_flagged(_page(content_type=None, refresh=refresh))
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == 0


def test_refresh_header_judged_on_404() -> None:
    """Refresh on a 404 page still sends browsers there (same rule as the meta refresh)."""
    response = _page(content_type=None, refresh="0;url=http://redirect-canary.invalid/", status=404)
    assert _first_probe_flagged(response)["vulnerable_refresh_header"] == [FIRST_HTTP]


def test_meta_refresh_page_never_requests_the_canary() -> None:
    """Finding a meta refresh doesn't make the scanner go there: 32 requests, all to example.com."""
    fake_get = MagicMock(return_value=_page(_meta("0;url=http://redirect-canary.invalid/")))
    result = _run(fake_get)
    assert len(result["vulnerable_meta_refresh"]) == TOTAL_PROBES
    assert fake_get.call_count == TOTAL_PROBES
    assert all(host_of(u) == "example.com" for u in _urls(fake_get))


@pytest.mark.parametrize(("content", "expected"), [
    ("0; url=http://a/", "http://a/"),
    ("0;URL = 'http://a/' trailing", "http://a/"),
    ('0;url="http://a/', "http://a/"),
    ("0", None),
    ("0; url=", None),
    ("soon; url=http://a/", None),   # no delay number: browsers ignore it
    (None, None),
    ("0url=http://a/", None),        # after the delay must come whitespace, ';' or ','
    ("0;", None),
    ("٠; url=http://a/", None),   # Arabic-Indic zero is not an ASCII digit
    (" 0; url=http://a/", None),  # a no-break space is not ASCII whitespace
    ("0;url=http://a/ ", "http://a/ "),  # ...so it isn't stripped from the end either
    (".5; url=http://a/", "http://a/"),
    ("1.5.2 url=http://a/", "http://a/"),
    ("\t\n0\r\n,\turl\t=\t'http://a/'", "http://a/"),
    ("0 http://a/", "http://a/"),
    ("0; URL=http://a/", "http://a/"),
    ("0; url x", "url x"),           # no '=': the whole rest is the URL
    ("0; urlhttp://a/", "urlhttp://a/"),
    ("0;;url=http://a/", ";url=http://a/"),   # only one separator is skipped
    ("0; url='http://a/'x'", "http://a/"),
])
def test_refresh_url_parsing(content: str | None, expected: str | None) -> None:
    """_refresh_url follows the HTML standard's shared declarative refresh steps."""
    assert redirects._refresh_url(content) == expected


@pytest.mark.parametrize("content", [
    "0url=http://redirect-canary.invalid/",
    "٠;url=http://redirect-canary.invalid/",
    " 0;url=http://redirect-canary.invalid/",
    "0; url x//redirect-canary.invalid/",
    "0;;url=http://redirect-canary.invalid/",
])
def test_refresh_values_browsers_ignore_or_keep_on_site_are_not_flagged(content: str) -> None:
    """Values a browser rejects, or reads as a same-site relative URL, are not findings."""
    result = _first_probe_flagged(_page(_meta(content), refresh=content))
    assert result["vulnerable"] == []


# --- Which encoding the page is read in -------------------------------------------

CANARY_HTML = '<html><meta http-equiv="refresh" content="0;url=http://redirect-canary.invalid/">'


@pytest.mark.parametrize(("body", "content_type"), [
    (b"\xff\xfe" + CANARY_HTML.encode("utf-16-le"), "text/html"),
    (b"\xfe\xff" + CANARY_HTML.encode("utf-16-be"), "text/html"),
    (b"\xff\xfe" + CANARY_HTML.encode("utf-16-le"), "text/html; charset=utf-8"),   # BOM wins
    (b"\xef\xbb\xbf" + CANARY_HTML.encode(), "text/html; charset=utf-16"),       # BOM wins
    (CANARY_HTML.encode("utf-16-le"), "text/html; charset=utf-16"),
    (CANARY_HTML.encode("utf-16-le"), 'text/html; charset="UTF-16LE"'),
    (CANARY_HTML.encode("utf-16-be"), "text/html; Charset = utf-16be"),
    (CANARY_HTML.encode("utf-16-le") + b"\x00", "text/html; charset=utf-16"),     # odd byte count
    (CANARY_HTML.encode("cp1252"), "text/html; charset=windows-1252"),
])
def test_meta_refresh_found_in_browser_encoding(body: bytes, content_type: str) -> None:
    """UTF-16 pages (by BOM or charset) and other encodings are read the way a browser would."""
    result = _first_probe_flagged(_page(body, content_type=content_type))
    assert result["vulnerable_meta_refresh"] == [FIRST_HTTP]


@pytest.mark.parametrize(("body", "content_type"), [
    (CANARY_HTML.encode(), "text/html; charset=utf-16"),       # browser reads it as UTF-16 noise
    (b"\xff\xfe" + CANARY_HTML.encode(), "text/html; charset=utf-8"),   # BOM says UTF-16
    (b"\xfe\xff" + CANARY_HTML.encode(), "text/html"),
])
def test_meta_refresh_not_found_when_browser_reads_other_encoding(body: bytes, content_type: str) -> None:
    """The same bytes decoded as UTF-16 are not a meta tag to a browser, so no finding."""
    result = _first_probe_flagged(_page(body, content_type=content_type))
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == 0


def test_decode_body_strips_bom_and_survives_odd_bytes() -> None:
    """The BOM is removed, and a dangling half character becomes a replacement mark, not a crash."""
    assert redirects._decode_body(b"\xef\xbb\xbfhi", "") == "hi"
    assert redirects._decode_body(b"\xff\xfeh\x00i\x00", "") == "hi"
    assert redirects._decode_body(b"h\x00i\x00!", "text/html; charset=utf-16") == "hi�"


def test_body_read_stops_at_the_time_limit_for_a_slow_drip_server() -> None:
    """A server dripping 1 byte per read can't hold a probe for long: reading stops at MAX_BODY_SECONDS."""
    response = _page()
    response.raw.read1.side_effect = lambda amt=8192, **kwargs: b"a"
    clock = iter(range(0, 10_000, 2))          # each look at the clock is 2 s later
    with patch("redirects._now", side_effect=lambda: next(clock)):
        result = _first_probe_flagged(response)
    assert redirects.MAX_BODY_SECONDS == 5
    assert response.raw.read1.call_count <= 3  # deadline 5 s: stops after a couple of reads
    assert result["probes_skipped"] == 0


def test_body_read_watchdog_breaks_a_stuck_read() -> None:
    """A single read1 that never returns (e.g. an endless gzip header) is cut off by the watchdog."""
    response = _page()
    unblocked = threading.Event()

    def stuck_read(amt: int = 8192, **kwargs: object) -> bytes:
        if not unblocked.wait(timeout=5):          # a real stuck socket would wait forever
            raise AssertionError("watchdog never shut the connection down")
        raise urllib3.exceptions.ProtocolError("connection shut down")

    response.raw.read1.side_effect = stuck_read
    response.raw.shutdown.side_effect = unblocked.set   # what the real shutdown() does to a blocked read
    with patch("redirects.MAX_BODY_SECONDS", 0.05):
        result = _first_probe_flagged(response)
    response.raw.shutdown.assert_called()
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == 0


def test_body_read_watchdog_is_cancelled_after_a_normal_read() -> None:
    """When the page is read normally, the watchdog never fires (the connection isn't shut down)."""
    response = _page(_meta("0;url=/home"))
    with patch("redirects.MAX_BODY_SECONDS", 0.05):
        _first_probe_flagged(response)
        threading.Event().wait(0.15)                 # longer than the watchdog's time limit
    response.raw.shutdown.assert_not_called()


@pytest.mark.parametrize("error", [ValueError, RuntimeError, OSError])
def test_stop_reading_ignores_an_already_closed_connection(error: type[Exception]) -> None:
    """If the watchdog fires just after the read finished, urllib3's complaint is ignored quietly."""
    raw = MagicMock()
    raw.shutdown.side_effect = error("already closed")
    redirects._stop_reading(raw)            # must not raise (no "Exception in thread" noise)
    raw.shutdown.assert_called_once()



@pytest.mark.parametrize("content_type", ["text", "html", "text/ html", "none"])
def test_invalid_content_type_is_sniffed_like_no_type(content_type: str) -> None:
    """A Content-Type that isn't a valid type/subtype counts as none: the page is sniffed (browsers do)."""
    page = _page(b"<html>" + _meta("0;url=http://redirect-canary.invalid/"), content_type=content_type)
    assert _first_probe_flagged(page)["vulnerable_meta_refresh"] == [FIRST_HTTP]


def test_last_valid_content_type_wins_when_headers_repeat() -> None:
    """'text/html, application/json': browsers use the last valid type (JSON), so no meta refresh."""
    page = _page(_meta("0;url=http://redirect-canary.invalid/"), content_type="text/html, application/json")
    assert _first_probe_flagged(page)["vulnerable"] == []
    page.raw.read1.assert_not_called()


def test_xhtml_page_is_searched_for_meta_refresh() -> None:
    """application/xhtml+xml is rendered as HTML by browsers, so its meta refresh counts."""
    page = _page(_meta("0;url=http://redirect-canary.invalid/"), content_type="application/xhtml+xml")
    assert _first_probe_flagged(page)["vulnerable_meta_refresh"] == [FIRST_HTTP]


def test_304_not_modified_is_never_judged() -> None:
    """A 304 shows no page, so even a Refresh header to the canary isn't a finding."""
    page = _page(content_type=None, refresh="0;url=http://redirect-canary.invalid/", status=304)
    assert _first_probe_flagged(page)["vulnerable"] == []


def test_refresh_value_with_stray_control_character_still_judged() -> None:
    """A vertical-tab before the URL is dropped like browsers' URL parser does: still flagged."""
    page = _page(content_type=None, refresh="0;\x0bhttp://redirect-canary.invalid/")
    assert _first_probe_flagged(page)["vulnerable_refresh_header"] == [FIRST_HTTP]


# --- Untyped pages: only the first SNIFF_BYTES are read until they have been judged ---


def _sized_page(body: bytes | None = None, content_type: str | None = None,
                most: int | None = None) -> tuple[MagicMock, list[int]]:
    """Fake page whose read1 honours `amt` and records every amt asked for.

    body=None means an endless page of b"a"; `most` caps how many bytes one read hands out
    (a slow server trickling data). Returns the response and the list of amounts asked for.
    """
    response = _page(content_type=content_type)
    asked: list[int] = []
    state = {"at": 0}

    def read1(amt: int = 8192, **kwargs: object) -> bytes:
        asked.append(amt)
        size = amt if most is None else min(amt, most)
        if body is None:
            return b"a" * size
        chunk = body[state["at"]:state["at"] + size]
        state["at"] += len(chunk)
        return chunk

    response.raw.read1.side_effect = read1
    return response, asked


def test_untyped_endless_non_html_page_stops_after_the_sniff_bytes() -> None:
    """An endless untyped page that isn't HTML: one read of exactly 1445 bytes, then reading stops."""
    response, asked = _sized_page()
    result = _first_probe_flagged(response)
    assert redirects.SNIFF_BYTES == 1445
    assert asked == [redirects.SNIFF_BYTES]
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == 0


def test_untyped_html_page_meta_refresh_past_sniff_bytes_is_flagged() -> None:
    """Sniffed as HTML from its start, so reading goes on and a meta refresh after byte 1445 is found."""
    body = b"<html>" + b" " * 2000 + CANARY_META
    response, asked = _sized_page(body)
    result = _first_probe_flagged(response)
    assert asked[0] == redirects.SNIFF_BYTES
    assert len(asked) > 1                                # it kept reading after the judgement
    assert result["vulnerable_meta_refresh"] == [FIRST_HTTP]


def test_untyped_trickle_never_asks_past_the_sniff_bytes() -> None:
    """100 bytes per read: each ask is exactly what's left of 1445, and reading stops at 1445."""
    response, asked = _sized_page(most=100)
    result = _first_probe_flagged(response)
    expected = [redirects.SNIFF_BYTES - 100 * i for i in range(15)]   # 1445, 1345, ... 45
    assert asked == expected
    assert sum(min(a, 100) for a in asked) == redirects.SNIFF_BYTES
    assert result["vulnerable"] == []
    assert all(amount > 0 for amount in asked)   # read1(0) would look like the end of the page


def test_untyped_short_html_page_ending_before_sniff_bytes_is_flagged() -> None:
    """A page shorter than 1445 bytes ends (EOF) before the judgement point: still judged and flagged."""
    assert len(CANARY_META) < redirects.SNIFF_BYTES
    response, asked = _sized_page(CANARY_META)
    result = _first_probe_flagged(response)
    assert asked[0] == redirects.SNIFF_BYTES
    assert result["vulnerable_meta_refresh"] == [FIRST_HTTP]


def test_untyped_page_that_breaks_off_early_uses_what_arrived() -> None:
    """The connection drops after a short first chunk: what arrived is sniffed, flagged, nothing skipped."""
    response = _page(content_type=None)
    response.raw.read1.side_effect = [
        b"<html>" + CANARY_META,
        urllib3.exceptions.ProtocolError("connection broken"),
    ]
    result = _first_probe_flagged(response)
    assert result["vulnerable_meta_refresh"] == [FIRST_HTTP]
    assert result["probes_skipped"] == 0


def test_typed_html_page_first_read_asks_for_a_full_chunk() -> None:
    """A page that says text/html isn't sniffed, so its first read asks for the normal 8192 bytes."""
    response, asked = _sized_page(CANARY_META, content_type="text/html")
    result = _first_probe_flagged(response)
    assert asked[0] == 8192
    assert result["vulnerable_meta_refresh"] == [FIRST_HTTP]


def test_typed_endless_page_asks_for_exactly_the_body_cap() -> None:
    """An endless text/html page: the amounts asked for add up to exactly MAX_BODY_BYTES, never more."""
    response, asked = _sized_page(content_type="text/html")
    _first_probe_flagged(response)
    assert sum(asked) == redirects.MAX_BODY_BYTES


def test_typed_trickle_last_ask_is_only_what_the_cap_leaves() -> None:
    """1000 bytes per read: the final ask is the 536 bytes left under 64 KB, not a full 8192."""
    response, asked = _sized_page(content_type="text/html", most=1000)
    _first_probe_flagged(response)
    assert asked[-1] == redirects.MAX_BODY_BYTES % 1000
    assert all(a <= 8192 for a in asked)
    assert sum(min(a, 1000) for a in asked) == redirects.MAX_BODY_BYTES


# --- Meta refresh inside <noscript> or <template>: ignored, as a browser with JavaScript on does ---

CANARY_TAG = '<meta http-equiv="refresh" content="0;url=http://redirect-canary.invalid/">'
SAME_SITE_TAG = '<meta http-equiv="refresh" content="0;url=/login">'


def _html(inner: str) -> bytes:
    return f"<html><head>{inner}</head></html>".encode()


@pytest.mark.parametrize("body", [
    _html(f"<noscript>{CANARY_TAG}</noscript>"),                         # noscript, closed
    _html(f"<noscript>{CANARY_TAG}"),                                    # noscript never closed
    _html(f"<template>{CANARY_TAG}</template>"),                         # template content is inert
    _html(f"<template><template></template>{CANARY_TAG}</template>"),    # still inside the outer one
    _html(f"<template>{CANARY_TAG}"),                                    # template never closed
    _html(f"<template/>{CANARY_TAG}"),                                   # "/" ignored: template opens
], ids=["noscript", "noscript-unclosed", "template", "nested-template", "template-unclosed",
        "self-closing-template"])
def test_meta_refresh_in_noscript_or_template_not_flagged(body: bytes) -> None:
    """A browser with JavaScript on never obeys a meta refresh inside <noscript> or <template>."""
    result = _first_probe_flagged(_page(body))
    assert result["vulnerable"] == []
    assert result["vulnerable_meta_refresh"] == []
    assert result["probes_skipped"] == 0
    assert redirects._meta_refresh_url(body) is None


@pytest.mark.parametrize("body", [
    _html(f"<template>x</template>{CANARY_TAG}"),                        # after a closed template
    _html(f"<noscript>x</noscript>{CANARY_TAG}"),                        # after a closed noscript
    _html(f"</template>{CANARY_TAG}"),                                   # stray end tag: depth stays 0
    _html(f"<noscript>{SAME_SITE_TAG}</noscript>{CANARY_TAG}"),          # ignored meta isn't "first"
    _html('<meta http-equiv="refresh" content="0;url=http://redirect-canary.invalid/" />'),
], ids=["after-template", "after-noscript", "stray-end-template", "noscript-meta-not-first",
        "self-closing-meta"])
def test_meta_refresh_outside_noscript_and_template_is_flagged(body: bytes) -> None:
    """Once <noscript>/<template> is closed (or was never opened), the meta refresh counts again."""
    result = _first_probe_flagged(_page(body))
    assert result["vulnerable"] == [FIRST_HTTP]
    assert result["vulnerable_meta_refresh"] == [FIRST_HTTP]
    assert redirects._meta_refresh_url(body) == "http://redirect-canary.invalid/"


def test_untyped_page_meta_refresh_in_noscript_not_flagged() -> None:
    """A sniffed page (no Content-Type) is read the same way: the <noscript> meta is ignored."""
    body = f"<html><noscript>{CANARY_TAG}".encode()
    result = _first_probe_flagged(_page(body, content_type=None))
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == 0


@pytest.fixture
def parser_without_scripting() -> Iterator[list[dict]]:
    """Make HTMLParser act like an older Python that has no `scripting` keyword.

    Yields the list of keyword-argument dicts each __init__ call received, so a test
    can confirm the fallback path really ran.
    """
    original = redirects.HTMLParser.__init__
    calls: list[dict] = []

    def old_style_init(self, *args, **kwargs):
        calls.append(kwargs)
        if "scripting" in kwargs:
            raise TypeError("__init__() got an unexpected keyword argument 'scripting'")
        original(self, *args, **kwargs)

    with patch.object(redirects.HTMLParser, "__init__", old_style_init):
        yield calls


def test_fallback_parser_still_ignores_noscript_meta(parser_without_scripting: list[dict]) -> None:
    """Without scripting=True, <noscript> is still read as plain text, so its meta doesn't count."""
    body = _html(f"<noscript>{CANARY_TAG}</noscript>")
    assert redirects._meta_refresh_url(body) is None
    assert parser_without_scripting == [{"scripting": True}, {}]   # tried the keyword, then fell back


def test_fallback_parser_finds_meta_after_noscript(parser_without_scripting: list[dict]) -> None:
    """In the fallback, </noscript> ends the plain text, so a later meta refresh is found."""
    body = _html(f"<noscript>{SAME_SITE_TAG}</noscript>{CANARY_TAG}")
    assert redirects._meta_refresh_url(body) == "http://redirect-canary.invalid/"
    assert {} in parser_without_scripting


def test_fallback_parser_still_ignores_template_meta(parser_without_scripting: list[dict]) -> None:
    """Template handling doesn't depend on scripting: still ignored in the fallback."""
    body = _html(f"<template>{CANARY_TAG}</template>")
    assert redirects._meta_refresh_url(body) is None
    assert {} in parser_without_scripting


@pytest.mark.parametrize("inner", [
    f"<noscript><template></noscript>{CANARY_TAG}",      # <template> in noscript is just text
    f"<noscript><!--</noscript>-->{CANARY_TAG}",         # no comments in noscript: </noscript> ends it
    f"<noscript><script></noscript>{CANARY_TAG}",        # no script in noscript either
], ids=["template-in-noscript", "comment-in-noscript", "script-in-noscript"])
@pytest.mark.parametrize("fallback", [False, True], ids=["scripting", "fallback"])
def test_noscript_content_is_plain_text(inner: str, fallback: bool, request: pytest.FixtureRequest) -> None:
    """Markup inside <noscript> can't hide a later meta refresh: a browser would still obey it."""
    if fallback:
        request.getfixturevalue("parser_without_scripting")
    assert redirects._meta_refresh_url(_html(inner)) == "http://redirect-canary.invalid/"


# --- Meta refresh inside other text-only elements (<script>, <style>, <title>, ...): ignored ---

TEXT_TAGS = ["script", "style", "title", "textarea", "xmp", "iframe", "noembed", "noframes", "plaintext"]


@pytest.mark.parametrize("tag", TEXT_TAGS)
def test_meta_refresh_in_self_closing_text_element_not_flagged(tag: str) -> None:
    """Browsers ignore the "/" in <script/> etc., so the meta after it is still text, not a tag."""
    body = _html(f"<{tag}/>{CANARY_TAG}</{tag}>")
    result = _first_probe_flagged(_page(body))
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == 0
    assert redirects._meta_refresh_url(body) is None


@pytest.mark.parametrize("body", [
    _html(f"<SCRIPT/>{CANARY_TAG}</SCRIPT>"),                 # tag names are case-insensitive
    _html(f"<title/>{CANARY_TAG}"),                           # never closed: rest of page is text
    _html(f"<plaintext/></plaintext>{CANARY_TAG}"),           # plaintext has no end tag at all
], ids=["upper-case-script", "title-unclosed", "plaintext-end-tag-ignored"])
def test_meta_refresh_in_text_element_edge_cases_not_flagged(body: bytes) -> None:
    """Upper case, a missing end tag, or a </plaintext> don't let the meta escape the text."""
    result = _first_probe_flagged(_page(body))
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == 0
    assert redirects._meta_refresh_url(body) is None


@pytest.mark.parametrize("tag", [t for t in TEXT_TAGS if t != "plaintext"])
def test_meta_refresh_after_closed_text_element_is_flagged(tag: str) -> None:
    """Once the closing tag ends the text, a later meta refresh counts again."""
    body = _html(f"<{tag}/>x</{tag}>{CANARY_TAG}")
    result = _first_probe_flagged(_page(body))
    assert result["vulnerable"] == [FIRST_HTTP]
    assert result["vulnerable_meta_refresh"] == [FIRST_HTTP]
    assert redirects._meta_refresh_url(body) == "http://redirect-canary.invalid/"


def test_meta_refresh_after_self_closing_void_tag_is_flagged() -> None:
    """<br/> isn't a text element, so it doesn't hide the meta that follows."""
    body = _html(f"<br/>{CANARY_TAG}")
    result = _first_probe_flagged(_page(body))
    assert result["vulnerable"] == [FIRST_HTTP]
    assert redirects._meta_refresh_url(body) == "http://redirect-canary.invalid/"


def test_meta_in_script_is_not_first_meta() -> None:
    """A same-site meta hidden in <script/> doesn't stop the later canary meta from counting."""
    body = _html(f"<script/>{SAME_SITE_TAG}</script>{CANARY_TAG}")
    result = _first_probe_flagged(_page(body))
    assert result["vulnerable"] == [FIRST_HTTP]
    assert redirects._meta_refresh_url(body) == "http://redirect-canary.invalid/"


@pytest.mark.parametrize("inner", [
    f"<script/>{CANARY_TAG}</script>",
    f"<xmp>{CANARY_TAG}</xmp>",
], ids=["self-closing-script", "xmp"])
def test_fallback_parser_ignores_meta_in_text_element(inner: str,
                                                      parser_without_scripting: list[dict]) -> None:
    """On older Python (no scripting keyword), text elements still hide their meta refresh."""
    assert redirects._meta_refresh_url(_html(inner)) is None
    assert {} in parser_without_scripting


@pytest.mark.parametrize("inner", [
    f"<svg><title/></svg>{CANARY_TAG}",                        # SVG <title/> is really empty
    f"<svg><style/><script/></svg>{CANARY_TAG}",
    f"<math><style/>{CANARY_TAG}",                             # meta ends the <math> by itself
    f"<svg><title/><p>{CANARY_TAG}",                           # so does <p>
    f"<svg/><script/></script>{CANARY_TAG}",                   # <svg/> is empty: back to HTML
], ids=["svg-title", "svg-style-script", "math-meta-breaks-out", "svg-p-breaks-out", "empty-svg"])
def test_self_closing_tag_inside_svg_or_math_does_not_hide_meta(inner: str) -> None:
    """Inside <svg>/<math> the "/" is obeyed, so <title/> etc. don't start text."""
    assert redirects._meta_refresh_url(_html(inner)) == "http://redirect-canary.invalid/"


@pytest.mark.parametrize("inner", [
    f"<svg></svg><script/>{CANARY_TAG}</script>",              # after </svg>: HTML rules again
    f"<svg><p><title/>{CANARY_TAG}",                           # <p> left the svg, so <title/> is text
], ids=["after-closed-svg", "after-breakout"])
def test_text_element_after_leaving_svg_still_hides_meta(inner: str) -> None:
    """Once the <svg> is over, <script/> or <title/> starts text again."""
    assert redirects._meta_refresh_url(_html(inner)) is None
