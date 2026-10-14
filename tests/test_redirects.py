"""Tests for redirects.py - open redirect check (requests.get mocked, nothing is ever sent)."""
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import pytest
import requests
from requests.structures import CaseInsensitiveDict

import redirects
from urltools import host_of

TOTAL_PROBES = len(redirects.REDIRECT_PATHS) * len(redirects.REDIRECT_PARAMS)
LOGIN_NEXT = f"http://example.com/login?next={redirects.CANARY_URL}"


def _response(location: str | None = None) -> MagicMock:
    """Fake response usable in `with`: a 3xx pointing at `location`, or a plain 200 if None."""
    response = MagicMock()
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    response.is_redirect = location is not None
    headers = CaseInsensitiveDict()
    if location is not None:
        headers["Location"] = location
    response.headers = headers
    return response


def _flagged_with_location(location: str) -> list[str]:
    """Run the check where every probe redirects to `location`; return the flagged probe URLs."""
    with patch("redirects.requests.get", return_value=_response(location)):
        return redirects.check_open_redirect("example.com")["vulnerable"]


def test_check_open_redirect_returns_empty_list_when_nothing_redirects() -> None:
    """No probe gets a redirect, so nothing is vulnerable."""
    with patch("redirects.requests.get", return_value=_response()):
        assert redirects.check_open_redirect("example.com")["vulnerable"] == []


def test_check_open_redirect_complete_run_counts_every_probe() -> None:
    """A normal run: all 32 sent, none skipped, marked complete, base_url recorded."""
    with patch("redirects.requests.get", return_value=_response()):
        result = redirects.check_open_redirect("example.com")
    assert result == {
        "base_url": "http://example.com", "vulnerable": [], "probes_total": TOTAL_PROBES,
        "probes_sent": TOTAL_PROBES, "probes_skipped": 0, "complete": True,
        "switch_reason": None,
    }
    assert TOTAL_PROBES == 32


def test_check_open_redirect_probes_every_path_and_param() -> None:
    """One request per path x param (32), covering every path, not just the root (backlog #6)."""
    with patch("redirects.requests.get", return_value=_response()) as fake_get:
        redirects.check_open_redirect("example.com")
    assert fake_get.call_count == TOTAL_PROBES
    probed_paths = {urlparse(call.args[0]).path for call in fake_get.call_args_list}
    assert probed_paths == set(redirects.REDIRECT_PATHS)


def test_check_open_redirect_never_follows_redirects() -> None:
    """Every request uses a 5 s timeout, allow_redirects=False and stream=True."""
    with patch("redirects.requests.get", return_value=_response()) as fake_get:
        redirects.check_open_redirect("example.com")
    for call in fake_get.call_args_list:
        assert call.kwargs == {"timeout": 5, "allow_redirects": False, "stream": True}


def test_check_open_redirect_flags_location_pointing_to_canary() -> None:
    """A redirect to the canary host is reported as the exact test URL that caused it."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        return _response(redirects.CANARY_URL) if url == LOGIN_NEXT else _response()

    with patch("redirects.requests.get", side_effect=fake_get):
        assert redirects.check_open_redirect("example.com")["vulnerable"] == [LOGIN_NEXT]


def test_check_open_redirect_flags_only_the_matching_probe() -> None:
    """Other probes redirect too, but only to the site itself, so only one is flagged."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        return _response(redirects.CANARY_URL) if url == LOGIN_NEXT else _response("/home")

    with patch("redirects.requests.get", side_effect=fake_get):
        assert redirects.check_open_redirect("example.com")["vulnerable"] == [LOGIN_NEXT]


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
    with patch("redirects.requests.get", return_value=response):
        assert redirects.check_open_redirect("example.com")["vulnerable"] == []


def test_check_open_redirect_stops_on_connection_error() -> None:
    """Refused on HTTP probe 1, then on HTTPS probe 1 too: one try each, then give up (2 calls)."""
    err = requests.exceptions.ConnectionError("refused")
    with patch("redirects.requests.get", side_effect=err) as fake_get:
        result = redirects.check_open_redirect("example.com")
    assert fake_get.call_count == 2
    assert fake_get.call_args_list[0].args[0].startswith("http://example.com/")
    assert fake_get.call_args_list[1].args[0].startswith("https://example.com/")
    assert result["vulnerable"] == []
    assert result["base_url"] == "https://example.com"
    assert result["switch_reason"] == "no_http"
    assert result["complete"] is False
    assert result["probes_sent"] == 1


def test_check_open_redirect_connection_error_marks_incomplete() -> None:
    """Refused on probe 1: complete is False and probes_sent counts that one failed attempt."""
    err = requests.exceptions.ConnectionError("refused")
    with patch("redirects.requests.get", side_effect=err):
        result = redirects.check_open_redirect("example.com")
    assert result["complete"] is False
    assert result["probes_sent"] == 1
    assert result["probes_skipped"] == 0
    assert result["probes_total"] == TOTAL_PROBES


def test_check_open_redirect_keeps_findings_when_connect_timeout_stops_scan() -> None:
    """First probe is vulnerable, second can't even connect (ConnectTimeout): keep the find and stop."""
    first = f"http://example.com/?next={redirects.CANARY_URL}"
    fake_get = MagicMock(
        side_effect=[_response(redirects.CANARY_URL), requests.exceptions.ConnectTimeout("no answer")]
    )
    with patch("redirects.requests.get", fake_get):
        result = redirects.check_open_redirect("example.com")
    assert result["vulnerable"] == [first]
    assert result["probes_sent"] == 2
    assert result["complete"] is False
    assert fake_get.call_count == 2


def test_check_open_redirect_read_timeout_skips_only_that_probe() -> None:
    """The first probe connects but the page is slow (ReadTimeout): skip it, keep scanning,
    and still report a vulnerable probe that comes later."""
    first = f"http://example.com/?next={redirects.CANARY_URL}"

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        if url == first:
            raise requests.exceptions.ReadTimeout("slow page")
        return _response(redirects.CANARY_URL) if url == LOGIN_NEXT else _response()

    with patch("redirects.requests.get", side_effect=fake_get) as mock_get:
        result = redirects.check_open_redirect("example.com")
    assert result["vulnerable"] == [LOGIN_NEXT]
    assert result["complete"] is True
    assert result["probes_skipped"] == 1
    assert result["probes_sent"] == TOTAL_PROBES
    assert mock_get.call_count == TOTAL_PROBES


def test_check_open_redirect_garbled_location_does_not_crash() -> None:
    """Location 'http://[oops' makes urljoin raise ValueError; each probe is skipped, none crash."""
    with patch("redirects.requests.get", return_value=_response("http://[oops")) as mock_get:
        result = redirects.check_open_redirect("example.com")
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == TOTAL_PROBES
    assert result["complete"] is True
    assert mock_get.call_count == TOTAL_PROBES


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


def test_check_open_redirect_skips_probe_on_other_request_error() -> None:
    """An odd error (InvalidURL) skips only that probe; the other 31 still run."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        if url == LOGIN_NEXT:
            raise requests.exceptions.InvalidURL("bad")
        return _response()

    with patch("redirects.requests.get", side_effect=fake_get) as mock_get:
        result = redirects.check_open_redirect("example.com")
    assert result["vulnerable"] == []
    assert result["probes_skipped"] == 1
    assert mock_get.call_count == TOTAL_PROBES


def test_check_open_redirect_brackets_ipv6_host() -> None:
    """An IPv6 address must be wrapped in [brackets] inside a URL."""
    with patch("redirects.requests.get", return_value=_response()) as fake_get:
        result = redirects.check_open_redirect("::1")
    assert fake_get.call_args_list[0].args[0].startswith("http://[::1]/")
    assert result["base_url"] == "http://[::1]"


def test_canary_host_is_reserved_invalid_name() -> None:
    """The canary must be a .invalid name, which can never resolve to a real third-party site."""
    assert redirects.CANARY_HOST.endswith(".invalid")
    assert redirects.CANARY_URL == f"http://{redirects.CANARY_HOST}/"


# --- Backlog #25: switch to https:// when plain HTTP redirects there or can't be reached ---

FIRST_HTTP = f"http://example.com/?next={redirects.CANARY_URL}"


def _upgrade_on_first_probe(location: str) -> MagicMock:
    """Fake requests.get: only the very first HTTP probe redirects to `location`; all else is 200."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        return _response(location) if url == FIRST_HTTP else _response()

    return MagicMock(side_effect=fake_get)


def _run(fake_get: MagicMock, host: str = "example.com") -> redirects.RedirectResults:
    with patch("redirects.requests.get", fake_get):
        return redirects.check_open_redirect(host)


def _urls(fake_get: MagicMock) -> list[str]:
    return [call.args[0] for call in fake_get.call_args_list]


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
    assert fake_get.call_count == TOTAL_PROBES


def test_check_open_redirect_upgrade_to_other_host_never_contacts_it() -> None:
    """https://www.example.com/ is a different host: no switch, and www.example.com is never requested."""
    fake_get = _upgrade_on_first_probe("https://www.example.com/")
    result = _run(fake_get)
    assert result["switch_reason"] is None
    assert fake_get.call_count == TOTAL_PROBES
    assert not any("www.example.com" in u for u in _urls(fake_get))


def test_check_open_redirect_switches_when_http_unreachable() -> None:
    """HTTP refuses the connection, HTTPS answers: all 32 probes run over HTTPS, reason no_http."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        if url.startswith("http://"):
            raise requests.exceptions.ConnectionError("refused")
        return _response()

    mock_get = MagicMock(side_effect=fake_get)
    result = _run(mock_get)
    assert result["switch_reason"] == "no_http"
    assert result["base_url"] == "https://example.com"
    assert result["complete"] is True
    assert result["probes_sent"] == TOTAL_PROBES
    assert mock_get.call_count == TOTAL_PROBES + 1


def test_check_open_redirect_https_ssl_error_after_switch_never_disables_verification() -> None:
    """HTTPS fails with an SSLError after the switch: incomplete, and verify=False is never used."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        if url.startswith("http://"):
            return _response("https://example.com/")
        raise requests.exceptions.SSLError("certificate verify failed")

    mock_get = MagicMock(side_effect=fake_get)
    result = _run(mock_get)
    assert result["complete"] is False
    assert result["switch_reason"] == "redirect"
    assert all(call.kwargs.get("verify", True) is not False for call in mock_get.call_args_list)


def test_check_open_redirect_upgrade_on_later_probe_is_ignored() -> None:
    """Only probe 1 can trigger the switch; an HTTPS upgrade on probe 2+ is neither a switch nor a finding."""
    mock_get = MagicMock(side_effect=[_response()] + [_response("https://example.com/")] * (TOTAL_PROBES - 1))
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
            raise requests.exceptions.ConnectionError("refused")
        return _response()

    result = _run(MagicMock(side_effect=fake_get), host="::1")
    assert result["base_url"] == "https://[::1]"
    assert result["switch_reason"] == "no_http"
