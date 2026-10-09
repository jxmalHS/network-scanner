"""Tests for headers.py - security header check over HTTPS with HTTP fallback (requests.get mocked)."""
from unittest.mock import MagicMock, call, patch

import requests
from requests.structures import CaseInsensitiveDict

import headers

ALL_HEADERS = {name: "value" for name in headers.SECURITY_HEADERS}
HSTS = "Strict-Transport-Security"
NON_HSTS = [h for h in headers.SECURITY_HEADERS if h != HSTS]


def _response(header_map: dict[str, str] | None = None, location: str | None = None) -> MagicMock:
    """Fake requests.Response usable in a `with` block.

    - .headers is case-insensitive, like the real thing.
    - If `location` is given, the response is a redirect: .is_redirect is True and
      a Location header points to where it redirects. Otherwise .is_redirect is False.
    """
    response = MagicMock()
    response.__enter__.return_value = response   # `with get(...) as r` -> r is this same fake
    response.__exit__.return_value = False       # don't swallow exceptions raised inside the with
    sent = dict(header_map or {})
    if location is not None:
        sent["Location"] = location
    response.headers = CaseInsensitiveDict(sent)
    response.is_redirect = location is not None
    return response


def _get_call(url: str) -> object:
    """The exact call _fetch should make to requests.get for one URL."""
    return call(url, timeout=5, allow_redirects=False, stream=True)


# --- constants ---------------------------------------------------------------

def test_security_headers_list_is_exact() -> None:
    """The checked header names and their order are pinned, so dropping one is caught."""
    assert headers.SECURITY_HEADERS == [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Referrer-Policy",
    ]


def test_https_only_headers_is_just_hsts() -> None:
    """Only HSTS is treated as meaningless over plain HTTP."""
    assert headers.HTTPS_ONLY_HEADERS == ["Strict-Transport-Security"]


def test_max_redirects_is_five() -> None:
    """The redirect limit is pinned at 5."""
    assert headers.MAX_REDIRECTS == 5


# --- HTTPS works (the normal case) -------------------------------------------

def test_check_headers_all_present_over_https() -> None:
    """Over HTTPS with all 5 headers sent: all present, none missing, nothing N/A, no extra keys."""
    with patch("headers.requests.get", return_value=_response(ALL_HEADERS)):
        result = headers.check_headers("example.com")
    assert result == {
        "url": "https://example.com",
        "present": headers.SECURITY_HEADERS,
        "missing": [],
        "not_applicable": [],
    }


def test_check_headers_none_present_over_https() -> None:
    """Over HTTPS with no security headers, all 5 are missing."""
    with patch("headers.requests.get", return_value=_response({"Server": "nginx"})):
        result = headers.check_headers("example.com")
    assert result == {
        "url": "https://example.com",
        "present": [],
        "missing": headers.SECURITY_HEADERS,
        "not_applicable": [],
    }


def test_check_headers_reports_missing_hsts_over_https() -> None:
    """Over HTTPS, a response lacking only HSTS lists exactly HSTS as missing."""
    sent = {k: v for k, v in ALL_HEADERS.items() if k != HSTS}
    with patch("headers.requests.get", return_value=_response(sent)):
        result = headers.check_headers("example.com")
    assert result["missing"] == [HSTS]
    assert result["not_applicable"] == []


def test_check_headers_matches_names_case_insensitively() -> None:
    """Lower-case header names from the server still count as present."""
    sent = {name.lower(): "v" for name in headers.SECURITY_HEADERS}
    with patch("headers.requests.get", return_value=_response(sent)):
        result = headers.check_headers("example.com")
    assert result["missing"] == []
    assert result["present"] == headers.SECURITY_HEADERS


def test_check_headers_tries_https_first_without_auto_redirects_and_stops() -> None:
    """When HTTPS works, requests.get is called once: https://<host>, timeout 5, no auto-redirects, streamed."""
    with patch("headers.requests.get", return_value=_response({})) as fake_get:
        headers.check_headers("example.com")
    assert fake_get.call_args_list == [_get_call("https://example.com")]


def test_check_headers_closes_response_via_with_block() -> None:
    """The response is used as a context manager, so its connection gets closed (__exit__ runs)."""
    response = _response({})
    with patch("headers.requests.get", return_value=response):
        headers.check_headers("example.com")
    response.__exit__.assert_called_once()


def test_check_headers_no_https_error_key_when_https_works() -> None:
    """A successful HTTPS check carries no https_error / tls / redirect notes."""
    with patch("headers.requests.get", return_value=_response({})):
        result = headers.check_headers("example.com")
    for key in ("https_error", "https_tls_problem", "downgraded_from", "offsite_redirect"):
        assert key not in result


def test_check_headers_wraps_ipv6_host_in_brackets() -> None:
    """An IPv6 host like ::1 must appear as [::1] in the URL."""
    with patch("headers.requests.get", return_value=_response({})) as fake_get:
        result = headers.check_headers("::1")
    assert fake_get.call_args_list[0] == _get_call("https://[::1]")
    assert result["url"] == "https://[::1]"


def test_check_headers_ipv4_host_not_bracketed() -> None:
    """An IPv4 address has no colon, so it is used as-is."""
    with patch("headers.requests.get", return_value=_response({})) as fake_get:
        headers.check_headers("192.168.56.101")
    assert fake_get.call_args_list[0] == _get_call("https://192.168.56.101")


# --- redirects ---------------------------------------------------------------

def test_check_headers_follows_same_host_redirect() -> None:
    """A redirect to another page on the same host is followed; headers come from the final page."""
    hop = _response({}, location="https://example.com/home")
    final = _response(ALL_HEADERS)
    with patch("headers.requests.get", side_effect=[hop, final]) as fake_get:
        result = headers.check_headers("example.com")
    assert fake_get.call_args_list == [
        _get_call("https://example.com"),
        _get_call("https://example.com/home"),
    ]
    assert result["url"] == "https://example.com/home"
    assert result["present"] == headers.SECURITY_HEADERS


def test_check_headers_joins_relative_location() -> None:
    """A relative Location like '/home' is joined onto the current URL."""
    hop = _response({}, location="/home")
    with patch("headers.requests.get", side_effect=[hop, _response({})]) as fake_get:
        result = headers.check_headers("example.com")
    assert fake_get.call_args_list[1] == _get_call("https://example.com/home")
    assert result["url"] == "https://example.com/home"


def test_check_headers_http_redirect_to_https_same_host_counts_as_https() -> None:
    """HTTP fallback redirected to https:// on the same host: HSTS is judged normally (present)."""
    hop = _response({}, location="https://example.com/")
    final = _response(ALL_HEADERS)
    with patch(
        "headers.requests.get",
        side_effect=[requests.exceptions.ConnectionError("refused"), hop, final],
    ) as fake_get:
        result = headers.check_headers("example.com")
    assert fake_get.call_args_list == [
        _get_call("https://example.com"),
        _get_call("http://example.com"),
        _get_call("https://example.com/"),
    ]
    assert result["url"] == "https://example.com/"
    assert HSTS in result["present"]
    assert result["not_applicable"] == []
    assert "downgraded_from" not in result


def test_check_headers_http_redirect_to_https_without_hsts_reports_missing() -> None:
    """HTTP fallback landing on https:// without HSTS: HSTS is missing, not N/A."""
    sent = {k: v for k, v in ALL_HEADERS.items() if k != HSTS}
    hop = _response({}, location="https://example.com/")
    with patch(
        "headers.requests.get",
        side_effect=[requests.exceptions.ConnectionError("refused"), hop, _response(sent)],
    ):
        result = headers.check_headers("example.com")
    assert result["missing"] == [HSTS]
    assert result["not_applicable"] == []


def test_check_headers_does_not_follow_offsite_redirect() -> None:
    """A redirect to a different host is recorded but never requested."""
    hop = _response({"X-Frame-Options": "DENY"}, location="https://evil.example.net/")
    with patch("headers.requests.get", side_effect=[hop]) as fake_get:
        result = headers.check_headers("example.com")
    assert fake_get.call_args_list == [_get_call("https://example.com")]
    assert result["offsite_redirect"] == "https://evil.example.net/"


def test_check_headers_backslash_trick_counts_as_offsite() -> None:
    """'evil.com\\@example.com' looks like example.com to urlsplit but requests would go to evil.com."""
    hop = _response({}, location="https://evil.com\\@example.com/")
    with patch("headers.requests.get", side_effect=[hop]) as fake_get:
        result = headers.check_headers("example.com")
    assert fake_get.call_args_list == [_get_call("https://example.com")]
    assert "offsite_redirect" in result


def test_check_headers_uppercase_scheme_downgrade_recorded() -> None:
    """A Location written as 'HTTP://' is still recognised as a downgrade to plain HTTP."""
    hop = _response({}, location="HTTP://example.com/")
    final = _response(ALL_HEADERS)
    with patch("headers.requests.get", side_effect=[hop, final]):
        result = headers.check_headers("example.com")
    assert result["downgraded_from"] == "https://example.com"
    assert result["not_applicable"] == [HSTS]


def test_check_headers_offsite_redirect_uses_redirect_response_headers() -> None:
    """When the off-site redirect is not followed, headers are judged from the redirect response itself."""
    hop = _response({"X-Frame-Options": "DENY"}, location="https://evil.example.net/")
    with patch("headers.requests.get", return_value=hop):
        result = headers.check_headers("example.com")
    assert result["url"] == "https://example.com"
    assert result["present"] == ["X-Frame-Options"]
    assert "X-Frame-Options" not in result["missing"]


def test_check_headers_subdomain_counts_as_offsite() -> None:
    """www.example.com is a different hostname from example.com, so it is not followed."""
    hop = _response({}, location="https://www.example.com/")
    with patch("headers.requests.get", return_value=hop) as fake_get:
        result = headers.check_headers("example.com")
    assert fake_get.call_count == 1
    assert result["offsite_redirect"] == "https://www.example.com/"


def test_check_headers_https_to_http_downgrade_recorded() -> None:
    """https:// redirected to http:// on the same host sets downgraded_from and makes HSTS N/A."""
    hop = _response({}, location="http://example.com/")
    final = _response(ALL_HEADERS)
    with patch("headers.requests.get", side_effect=[hop, final]):
        result = headers.check_headers("example.com")
    assert result["downgraded_from"] == "https://example.com"
    assert result["url"] == "http://example.com/"
    assert result["not_applicable"] == [HSTS]
    assert result["present"] == NON_HSTS


def test_fetch_five_redirects_then_success_is_allowed() -> None:
    """Exactly MAX_REDIRECTS (5) hops is fine; the 6th request's page is judged."""
    hops = [_response({}, location=f"/p{i}") for i in range(5)]
    with patch("headers.requests.get", side_effect=[*hops, _response({})]) as fake_get:
        result = headers._fetch("https://example.com")
    assert "error" not in result
    assert result["url"] == "https://example.com/p4"
    assert fake_get.call_count == 6


def test_fetch_six_redirects_returns_error() -> None:
    """Six redirects in a row exceeds the limit and returns an error dict."""
    hops = [_response({}, location=f"/p{i}") for i in range(6)]
    with patch("headers.requests.get", side_effect=hops) as fake_get:
        result = headers._fetch("https://example.com")
    assert result == {"error": "more than 5 redirects"}
    assert fake_get.call_count == 6


def test_check_headers_redirect_loop_on_both_schemes_returns_error() -> None:
    """A server that redirects forever on https and http ends in an error, not a hang."""
    loop = _response({}, location="/again")
    with patch("headers.requests.get", return_value=loop):
        result = headers.check_headers("example.com")
    assert result == {"error": "more than 5 redirects", "https_error": "more than 5 redirects"}


def test_fetch_error_during_redirect_hop_returns_error() -> None:
    """If a later hop times out, the whole fetch returns an error dict."""
    hop = _response({}, location="/home")
    with patch("headers.requests.get", side_effect=[hop, requests.exceptions.Timeout("timed out")]):
        result = headers._fetch("https://example.com")
    assert result == {"error": "timed out"}


# --- HTTPS fails, HTTP fallback ----------------------------------------------

def test_check_headers_falls_back_to_http_on_connection_error() -> None:
    """If HTTPS raises ConnectionError, http://<host> is tried next with the same arguments."""
    with patch(
        "headers.requests.get",
        side_effect=[requests.exceptions.ConnectionError("443 refused"), _response({})],
    ) as fake_get:
        headers.check_headers("example.com")
    assert fake_get.call_args_list == [
        _get_call("https://example.com"),
        _get_call("http://example.com"),
    ]


def test_check_headers_fallback_records_https_error_and_http_url() -> None:
    """The fallback result says which URL was checked and why HTTPS failed."""
    with patch(
        "headers.requests.get",
        side_effect=[requests.exceptions.ConnectionError("443 refused"), _response({})],
    ):
        result = headers.check_headers("example.com")
    assert result["url"] == "http://example.com"
    assert result["https_error"] == "443 refused"
    assert "error" not in result


def test_check_headers_connection_error_fallback_has_no_tls_flag() -> None:
    """A plain connection failure is not a certificate problem: no https_tls_problem key."""
    with patch(
        "headers.requests.get",
        side_effect=[requests.exceptions.ConnectionError("443 refused"), _response({})],
    ):
        result = headers.check_headers("example.com")
    assert "https_tls_problem" not in result


def test_check_headers_ssl_error_fallback_sets_tls_flag() -> None:
    """A bad certificate (SSLError) triggers the fallback and sets https_tls_problem True."""
    with patch(
        "headers.requests.get",
        side_effect=[requests.exceptions.SSLError("certificate verify failed"), _response({})],
    ):
        result = headers.check_headers("example.com")
    assert result["url"] == "http://example.com"
    assert result["https_error"] == "certificate verify failed"
    assert result["https_tls_problem"] is True


def test_fetch_ssl_error_returns_tls_problem() -> None:
    """_fetch itself marks SSLError results with tls_problem True."""
    with patch("headers.requests.get", side_effect=requests.exceptions.SSLError("bad cert")):
        result = headers._fetch("https://example.com")
    assert result == {"error": "bad cert", "tls_problem": True}


def test_check_headers_falls_back_to_http_on_https_timeout() -> None:
    """An HTTPS timeout also triggers the HTTP fallback, without the TLS flag."""
    with patch(
        "headers.requests.get",
        side_effect=[requests.exceptions.Timeout("timed out"), _response({})],
    ):
        result = headers.check_headers("example.com")
    assert result["https_error"] == "timed out"
    assert result["url"] == "http://example.com"
    assert "https_tls_problem" not in result


def test_check_headers_hsts_not_applicable_over_plain_http_even_if_sent() -> None:
    """Over plain HTTP, HSTS goes to not_applicable even though the server sent it."""
    with patch(
        "headers.requests.get",
        side_effect=[requests.exceptions.ConnectionError("refused"), _response(ALL_HEADERS)],
    ):
        result = headers.check_headers("example.com")
    assert result["not_applicable"] == [HSTS]
    assert HSTS not in result["present"]
    assert result["present"] == NON_HSTS
    assert result["missing"] == []


def test_check_headers_hsts_not_reported_missing_over_plain_http() -> None:
    """Over plain HTTP with no headers at all, HSTS is N/A, not missing."""
    with patch(
        "headers.requests.get",
        side_effect=[requests.exceptions.ConnectionError("refused"), _response({})],
    ):
        result = headers.check_headers("example.com")
    assert result["missing"] == NON_HSTS
    assert result["not_applicable"] == [HSTS]


# --- both fail ---------------------------------------------------------------

def test_check_headers_both_fail_returns_both_errors() -> None:
    """HTTPS SSLError + HTTP refused: error, https_error and the TLS flag, nothing else."""
    with patch(
        "headers.requests.get",
        side_effect=[
            requests.exceptions.SSLError("bad cert"),
            requests.exceptions.ConnectionError("80 refused"),
        ],
    ):
        result = headers.check_headers("example.com")
    assert result == {"error": "80 refused", "https_error": "bad cert", "https_tls_problem": True}


def test_check_headers_both_time_out_returns_error_not_exception() -> None:
    """Timeouts on both attempts become an error dict instead of crashing."""
    with patch("headers.requests.get", side_effect=requests.exceptions.Timeout("timed out")):
        result = headers.check_headers("example.com")
    assert result == {"error": "timed out", "https_error": "timed out"}
