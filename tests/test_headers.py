"""Tests for headers.py - HTTP security header check (requests.get mocked)."""
from unittest.mock import MagicMock, patch

import requests
from requests.structures import CaseInsensitiveDict

import headers

ALL_HEADERS = {name: "value" for name in headers.SECURITY_HEADERS}


def _response(header_map: dict[str, str]) -> MagicMock:
    """Fake requests.Response whose .headers behaves like the real (case-insensitive) one."""
    response = MagicMock()
    response.headers = CaseInsensitiveDict(header_map)
    return response


def test_security_headers_list_is_exact() -> None:
    """The checked header names and their order are pinned, so dropping one is caught."""
    assert headers.SECURITY_HEADERS == [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Referrer-Policy",
    ]


def test_check_headers_all_present() -> None:
    """When all 5 security headers are sent, all are 'present' and none 'missing'."""
    with patch("headers.requests.get", return_value=_response(ALL_HEADERS)):
        result = headers.check_headers("http://example.com")
    assert result == {"present": headers.SECURITY_HEADERS, "missing": []}


def test_check_headers_none_present() -> None:
    """With no security headers, all 5 are reported missing."""
    with patch("headers.requests.get", return_value=_response({"Server": "nginx"})):
        result = headers.check_headers("http://example.com")
    assert result == {"present": [], "missing": headers.SECURITY_HEADERS}


def test_check_headers_reports_missing_hsts() -> None:
    """A response lacking only HSTS lists exactly Strict-Transport-Security as missing."""
    sent = {k: v for k, v in ALL_HEADERS.items() if k != "Strict-Transport-Security"}
    with patch("headers.requests.get", return_value=_response(sent)):
        result = headers.check_headers("http://example.com")
    assert result["missing"] == ["Strict-Transport-Security"]


def test_check_headers_matches_names_case_insensitively() -> None:
    """Lower-case header names from the server still count as present."""
    sent = {name.lower(): "v" for name in headers.SECURITY_HEADERS}
    with patch("headers.requests.get", return_value=_response(sent)):
        result = headers.check_headers("http://example.com")
    assert result["missing"] == []


def test_check_headers_requests_given_url_with_timeout() -> None:
    """The URL passed in is fetched with a 5-second timeout."""
    with patch("headers.requests.get", return_value=_response({})) as fake_get:
        headers.check_headers("http://example.com")
    fake_get.assert_called_once_with("http://example.com", timeout=5)


def test_check_headers_timeout_returns_error() -> None:
    """A request timeout is turned into an {'error': ...} dict, not an exception."""
    with patch("headers.requests.get", side_effect=requests.exceptions.Timeout("timed out")):
        assert headers.check_headers("http://example.com") == {"error": "timed out"}


def test_check_headers_connection_refused_returns_error() -> None:
    """A connection error is turned into an {'error': ...} dict."""
    with patch("headers.requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
        assert headers.check_headers("http://example.com") == {"error": "refused"}
