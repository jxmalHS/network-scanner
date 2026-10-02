"""Tests for redirects.py - open redirect check (requests.get mocked)."""
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

import pytest
import requests

import redirects


def _response(final_url: str, redirected: bool) -> MagicMock:
    """Fake response: .url is where we ended up, .history is non-empty if a redirect happened."""
    response = MagicMock()
    response.url = final_url
    response.history = [MagicMock()] if redirected else []
    return response


def test_check_open_redirect_none_found() -> None:
    """If no parameter causes a redirect, the result is an empty list."""
    with patch("redirects.requests.get", return_value=_response("http://example.com/", False)):
        assert redirects.check_open_redirect("example.com") == []


def test_check_open_redirect_flags_vulnerable_param() -> None:
    """A param that redirects to evil.com is reported as its full test URL."""

    def fake_get(url: str, **kwargs: object) -> MagicMock:
        if "?next=" in url:
            return _response("http://evil.com/", True)
        return _response("http://example.com/", False)

    with patch("redirects.requests.get", side_effect=fake_get):
        assert redirects.check_open_redirect("example.com") == [
            "http://example.com?next=http://evil.com"
        ]


def test_check_open_redirect_ignores_redirect_to_same_site() -> None:
    """A redirect that stays on the target site is not flagged."""
    with patch("redirects.requests.get", return_value=_response("http://example.com/login", True)):
        assert redirects.check_open_redirect("example.com") == []


def test_check_open_redirect_requires_an_actual_redirect() -> None:
    """evil.com in the final URL without any redirect (empty history) is not flagged."""
    resp = _response("http://example.com/?next=http://evil.com", False)
    with patch("redirects.requests.get", return_value=resp):
        assert redirects.check_open_redirect("example.com") == []


def test_check_open_redirect_tries_every_param() -> None:
    """One request per REDIRECT_PARAMS entry, following redirects with a 5s timeout."""
    resp = _response("http://example.com/", False)
    with patch("redirects.requests.get", return_value=resp) as fake_get:
        redirects.check_open_redirect("example.com")
    assert fake_get.call_count == len(redirects.REDIRECT_PARAMS)
    for call in fake_get.call_args_list:
        assert call.kwargs == {"timeout": 5, "allow_redirects": True}


def test_check_open_redirect_survives_request_errors() -> None:
    """Request errors (e.g. connection refused) are skipped and the result is []."""
    err = requests.exceptions.ConnectionError("refused")
    with patch("redirects.requests.get", side_effect=err) as fake_get:
        assert redirects.check_open_redirect("example.com") == []
    assert fake_get.call_count == len(redirects.REDIRECT_PARAMS)


@pytest.mark.xfail(
    strict=True, raises=AssertionError, reason="backlog item 6: open-redirect check only hits the site root"
)
def test_check_open_redirect_tests_paths_beyond_root() -> None:
    """At least one probe should target a real path (e.g. /login), not just the root."""
    resp = _response("http://example.com/", False)
    with patch("redirects.requests.get", return_value=resp) as fake_get:
        redirects.check_open_redirect("example.com")
    paths = [urlparse(call.args[0]).path for call in fake_get.call_args_list]
    assert any(p not in ("", "/") for p in paths)


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="backlog item 13: evil.com anywhere in the final URL counts, so same-site redirects are false positives",
)
def test_check_open_redirect_ignores_same_site_redirect_carrying_param() -> None:
    """A same-site redirect to /login?next=http://evil.com never leaves the site, so it is not vulnerable."""
    resp = _response("http://example.com/login?next=http://evil.com", True)
    with patch("redirects.requests.get", return_value=resp):
        assert redirects.check_open_redirect("example.com") == []
