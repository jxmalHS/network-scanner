"""Tests for urltools.py - the shared URL helpers (pure functions, no network)."""
import pytest
import requests

import urltools


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("example.com", "example.com"),
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "[::1]"),            # IPv6 addresses need brackets inside a URL
    ],
)
def test_url_host(host: str, expected: str) -> None:
    """url_host only adds brackets around IPv6 addresses."""
    assert urltools.url_host(host) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://Example.COM./p", "example.com"),          # lower-cased, trailing dot removed
        ("https://[::1]:8443/", "[::1]"),                    # IPv6 keeps its brackets; port dropped
        ("http://user:pw@Good.com/", "good.com"),           # login details are not the host
        ("http://bücher.de/", "xn--bcher-kva.de"),     # non-English name -> punycode
        ("http://127.0.0.1:8080", "127.0.0.1"),
        (r"http://example.com\@evil.com/", "example.com"),  # backslash trick: requests goes to example.com
    ],
)
def test_host_of_matches_where_requests_connects(url: str, expected: str) -> None:
    """host_of gives the host requests would really connect to."""
    assert urltools.host_of(url) == expected


@pytest.mark.parametrize("url", ["file:///etc/x", "mailto:a@b.com"])
def test_host_of_url_without_host_is_none(url: str) -> None:
    """URLs that have no network host give None."""
    assert urltools.host_of(url) is None


@pytest.mark.parametrize("url", ["not a url", "http://"])
def test_host_of_invalid_url_raises(url: str) -> None:
    """Garbage raises requests' InvalidURL/MissingSchema; callers already catch RequestException."""
    with pytest.raises(requests.exceptions.RequestException):
        urltools.host_of(url)
