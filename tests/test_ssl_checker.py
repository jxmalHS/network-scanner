"""Tests for ssl_checker.py - certificate inspection (socket + ssl fully mocked)."""
import ssl
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import ssl_checker


def _not_after(days_from_now: int) -> str:
    """Build a cert 'notAfter' string N days (plus 1h, to avoid rounding) from now, in UTC."""
    when = datetime.now(timezone.utc) + timedelta(days=days_from_now, hours=1)
    return when.strftime("%b %d %H:%M:%S %Y GMT")


def _cert(cn: str = "example.com", days: int = 100, **extra: Any) -> dict[str, Any]:
    """A certificate dict shaped like ssl.SSLSocket.getpeercert() output."""
    cert: dict[str, Any] = {
        "subject": ((("commonName", cn),),),
        "issuer": (
            (("countryName", "US"),),
            (("organizationName", "Let's Encrypt"),),
            (("commonName", "R3"),),
        ),
        "notAfter": _not_after(days),
    }
    cert.update(extra)
    return cert


@contextmanager
def _serve_cert(cert: dict[str, Any]) -> Iterator[tuple[MagicMock, MagicMock]]:
    """Patch the TCP connect and TLS wrap so check_ssl 'receives' the given cert."""
    ssock = MagicMock()
    ssock.getpeercert.return_value = cert
    context = MagicMock()
    context.wrap_socket.return_value.__enter__.return_value = ssock
    with patch("ssl_checker.ssl.create_default_context", return_value=context), patch(
        "ssl_checker.socket.create_connection"
    ) as fake_conn:
        yield fake_conn, context


def test_check_ssl_reads_issued_to_and_issued_by() -> None:
    """Subject CN becomes issued_to and issuer organizationName becomes issued_by."""
    with _serve_cert(_cert()):
        result = ssl_checker.check_ssl("example.com")
    assert (result["issued_to"], result["issued_by"]) == ("example.com", "Let's Encrypt")


def test_check_ssl_formats_expire_date() -> None:
    """expire_date is returned as YYYY-MM-DD."""
    cert = _cert(notAfter="Jan 15 12:00:00 2031 GMT")
    with _serve_cert(cert):
        assert ssl_checker.check_ssl("example.com")["expire_date"] == "2031-01-15"


def test_check_ssl_valid_cert_not_expired_or_expiring() -> None:
    """A cert valid for 100 more days: days_remaining 100, not expired, not expiring soon."""
    with _serve_cert(_cert(days=100)):
        result = ssl_checker.check_ssl("example.com")
    assert (result["days_remaining"], result["expired"], result["expiring_soon"]) == (100, False, False)


def test_check_ssl_flags_expiring_soon_at_30_days() -> None:
    """30 days left is the boundary and counts as expiring soon."""
    with _serve_cert(_cert(days=30)):
        result = ssl_checker.check_ssl("example.com")
    assert result["expiring_soon"] is True
    assert result["expired"] is False


def test_check_ssl_not_expiring_soon_at_31_days() -> None:
    """31 days left is outside the 30-day warning window."""
    with _serve_cert(_cert(days=31)):
        assert ssl_checker.check_ssl("example.com")["expiring_soon"] is False


def test_check_ssl_flags_expired_cert() -> None:
    """A notAfter in the past marks the cert expired (and not 'expiring soon')."""
    with _serve_cert(_cert(days=-5)):
        result = ssl_checker.check_ssl("example.com")
    assert result["expired"] is True
    assert result["expiring_soon"] is False


def test_check_ssl_domain_match_exact_cn() -> None:
    """A CN equal to the host is a domain match."""
    with _serve_cert(_cert(cn="example.com")):
        assert ssl_checker.check_ssl("example.com")["domain_match"] is True


def test_check_ssl_domain_mismatch() -> None:
    """A CN for a different host is not a domain match."""
    with _serve_cert(_cert(cn="other.org")):
        assert ssl_checker.check_ssl("example.com")["domain_match"] is False


def test_check_ssl_wildcard_matches_subdomain() -> None:
    """*.example.com legitimately covers www.example.com."""
    with _serve_cert(_cert(cn="*.example.com")):
        assert ssl_checker.check_ssl("www.example.com")["domain_match"] is True


@pytest.mark.xfail(
    strict=True, raises=AssertionError, reason="backlog item 4: any wildcard CN is accepted as a domain match"
)
def test_check_ssl_wildcard_for_other_domain_does_not_match() -> None:
    """*.other.org must NOT count as a match for example.com."""
    with _serve_cert(_cert(cn="*.other.org")):
        assert ssl_checker.check_ssl("example.com")["domain_match"] is False


@pytest.mark.xfail(
    strict=True, raises=AssertionError, reason="backlog item 4: Subject Alternative Names are not checked"
)
def test_check_ssl_matches_host_listed_in_san() -> None:
    """A host listed in subjectAltName should match even if the CN differs."""
    cert = _cert(cn="other.org", subjectAltName=(("DNS", "other.org"), ("DNS", "example.com")))
    with _serve_cert(cert):
        assert ssl_checker.check_ssl("example.com")["domain_match"] is True


def test_check_ssl_missing_names_default_to_unknown() -> None:
    """A cert with no CN / issuer org reports 'Unknown' for both."""
    cert = _cert()
    cert["subject"] = ((("organizationName", "Acme"),),)
    cert["issuer"] = ((("commonName", "Some CA"),),)
    with _serve_cert(cert):
        result = ssl_checker.check_ssl("example.com")
    assert (result["issued_to"], result["issued_by"]) == ("Unknown", "Unknown")


def test_check_ssl_connects_to_port_443_with_sni() -> None:
    """It connects to (host, 443) with a 5s timeout and sends the host as SNI server_hostname."""
    with _serve_cert(_cert()) as (fake_conn, context):
        ssl_checker.check_ssl("example.com")
    fake_conn.assert_called_once_with(("example.com", 443), timeout=5)
    assert context.wrap_socket.call_args.kwargs == {"server_hostname": "example.com"}


def test_check_ssl_connection_refused_returns_error() -> None:
    """A refused connection on 443 becomes an {'error': ...} dict."""
    err = ConnectionRefusedError(10061, "No connection could be made")
    with patch("ssl_checker.socket.create_connection", side_effect=err):
        result = ssl_checker.check_ssl("example.com")
    assert set(result) == {"error"}
    assert "10061" in result["error"]


def test_check_ssl_timeout_returns_error() -> None:
    """A connect timeout becomes an {'error': ...} dict."""
    with patch("ssl_checker.socket.create_connection", side_effect=TimeoutError("timed out")):
        assert ssl_checker.check_ssl("example.com") == {"error": "timed out"}


def test_check_ssl_verification_failure_returns_error() -> None:
    """A TLS certificate verification failure becomes an {'error': ...} dict."""
    context = MagicMock()
    context.wrap_socket.side_effect = ssl.SSLCertVerificationError("certificate verify failed")
    with patch("ssl_checker.ssl.create_default_context", return_value=context), patch(
        "ssl_checker.socket.create_connection"
    ):
        result = ssl_checker.check_ssl("example.com")
    assert "certificate verify failed" in result["error"]


def test_check_ssl_emits_no_deprecation_warning() -> None:
    """check_ssl should not trigger any DeprecationWarning (e.g. from datetime.utcnow())."""
    with _serve_cert(_cert()), warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        result = ssl_checker.check_ssl("example.com")
    deprecations = [str(w.message) for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecations == []
    assert "error" not in result
