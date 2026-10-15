"""Tests for ssl_checker.py - certificate inspection (socket + ssl fully mocked)."""
import locale
import socket
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


def test_check_ssl_wildcard_for_other_domain_does_not_match() -> None:
    """*.other.org must NOT count as a match for example.com."""
    with _serve_cert(_cert(cn="*.other.org")):
        assert ssl_checker.check_ssl("example.com")["domain_match"] is False


def test_check_ssl_matches_host_listed_in_san() -> None:
    """A host listed in subjectAltName should match even if the CN differs."""
    cert = _cert(cn="other.org", subjectAltName=(("DNS", "other.org"), ("DNS", "example.com")))
    with _serve_cert(cert):
        assert ssl_checker.check_ssl("example.com")["domain_match"] is True


def test_check_ssl_wildcard_cn_does_not_match_bare_domain() -> None:
    """*.example.com needs one extra label, so it does not cover example.com itself."""
    with _serve_cert(_cert(cn="*.example.com")):
        assert ssl_checker.check_ssl("example.com")["domain_match"] is False


def test_check_ssl_wildcard_cn_does_not_match_two_levels_down() -> None:
    """*.example.com covers only one label, so a.b.example.com is not a match."""
    with _serve_cert(_cert(cn="*.example.com")):
        assert ssl_checker.check_ssl("a.b.example.com")["domain_match"] is False


def test_check_ssl_domain_match_is_case_insensitive() -> None:
    """DNS names are case-insensitive: WWW.Example.COM matches a CN of www.example.com."""
    with _serve_cert(_cert(cn="www.example.com")):
        assert ssl_checker.check_ssl("WWW.Example.COM")["domain_match"] is True


def test_check_ssl_san_list_overrides_matching_cn() -> None:
    """When a SAN list exists the CN is ignored, even if the CN equals the host."""
    cert = _cert(cn="example.com", subjectAltName=(("DNS", "other.org"), ("DNS", "www.other.org")))
    with _serve_cert(cert):
        assert ssl_checker.check_ssl("example.com")["domain_match"] is False


def test_check_ssl_wildcard_in_san_matches_subdomain() -> None:
    """A wildcard entry inside subjectAltName covers a one-label subdomain."""
    cert = _cert(cn="other.org", subjectAltName=(("DNS", "other.org"), ("DNS", "*.example.com")))
    with _serve_cert(cert):
        assert ssl_checker.check_ssl("www.example.com")["domain_match"] is True


def test_check_ssl_ignores_non_dns_san_entries() -> None:
    """IP Address SAN entries are skipped, so a SAN list with no DNS names falls back to the CN."""
    cert = _cert(cn="example.com", subjectAltName=(("IP Address", "1.2.3.4"),))
    with _serve_cert(cert):
        assert ssl_checker.check_ssl("example.com")["domain_match"] is True


def test_check_ssl_ip_target_matches_ip_san() -> None:
    """Scanning by IP matches the certificate's IP Address entry (e.g. a lab VM)."""
    cert = _cert(cn="other.org", subjectAltName=(("IP Address", "1.2.3.4"), ("DNS", "other.org")))
    with _serve_cert(cert):
        assert ssl_checker.check_ssl("1.2.3.4")["domain_match"] is True


def test_check_ssl_ip_target_does_not_match_dns_only_cert() -> None:
    """An IP target never matches DNS names or the CN, even if the CN is that IP."""
    cert = _cert(cn="1.2.3.4", subjectAltName=(("DNS", "1.2.3.4"),))
    with _serve_cert(cert):
        assert ssl_checker.check_ssl("1.2.3.4")["domain_match"] is False


def test_check_ssl_ipv6_target_matches_differently_written_san() -> None:
    """Two spellings of the same IPv6 address count as equal (SAN value may end in a newline)."""
    cert = _cert(subjectAltName=(("IP Address", "2001:DB8:0:0:0:0:0:1\n"),))
    with _serve_cert(cert):
        assert ssl_checker.check_ssl("2001:db8::1")["domain_match"] is True


@pytest.mark.parametrize(
    ("pattern", "host", "expected"),
    [
        ("example.com", "example.com", True),
        ("example.com", "www.example.com", False),
        ("*.example.com", "www.example.com", True),
        ("*.example.com", "example.com", False),
        ("*.example.com", "a.b.example.com", False),
        ("*.example.com", "wwwexample.com", False),
        ("*.Example.COM", "WWW.example.com", True),
        ("", "example.com", False),
        ("example.com", "example.com.", True),
        ("*.example.com", "www.example.com.", True),
        ("*.com", "example.com", False),
    ],
)
def test_name_matches(pattern: str, host: str, expected: bool) -> None:
    """_name_matches handles exact names, one-label wildcards and letter case."""
    assert ssl_checker._name_matches(pattern, host) is expected


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
    """A refused connection on 443 becomes an error dict tagged error_kind 'refused'."""
    err = ConnectionRefusedError(10061, "No connection could be made")
    with patch("ssl_checker.socket.create_connection", side_effect=err):
        result = ssl_checker.check_ssl("example.com")
    assert set(result) == {"error", "error_kind"}
    assert result["error_kind"] == "refused"
    assert "10061" in result["error"]


@pytest.mark.parametrize("err", [
    TimeoutError("timed out"),
    ConnectionResetError("connection refused by peer"),   # says "refused" but isn't a refusal
    OSError("Connection refused"),                         # plain OSError: text alone doesn't count
    ssl.SSLError(1, "wrong version number"),
])
def test_check_ssl_other_errors_have_no_error_kind(err: Exception) -> None:
    """Only a real ConnectionRefusedError gets error_kind; other failures (even saying 'refused') don't."""
    with patch("ssl_checker.socket.create_connection", side_effect=err):
        result = ssl_checker.check_ssl("example.com")
    assert "error" in result
    assert "error_kind" not in result


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


def _verify_error(code: int | None) -> ssl.SSLCertVerificationError:
    """A cert-verify error like Python raises; verify_code is only set if code is not None."""
    error = ssl.SSLCertVerificationError(1, "certificate verify failed: test reason")
    if code is not None:
        error.verify_code = code
    return error


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (62, "hostname_mismatch"),
        (64, "hostname_mismatch"),
        (10, "expired"),
        (9, "not_yet_valid"),
        (2, "untrusted"),
        (18, "untrusted"),
        (19, "untrusted"),
        (20, "untrusted"),
        (21, "untrusted"),
        (999, "invalid"),
        (None, "invalid"),
    ],
    ids=["62", "64", "10", "9", "2", "18", "19", "20", "21", "unknown-999", "no-verify-code"],
)
def test_check_ssl_maps_verify_code_to_cert_problem(code: int | None, expected: str) -> None:
    """Each OpenSSL verify code becomes the right cert_problem word, and 'error' is kept."""
    context = MagicMock()
    context.wrap_socket.side_effect = _verify_error(code)
    with patch("ssl_checker.ssl.create_default_context", return_value=context), patch(
        "ssl_checker.socket.create_connection"
    ):
        result = ssl_checker.check_ssl("example.com")
    assert result["cert_problem"] == expected
    assert "certificate verify failed: test reason" in result["error"]


def test_check_ssl_prefers_short_verify_message() -> None:
    """When Python provides OpenSSL's short reason, 'error' uses it instead of the noisy full text."""
    error = _verify_error(18)
    error.verify_message = "self-signed certificate"
    context = MagicMock()
    context.wrap_socket.side_effect = error
    with patch("ssl_checker.ssl.create_default_context", return_value=context), patch(
        "ssl_checker.socket.create_connection"
    ):
        result = ssl_checker.check_ssl("example.com")
    assert result["error"] == "self-signed certificate"


# --- Someday #17: expiry dates are parsed without fromtimestamp / locale problems ---


def test_check_ssl_handles_never_expires_date_9999() -> None:
    """The 'never expires' date 9999-12-31 parses (fromtimestamp rejects it on Windows)."""
    with _serve_cert(_cert(notAfter="Dec 31 23:59:59 9999 GMT")):
        result = ssl_checker.check_ssl("example.com")
    assert "error" not in result
    assert result["expire_date"] == "9999-12-31"


def test_check_ssl_parses_space_padded_day() -> None:
    """OpenSSL pads single-digit days with a space ('Jan  5'); that still parses."""
    with _serve_cert(_cert(notAfter="Jan  5 12:00:00 2031 GMT")):
        assert ssl_checker.check_ssl("example.com")["expire_date"] == "2031-01-05"


def test_check_ssl_parses_expiry_under_non_english_locale() -> None:
    """English month names in notAfter still parse when the computer's LC_TIME is German."""
    old = locale.setlocale(locale.LC_TIME)
    try:
        for name in ("German", "de_DE.UTF-8"):
            try:
                locale.setlocale(locale.LC_TIME, name)
                break
            except locale.Error:
                continue
        else:
            pytest.skip("no German locale installed")
        with _serve_cert(_cert(notAfter="Mar 15 12:00:00 2031 GMT")):
            result = ssl_checker.check_ssl("example.com")
    finally:
        locale.setlocale(locale.LC_TIME, old)
    assert "error" not in result
    assert result["expire_date"] == "2031-03-15"


# --- Someday #18: only target-caused errors are caught; bugs propagate ---


def _patched_connect(**wrap_kwargs: Any):
    """Patch create_default_context only (callers patch create_connection); wrap_kwargs configure wrap_socket."""
    context = MagicMock()
    context.wrap_socket.configure_mock(**wrap_kwargs)
    return patch("ssl_checker.ssl.create_default_context", return_value=context)


def test_check_ssl_plain_ssl_error_returns_error_without_cert_problem() -> None:
    """A non-certificate TLS failure (plain ssl.SSLError) is an error but has no cert_problem."""
    with _patched_connect(side_effect=ssl.SSLError(1, "wrong version number")), patch(
        "ssl_checker.socket.create_connection"
    ):
        result = ssl_checker.check_ssl("example.com")
    assert set(result) == {"error"}
    assert "wrong version number" in result["error"]


def test_check_ssl_dns_failure_returns_error() -> None:
    """A DNS lookup failure (socket.gaierror) becomes an {'error': ...} dict."""
    err = socket.gaierror(11001, "getaddrinfo failed")
    with patch("ssl_checker.socket.create_connection", side_effect=err):
        result = ssl_checker.check_ssl("nope.invalid")
    assert set(result) == {"error"}
    assert "getaddrinfo failed" in result["error"]


def test_check_ssl_connection_reset_returns_error() -> None:
    """A connection reset by the target becomes an {'error': ...} dict."""
    with patch("ssl_checker.socket.create_connection", side_effect=ConnectionResetError("reset by peer")):
        assert ssl_checker.check_ssl("example.com") == {"error": "reset by peer"}


def test_check_ssl_bad_idna_hostname_returns_error() -> None:
    """A hostname the IDNA encoder rejects (UnicodeError) becomes an {'error': ...} dict."""
    err = UnicodeError("label empty or too long")
    with patch("ssl_checker.socket.create_connection", side_effect=err):
        assert ssl_checker.check_ssl("a..example.com") == {"error": "label empty or too long"}


def test_check_ssl_unreadable_expiry_returns_error() -> None:
    """A notAfter that isn't a date gives a clear error naming the bad value."""
    with _serve_cert(_cert(notAfter="garbage")):
        result = ssl_checker.check_ssl("example.com")
    assert result == {"error": "unreadable certificate expiry date: garbage"}


def test_check_ssl_missing_not_after_propagates_key_error() -> None:
    """A cert dict without notAfter is a bug, not a target problem, so KeyError escapes."""
    cert = _cert()
    del cert["notAfter"]
    with _serve_cert(cert), pytest.raises(KeyError):
        ssl_checker.check_ssl("example.com")


def test_check_ssl_internal_runtime_error_propagates() -> None:
    """A bug inside the checker (RuntimeError) crashes loudly instead of hiding in the report."""
    with _serve_cert(_cert()), patch("ssl_checker._domain_matches", side_effect=RuntimeError("bug")):
        with pytest.raises(RuntimeError, match="bug"):
            ssl_checker.check_ssl("example.com")


def test_check_ssl_value_error_outside_date_parsing_propagates() -> None:
    """The ValueError catch only wraps date parsing; a ValueError elsewhere still escapes."""
    with _serve_cert(_cert()), patch("ssl_checker._domain_matches", side_effect=ValueError("bug")):
        with pytest.raises(ValueError, match="bug"):
            ssl_checker.check_ssl("example.com")
