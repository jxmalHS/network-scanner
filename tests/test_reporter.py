"""Tests for reporter.py - text report writing (all files go to pytest's tmp_path)."""
import re
from pathlib import Path
from typing import Any

import pytest

import reporter

NO_HEADERS: dict[str, list[str]] = {"present": [], "missing": []}
VALID_SSL: dict[str, Any] = {
    "issued_to": "example.com",
    "issued_by": "Let's Encrypt",
    "expire_date": "2031-01-15",
    "days_remaining": 100,
    "expired": False,
    "expiring_soon": False,
    "domain_match": True,
}


@pytest.fixture(autouse=True)
def in_tmp_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Run every test inside a temp dir so report_*.txt never lands in the project."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _report(
    open_ports: list[dict[str, Any]] | None = None,
    header_results: dict[str, Any] | None = None,
    redirect_results: list[str] | None = None,
    ssl_results: dict[str, Any] | None = None,
) -> str:
    """Generate a report with sensible defaults and return its text."""
    filename = reporter.generate_report(
        "example.com",
        open_ports if open_ports is not None else [],
        header_results if header_results is not None else NO_HEADERS,
        redirect_results if redirect_results is not None else [],
        ssl_results if ssl_results is not None else VALID_SSL,
    )
    # reporter.py calls open() with no encoding, so read back with no encoding too.
    # Both then follow the same default (cp1252 normally, UTF-8 under PYTHONUTF8=1).
    # encoding="locale" would NOT follow UTF-8 mode and garbles the em dash.
    return Path(filename).read_text()


def test_generate_report_returns_timestamped_filename(in_tmp_dir: Path) -> None:
    """The returned filename is report_<host>_<YYYYMMDD_HHMMSS>.txt and the file exists."""
    filename = reporter.generate_report("example.com", [], NO_HEADERS, [], VALID_SSL)
    assert re.fullmatch(r"report_example\.com_\d{8}_\d{6}\.txt", filename)
    assert (in_tmp_dir / filename).is_file()


def test_generate_report_includes_target_header() -> None:
    """The report starts with its title and the target host."""
    text = _report()
    assert text.startswith("Network Vulnerability Scan Report\nTarget: example.com\n")


def test_generate_report_lists_open_port_with_banner() -> None:
    """An open port with a banner is written as [OPEN] Port N — banner."""
    text = _report(open_ports=[{"port": 22, "banner": "SSH-2.0-OpenSSH_8.9"}])
    assert "[OPEN] Port 22 — SSH-2.0-OpenSSH_8.9\n" in text


def test_generate_report_truncates_long_banner_to_100_chars() -> None:
    """Banners longer than 100 characters are cut to 100."""
    text = _report(open_ports=[{"port": 80, "banner": "A" * 150}])
    assert f"[OPEN] Port 80 — {'A' * 100}\n" in text


def test_generate_report_open_port_without_banner() -> None:
    """A None banner is written as 'no banner'."""
    text = _report(open_ports=[{"port": 443, "banner": None}])
    assert "[OPEN] Port 443 — no banner\n" in text


def test_generate_report_empty_banner_counts_as_no_banner() -> None:
    """An empty-string banner is also written as 'no banner'."""
    text = _report(open_ports=[{"port": 443, "banner": ""}])
    assert "[OPEN] Port 443 — no banner\n" in text


def test_generate_report_no_open_ports() -> None:
    """An empty port list is written as 'No open ports found.'."""
    assert "No open ports found.\n" in _report(open_ports=[])


def test_generate_report_lists_present_and_missing_headers() -> None:
    """Present headers get [PRESENT], missing ones get [MISSING]."""
    text = _report(header_results={"present": ["X-Frame-Options"], "missing": ["Strict-Transport-Security"]})
    assert "[PRESENT] X-Frame-Options\n" in text
    assert "[MISSING] Strict-Transport-Security\n" in text


def test_generate_report_header_error() -> None:
    """A header-check error dict is written as an error line."""
    text = _report(header_results={"error": "timed out"})
    assert "Error fetching headers: timed out\n" in text


def test_generate_report_header_error_skips_https_warning() -> None:
    """When both HTTPS and HTTP failed, only the error line is written, not the fallback warning."""
    text = _report(header_results={"error": "80 refused", "https_error": "443 refused"})
    assert "Error fetching headers: 80 refused\n" in text
    assert "HTTPS attempt failed" not in text


def test_generate_report_writes_checked_url() -> None:
    """A result with a 'url' key gets a 'Checked: <url>' line."""
    text = _report(header_results={"url": "https://example.com/", "present": [], "missing": []})
    assert "Checked: https://example.com/\n" in text


def test_generate_report_https_fallback_warning_connection_failure() -> None:
    """https_error without the TLS flag: 'could not connect' warning followed by a Details line."""
    text = _report(header_results={
        "url": "http://example.com", "https_error": "443 refused",
        "present": [], "missing": [], "not_applicable": ["Strict-Transport-Security"],
    })
    assert (
        "[WARNING] HTTPS attempt failed (could not connect) — fell back to http://\n"
        "Details: 443 refused\n"
    ) in text


def test_generate_report_https_fallback_warning_certificate_problem() -> None:
    """https_error with https_tls_problem: 'TLS problem' warning followed by a Details line."""
    text = _report(header_results={
        "url": "http://example.com", "https_error": "certificate verify failed",
        "https_tls_problem": True,
        "present": [], "missing": [], "not_applicable": ["Strict-Transport-Security"],
    })
    assert (
        "[WARNING] HTTPS attempt failed (TLS problem) — fell back to http://\n"
        "Details: certificate verify failed\n"
    ) in text


def test_generate_report_downgrade_warning() -> None:
    """A downgraded_from key produces the HTTPS-to-plain-HTTP warning with both URLs."""
    text = _report(header_results={
        "url": "http://example.com/", "downgraded_from": "https://example.com",
        "present": [], "missing": [], "not_applicable": ["Strict-Transport-Security"],
    })
    assert "[WARNING] HTTPS redirected to plain HTTP (https://example.com -> http://example.com/)\n" in text


def test_generate_report_offsite_redirect_info() -> None:
    """An offsite_redirect key produces an [INFO] line naming the URL that was not followed."""
    text = _report(header_results={
        "url": "https://example.com", "offsite_redirect": "https://other.example.net/",
        "present": [], "missing": [], "not_applicable": [],
    })
    assert "[INFO] Redirect to another host not followed: https://other.example.net/\n" in text


def test_generate_report_no_redirect_lines_normally() -> None:
    """Without downgraded_from / offsite_redirect, neither redirect line is written."""
    text = _report(header_results={
        "url": "https://example.com", "present": [], "missing": [], "not_applicable": [],
    })
    assert "HTTPS redirected to plain HTTP" not in text
    assert "[INFO] Redirect to another host" not in text


def test_generate_report_no_https_warning_without_https_error() -> None:
    """Without 'https_error', the fallback warning is not written."""
    text = _report(header_results={"url": "https://example.com/", "present": [], "missing": []})
    assert "HTTPS attempt failed" not in text


def test_generate_report_lists_not_applicable_headers() -> None:
    """Each not_applicable header gets an [N/A] line explaining it only counts over HTTPS."""
    text = _report(header_results={
        "url": "http://example.com/", "present": [], "missing": [],
        "not_applicable": ["Strict-Transport-Security"],
    })
    assert "[N/A] Strict-Transport-Security (only counts over HTTPS)\n" in text


def test_generate_report_header_lines_in_order() -> None:
    """Checked, WARNING, PRESENT, MISSING and N/A lines appear in that order."""
    text = _report(header_results={
        "url": "http://example.com/", "https_error": "refused",
        "present": ["X-Frame-Options"], "missing": ["Referrer-Policy"],
        "not_applicable": ["Strict-Transport-Security"],
    })
    markers = ("Checked:", "[WARNING] HTTPS", "[PRESENT]", "[MISSING]", "[N/A]")
    positions = [text.index(m) for m in markers]
    assert positions == sorted(positions)


def test_generate_report_old_style_header_result_still_works() -> None:
    """An old-style result with only present/missing renders, with no Checked/WARNING/N/A lines."""
    text = _report(header_results={"present": [], "missing": ["Strict-Transport-Security"]})
    assert "[MISSING] Strict-Transport-Security\n" in text
    assert "Checked:" not in text
    assert "HTTPS attempt failed" not in text
    assert "[N/A]" not in text


def test_generate_report_lists_vulnerable_redirects() -> None:
    """Each vulnerable redirect URL is written with [VULNERABLE]."""
    url = "http://example.com?next=http://evil.com"
    assert f"[VULNERABLE] {url}\n" in _report(redirect_results=[url])


def test_generate_report_no_redirects() -> None:
    """An empty redirect list is written as 'No open redirects found.'."""
    assert "No open redirects found.\n" in _report(redirect_results=[])


def test_generate_report_ssl_refused_by_winerror_code() -> None:
    """An SSL error containing WinError 10061 is reported as port 443 closed."""
    text = _report(ssl_results={"error": "[WinError 10061] No connection could be made"})
    assert "[CRITICAL] Port 443 is closed — HTTPS is not enabled on this server\n" in text


def test_generate_report_ssl_refused_by_message() -> None:
    """An SSL error mentioning 'refused' (any case) is reported as port 443 closed."""
    text = _report(ssl_results={"error": "Connection Refused"})
    assert "[CRITICAL] Port 443 is closed" in text


def test_generate_report_ssl_other_error() -> None:
    """Any other SSL error is written verbatim."""
    text = _report(ssl_results={"error": "timed out"})
    assert "Error checking SSL: timed out\n" in text


def test_generate_report_valid_ssl_cert() -> None:
    """A valid, matching cert gets its details plus two [OK] lines."""
    text = _report(ssl_results=VALID_SSL)
    assert "Issued to: example.com\nIssued by: Let's Encrypt\n" in text
    assert "Expires: 2031-01-15 (100 days remaining)\n" in text
    assert "[OK] Certificate is valid\n" in text
    assert "[OK] Domain matches certificate\n" in text


def test_generate_report_expired_ssl_cert() -> None:
    """An expired cert is flagged [CRITICAL]."""
    text = _report(ssl_results={**VALID_SSL, "expired": True, "days_remaining": -3})
    assert "[CRITICAL] Certificate has expired\n" in text


def test_generate_report_expiring_soon_ssl_cert() -> None:
    """A cert expiring within 30 days is flagged [WARNING]."""
    text = _report(ssl_results={**VALID_SSL, "expiring_soon": True, "days_remaining": 10})
    assert "[WARNING] Certificate expiring within 30 days\n" in text


def test_generate_report_ssl_domain_mismatch() -> None:
    """A cert that does not match the host is flagged [CRITICAL]."""
    text = _report(ssl_results={**VALID_SSL, "domain_match": False})
    assert "[CRITICAL] Certificate domain does not match target\n" in text


@pytest.mark.xfail(
    raises=UnicodeDecodeError,
    reason=(
        "backlog item 8: report is written in the OS default encoding (cp1252 on Windows), not UTF-8. "
        "Non-strict because it passes wherever the default already is UTF-8 (Linux/macOS, PYTHONUTF8=1)."
    ),
)
def test_generate_report_is_utf8_encoded() -> None:
    """The report bytes should decode as UTF-8 so the em dash displays correctly."""
    filename = reporter.generate_report("example.com", [{"port": 22, "banner": None}], NO_HEADERS, [], VALID_SSL)
    assert "—" in Path(filename).read_bytes().decode("utf-8")


@pytest.mark.parametrize(
    ("problem", "phrase"),
    [
        ("hostname_mismatch", "name does not match the host"),
        ("expired", "has expired"),
        ("not_yet_valid", "is not valid yet"),
        ("untrusted", "is not from a trusted issuer (self-signed or unknown)"),
        ("invalid", "failed verification"),
        ("something_new", "failed verification"),  # unknown word -> fallback phrase
    ],
)
def test_generate_report_cert_problem_writes_critical_and_details(problem: str, phrase: str) -> None:
    """A cert_problem result prints the [CRITICAL] reason line followed by a Details line."""
    text = _report(ssl_results={"error": "certificate verify failed", "cert_problem": problem})
    expected = (
        f"[CRITICAL] Certificate rejected: {phrase}\n"
        "Details: certificate verify failed\n"
    )
    assert expected in text


def test_generate_report_cert_problem_skips_generic_error_lines() -> None:
    """A cert_problem result must not also print the generic error or port-443-closed lines."""
    # The error text mentions "refused" on purpose: the old branch would treat it as port closed.
    text = _report(ssl_results={"error": "peer refused: certificate verify failed",
                                "cert_problem": "untrusted"})
    assert "Error checking SSL" not in text
    assert "Port 443 is closed" not in text
    assert "[CRITICAL] Certificate rejected:" in text


def test_generate_report_cert_problem_without_error_text_does_not_crash() -> None:
    """A cert_problem with no 'error' key still writes the report, with 'no details'."""
    text = _report(ssl_results={"cert_problem": "expired"})
    assert "[CRITICAL] Certificate rejected: has expired\nDetails: no details\n" in text
