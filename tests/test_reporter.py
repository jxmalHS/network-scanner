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
