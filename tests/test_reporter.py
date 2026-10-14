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


def _redirects(
    vulnerable: list[str] | None = None, sent: int = 32, skipped: int = 0, complete: bool = True
) -> dict[str, Any]:
    """Build a redirect result shaped like redirects.RedirectResults (default: clean, complete run)."""
    return {
        "base_url": "http://example.com",
        "vulnerable": vulnerable if vulnerable is not None else [],
        "probes_total": 32,
        "probes_sent": sent,
        "probes_skipped": skipped,
        "complete": complete,
    }


def _redirect_section(text: str) -> str:
    """Just the OPEN REDIRECT CHECK section of a report (up to the SSL heading)."""
    start = text.index("OPEN REDIRECT CHECK\n")
    return text[start:text.index("SSL/TLS CERTIFICATE\n", start)]


def _report(
    open_ports: list[dict[str, Any]] | None = None,
    header_results: dict[str, Any] | None = None,
    redirect_results: dict[str, Any] | None = None,
    ssl_results: dict[str, Any] | None = None,
) -> str:
    """Generate a report with sensible defaults and return its text."""
    filename = reporter.generate_report(
        "example.com",
        open_ports if open_ports is not None else [],
        header_results if header_results is not None else NO_HEADERS,
        redirect_results if redirect_results is not None else _redirects(),
        ssl_results if ssl_results is not None else VALID_SSL,
    )
    # reporter.py writes the report as UTF-8, so read it back as UTF-8.
    return Path(filename).read_text(encoding="utf-8")


def test_generate_report_returns_timestamped_filename(in_tmp_dir: Path) -> None:
    """The returned filename is report_<host>_<YYYYMMDD_HHMMSS>.txt and the file exists."""
    filename = reporter.generate_report("example.com", [], NO_HEADERS, _redirects(), VALID_SSL)
    assert re.fullmatch(r"report_example\.com_\d{8}_\d{6}\.txt", filename)
    assert (in_tmp_dir / filename).is_file()


def test_generate_report_ipv6_host_gets_safe_filename(in_tmp_dir: Path) -> None:
    """':' is illegal in Windows filenames, so '::1' becomes '__1' in the name; Target keeps '::1'."""
    filename = reporter.generate_report("::1", [], NO_HEADERS, _redirects(), VALID_SSL)
    assert re.fullmatch(r"report___1_\d{8}_\d{6}\.txt", filename)
    assert (in_tmp_dir / filename).is_file()
    assert "Target: ::1\n" in (in_tmp_dir / filename).read_text(encoding="utf-8")


def test_generate_report_includes_target_header() -> None:
    """The report starts with its title and the target host."""
    text = _report()
    assert text.startswith("Network Vulnerability Scan Report\nTarget: example.com\n")


def _target_line(in_tmp_dir: Path, host: str, **kwargs: Any) -> str:
    """Write a report for host (extra kwargs passed through) and return its 'Target:' line."""
    filename = reporter.generate_report(host, [], NO_HEADERS, _redirects(), VALID_SSL, **kwargs)
    return (in_tmp_dir / filename).read_text(encoding="utf-8").splitlines()[1]


def test_generate_report_target_shows_resolved_address(in_tmp_dir: Path) -> None:
    """When the resolved address differs from the host, both are shown."""
    assert _target_line(in_tmp_dir, "localhost", address="127.0.0.1") == "Target: localhost (127.0.0.1)"


def test_generate_report_target_not_duplicated_for_ip_host(in_tmp_dir: Path) -> None:
    """An IP target whose address is itself is shown once, not 'IP (IP)'."""
    assert _target_line(in_tmp_dir, "127.0.0.1", address="127.0.0.1") == "Target: 127.0.0.1"


def test_generate_report_target_without_address_is_just_host(in_tmp_dir: Path) -> None:
    """Omitting address keeps the old 'Target: <host>' line."""
    assert _target_line(in_tmp_dir, "localhost") == "Target: localhost"


def test_generate_report_long_host_truncated_to_100_chars_in_filename(in_tmp_dir: Path) -> None:
    """A 253-char host (the DNS maximum) is cut to 100 chars in the filename, and the file is created."""
    filename = reporter.generate_report("a" * 253, [], NO_HEADERS, _redirects(), VALID_SSL)
    match = re.fullmatch(r"report_(.+)_\d{8}_\d{6}\.txt", filename)
    assert match is not None
    assert match.group(1) == "a" * 100
    assert (in_tmp_dir / filename).is_file()


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
    assert f"[VULNERABLE] {url}\n" in _report(redirect_results=_redirects([url]))


def test_generate_report_no_redirects() -> None:
    """A complete, clean run is written as exactly 'No open redirects found.', with no warnings."""
    section = _redirect_section(_report(redirect_results=_redirects()))
    assert section == "OPEN REDIRECT CHECK\n" + "-" * 20 + "\nNo open redirects found.\n\n"
    assert "[WARNING]" not in section
    assert "[INFO]" not in section


def test_generate_report_incomplete_redirect_check_does_not_claim_clean() -> None:
    """Could not connect at probe 1: say so, and never print any 'No open redirects found' line."""
    text = _report(redirect_results=_redirects(sent=1, complete=False))
    assert ("[WARNING] Check incomplete: could not connect to http://example.com; "
            "no probes were answered\n") in text
    assert "[WARNING] No probe got a usable answer; the redirect check could not run.\n" in text
    assert "No open redirects found" not in text


def test_generate_report_incomplete_after_some_answers_counts_them() -> None:
    """Host went quiet at probe 5: 4 probes were answered, and the wording says exactly that."""
    text = _report(redirect_results=_redirects(sent=5, complete=False))
    assert "host stopped answering at probe 5 of 32; the rest were not sent\n" in text
    assert "No open redirects found in the 4 probes that got an answer.\n" in text
    assert "No open redirects found.\n" not in text


def test_generate_report_all_probes_skipped_says_check_could_not_run() -> None:
    """Every probe skipped (e.g. all timed out): no 'no redirects found' claim at all."""
    text = _report(redirect_results=_redirects(skipped=32))
    assert "[WARNING] No probe got a usable answer; the redirect check could not run.\n" in text
    assert "No open redirects found" not in text


def test_generate_report_incomplete_redirect_check_keeps_finding() -> None:
    """A finding before the host went quiet is still listed, alongside the incomplete warning."""
    url = "http://example.com/?next=http://redirect-canary.invalid/"
    section = _redirect_section(_report(redirect_results=_redirects([url], sent=2, complete=False)))
    assert f"[VULNERABLE] {url}\n" in section
    assert "[WARNING] Check incomplete: host stopped answering at probe 2 of 32" in section
    assert "No open redirects found" not in section


def test_generate_report_skipped_redirect_probes_info_line() -> None:
    """Skipped probes get an [INFO] line with the count and the hedged 'no redirects' wording."""
    text = _report(redirect_results=_redirects(skipped=3))
    assert ("[INFO] 3 of 32 probes got no usable answer (timeout or unreadable reply) "
            "and were skipped\n") in text
    assert "No open redirects found in the 29 probes that got an answer.\n" in text
    assert "No open redirects found.\n" not in text
    assert "[WARNING] Check incomplete" not in text


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


EVIL = "evil\n[OK] Fake line\x1b[2J\u202e"


@pytest.mark.parametrize("kwargs", [
    pytest.param({"header_results": {"url": "https://example.com", "offsite_redirect": EVIL,
                                     "present": [], "missing": [], "not_applicable": []}},
                 id="offsite_redirect"),
    pytest.param({"header_results": {"error": EVIL}}, id="header_error"),
    pytest.param({"ssl_results": {"error": EVIL}}, id="ssl_error"),
    pytest.param({"ssl_results": {"cert_problem": "invalid", "error": EVIL}}, id="cert_problem_details"),
    pytest.param({"ssl_results": {**VALID_SSL, "issued_to": EVIL}}, id="issued_to"),
    pytest.param({"ssl_results": {**VALID_SSL, "issued_by": EVIL}}, id="issued_by"),
])
def test_generate_report_server_text_cannot_inject_lines_or_escapes(kwargs: dict[str, Any]) -> None:
    """Server-controlled text can't start a fake '[OK]' line, send ESC codes or flip text direction."""
    text = _report(**kwargs)
    assert "evil" in text  # the field really was written, just cleaned
    assert not any(line.startswith("[OK] Fake") for line in text.splitlines())
    assert "\x1b" not in text
    assert "\u202e" not in text


def test_generate_report_ssl_10061_still_reports_port_closed() -> None:
    """The port-443-closed check reads the raw error, so cleaning doesn't break it."""
    text = _report(ssl_results={"error": "[WinError 10061]\nrefused\x1b[0m"})
    assert "[CRITICAL] Port 443 is closed — HTTPS is not enabled on this server\n" in text


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


def test_generate_report_is_utf8_encoded() -> None:
    """The report bytes should decode as UTF-8 so the em dash displays correctly."""
    filename = reporter.generate_report("example.com", [{"port": 22, "banner": None}], NO_HEADERS, _redirects(), VALID_SSL)
    assert "—" in Path(filename).read_bytes().decode("utf-8")


def test_generate_report_non_cp1252_banner_written_as_utf8() -> None:
    """A banner with characters outside cp1252 (Chinese, check mark) is written without crashing."""
    text = _report(open_ports=[{"port": 22, "banner": "SSH-2.0 中文 ✓"}])
    assert "[OPEN] Port 22 — SSH-2.0 中文 ✓" in text.splitlines()


def test_generate_report_has_no_utf8_bom() -> None:
    """The report is plain UTF-8 with no byte-order mark (BOM) at the start."""
    filename = reporter.generate_report("example.com", [], NO_HEADERS, _redirects(), VALID_SSL)
    assert not Path(filename).read_bytes().startswith(b"\xef\xbb\xbf")


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
