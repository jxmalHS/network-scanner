"""Tests for reporter.py - text report writing (all files go to pytest's tmp_path)."""
import re
from pathlib import Path
from unittest.mock import patch
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
    vulnerable: list[str] | None = None, sent: int = 32, skipped: int = 0, complete: bool = True,
    switch_reason: str | None = None,
) -> dict[str, Any]:
    """Build a redirect result shaped like redirects.RedirectResults (default: clean, complete run).

    A switch_reason means the probes went to https://, so base_url becomes https://example.com.
    """
    return {
        "base_url": "https://example.com" if switch_reason else "http://example.com",
        "vulnerable": vulnerable if vulnerable is not None else [],
        "probes_total": 32,
        "probes_sent": sent,
        "probes_skipped": skipped,
        "complete": complete,
        "switch_reason": switch_reason,
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
    assert text.startswith("Tamer Network Vulnerability Scan Report\nTarget: example.com\n")


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


def test_generate_report_empty_banner_is_non_printable_reply() -> None:
    """An empty-string banner means bytes arrived but none were printable."""
    text = _report(open_ports=[{"port": 443, "banner": ""}])
    assert "[OPEN] Port 443 — (non-printable reply)\n" in text
    assert "no banner" not in text


def test_generate_report_none_banner_is_no_banner() -> None:
    """A None banner means nothing was received: 'no banner'."""
    text = _report(open_ports=[{"port": 443, "banner": None}])
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
    """When both HTTPS and HTTP failed, three error lines are written, not the fallback warning."""
    text = _report(header_results={"error": "80 refused", "https_error": "443 refused"})
    assert (
        "Error fetching headers: HTTPS and HTTP both failed\n"
        "HTTPS (could not connect): 443 refused\n"
        "HTTP: 80 refused\n"
    ) in text
    assert "HTTPS attempt failed" not in text


def test_generate_report_both_failed_names_tls_problem() -> None:
    """Both failed with the HTTPS side a TLS problem: the HTTPS line says so."""
    text = _report(header_results={"error": "80 refused", "https_error": "bad cert",
                                   "https_tls_problem": True})
    assert "HTTPS (TLS problem): bad cert\n" in text


def test_generate_report_both_failed_cannot_inject_fake_line() -> None:
    """A newline in https_error can't start a fake '[PRESENT] X' line in the both-failed block."""
    text = _report(header_results={"error": "80 refused",
                                   "https_error": "oops\n[PRESENT] X"})
    assert not any(line.startswith("[PRESENT] X") for line in text.splitlines())


def test_generate_report_https_fallback_warning_too_many_redirects() -> None:
    """https_too_many_redirects: the fallback warning says '(too many redirects)'."""
    text = _report(header_results={
        "url": "http://example.com", "https_error": "more than 5 redirects",
        "https_too_many_redirects": True,
        "present": [], "missing": [], "not_applicable": ["Strict-Transport-Security"],
    })
    assert (
        "[WARNING] HTTPS attempt failed (too many redirects) — fell back to http://\n"
        "Details: more than 5 redirects\n"
    ) in text


def test_generate_report_tls_problem_wins_over_too_many_redirects() -> None:
    """If both flags are set, the TLS problem is what gets reported."""
    text = _report(header_results={
        "url": "http://example.com", "https_error": "x",
        "https_tls_problem": True, "https_too_many_redirects": True,
        "present": [], "missing": [], "not_applicable": [],
    })
    assert "HTTPS attempt failed (TLS problem)" in text
    assert "too many redirects" not in text


# --- HSTS max-age wording ----------------------------------------------------

def _hsts_report(max_age: Any, present: bool, short: bool = False) -> str:
    """Report over HTTPS with HSTS present or missing, the given hsts_max_age and hsts_short flag."""
    hsts = ["Strict-Transport-Security"]
    return _report(header_results={
        "url": "https://example.com", "hsts_max_age": max_age, "hsts_short": short,
        "present": hsts if present else [], "missing": [] if present else hsts,
        "not_applicable": [],
    })


def test_generate_report_hsts_max_age_zero_missing_reason() -> None:
    """hsts_max_age 0: the [MISSING] line explains max-age=0 switches HSTS off."""
    text = _hsts_report(0, present=False)
    assert ("[MISSING] Strict-Transport-Security "
            "(sent with max-age=0, which switches HSTS off)\n") in text


def test_generate_report_hsts_unreadable_max_age_missing_reason() -> None:
    """hsts_max_age None: the [MISSING] line says max-age is missing or unreadable."""
    text = _hsts_report(None, present=False)
    assert ("[MISSING] Strict-Transport-Security "
            "(sent, but max-age is missing or unreadable, so browsers ignore it)\n") in text


def test_generate_report_short_hsts_max_age_warning() -> None:
    """A present HSTS with a 2-day max-age gets a warning with seconds and days, after [PRESENT]."""
    text = _hsts_report(172800, present=True, short=True)
    warning = ("[WARNING] HSTS max-age is only 172800 seconds (about 2 days); "
               "6 months or more is recommended\n")
    assert "[PRESENT] Strict-Transport-Security\n" + warning in text


def test_generate_report_short_hsts_under_a_day_shows_seconds_only() -> None:
    """A max-age under one day doesn't print the odd "about 0 days"."""
    text = _hsts_report(300, present=True, short=True)
    assert "[WARNING] HSTS max-age is only 300 seconds; 6 months or more is recommended\n" in text
    assert "about 0 days" not in text


def test_generate_report_no_hsts_warning_at_exactly_six_months() -> None:
    """max-age exactly HSTS_MIN_MAX_AGE is long enough: no short-max-age warning."""
    text = _hsts_report(15_768_000, present=True)
    assert "HSTS max-age is only" not in text


def test_generate_report_no_hsts_warning_without_max_age_key() -> None:
    """HSTS present but no hsts_max_age key (old-style result): no warning, plain [PRESENT]."""
    text = _report(header_results={"present": ["Strict-Transport-Security"], "missing": []})
    assert "[PRESENT] Strict-Transport-Security\n" in text
    assert "HSTS max-age is only" not in text


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
    assert ("[INFO] 3 of 32 probes got no usable answer (timeout, dropped connection or "
            "unreadable reply) and were skipped\n") in text
    assert "No open redirects found in the 29 probes that got an answer.\n" in text
    assert "No open redirects found.\n" not in text
    assert "[WARNING] Check incomplete" not in text


REDIRECT_INFO = ("[INFO] http://example.com redirects to HTTPS; "
                 "probes were sent to https://example.com instead\n")
NO_HTTP_INFO = ("[INFO] http://example.com could not be reached; "
                "probes were sent to https://example.com instead\n")


def test_generate_report_https_switch_by_redirect_info_line() -> None:
    """switch_reason 'redirect' explains that HTTP redirected and probes went to HTTPS."""
    section = _redirect_section(_report(redirect_results=_redirects(switch_reason="redirect")))
    assert REDIRECT_INFO in section
    assert NO_HTTP_INFO not in section


def test_generate_report_https_switch_no_http_info_line() -> None:
    """switch_reason 'no_http' explains that HTTP was unreachable and probes went to HTTPS."""
    section = _redirect_section(_report(redirect_results=_redirects(switch_reason="no_http")))
    assert NO_HTTP_INFO in section
    assert REDIRECT_INFO not in section


def test_generate_report_no_switch_info_without_switch_reason() -> None:
    """switch_reason None: neither switch line is written."""
    section = _redirect_section(_report(redirect_results=_redirects()))
    assert "redirects to HTTPS" not in section
    assert "could not be reached" not in section


def test_generate_report_no_http_and_https_unreachable_shows_both_lines() -> None:
    """HTTP unreachable, then HTTPS also failed at probe 1: INFO line plus could-not-connect warning."""
    section = _redirect_section(_report(redirect_results=_redirects(
        sent=1, complete=False, switch_reason="no_http")))
    assert NO_HTTP_INFO in section
    assert ("[WARNING] Check incomplete: could not connect to https://example.com; "
            "no probes were answered\n") in section
    assert "No open redirects found" not in section


def test_generate_report_switched_clean_run_still_says_no_redirects() -> None:
    """A switched, complete, clean run still ends with 'No open redirects found.'."""
    section = _redirect_section(_report(redirect_results=_redirects(switch_reason="redirect")))
    assert section.endswith("No open redirects found.\n\n")
    assert section.index(REDIRECT_INFO) < section.index("No open redirects found.")


def test_generate_report_switch_line_mentions_earlier_http_probe() -> None:
    """One HTTP probe before the switch: the [INFO] line says so (singular)."""
    r = {**_redirects(switch_reason="redirect"), "http_probes_sent": 1}
    section = _redirect_section(_report(redirect_results=r))
    assert ("[INFO] http://example.com redirects to HTTPS; probes were sent to "
            "https://example.com instead (plus 1 earlier probe over HTTP)\n") in section


def test_generate_report_no_http_line_mentions_earlier_http_probes() -> None:
    """Two failed HTTP probes before the switch: plural wording on the no_http line."""
    r = {**_redirects(switch_reason="no_http"), "http_probes_sent": 2}
    section = _redirect_section(_report(redirect_results=r))
    assert ("[INFO] http://example.com could not be reached; probes were sent to "
            "https://example.com instead (plus 2 earlier probes over HTTP)\n") in section


def test_generate_report_no_earlier_probe_suffix_without_switch() -> None:
    """http_probes_sent 0 (no switch): no '(plus ...)' text anywhere."""
    r = {**_redirects(), "http_probes_sent": 0}
    assert "earlier probe" not in _redirect_section(_report(redirect_results=r))


def test_generate_report_tls_stop_with_no_answers() -> None:
    """stop_reason 'tls' on the first probe: TLS/certificate wording, not 'could not connect'."""
    r = {**_redirects(sent=1, complete=False, switch_reason="redirect"), "stop_reason": "tls"}
    section = _redirect_section(_report(redirect_results=r))
    assert ("[WARNING] Check incomplete: TLS/certificate problem with https://example.com; "
            "no probes were answered\n") in section
    assert "could not connect" not in section
    assert "No open redirects found" not in section


def test_generate_report_tls_stop_after_some_answers() -> None:
    """stop_reason 'tls' at probe 6: says where it stopped and keeps the hedged clean line."""
    r = {**_redirects(sent=6, complete=False), "stop_reason": "tls"}
    section = _redirect_section(_report(redirect_results=r))
    assert ("[WARNING] Check incomplete: TLS/certificate problem with http://example.com "
            "at probe 6 of 32; the rest were not sent\n") in section
    assert "No open redirects found in the 5 probes that got an answer.\n" in section


def test_generate_report_two_failures_with_no_answers_says_could_not_connect() -> None:
    """Stopped after 2 failed connections (1 skipped + the stopping one): nothing was answered."""
    r = {**_redirects(sent=2, skipped=1, complete=False), "stop_reason": "connection"}
    section = _redirect_section(_report(redirect_results=r))
    assert ("[WARNING] Check incomplete: could not connect to http://example.com; "
            "no probes were answered\n") in section
    assert "[WARNING] No probe got a usable answer" in section


def test_generate_report_offsite_redirect_info_line() -> None:
    """An off-host redirect on the first probe gets an [INFO] line saying it was not tested."""
    r = {**_redirects(), "offsite_redirect": "https://www.example.com/"}
    section = _redirect_section(_report(redirect_results=r))
    assert ("[INFO] http://example.com redirects to another host (https://www.example.com/); "
            "that host was not tested\n") in section


def test_generate_report_offsite_redirect_is_cleaned() -> None:
    """The off-host target comes from the server, so it can't inject lines or escape codes."""
    r = {**_redirects(), "offsite_redirect": EVIL}
    text = _report(redirect_results=r)
    assert "evil" in text
    assert not any(line.startswith("[OK] Fake") for line in text.splitlines())
    assert "\x1b" not in text
    assert "\u202e" not in text


def test_generate_report_no_offsite_line_when_none() -> None:
    """offsite_redirect None: no 'another host' line."""
    r = {**_redirects(), "offsite_redirect": None}
    assert "another host" not in _redirect_section(_report(redirect_results=r))


META_URL = "http://example.com/?next=http://redirect-canary.invalid/"
LOGIN_URL = "http://example.com/login?next=http://redirect-canary.invalid/"


def test_generate_report_labels_meta_refresh_finding() -> None:
    """A finding from a <meta refresh> says so; a plain Location finding has no label."""
    r = {**_redirects([META_URL, LOGIN_URL]), "vulnerable_meta_refresh": [META_URL]}
    section = _redirect_section(_report(redirect_results=r))
    assert f"[VULNERABLE] {META_URL} (via <meta refresh> in the page)\n" in section
    assert f"[VULNERABLE] {LOGIN_URL}\n" in section


def test_generate_report_labels_refresh_header_finding() -> None:
    """A finding from a Refresh: response header says so."""
    r = {**_redirects([META_URL]), "vulnerable_refresh_header": [META_URL]}
    section = _redirect_section(_report(redirect_results=r))
    assert f"[VULNERABLE] {META_URL} (via a Refresh header)\n" in section


def test_generate_report_vulnerable_line_is_cleaned() -> None:
    """Text on a [VULNERABLE] line goes through clean_text, so it can't add fake lines."""
    r = {**_redirects([EVIL]), "vulnerable_meta_refresh": [EVIL]}
    text = _report(redirect_results=r)
    assert "evil" in text
    assert not any(line.startswith("[OK] Fake") for line in text.splitlines())
    assert "\x1b" not in text
    assert "\u202e" not in text


def test_generate_report_ssl_refused_by_error_kind() -> None:
    """error_kind 'refused' is reported as port 443 closed, not as a generic SSL error."""
    text = _report(ssl_results={"error": "[WinError 10061] No connection could be made",
                                "error_kind": "refused"})
    assert "[CRITICAL] Port 443 is closed — HTTPS is not enabled on this server\n" in text
    assert "Error checking SSL" not in text


@pytest.mark.parametrize("error", ["[WinError 10061] No connection could be made",
                                   "Connection Refused", "peer refused the handshake"])
def test_generate_report_ssl_refused_text_alone_is_not_port_closed(error: str) -> None:
    """Without error_kind, text mentioning 10061/'refused' is shown as an ordinary SSL error."""
    text = _report(ssl_results={"error": error})
    assert "Port 443 is closed" not in text
    assert f"Error checking SSL: {error}\n" in text


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


def test_generate_report_ssl_refused_kind_ignores_messy_error_text() -> None:
    """The port-443-closed line depends only on error_kind, whatever the error text contains."""
    text = _report(ssl_results={"error": "[WinError 10061]\nrefused\x1b[0m", "error_kind": "refused"})
    assert "[CRITICAL] Port 443 is closed — HTTPS is not enabled on this server\n" in text
    assert "\x1b" not in text


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


def test_reporter_does_not_import_hsts_threshold() -> None:
    """The reporter only formats results; the "too short" threshold lives in headers.py."""
    assert not hasattr(reporter, "HSTS_MIN_MAX_AGE")


@pytest.mark.parametrize("bad_max_age", [None, "abc", True], ids=["none", "text", "bool"])
def test_generate_report_hsts_short_without_usable_number_still_warns(bad_max_age: Any) -> None:
    """hsts_short set but no real int max-age: a plain warning instead of a crash."""
    text = _hsts_report(bad_max_age, present=True, short=True)
    assert "[WARNING] HSTS max-age is shorter than recommended (6 months or more)\n" in text
    assert "max-age is only" not in text


def test_generate_report_hsts_not_short_has_no_warning() -> None:
    """hsts_short False: no HSTS warning at all, whatever max-age says."""
    text = _hsts_report(172800, present=True, short=False)
    assert "[WARNING] HSTS" not in text


def test_generate_report_leaves_no_tmp_file_on_success(in_tmp_dir: Path) -> None:
    """A normal run leaves exactly one finished report and no .tmp file."""
    filename = reporter.generate_report("example.com", [], NO_HEADERS, _redirects(), VALID_SSL)
    assert sorted(p.name for p in in_tmp_dir.iterdir()) == [filename]


@pytest.mark.parametrize("error", [KeyboardInterrupt, RuntimeError], ids=["ctrl_c", "bug"])
def test_generate_report_failure_midway_leaves_no_files(in_tmp_dir: Path, error: type[BaseException]) -> None:
    """Ctrl+C or a bug while writing: the error still propagates, and no report_* file of any kind remains."""
    with patch("reporter.clean_text", side_effect=error):
        with pytest.raises(error):
            reporter.generate_report("example.com", [], {"error": "x"}, _redirects(), VALID_SSL)
    assert list(in_tmp_dir.iterdir()) == []


def test_generate_report_rename_failure_removes_tmp(in_tmp_dir: Path) -> None:
    """If the final rename fails, the error propagates and the .tmp file is cleaned up."""
    with patch("reporter.os.replace", side_effect=OSError("disk full")):
        with pytest.raises(OSError, match="disk full"):
            reporter.generate_report("example.com", [], NO_HEADERS, _redirects(), VALID_SSL)
    assert list(in_tmp_dir.iterdir()) == []



@pytest.mark.parametrize(
    ("key", "heading", "kwarg"),
    [
        ("ports", "OPEN PORTS", "open_ports"),
        ("headers", "HTTP SECURITY HEADERS", "header_results"),
        ("redirects", "OPEN REDIRECT CHECK", "redirect_results"),
        ("ssl", "SSL/TLS CERTIFICATE", "ssl_results"),
    ],
)
def test_generate_report_internal_error_section(key: str, heading: str, kwarg: str) -> None:
    """A crashed check gets an [INTERNAL ERROR] line in its own section; the others are normal."""
    detail = "ValueError: x (ssl_checker.py line 81)"
    results = {"open_ports": [], "header_results": NO_HEADERS,
               "redirect_results": _redirects(), "ssl_results": VALID_SSL}
    results[kwarg] = None                       # the crashed check produced nothing
    filename = reporter.generate_report("example.com", **results, internal_errors={key: detail})
    text = Path(filename).read_text(encoding="utf-8")
    section = text.split(heading + "\n", 1)[1]
    assert section.split("\n", 2)[1].startswith(f"[INTERNAL ERROR] Check did not run: {detail}.")
    assert "please report it" in text
    assert text.count("[INTERNAL ERROR]") == 1


@pytest.mark.parametrize("internal_errors", [None, {}])
def test_generate_report_no_internal_errors_is_unchanged(internal_errors: object) -> None:
    """internal_errors None or empty: the report is exactly what it was before the safety net."""
    plain = Path(reporter.generate_report("example.com", [], NO_HEADERS, _redirects(), VALID_SSL)).read_text(encoding="utf-8")
    with_arg = Path(reporter.generate_report("example.com", [], NO_HEADERS, _redirects(), VALID_SSL,
                                             internal_errors=internal_errors)).read_text(encoding="utf-8")
    strip_date = lambda t: "\n".join(l for l in t.splitlines() if not l.startswith("Date:"))
    assert strip_date(with_arg) == strip_date(plain)
    assert "[INTERNAL ERROR]" not in with_arg



def test_generate_report_retries_a_briefly_locked_rename(in_tmp_dir: Path) -> None:
    """Windows says "busy" twice (antivirus), then the rename works: the report is saved."""
    real_replace = reporter.os.replace
    calls = {"n": 0}

    def flaky_replace(src: str, dst: str) -> None:
        calls["n"] += 1
        if calls["n"] <= 2:
            raise PermissionError("file is being used by another process")
        real_replace(src, dst)

    with patch("reporter.os.replace", side_effect=flaky_replace), patch("reporter.time.sleep") as nap:
        filename = reporter.generate_report("example.com", [], NO_HEADERS, _redirects(), VALID_SSL)
    assert sorted(p.name for p in in_tmp_dir.iterdir()) == [filename]
    assert nap.call_count == 2


def test_generate_report_gives_up_after_repeated_locks_and_cleans_up(in_tmp_dir: Path) -> None:
    """Still locked after every retry: the error propagates and no .tmp file is left behind."""
    with patch("reporter.os.replace", side_effect=PermissionError("locked")) as rep, \
            patch("reporter.time.sleep"):
        with pytest.raises(PermissionError):
            reporter.generate_report("example.com", [], NO_HEADERS, _redirects(), VALID_SSL)
    assert rep.call_count == reporter.RENAME_ATTEMPTS
    assert list(in_tmp_dir.iterdir()) == []
