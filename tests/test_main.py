"""Tests for main.py - argparse handling and wiring of the checks (every check mocked)."""
import argparse
import socket
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

import main as main_module

# A clean, complete result shaped like redirects.RedirectResults.
REDIRECT_RESULTS = {
    "base_url": "http://localhost", "vulnerable": [], "probes_total": 32,
    "probes_sent": 32, "probes_skipped": 0, "complete": True, "switch_reason": None,
}


@pytest.fixture
def checks() -> Iterator[dict[str, MagicMock]]:
    """Replace every check and the reporter inside main.py with mocks."""
    with (
        patch("main.resolve_host", return_value=(socket.AF_INET, "127.0.0.1")) as resolve_host,
        patch("main.scan_ports", return_value=[]) as scan_ports,
        patch("main.check_headers", return_value={"present": [], "missing": []}) as check_headers,
        patch("main.check_open_redirect", return_value=dict(REDIRECT_RESULTS)) as check_open_redirect,
        patch("main.check_ssl", return_value={"error": "refused"}) as check_ssl,
        patch("main.generate_report", return_value="report.txt") as generate_report,
    ):
        yield {
            "resolve_host": resolve_host,
            "scan_ports": scan_ports,
            "check_headers": check_headers,
            "check_open_redirect": check_open_redirect,
            "check_ssl": check_ssl,
            "generate_report": generate_report,
        }


def _run(monkeypatch: pytest.MonkeyPatch, *args: str) -> None:
    """Run main() as if called from the command line with the given arguments."""
    monkeypatch.setattr("sys.argv", ["main.py", *args])
    main_module.main()


def test_main_uses_common_ports_by_default(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """Without --ports, the default COMMON_PORTS list is scanned."""
    _run(monkeypatch, "localhost")
    checks["scan_ports"].assert_called_once_with("127.0.0.1", main_module.COMMON_PORTS, 20)


def test_main_parses_ports_as_ints(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """--ports 22 80 is parsed into the integer list [22, 80]."""
    _run(monkeypatch, "localhost", "--ports", "22", "80")
    checks["scan_ports"].assert_called_once_with("127.0.0.1", [22, 80], 20)


def test_main_rejects_non_integer_port(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """A non-numeric port makes argparse exit with code 2 before any scan runs."""
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost", "--ports", "http")
    assert exc.value.code == 2
    checks["scan_ports"].assert_not_called()


@pytest.mark.parametrize("value", ["0", "65536", "-1", "99999", "abc"])
def test_main_rejects_bad_port_with_exit_code_2(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock], value: str
) -> None:
    """Out-of-range or non-numeric ports exit 2 before scanning (--ports=VALUE so '-1' isn't a flag)."""
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost", f"--ports={value}")
    assert exc.value.code == 2
    checks["scan_ports"].assert_not_called()


@pytest.mark.parametrize("value", ["1", "65535"])
def test_main_accepts_port_boundaries(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock], value: str
) -> None:
    """The lowest (1) and highest (65535) ports both reach scan_ports as ints."""
    _run(monkeypatch, "localhost", "--ports", value)
    checks["scan_ports"].assert_called_once_with("127.0.0.1", [int(value)], 20)


@pytest.mark.parametrize("value, expected", [("1", 1), ("443", 443), ("65535", 65535)])
def test_port_number_returns_int_for_valid_values(value: str, expected: int) -> None:
    """port_number turns a valid string into an int."""
    assert main_module.port_number(value) == expected


@pytest.mark.parametrize("value", ["0", "65536", "-1"])
def test_port_number_rejects_out_of_range_with_message(value: str) -> None:
    """Ports outside 1..65535 raise ArgumentTypeError naming the range and the bad value."""
    with pytest.raises(argparse.ArgumentTypeError, match=f"port must be between 1 and 65535, got {value}"):
        main_module.port_number(value)


@pytest.mark.parametrize("value", ["abc", "8.5", ""])
def test_port_number_rejects_non_whole_numbers_with_message(value: str) -> None:
    """Text, decimals and empty strings raise ArgumentTypeError saying it's not a whole number."""
    with pytest.raises(argparse.ArgumentTypeError, match="not a whole number"):
        main_module.port_number(value)


def test_main_requires_host(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """Running with no host makes argparse exit with code 2."""
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch)
    assert exc.value.code == 2


def test_main_passes_all_results_to_reporter(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """Every check's result is handed to generate_report in order."""
    _run(monkeypatch, "localhost")
    checks["generate_report"].assert_called_once_with(
        "localhost", [], {"present": [], "missing": []}, REDIRECT_RESULTS, {"error": "refused"},
        address="127.0.0.1",
    )


def test_main_passes_redirect_results_dict_unchanged(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]
) -> None:
    """The exact dict from check_open_redirect reaches generate_report (same object, not rebuilt)."""
    _run(monkeypatch, "localhost")
    redirect_arg = checks["generate_report"].call_args.args[3]
    assert redirect_arg is checks["check_open_redirect"].return_value


def test_main_runs_redirect_and_ssl_checks_on_host(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]
) -> None:
    """The redirect and SSL checks receive the bare host name."""
    _run(monkeypatch, "localhost")
    checks["check_open_redirect"].assert_called_once_with("localhost")
    checks["check_ssl"].assert_called_once_with("localhost")


def test_main_checks_headers_on_bare_host(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """The header check receives the bare host; headers.py decides https:// vs http:// itself."""
    _run(monkeypatch, "localhost")
    checks["check_headers"].assert_called_once_with("localhost")


def test_main_prints_progress_and_results(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """Console shows the target, each open port (banner cut to 50 chars) and the report filename."""
    checks["scan_ports"].return_value = [{"port": 22, "banner": "S" * 80}, {"port": 80, "banner": None}]
    _run(monkeypatch, "localhost")
    out = capsys.readouterr().out
    assert "[*] Starting scan on localhost" in out
    assert f"[+] Port 22 open — {'S' * 50}\n" in out
    assert "[+] Port 80 open — no banner\n" in out
    assert "[+] Report saved to report.txt" in out


def test_main_prints_cleaned_banner_on_one_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """A banner already cleaned by scanner ('A | B') is printed as a single console line."""
    checks["scan_ports"].return_value = [{"port": 80, "banner": "A | B"}]
    _run(monkeypatch, "localhost")
    assert "[+] Port 80 open — A | B\n" in capsys.readouterr().out


def test_main_prints_non_printable_reply_and_no_banner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """Banner "" prints "(non-printable reply)"; banner None prints "no banner"."""
    checks["scan_ports"].return_value = [{"port": 80, "banner": ""}, {"port": 81, "banner": None}]
    _run(monkeypatch, "localhost")
    out = capsys.readouterr().out
    assert "[+] Port 80 open — (non-printable reply)\n" in out
    assert "[+] Port 81 open — no banner\n" in out


def test_main_prints_security_headers_progress(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """The header step announces itself as 'security headers' (no longer 'HTTP')."""
    _run(monkeypatch, "localhost")
    assert "[*] Checking security headers...\n" in capsys.readouterr().out


# --- valid_host: which targets argparse accepts ------------------------------

GOOD_HOSTS = ["localhost", "scanme.nmap.org", "192.168.56.101", "::1"]
BAD_HOSTS = ["site.com@other.com", "site.com/path", "host:8080", "a b", "", "fe80::1%eth0", "::1%1"]


@pytest.mark.parametrize("host", GOOD_HOSTS)
def test_valid_host_accepts_plain_hosts_and_ips(host: str) -> None:
    """Plain hostnames and IPv4/IPv6 literals are returned unchanged."""
    assert main_module.valid_host(host) == host


@pytest.mark.parametrize("host", BAD_HOSTS)
def test_valid_host_rejects_unsafe_values(host: str) -> None:
    """Anything with @, /, a port, a space, or nothing at all raises ArgumentTypeError."""
    with pytest.raises(argparse.ArgumentTypeError):
        main_module.valid_host(host)


def test_valid_host_rejects_name_longer_than_253_chars() -> None:
    """A hostname over 253 characters (the DNS limit) is rejected; exactly 253 is fine."""
    assert main_module.valid_host("a" * 253) == "a" * 253
    with pytest.raises(argparse.ArgumentTypeError):
        main_module.valid_host("a" * 254)


@pytest.mark.parametrize("host", GOOD_HOSTS)
def test_main_accepts_good_host_and_runs_checks(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock], host: str
) -> None:
    """Through the real CLI, a good host reaches every check unchanged."""
    _run(monkeypatch, host)
    checks["check_headers"].assert_called_once_with(host)


@pytest.mark.parametrize("host", BAD_HOSTS)
def test_main_rejects_bad_host_with_exit_code_2(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock], host: str
) -> None:
    """Through the real CLI, a bad host makes argparse exit with code 2 before any check runs."""
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, host)
    assert exc.value.code == 2
    for mock in checks.values():
        mock.assert_not_called()


# --- --workers: how many ports are checked at the same time ------------------


def test_main_default_workers_is_20(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """Without --workers, scan_ports gets 20 workers (scanner.DEFAULT_WORKERS)."""
    _run(monkeypatch, "localhost")
    assert checks["scan_ports"].call_args.args[2] == 20


def test_main_passes_workers_option_to_scan_ports(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]
) -> None:
    """--workers 50 is parsed as the int 50 and handed to scan_ports."""
    _run(monkeypatch, "localhost", "--ports", "80", "--workers", "50")
    checks["scan_ports"].assert_called_once_with("127.0.0.1", [80], 50)


@pytest.mark.parametrize("value", ["0", "201", "abc", "-5", "2.5"])
def test_main_rejects_bad_workers_with_exit_code_2(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock], value: str
) -> None:
    """Out-of-range or non-whole-number --workers makes argparse exit with code 2, before scanning."""
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost", f"--workers={value}")
    assert exc.value.code == 2
    checks["scan_ports"].assert_not_called()


@pytest.mark.parametrize("value", ["1", "200"])
def test_main_accepts_workers_boundaries(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock], value: str
) -> None:
    """The smallest (1) and largest (200) allowed values both reach scan_ports."""
    _run(monkeypatch, "localhost", "--ports", "80", "--workers", value)
    checks["scan_ports"].assert_called_once_with("127.0.0.1", [80], int(value))


@pytest.mark.parametrize("value, expected", [("1", 1), ("20", 20), ("200", 200), (" 7 ", 7)])
def test_worker_count_returns_int_for_valid_values(value: str, expected: int) -> None:
    """worker_count turns a valid string into an int (int() also tolerates surrounding spaces)."""
    assert main_module.worker_count(value) == expected


@pytest.mark.parametrize("value", ["0", "201", "-5"])
def test_worker_count_rejects_out_of_range_with_message(value: str) -> None:
    """Numbers outside 1..200 raise ArgumentTypeError naming the allowed range."""
    with pytest.raises(argparse.ArgumentTypeError, match="between 1 and 200"):
        main_module.worker_count(value)


@pytest.mark.parametrize("value", ["abc", "2.5", ""])
def test_worker_count_rejects_non_whole_numbers_with_message(value: str) -> None:
    """Text, decimals and empty strings raise ArgumentTypeError saying it's not a whole number."""
    with pytest.raises(argparse.ArgumentTypeError, match="not a whole number"):
        main_module.worker_count(value)


def test_main_prints_port_count_and_workers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """The progress line says how many ports are scanned and how many at a time."""
    _run(monkeypatch, "localhost", "--ports", "22", "80", "443", "--workers", "5")
    assert "[*] Scanning 3 ports (5 at a time)...\n" in capsys.readouterr().out


# --- Ctrl+C: KeyboardInterrupt becomes a clean exit with code 130 -------------


def test_main_ctrl_c_during_port_scan_exits_130_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """Ctrl+C in scan_ports exits 130 with '[!] Scan aborted', skips later checks, no traceback."""
    checks["scan_ports"].side_effect = KeyboardInterrupt
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 130
    captured = capsys.readouterr()
    assert "[!] Scan aborted" in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    for name in ("check_headers", "check_open_redirect", "check_ssl", "generate_report"):
        checks[name].assert_not_called()


def test_main_ctrl_c_during_ssl_check_exits_130_without_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """Ctrl+C late in the scan (check_ssl) is caught too, and no report is written."""
    checks["check_ssl"].side_effect = KeyboardInterrupt
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 130
    assert "[!] Scan aborted" in capsys.readouterr().out
    checks["generate_report"].assert_not_called()


def test_main_normal_run_does_not_print_aborted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """A scan that finishes normally returns without SystemExit and never says 'Scan aborted'."""
    _run(monkeypatch, "localhost")  # would fail the test if SystemExit were raised
    assert "Scan aborted" not in capsys.readouterr().out


def test_main_unresolvable_host_exits_1_without_other_checks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """HostResolutionError from resolve_host exits 1 with a clear message; nothing else runs, no report."""
    checks["resolve_host"].side_effect = main_module.HostResolutionError("no-such-host.invalid (failed)")
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "no-such-host.invalid")
    assert exc.value.code == 1
    assert "[!] Could not resolve host: no-such-host.invalid (failed)" in capsys.readouterr().out
    for name in ("scan_ports", "check_headers", "check_open_redirect", "check_ssl", "generate_report"):
        checks[name].assert_not_called()


# --- resolve_host: the target is looked up once, in run_scan ------------------


def test_main_resolves_host_exactly_once(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """run_scan looks the name up once, with the host exactly as typed."""
    _run(monkeypatch, "localhost")
    checks["resolve_host"].assert_called_once_with("localhost")


def test_main_progress_line_shows_host_and_resolved_address(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """For a name, the first progress line shows the name and the IP it resolved to."""
    _run(monkeypatch, "localhost")
    assert "[*] Starting scan on localhost (127.0.0.1)\n" in capsys.readouterr().out


def test_main_progress_line_shows_ip_literal_once(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """For an IP target (resolve_host returns it unchanged), the line shows just the IP, not 'IP (IP)'."""
    checks["resolve_host"].return_value = (socket.AF_INET, "192.168.56.101")
    _run(monkeypatch, "192.168.56.101")
    assert "[*] Starting scan on 192.168.56.101\n" in capsys.readouterr().out


def test_main_bad_host_still_exits_2_not_130(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """argparse errors happen outside the try, so they keep exit code 2 and no abort message."""
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "site.com/path")
    assert exc.value.code == 2
    assert "Scan aborted" not in capsys.readouterr().out
