"""Tests for main.py - argparse handling and wiring of the checks (every check mocked)."""
import argparse
import builtins
import io
import socket
import sys
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

import main as main_module

# A clean, complete result shaped like redirects.RedirectResults.
REDIRECT_RESULTS = {
    "base_url": "http://localhost", "vulnerable": [], "probes_total": 32,
    "probes_sent": 32, "probes_skipped": 0, "complete": True, "switch_reason": None,
}


@pytest.fixture(autouse=True)
def keep_pytest_streams(request: pytest.FixtureRequest) -> Iterator[None]:
    """Stop main()'s console fix from permanently changing pytest's own capture streams.

    Tests that check the console fix itself (marked by name) still run the real one.
    """
    if "redirected" in request.node.name or "reconfigure" in request.node.name:
        yield
        return
    with patch("main._safe_console"):
        yield


@pytest.fixture(autouse=True)
def fake_signal() -> Iterator[MagicMock]:
    """Never let main() replace pytest's own Ctrl+C handler: record signal.signal calls instead."""
    with patch("main.signal.signal") as fake:
        yield fake


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
        address="127.0.0.1", internal_errors={},
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


REDIRECT_INCOMPLETE = "[!] Redirect check incomplete — see the report for details\n"


def test_main_no_redirect_warning_after_clean_check(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """A complete redirect check with nothing skipped prints no warning line."""
    _run(monkeypatch, "localhost")
    assert "Redirect check incomplete" not in capsys.readouterr().out


def test_main_warns_when_redirect_check_incomplete(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """complete False: the console says so right after the redirect step, before the SSL step."""
    checks["check_open_redirect"].return_value = {**REDIRECT_RESULTS, "complete": False, "probes_sent": 2}
    _run(monkeypatch, "localhost")
    out = capsys.readouterr().out
    assert REDIRECT_INCOMPLETE in out
    assert out.index("[*] Checking for open redirects...") < out.index(REDIRECT_INCOMPLETE)
    assert out.index(REDIRECT_INCOMPLETE) < out.index("[*] Checking SSL/TLS certificate...")


def test_main_warns_when_redirect_probes_skipped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """A complete check where some probes were skipped also gets the warning line."""
    checks["check_open_redirect"].return_value = {**REDIRECT_RESULTS, "probes_skipped": 3}
    _run(monkeypatch, "localhost")
    assert REDIRECT_INCOMPLETE in capsys.readouterr().out


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


ABORT_MESSAGE = "[!] Scan interrupted by keyboard input (Ctrl+C) — stopped early, no report was written"


# --- Ctrl+C: KeyboardInterrupt becomes a clean exit with code 130 -------------


def test_main_ctrl_c_during_port_scan_exits_130_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """Ctrl+C in scan_ports exits 130 with the 'interrupted by keyboard input' message, skips later checks, no traceback."""
    checks["scan_ports"].side_effect = KeyboardInterrupt
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 130
    captured = capsys.readouterr()
    assert ABORT_MESSAGE in captured.out
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
    assert ABORT_MESSAGE in capsys.readouterr().out
    checks["generate_report"].assert_not_called()


def test_main_normal_run_does_not_print_interrupted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """A scan that finishes normally returns without SystemExit and never says it was interrupted."""
    _run(monkeypatch, "localhost")  # would fail the test if SystemExit were raised
    assert "interrupted by keyboard input" not in capsys.readouterr().out


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
    assert "interrupted by keyboard input" not in capsys.readouterr().out


@pytest.mark.parametrize("value", ["fe80::1", "FE80::abcd", "febf::1", "ff02::1", "ff05::2", "224.0.0.1", "239.255.255.250", "255.255.255.255"])
def test_valid_host_rejects_link_local_ipv6(value: str) -> None:
    """fe80::/10 without a zone ID would show every port closed, so it's refused up front."""
    with pytest.raises(argparse.ArgumentTypeError, match="link-local, multicast and broadcast"):
        main_module.valid_host(value)


@pytest.mark.parametrize("value", ["fec0::1", "::1", "2001:db8::1", "169.254.1.1"])
def test_valid_host_accepts_addresses_outside_ipv6_link_local(value: str) -> None:
    """Just outside fe80::/10, loopback, global IPv6 and IPv4 link-local (no zone needed) are fine."""
    assert main_module.valid_host(value) == value


def test_main_link_local_ipv6_exits_2_without_scanning(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]
) -> None:
    """Running main with fe80::1 stops at argparse (exit 2): no lookup, no scan."""
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "fe80::1")
    assert exc.value.code == 2
    checks["resolve_host"].assert_not_called()
    checks["scan_ports"].assert_not_called()


def test_main_redirected_cp1252_stdout_does_not_crash_on_unusual_banner(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]
) -> None:
    """Output saved to a cp1252 file: an unencodable banner prints as '?' instead of crashing."""
    raw = io.BytesIO()
    monkeypatch.setattr("sys.stdout", io.TextIOWrapper(raw, encoding="cp1252"))
    checks["scan_ports"].return_value = [{"port": 22, "banner": "Привет"}]
    _run(monkeypatch, "localhost")
    sys.stdout.flush()
    assert b"Port 22 open" in raw.getvalue()
    assert b"??????" in raw.getvalue()


def test_main_stdout_without_reconfigure_still_runs(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]
) -> None:
    """A stdout replacement without .reconfigure (like StringIO) doesn't break the scan."""
    fake = io.StringIO()
    monkeypatch.setattr("sys.stdout", fake)
    _run(monkeypatch, "localhost")
    assert "Report saved" in fake.getvalue()


def test_main_installs_the_interrupt_once_handler(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock], fake_signal: MagicMock
) -> None:
    """main() installs _interrupt_once for Ctrl+C before the scan starts."""
    _run(monkeypatch, "localhost")
    fake_signal.assert_called_once_with(main_module.signal.SIGINT, main_module._interrupt_once)


def test_interrupt_once_ignores_later_presses_then_stops_the_scan(fake_signal: MagicMock) -> None:
    """The first Ctrl+C switches further presses to "ignore" and then raises KeyboardInterrupt."""
    with pytest.raises(KeyboardInterrupt):
        main_module._interrupt_once(main_module.signal.SIGINT, None)
    fake_signal.assert_called_once_with(main_module.signal.SIGINT, main_module.signal.SIG_IGN)


def test_main_normal_run_leaves_ctrl_c_alone(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock], fake_signal: MagicMock
) -> None:
    """A scan that isn't interrupted only installs the handler; it never switches to "ignore"."""
    _run(monkeypatch, "localhost")
    assert (main_module.signal.SIGINT, main_module.signal.SIG_IGN) not in [c.args for c in fake_signal.call_args_list]


# --- Safety net: a bug in one check doesn't lose the rest, but stays loud ---------


def test_main_internal_error_in_one_check_still_runs_the_others(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """check_ssl crashes with a bug: headers/redirects still run, the report is written, exit code 3."""
    checks["check_ssl"].side_effect = ValueError("boom")
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 3
    checks["check_headers"].assert_called_once()
    checks["check_open_redirect"].assert_called_once()
    kwargs = checks["generate_report"].call_args.kwargs
    args = checks["generate_report"].call_args.args
    assert args[4] is None                                  # ssl_results: the check didn't produce any
    assert "ValueError: boom" in kwargs["internal_errors"]["ssl"]
    out = capsys.readouterr().out
    assert "[!] Internal error in the SSL/TLS check: ValueError: boom" in out
    assert "please report it" in out
    assert out.index("Report saved") < out.index("1 check(s) hit an internal error")


def test_main_internal_error_in_port_scan_does_not_crash_the_banner_loop(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]
) -> None:
    """scan_ports crashing gives open_ports None; the console loop copes and the report is written."""
    checks["scan_ports"].side_effect = RuntimeError("bug")
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 3
    checks["generate_report"].assert_called_once()
    assert "ports" in checks["generate_report"].call_args.kwargs["internal_errors"]


def test_main_internal_error_in_redirect_check_skips_its_console_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """A crashed redirect check (None result) doesn't trip the 'incomplete' console line."""
    checks["check_open_redirect"].side_effect = KeyError("x")
    with pytest.raises(SystemExit):
        _run(monkeypatch, "localhost")
    out = capsys.readouterr().out
    assert "Redirect check incomplete" not in out
    assert "Internal error in the redirect check: KeyError" in out


def test_main_ctrl_c_inside_a_check_is_not_swallowed_by_the_safety_net(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]
) -> None:
    """Ctrl+C during a check still aborts the scan (exit 130) instead of counting as a bug."""
    checks["check_headers"].side_effect = KeyboardInterrupt
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 130
    checks["generate_report"].assert_not_called()


def test_main_internal_error_message_is_cleaned(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """An error message carrying server text can't put escape codes or fake lines on the console."""
    checks["check_headers"].side_effect = ValueError("evil\x1b[2J\n[+] Port 1 open")
    with pytest.raises(SystemExit):
        _run(monkeypatch, "localhost")
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\n[+] Port 1 open" not in out


def test_main_two_internal_errors_exit_3_with_one_report(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock], capsys: pytest.CaptureFixture[str]
) -> None:
    """Two checks hit bugs: one report is still written, the console counts both, exit code 3."""
    checks["check_headers"].side_effect = ValueError("bug one")
    checks["check_ssl"].side_effect = RuntimeError("bug two")
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 3
    checks["generate_report"].assert_called_once()
    assert set(checks["generate_report"].call_args.kwargs["internal_errors"]) == {"headers", "ssl"}
    assert "2 check(s) hit an internal error" in capsys.readouterr().out


# --- Report can't be saved (exit 4) and catch-all for bugs (exit 5) ---------------


def test_main_report_permission_denied_exits_4_with_clear_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """A PermissionError while writing the report exits 4 with a save message, not a traceback or 'bug'."""
    checks["generate_report"].side_effect = PermissionError(13, "Permission denied", "report_x.txt.tmp")
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 4
    captured = capsys.readouterr()
    assert "[!] Could not save the report:" in captured.out
    assert "Permission denied" in captured.out
    assert "please report it" not in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err


def test_main_report_disk_full_exits_4(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]
) -> None:
    """Any OSError from the reporter (here: disk full) is a save failure, exit 4."""
    checks["generate_report"].side_effect = OSError(28, "No space left on device")
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 4


def test_main_unexpected_bug_outside_checks_exits_5_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """A bug in resolve_host (outside the per-check safety net) exits 5 with a one-line message."""
    checks["resolve_host"].side_effect = RuntimeError("bug")
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 5
    captured = capsys.readouterr()
    assert "[!] Internal error: RuntimeError: bug" in captured.out
    assert "please report it" in captured.out
    assert "The scan stopped" in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    for name in ("scan_ports", "check_headers", "check_open_redirect", "check_ssl", "generate_report"):
        checks[name].assert_not_called()


def test_main_non_oserror_bug_in_reporter_exits_5_not_4(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]
) -> None:
    """Only OSError counts as 'could not save'; a KeyError in the reporter is a bug (exit 5)."""
    checks["generate_report"].side_effect = KeyError("x")
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 5


def test_main_catch_all_error_message_is_cleaned(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """The exit-5 message can't put escape codes or fake result lines on the console."""
    checks["resolve_host"].side_effect = RuntimeError("evil\x1b[2J\n[+] Port 1 open")
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 5
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert not any(line.startswith("[+] Port 1 open") for line in out.splitlines())


def test_main_ctrl_c_while_saving_report_exits_130(
    monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]
) -> None:
    """Ctrl+C during generate_report is still a Ctrl+C (130), not a save failure or a bug."""
    checks["generate_report"].side_effect = KeyboardInterrupt
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 130


def test_main_system_exit_passes_through_the_catch_all(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """SystemExit is not an Exception, so its own code survives and no 'Internal error' is printed."""
    checks["resolve_host"].side_effect = SystemExit(7)
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 7
    assert "Internal error" not in capsys.readouterr().out


def test_main_bug_inside_one_check_still_exits_3_not_5(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """The per-check safety net still handles check bugs (3); the catch-all (5) is not reached."""
    checks["check_ssl"].side_effect = ValueError("boom")
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 3
    assert "[!] Internal error:" not in capsys.readouterr().out   # the exit-5 wording


# --- Stopped after the report was saved: the console says the file exists ------------

ALREADY_SAVED = "the report was already saved: "


def _fail_on_report_saved(monkeypatch: pytest.MonkeyPatch, error: BaseException) -> None:
    """Make main.py's print raise `error` on the "[+] Report saved" line; other lines print normally.

    This simulates something going wrong in the gap right after generate_report returned.
    """
    real_print = builtins.print

    def fake_print(*args: object, **kwargs: object) -> None:
        if args and str(args[0]).startswith("[+] Report saved"):
            raise error
        real_print(*args, **kwargs)

    monkeypatch.setattr(main_module, "print", fake_print, raising=False)


def test_main_ctrl_c_after_report_saved_says_report_was_saved(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """Ctrl+C just after the report is written: exit 130 and the message names the saved file."""
    checks["generate_report"].return_value = "report_localhost_20261017.txt"
    _fail_on_report_saved(monkeypatch, KeyboardInterrupt())
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 130
    out = capsys.readouterr().out
    assert ALREADY_SAVED + "report_localhost_20261017.txt" in out
    assert "no report was written" not in out


def test_main_ctrl_c_inside_generate_report_says_no_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """Ctrl+C while the report is still being written: the file isn't confirmed, so the usual message."""
    checks["generate_report"].side_effect = KeyboardInterrupt
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 130
    out = capsys.readouterr().out
    assert ABORT_MESSAGE in out
    assert ALREADY_SAVED not in out


def test_main_ctrl_c_after_saving_with_check_error_exits_130_not_3(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """A check bug would mean exit 3, but Ctrl+C after saving wins: exit 130, 'already saved'."""
    checks["check_ssl"].side_effect = ValueError("boom")
    _fail_on_report_saved(monkeypatch, KeyboardInterrupt())
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 130
    assert ALREADY_SAVED + "report.txt" in capsys.readouterr().out


def test_main_bug_after_report_saved_exits_5_and_says_report_was_saved(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """A bug after the file is written still exits 5, but tells the user the report exists."""
    _fail_on_report_saved(monkeypatch, RuntimeError("late bug"))
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 5
    out = capsys.readouterr().out
    assert "[!] Internal error: RuntimeError: late bug" in out
    assert "The scan stopped, but the report was already saved: report.txt." in out
    assert "no report was written" not in out


def test_main_bug_before_report_saved_exits_5_and_says_no_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """A bug before anything is written (resolve_host) exits 5 and says no report was written."""
    checks["resolve_host"].side_effect = RuntimeError("bug")
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost")
    assert exc.value.code == 5
    out = capsys.readouterr().out
    assert "The scan stopped; no report was written." in out
    assert ALREADY_SAVED not in out
