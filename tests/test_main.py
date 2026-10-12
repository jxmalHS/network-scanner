"""Tests for main.py - argparse handling and wiring of the checks (every check mocked)."""
import argparse
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

import main as main_module


@pytest.fixture
def checks() -> Iterator[dict[str, MagicMock]]:
    """Replace every check and the reporter inside main.py with mocks."""
    with (
        patch("main.scan_ports", return_value=[]) as scan_ports,
        patch("main.check_headers", return_value={"present": [], "missing": []}) as check_headers,
        patch("main.check_open_redirect", return_value=[]) as check_open_redirect,
        patch("main.check_ssl", return_value={"error": "refused"}) as check_ssl,
        patch("main.generate_report", return_value="report.txt") as generate_report,
    ):
        yield {
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
    checks["scan_ports"].assert_called_once_with("localhost", main_module.COMMON_PORTS, 20)


def test_main_parses_ports_as_ints(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """--ports 22 80 is parsed into the integer list [22, 80]."""
    _run(monkeypatch, "localhost", "--ports", "22", "80")
    checks["scan_ports"].assert_called_once_with("localhost", [22, 80], 20)


def test_main_rejects_non_integer_port(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """A non-numeric port makes argparse exit with code 2 before any scan runs."""
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, "localhost", "--ports", "http")
    assert exc.value.code == 2
    checks["scan_ports"].assert_not_called()


def test_main_requires_host(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """Running with no host makes argparse exit with code 2."""
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch)
    assert exc.value.code == 2


def test_main_passes_all_results_to_reporter(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """Every check's result is handed to generate_report in order."""
    _run(monkeypatch, "localhost")
    checks["generate_report"].assert_called_once_with(
        "localhost", [], {"present": [], "missing": []}, [], {"error": "refused"}
    )


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


def test_main_prints_security_headers_progress(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], checks: dict[str, MagicMock]
) -> None:
    """The header step announces itself as 'security headers' (no longer 'HTTP')."""
    _run(monkeypatch, "localhost")
    assert "[*] Checking security headers...\n" in capsys.readouterr().out


# --- valid_host: which targets argparse accepts ------------------------------

GOOD_HOSTS = ["localhost", "scanme.nmap.org", "192.168.56.101", "::1"]
BAD_HOSTS = ["site.com@other.com", "site.com/path", "host:8080", "a b", ""]


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
    checks["scan_ports"].assert_called_once_with("localhost", [80], 50)


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
    checks["scan_ports"].assert_called_once_with("localhost", [80], int(value))


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
