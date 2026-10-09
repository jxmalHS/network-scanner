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
    checks["scan_ports"].assert_called_once_with("localhost", main_module.COMMON_PORTS)


def test_main_parses_ports_as_ints(monkeypatch: pytest.MonkeyPatch, checks: dict[str, MagicMock]) -> None:
    """--ports 22 80 is parsed into the integer list [22, 80]."""
    _run(monkeypatch, "localhost", "--ports", "22", "80")
    checks["scan_ports"].assert_called_once_with("localhost", [22, 80])


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
