"""Tests for scanner.py - TCP connect scan and banner grabbing (socket fully mocked)."""
import socket
from unittest.mock import MagicMock, patch

import pytest

import scanner


def _fake_socket(connect_result: int, recv: bytes | BaseException = b"") -> MagicMock:
    """Build a stand-in socket whose connect_ex/recv return what the test needs."""
    sock = MagicMock()
    # Behave like a real socket in a `with` block: enter returns itself, exit closes it.
    def _exit(*exc_info: object) -> bool:
        sock.close()
        return False  # False = don't swallow the exception, like a real socket

    sock.__enter__.return_value = sock
    sock.__exit__.side_effect = _exit
    sock.connect_ex.return_value = connect_result
    if isinstance(recv, BaseException):
        sock.recv.side_effect = recv
    else:
        sock.recv.return_value = recv
    return sock


def test_scan_port_open_returns_true_and_banner() -> None:
    """An open port (connect_ex == 0) reports True plus the stripped, decoded banner."""
    sock = _fake_socket(0, b"HTTP/1.0 200 OK\r\nServer: nginx\r\n\r\n")
    with patch("scanner.socket.socket", return_value=sock):
        assert scanner.scan_port("127.0.0.1", 80) == (True, "HTTP/1.0 200 OK\r\nServer: nginx")


def test_scan_port_sends_http_head_probe_to_open_port() -> None:
    """On an open port the scanner sends a HEAD request to coax out a banner."""
    sock = _fake_socket(0, b"x")
    with patch("scanner.socket.socket", return_value=sock):
        scanner.scan_port("127.0.0.1", 80)
    sock.send.assert_called_once_with(b"HEAD / HTTP/1.0\r\n\r\n")


def test_scan_port_closed_returns_false_and_no_banner() -> None:
    """A refused connection (non-zero connect_ex) reports (False, None)."""
    sock = _fake_socket(10061)
    with patch("scanner.socket.socket", return_value=sock):
        assert scanner.scan_port("127.0.0.1", 81) == (False, None)


def test_scan_port_closed_does_not_send_probe() -> None:
    """Nothing is sent to a closed port."""
    sock = _fake_socket(10061)
    with patch("scanner.socket.socket", return_value=sock):
        scanner.scan_port("127.0.0.1", 81)
    sock.send.assert_not_called()


def test_scan_port_open_but_silent_returns_none_banner() -> None:
    """If reading the banner times out, the port is still open with banner None."""
    sock = _fake_socket(0, TimeoutError("timed out"))
    with patch("scanner.socket.socket", return_value=sock):
        assert scanner.scan_port("127.0.0.1", 22) == (True, None)


def test_scan_port_open_but_reset_returns_none_banner() -> None:
    """If the peer resets the connection while we send, the port is still open with banner None."""
    sock = _fake_socket(0)
    sock.send.side_effect = ConnectionResetError("reset")
    with patch("scanner.socket.socket", return_value=sock):
        assert scanner.scan_port("127.0.0.1", 22) == (True, None)


def test_scan_port_keyboard_interrupt_propagates() -> None:
    """Ctrl+C during the banner grab is not swallowed; it escapes scan_port."""
    sock = _fake_socket(0, KeyboardInterrupt())
    with patch("scanner.socket.socket", return_value=sock):
        with pytest.raises(KeyboardInterrupt):
            scanner.scan_port("127.0.0.1", 80)


def test_scan_port_empty_reply_gives_empty_string_banner() -> None:
    """A port that closes without sending data yields an empty-string banner."""
    sock = _fake_socket(0, b"")
    with patch("scanner.socket.socket", return_value=sock):
        assert scanner.scan_port("127.0.0.1", 80) == (True, "")


def test_scan_port_ignores_undecodable_bytes() -> None:
    """Non-UTF-8 bytes in the banner are dropped rather than raising."""
    sock = _fake_socket(0, b"SSH-2.0\xff\xfe")
    with patch("scanner.socket.socket", return_value=sock):
        assert scanner.scan_port("127.0.0.1", 22) == (True, "SSH-2.0")


def test_scan_port_connects_to_given_host_and_port() -> None:
    """The host and port passed in are handed to connect_ex as one (host, port) tuple."""
    sock = _fake_socket(10061)
    with patch("scanner.socket.socket", return_value=sock):
        scanner.scan_port("127.0.0.1", 80)
    sock.connect_ex.assert_called_once_with(("127.0.0.1", 80))


def test_scan_port_uses_one_second_timeout() -> None:
    """The socket timeout is set to 1 second."""
    sock = _fake_socket(10061)
    with patch("scanner.socket.socket", return_value=sock):
        scanner.scan_port("127.0.0.1", 80)
    sock.settimeout.assert_called_once_with(1)


def test_scan_port_closes_socket_when_open() -> None:
    """The socket is closed after scanning an open port."""
    sock = _fake_socket(0, b"x")
    with patch("scanner.socket.socket", return_value=sock):
        scanner.scan_port("127.0.0.1", 80)
    sock.close.assert_called_once()


def test_scan_port_closes_socket_when_closed() -> None:
    """The socket is closed after scanning a closed port."""
    sock = _fake_socket(10061)
    with patch("scanner.socket.socket", return_value=sock):
        scanner.scan_port("127.0.0.1", 80)
    sock.close.assert_called_once()


def test_scan_port_closes_socket_on_keyboard_interrupt() -> None:
    """Ctrl+C during the banner grab still closes the socket (backlog #10)."""
    sock = _fake_socket(0, KeyboardInterrupt())
    with patch("scanner.socket.socket", return_value=sock):
        with pytest.raises(KeyboardInterrupt):
            scanner.scan_port("127.0.0.1", 80)
    sock.close.assert_called_once()


def test_scan_ports_returns_only_open_ports_with_banners() -> None:
    """scan_ports keeps open ports (with their banners) and drops closed ones, in order."""
    results = {22: (True, "SSH-2.0-OpenSSH"), 23: (False, None), 80: (True, None)}
    with patch("scanner.scan_port", side_effect=lambda host, port: results[port]):
        assert scanner.scan_ports("127.0.0.1", [22, 23, 80]) == [
            {"port": 22, "banner": "SSH-2.0-OpenSSH"},
            {"port": 80, "banner": None},
        ]


def test_scan_ports_all_closed_returns_empty_list() -> None:
    """When every port is closed the result is an empty list."""
    with patch("scanner.scan_port", return_value=(False, None)):
        assert scanner.scan_ports("127.0.0.1", [21, 22]) == []


def test_scan_ports_empty_port_list_returns_empty_list() -> None:
    """An empty port list scans nothing and returns []."""
    with patch("scanner.scan_port") as fake:
        assert scanner.scan_ports("127.0.0.1", []) == []
    fake.assert_not_called()


@pytest.mark.xfail(
    strict=True,
    raises=socket.gaierror,
    reason="backlog item 12: connect_ex is outside the try, so an unresolvable host crashes the scan",
)
def test_scan_ports_unresolvable_host_does_not_crash() -> None:
    """A host name that DNS can't resolve should give 'no open ports', not an exception."""
    sock = _fake_socket(0)
    sock.connect_ex.side_effect = socket.gaierror(11001, "getaddrinfo failed")
    with patch("scanner.socket.socket", return_value=sock):
        assert scanner.scan_ports("no-such-host.invalid", [80]) == []
