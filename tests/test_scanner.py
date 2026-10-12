"""Tests for scanner.py - TCP connect scan and banner grabbing (socket fully mocked)."""
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
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


# --- scan_ports concurrency (backlog #7) --------------------------------------


class RecordingExecutor(ThreadPoolExecutor):
    """A real ThreadPoolExecutor that also remembers how it was created and shut down."""

    instances: list["RecordingExecutor"] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.init_args = args
        self.init_kwargs = kwargs
        self.shutdown_calls: list[dict[str, Any]] = []
        RecordingExecutor.instances.append(self)
        super().__init__(*args, **kwargs)

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        self.shutdown_calls.append({"wait": wait, "cancel_futures": cancel_futures})
        super().shutdown(wait=wait, cancel_futures=cancel_futures)


@pytest.fixture
def recording_executor() -> Any:
    """Swap scanner's ThreadPoolExecutor for RecordingExecutor during one test."""
    RecordingExecutor.instances = []
    with patch("scanner.ThreadPoolExecutor", RecordingExecutor):
        yield RecordingExecutor


def test_scan_ports_keeps_port_order_when_later_ports_finish_first() -> None:
    """Results follow the input port order even if higher ports finish scanning earlier."""
    finished: list[int] = []
    delays = {1: 0.06, 2: 0.03, 3: 0.0}  # port 1 is the slowest, port 3 the fastest

    def slow_for_low_ports(host: str, port: int) -> tuple[bool, str]:
        time.sleep(delays[port])
        finished.append(port)
        return True, f"banner-{port}"

    with patch("scanner.scan_port", side_effect=slow_for_low_ports):
        result = scanner.scan_ports("127.0.0.1", [1, 2, 3], workers=3)

    assert finished[-1] == 1  # sanity check: port 1 really did finish last
    assert result == [
        {"port": 1, "banner": "banner-1"},
        {"port": 2, "banner": "banner-2"},
        {"port": 3, "banner": "banner-3"},
    ]


def test_scan_ports_creates_pool_with_given_workers(recording_executor: Any) -> None:
    """scan_ports(..., workers=7) builds the thread pool with max_workers=7."""
    with patch("scanner.scan_port", return_value=(False, None)):
        scanner.scan_ports("127.0.0.1", [80], workers=7)
    assert len(recording_executor.instances) == 1
    assert recording_executor.instances[0].init_kwargs == {"max_workers": 7}


def test_scan_ports_default_workers_is_20(recording_executor: Any) -> None:
    """Without a workers argument the pool gets max_workers=20 (DEFAULT_WORKERS)."""
    with patch("scanner.scan_port", return_value=(False, None)):
        scanner.scan_ports("127.0.0.1", [80])
    assert scanner.DEFAULT_WORKERS == 20
    assert recording_executor.instances[0].init_kwargs == {"max_workers": 20}


def test_scan_ports_runs_scans_at_the_same_time() -> None:
    """With 2 workers, two scans are in progress at once (both reach the barrier together)."""
    barrier = threading.Barrier(2, timeout=2)  # timeout guards against hanging forever

    def wait_for_partner(host: str, port: int) -> tuple[bool, None]:
        barrier.wait()  # only returns once BOTH scans are waiting here
        return True, None

    with patch("scanner.scan_port", side_effect=wait_for_partner):
        result = scanner.scan_ports("127.0.0.1", [22, 80], workers=2)
    assert result == [{"port": 22, "banner": None}, {"port": 80, "banner": None}]


def test_scan_ports_one_worker_scans_one_port_at_a_time() -> None:
    """With 1 worker the second scan never starts while the first waits, so the barrier breaks."""
    barrier = threading.Barrier(2, timeout=0.2)  # short timeout: this test expects it to expire

    def wait_for_partner(host: str, port: int) -> tuple[bool, None]:
        barrier.wait()
        return True, None

    with patch("scanner.scan_port", side_effect=wait_for_partner):
        with pytest.raises(threading.BrokenBarrierError):
            scanner.scan_ports("127.0.0.1", [22, 80], workers=1)


def test_scan_ports_propagates_exception_from_scan_port() -> None:
    """An error inside a worker thread (e.g. DNS failure) is re-raised to the caller."""
    error = socket.gaierror(11001, "getaddrinfo failed")
    with patch("scanner.scan_port", side_effect=error):
        with pytest.raises(socket.gaierror):
            scanner.scan_ports("no-such-host.invalid", [80, 443], workers=2)


def test_scan_ports_keyboard_interrupt_stops_remaining_scans() -> None:
    """Ctrl+C on the first port escapes scan_ports and the queued ports are dropped, not scanned."""
    calls: list[int] = []

    def interrupt_first(host: str, port: int) -> tuple[bool, None]:
        calls.append(port)
        if port == 1:
            raise KeyboardInterrupt
        time.sleep(0.05)  # keep later scans slow so cancelling clearly wins the race
        return False, None

    with patch("scanner.scan_port", side_effect=interrupt_first):
        with pytest.raises(KeyboardInterrupt):
            scanner.scan_ports("127.0.0.1", list(range(1, 11)), workers=1)
    assert calls[0] == 1
    assert len(calls) <= 3  # far fewer than all 10 ports


def test_scan_ports_shuts_pool_down_with_cancel_futures_on_success(recording_executor: Any) -> None:
    """Even when nothing goes wrong, the pool is shut down once with wait=True, cancel_futures=True."""
    with patch("scanner.scan_port", return_value=(True, None)):
        scanner.scan_ports("127.0.0.1", [22, 80], workers=2)
    assert recording_executor.instances[0].shutdown_calls == [{"wait": True, "cancel_futures": True}]


def test_scan_ports_shuts_pool_down_when_scan_port_fails(recording_executor: Any) -> None:
    """If a scan raises, the finally block still shuts the pool down with cancel_futures=True."""
    with patch("scanner.scan_port", side_effect=OSError("boom")):
        with pytest.raises(OSError):
            scanner.scan_ports("127.0.0.1", [22], workers=1)
    assert recording_executor.instances[0].shutdown_calls == [{"wait": True, "cancel_futures": True}]


def test_scan_ports_zero_workers_raises_value_error() -> None:
    """workers=0 is rejected by ThreadPoolExecutor itself - why main.py validates --workers first."""
    with patch("scanner.scan_port") as fake:
        with pytest.raises(ValueError):
            scanner.scan_ports("127.0.0.1", [80], workers=0)
    fake.assert_not_called()
