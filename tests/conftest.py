"""Shared pytest setup: make project modules importable and block real network access."""
import socket
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

# The modules (scanner.py, headers.py, ...) live in the project root, one level up.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Every way the code under test could reach the network: opening a connection,
# sending a UDP packet, or resolving a hostname (a DNS lookup is network traffic too).
# gethostname() is deliberately NOT blocked - it only reads this machine's own name.
_BLOCKED_SOCKET_METHODS = ("connect", "connect_ex", "sendto")
_BLOCKED_SOCKET_FUNCTIONS = (
    "create_connection",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
)


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail any test that tries to use the real network, even if the error is swallowed.

    Each blocked call raises RuntimeError AND is recorded in ``attempts``. Raising
    stops the traffic; recording matters because scanner modules wrap network code
    in ``except Exception`` and would otherwise hide the RuntimeError, letting a
    test with a forgotten mock pass silently. After the test, the fixture asserts
    that nothing was recorded.
    """
    attempts: list[str] = []

    def make_blocker(name: str) -> Callable[..., None]:
        def blocker(*args: object, **kwargs: object) -> None:
            attempts.append(f"{name}{args!r}")
            raise RuntimeError(f"Real network access ({name}) attempted in a test - mock it instead.")

        return blocker

    for name in _BLOCKED_SOCKET_METHODS:
        monkeypatch.setattr(socket.socket, name, make_blocker(f"socket.{name}"))
    for name in _BLOCKED_SOCKET_FUNCTIONS:
        monkeypatch.setattr(socket, name, make_blocker(name))

    yield  # the test runs here

    assert not attempts, f"Test tried to use the real network (mock missing?): {attempts}"
