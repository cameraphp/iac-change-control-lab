"""Test configuration. Every test runs under a socket guard (SAFE-001)."""

from __future__ import annotations

import socket

import pytest


class NetworkAccessBlocked(RuntimeError):
    """Raised when code under test attempts a network connection."""


def _blocked(*_args, **_kwargs):
    raise NetworkAccessBlocked("network access is blocked in the iac-change-control-lab test suite")


@pytest.fixture(autouse=True, scope="session")
def socket_guard():
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(socket.socket, "connect", _blocked)
        patch.setattr(socket.socket, "connect_ex", _blocked)
        patch.setattr(socket, "create_connection", _blocked)
        patch.setattr(socket, "getaddrinfo", _blocked)
        yield
