from __future__ import annotations

import os
import socket
import sys

import pytest

from product.clients import runtime_handoff as rh

_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
    "   uid  timeout inode\n"
)
_TCP = _HEADER + (
    "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
    "  1000        0 11111 1 0000000000000000 100 0 0 10 0\n"
    "   1: 0100007F:1F90 0100007F:D2A0 01 00000000:00000000 00:00000000 00000000"
    "  1000        0 22222 1 0000000000000000 100 0 0 10 0\n"
    "   2: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
    "  1000        0 33333 1 0000000000000000 100 0 0 10 0\n"
)
_TCP6 = _HEADER + (
    "   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A"
    " 00000000:00000000 00:00000000 00000000  1000        0 44444 1 0000000000000000"
    " 100 0 0 10 0\n"
)


def test_parse_proc_net_tcp_selects_only_listen_rows_for_port() -> None:
    assert rh._parse_proc_net_tcp_listen_inodes(_TCP, 8080) == {11111}
    assert rh._parse_proc_net_tcp_listen_inodes(_TCP, 80) == {33333}
    assert rh._parse_proc_net_tcp_listen_inodes(_TCP, 9999) == set()


def test_parse_proc_net_tcp6_format() -> None:
    assert rh._parse_proc_net_tcp_listen_inodes(_TCP6, 8080) == {44444}


def test_parse_ignores_malformed_rows() -> None:
    assert rh._parse_proc_net_tcp_listen_inodes(_HEADER + "garbage\n", 8080) == set()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="procfs is Linux-only")
def test_procfs_finds_pid_of_listening_socket() -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        assert rh._find_pid_for_port_procfs(port) == os.getpid()
    assert rh._find_pid_for_port_procfs(port) is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="procfs is Linux-only")
def test_find_pid_uses_procfs_when_lsof_is_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rh.shutil, "which", lambda name, *a, **k: None)
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        assert rh._find_pid_for_port(server.getsockname()[1]) == os.getpid()


def test_find_pid_falls_back_to_procfs_helper_when_lsof_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rh.shutil, "which", lambda name, *a, **k: None)
    monkeypatch.setattr(rh.sys, "platform", "linux")
    monkeypatch.setattr(rh, "_find_pid_for_port_procfs", lambda port: 4242)
    assert rh._find_pid_for_port(1234) == 4242


def test_find_pid_does_not_use_procfs_when_lsof_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rh.shutil, "which", lambda name, *a, **k: "/usr/bin/lsof")
    monkeypatch.setattr(rh, "_find_pid_for_port_procfs", lambda port: 1)

    class _Done:
        returncode = 0
        stdout = "77\n"

    monkeypatch.setattr(rh.subprocess, "run", lambda *a, **k: _Done())
    assert rh._find_pid_for_port(1234) == 77


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="procfs is Linux-only")
def test_process_helpers_fall_back_to_procfs_without_ps(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_ps(*a: object, **k: object) -> None:
        raise FileNotFoundError("ps")

    monkeypatch.setattr(rh.subprocess, "run", no_ps)
    assert (rh._get_process_start_time(os.getpid()) or "").startswith("procfs-starttime-ticks:")
    assert rh._get_process_executable(os.getpid())
