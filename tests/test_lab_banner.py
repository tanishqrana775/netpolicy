"""Unit tests for the lab banner listener (lab/banner_servers.py)."""

from __future__ import annotations

import socket

from lab.banner_servers import BANNERS, BannerListener, MultiBannerServer


def test_banner_listener_connect_and_receive() -> None:
    # Use ephemeral port
    listener = BannerListener("127.0.0.1", 0, banner=b"220 test banner\r\n")
    listener.start()
    assert listener.sock is not None
    port = listener.sock.getsockname()[1]

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2.0)
        client.connect(("127.0.0.1", port))
        received = client.recv(1024)
        client.close()
        assert received == b"220 test banner\r\n"
    finally:
        listener.stop()


def test_banner_defaults_contain_required_ports() -> None:
    required_ports = {21, 22, 25, 443, 587}
    assert required_ports.issubset(BANNERS.keys())
    assert b"SSH" in BANNERS[22]
    assert b"ESMTP" in BANNERS[25]
    assert b"Submission" in BANNERS[587]
    assert b"FTP" in BANNERS[21]
    assert b"200 OK" in BANNERS[443]


def test_multi_banner_server_init() -> None:
    server = MultiBannerServer("127.0.0.1", [21, 22])
    assert len(server.listeners) == 2
