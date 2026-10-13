"""Admin dashboard over HTTP: routing, bearer auth, and live metrics.

Networking concept demonstrated
-------------------------------
**HTTP/1.1 as a second application protocol over TCP.**  These tests speak the
admin plane the same way a browser would -- an ASCII request line + headers,
``CRLF CRLF``, then a body -- proving the hand-rolled server parses real HTTP
and that its metrics reflect the CSCP protocol traffic on the *other* socket.
"""

# ruff: noqa: S106 -- stub admin tokens set for the duration of each test

from __future__ import annotations

import asyncio
import json

import pytest

from protocol.messages import MsgDirect
from server.admin import AdminHttpConfig, AdminHttpServer
from server.config import Config


async def _http(
    port: int,
    target: str,
    *,
    method: str = "GET",
    token: str | None = None,
    host: str = "localhost",
) -> tuple[int, str, bytes]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    req = f"{method} {target} HTTP/1.1\r\nHost: {host}\r\n"
    if token is not None:
        req += f"Authorization: Bearer {token}\r\n"
    req += "\r\n"
    writer.write(req.encode())
    await writer.drain()
    raw = await reader.read()
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001, S110 -- server closes first
        pass
    head, _, body = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    return status, head.decode("latin-1"), body


def _admin_cfg(**kw: object) -> AdminHttpConfig:
    base: dict[str, object] = {"enable": True, "port": 0, "host_v4": "127.0.0.1", "auth_token_env": "CSCP_ADMIN_TOKEN"}
    base.update(kw)
    return AdminHttpConfig.from_mapping(base)


@pytest.mark.asyncio
async def test_admin_http_routes_and_bearer_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CSCP_ADMIN_TOKEN", "s3cr3t")
    admin = AdminHttpServer(_admin_cfg(), lambda: {"connections_total": 3})
    port = await admin.start()
    try:
        # /health is a public liveness probe.
        status, _, body = await _http(port, "/health")
        assert status == 200
        assert json.loads(body)["status"] == "ok"

        # /metrics is protected by the bearer token.
        status, head, _ = await _http(port, "/metrics")
        assert status == 401
        assert "application/json" in head

        status, _, body = await _http(port, "/metrics", token="s3cr3t")
        assert status == 200
        assert json.loads(body)["connections_total"] == 3

        # Wrong token -> still unauthorized.
        assert (await _http(port, "/metrics", token="nope"))[0] == 401

        # The static dashboard shell is public (it carries no data); the page's
        # JavaScript then supplies the bearer token to fetch /metrics.
        status, head, body = await _http(port, "/")
        assert status == 200
        assert "text/html" in head
        assert b"/metrics" in body
        assert "Authorization" in body.decode("latin-1")

        # Method + routing errors.
        assert (await _http(port, "/metrics", method="POST", token="s3cr3t"))[0] == 405
        assert (await _http(port, "/unknown"))[0] == 404
    finally:
        await admin.shutdown()


@pytest.mark.asyncio
async def test_admin_http_rejects_oversized_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CSCP_ADMIN_TOKEN", "t")
    admin = AdminHttpServer(_admin_cfg(), lambda: {})
    port = await admin.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /metrics HTTP/1.1\r\nX-Filler: " + b"a" * 5000 + b"\r\n\r\n")
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(), timeout=5)
        writer.close()
        assert b"431" in raw.split(b"\r\n", 1)[0]
    finally:
        await admin.shutdown()


@pytest.mark.asyncio
async def test_admin_metrics_reflect_cscp_traffic(running_server, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("CSCP_ADMIN_TOKEN", "tok")
    from tests.server.conftest import connect

    server, _port = await running_server(users={"alice": "sa", "bob": "sb"})
    admin = AdminHttpServer(_admin_cfg(), server.summary)
    admin_port = await admin.start()
    try:
        client = await connect(server.listeners[0].server.sockets[0].getsockname()[1])
        auth = await client.handshake("alice", "sa")
        sender = auth.user_id  # "u_alice"
        await client.send(
            MsgDirect(
                msg_id="m-metrics-1",
                sender_id=sender,
                recipient_id="u_bob",
                ciphertext=b"hello",
                ts=0.0,
                reply_to=None,
                ratchet_header=None,
            )
        )
        await asyncio.sleep(0.2)

        status, _, body = await _http(admin_port, "/metrics", token="tok")
        assert status == 200
        snap = json.loads(body)["metrics"]
        assert snap["connections_total"] >= 1
        assert snap["auth_success"] >= 1
        assert snap["messages_direct"] >= 1
        assert snap["bytes_in"] > 0
        await client.close()
    finally:
        await admin.shutdown()


def test_config_parses_admin_section() -> None:
    cfg = Config.from_mapping(
        {
            "tls": {"certfile": "c.pem", "keyfile": "c.key", "ca_file": "ca.pem"},
            "admin": {"enable": True, "port": 1234, "auth_token_env": "MY_TOKEN"},
        }
    )
    assert cfg.admin.enable is True
    assert cfg.admin.port == 1234
    assert cfg.admin.auth_token() is None  # env not set
