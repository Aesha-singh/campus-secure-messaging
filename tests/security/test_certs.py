"""PKI generation + real TLS 1.3 mTLS handshake over a loopback socket.

This is the closest we can get to a live TLS negotiation in-process: a server
(``PROTOCOL_TLS_SERVER``) demanding a client certificate, and clients that
either present one (success) or not (handshake must fail).
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import threading
from pathlib import Path

import pytest

from security.certs import (
    TLSMaterial,
    ensure_ca,
    ensure_leaf,
    load_tls_client_context,
    load_tls_server_context,
)


@pytest.fixture()
def pki(tmp_path: Path) -> Path:
    ca_key, ca_pem = ensure_ca(tmp_path)
    ensure_leaf(
        tmp_path,
        ca_key=ca_key,
        ca_cert=ca_pem,
        common_name="server.test",
        dns_names=["localhost"],
        ip_addresses=["127.0.0.1", "::1"],
        kind="server",
        stem="server",
    )
    ensure_leaf(
        tmp_path,
        ca_key=ca_key,
        ca_cert=ca_pem,
        common_name="client.test",
        dns_names=[],
        ip_addresses=[],
        kind="client",
        stem="cscp-client",
    )
    return tmp_path


async def _echo_server(sslctx: ssl.SSLContext, *, authfail_fixture: bool = False):  # noqa: FBT002
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(1024)
        writer.write(data[::-1])
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=sslctx)
    port = next(iter(server.sockets)).getsockname()[1]  # type: ignore[union-attr]
    return server, port


async def _probe(port: int, ctx: ssl.SSLContext) -> str:
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=ctx, server_hostname="localhost"
    )
    sslobj = writer.get_extra_info("ssl_object")
    writer.write(b"hello")
    await writer.drain()
    data = await reader.read(1024)
    writer.close()
    await writer.wait_closed()
    return data, sslobj.version() if sslobj else ""


@pytest.mark.asyncio
async def test_mtls_handshake_with_client_cert(pki: Path) -> None:
    server_ctx = load_tls_server_context(TLSMaterial.from_dir(pki, peer="server"), require_client_cert=True)
    client_ctx = load_tls_client_context(TLSMaterial.from_dir(pki, peer="cscp-client"))
    server, port = await _echo_server(server_ctx)
    try:
        data, version = await _probe(port, client_ctx)
        assert data == b"olleh"
        assert version == "TLSv1.3"
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_handshake_rejected_without_client_cert(pki: Path) -> None:
    """mTLS: a client presenting no certificate must be refused.

    With asyncio the rejection surfaces only once the app reads, so we assert
    on *blocking* sockets (deterministic: OpenSSL enforces CERT_REQUIRED during
    the server-side handshake, and `PEER_DID_NOT_RETURN_A_CERTIFICATE` fires).
    """

    server_ctx = load_tls_server_context(TLSMaterial.from_dir(pki, peer="server"), require_client_cert=True)
    # Client that pins the CA but presents NO client certificate.
    naked = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    naked.verify_mode = ssl.CERT_REQUIRED
    naked.load_verify_locations(cafile=str(TLSMaterial.from_dir(pki, peer="server").ca_pem))
    naked.minimum_version = ssl.TLSVersion.TLSv1_3

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    server_failure: list[BaseException] = []

    def serve() -> None:
        conn, _ = srv.accept()
        try:
            with server_ctx.wrap_socket(conn, server_side=True) as sc:  # type: ignore[union-attr]
                sc.recv(4)
        except Exception as exc:  # noqa: BLE001 -- the point of this test
            server_failure.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = socket.socket()
    client.connect(("127.0.0.1", port))
    try:
        # TLS 1.3: the client's own handshake completes first; the server rejects
        # the missing certificate afterwards (PEER_DID_NOT_RETURN_A_CERTIFICATE).
        wrapped = naked.wrap_socket(client, server_hostname="localhost")
        wrapped.send(b"hi")
        with pytest.raises((ssl.SSLError, ConnectionResetError, OSError)):
            while wrapped.recv(64):
                continue
    except (ssl.SSLError, ConnectionResetError, OSError):
        pass  # server aborted before we even wrote -- equally correct
    finally:
        client.close()
        srv.close()
        thread.join(timeout=5)

    assert server_failure  # the server ALSO rejected the bare peer
    assert any("certificate" in str(e).lower() for e in server_failure)


@pytest.mark.asyncio
async def test_server_rejects_wrong_ca(tmp_path_factory: pytest.TempPathFactory) -> None:
    """A client trusting a *different* CA must not even reach the app bytes."""

    evil = tmp_path_factory.mktemp("evil-ca")
    ensure_ca(evil)
    evil_key, evil_ca = ensure_ca(evil)
    ensure_leaf(
        evil, ca_key=evil_key, ca_cert=evil_ca,
        common_name="client.evil", dns_names=[], ip_addresses=[], kind="client", stem="cscp-client",
    )
    evil_material = TLSMaterial.from_dir(evil, peer="cscp-client")
    honest = tmp_path_factory.mktemp("honest-ca")
    ca_key, ca_pem = ensure_ca(honest)
    ensure_leaf(
        honest, ca_key=ca_key, ca_cert=ca_pem,
        common_name="server.test", dns_names=["localhost"], ip_addresses=["127.0.0.1"],
        kind="server", stem="server",
    )
    ensure_leaf(
        honest, ca_key=ca_key, ca_cert=ca_pem,
        common_name="client.test", dns_names=[], ip_addresses=[], kind="client", stem="cscp-client",
    )
    server_ctx = load_tls_server_context(TLSMaterial.from_dir(honest, peer="server"), require_client_cert=True)
    # evil-material client -> server's trust store rejects it (blocking sockets).
    import ssl

    evil_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    evil_ctx.verify_mode = ssl.CERT_REQUIRED
    evil_ctx.load_verify_locations(cafile=str(evil_material.ca_pem))
    evil_ctx.load_cert_chain(certfile=str(evil_material.cert_pem), keyfile=str(evil_material.key_pem))
    evil_ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    server_errors: list[BaseException] = []

    def serve_wrong_ca_peer() -> None:
        conn, _ = srv.accept()
        try:
            with server_ctx.wrap_socket(conn, server_side=True) as sc:  # type: ignore[union-attr]
                sc.recv(4)
        except Exception as exc:  # noqa: BLE001 -- the point of this test
            server_errors.append(exc)

    thread = threading.Thread(target=serve_wrong_ca_peer, daemon=True)
    thread.start()
    client = socket.socket()
    client.connect(("127.0.0.1", port))
    with pytest.raises((ssl.SSLError, ConnectionResetError, OSError)):
        evil_ctx.wrap_socket(client, server_hostname="localhost")
    client.close()
    srv.close()
    thread.join(timeout=5)
    assert server_errors  # the honest server rejected the evil-CA client cert


def test_leaf_eku_and_sans(pki: Path) -> None:
    from cryptography import x509

    cert = x509.load_pem_x509_certificate((pki / "server.pem").read_bytes())
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in sans.get_values_for_type(x509.DNSName)
    assert "127.0.0.1" in [str(v) for v in sans.get_values_for_type(x509.IPAddress)]
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False