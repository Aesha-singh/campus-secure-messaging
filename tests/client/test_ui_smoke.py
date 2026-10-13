"""GUI test: real session inside a qasync loop, driving the desktop window.

Networking concept demonstrated
-------------------------------
**One event loop owns the wire and the widgets.**  The stub CSCP server, the
TLS-agnostic asyncio transport, the E2EE channel and the QListWidget/QSplitter
tree all run on a single ``qasync`` loop -- the drop-in proof that Qt needs no
threading to talk to a socket.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6")
pytest.importorskip("qasync")

import qasync  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from client.config import ClientConfig  # noqa: E402
from client.crypto import ClientCrypto, load_or_create_identity  # noqa: E402
from client.session import ClientCallbacks, ClientSession  # noqa: E402
from client.store import ClientStore  # noqa: E402
from client.ui.chat import ChatWindow  # noqa: E402
from server.auth import StubAuthenticator  # noqa: E402
from server.config import Config  # noqa: E402
from server.server import CSCPServer  # noqa: E402
from server.storage import convo_key  # noqa: E402

USERS = {"alice": "sa", "bob": "sb"}


def test_live_gui_reaches_ready_and_renders() -> None:
    app = QApplication.instance() or QApplication(sys.argv[:1])
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    with tempfile.TemporaryDirectory() as tmp:
        async def scenario() -> None:
            cfg = Config()
            cfg.net.enable_v4 = True
            cfg.net.host_v4 = "127.0.0.1"
            cfg.net.enable_v6 = False
            cfg.net.port = 0
            srv = CSCPServer(cfg, auth=StubAuthenticator(USERS), secret=b"k" * 32)
            await srv.start()
            port = srv.listeners[0].server.sockets[0].getsockname()[1]

            ccfg = ClientConfig(
                host="127.0.0.1",
                port=port,
                username="bob",
                password="sb",  # noqa: S106 -- stub test credential
                require_tls=False,
                data_dir=tmp,
                ping_interval=2.0,
            )
            root = Path(tmp)
            _ident = load_or_create_identity(root / "identity.key")
            crypto = ClientCrypto(_ident)
            store = ClientStore(root / "profile.sqlite3")
            await store.open()
            session = ClientSession(
                cfg=ccfg,
                crypto=crypto,
                store=store,
                callbacks=ClientCallbacks(),
            )
            session.set_credentials("bob", "sb")

            window = ChatWindow(session, store)
            window.show()  # rendered by the Qt "window system" plugin (offscreen)

            task = asyncio.create_task(session.run(), name="live-session")
            try:
                deadline = time.monotonic() + 6.0
                while not session.is_ready:
                    assert time.monotonic() < deadline, "auth timeout"
                    await asyncio.sleep(0.05)

                assert session.is_ready
                assert "connected" in window.status.text()

                # Select a conversation and send through the composer path ---
                # exercises the exact code the user's Enter key triggers.
                convo = convo_key("dm", session.user_id, "alice")
                window._current_convo = convo
                window._add_convo(convo)
                window.composer.setText("hello from the widget layer")
                window._send()
                await asyncio.sleep(0.3)
                assert "hello from the widget layer" in window.transcript.toPlainText()
            finally:
                await session.stop()
                await srv.shutdown()
                if not task.done():
                    task.cancel()
                await store.close()

        loop.run_until_complete(scenario())

    pending = asyncio.all_tasks(loop=loop)
    for t in pending:
        t.cancel()
    if pending:
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    loop.close()