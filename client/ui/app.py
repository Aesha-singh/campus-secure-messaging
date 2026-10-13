"""QApplication bootstrap: login dialog -> store/identity -> main window.

Networking concept demonstrated
-------------------------------
**Single event loop owns both Qt and the socket.**  ``qasync`` runs the
asyncio transport and the widget event loop on one thread, so TLS handshakes,
keep-alive pings and message receipts all arrive as ordinary loop events with
no barrier between network code and UI code -- the desktop equivalent of an
event-driven protocol stack.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import qasync
from PyQt6.QtWidgets import QApplication

from client.config import ClientConfig
from client.crypto import ClientCrypto, load_or_create_identity
from client.session import ClientCallbacks, ClientSession
from client.store import ClientStore
from client.ui.chat import ChatWindow
from client.ui.login import LoginDialog

log = logging.getLogger("cscp.client.ui")


def run_gui(base: Mapping[str, Any] | None = None) -> int:
    """Entry point for ``python -m client.main --gui``.

    ``base`` may carry host/port/TLS paths/Credentials from a config file so
    the dialog starts pre-filled.
    """
    app = QApplication(sys.argv[:1])
    app.setApplicationName("CSCP secure messaging")

    cfg = ClientConfig.from_mapping(dict(base or {}))
    dialog = LoginDialog()
    dialog.host_edit.setText(cfg.host)
    dialog.port_edit.setValue(cfg.port)
    if cfg.username:
        dialog.username_edit.setText(cfg.username)
    if cfg.password:
        dialog.password_edit.setText(cfg.password)
    dialog.tls_check.setChecked(cfg.require_tls)
    if not dialog.exec():
        return 0

    vals = dialog.values()
    cfg.host = vals.host
    cfg.port = vals.port
    cfg.require_tls = vals.require_tls
    cfg.username = vals.username
    cfg.password = vals.password or None
    cfg.totp = vals.totp

    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    async def bootstrap() -> None:
        data_dir = Path(cfg.data_dir)
        await asyncio.to_thread(data_dir.mkdir, parents=True, exist_ok=True)
        store = ClientStore(data_dir / "profile.sqlite3")
        await store.open()
        identity = load_or_create_identity(data_dir / "identity.key")
        crypto = ClientCrypto(identity)
        for peer, key in (await store.load_peers()).items():
            crypto.pin_peer(peer, key)
        session = ClientSession(
            cfg=cfg,
            crypto=crypto,
            store=store,
            callbacks=ClientCallbacks(),
        )
        window = ChatWindow(session, store)
        window.show()
        asyncio.create_task(session.run(), name="client-session")

    def _run() -> None:
        loop.create_task(bootstrap(), name="client-bootstrap")

    try:
        with loop:
            _run()
            loop.run_forever()
    finally:
        async def _shutdown() -> None:
            for task in asyncio.all_tasks(loop):
                if task is not asyncio.current_task():
                    task.cancel()
            await asyncio.gather(*asyncio.all_tasks(loop), return_exceptions=True)

        loop.run_until_complete(_shutdown())
    return 0