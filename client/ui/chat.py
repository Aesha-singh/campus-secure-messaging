"""Main chat window: conversation list, transcript, composer, status bar.

Networking concept demonstrated
-------------------------------
**Asynchronous GUI -- the event loop owns the network.**  The window runs on
the same qasync loop as the ``ClientSession``: socket callbacks and widget
signals are *both* events, so no thread locks are needed and the UI never
blocks the wire.  The status bar surfaces live transport facts the user can
see -- connected/TLS, message delivered-vs-queued, contact online/offline --
turning the network's behaviour into visible evidence for the viva demo.
"""

from __future__ import annotations

import asyncio
import logging

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QColor, QTextCharFormat
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenuBar,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from client.session import ChatMessage, ClientCallbacks, ClientSession
from client.store import ClientStore
from protocol.constants import ErrorCode
from server.storage import convo_key

log = logging.getLogger("cscp.client.ui")


class SessionBridge(QObject):
    """Qt-side reflection of asyncio callbacks (queued, thread-safe signals)."""

    ready = pyqtSignal(str)
    message = pyqtSignal(object)
    ack = pyqtSignal(str)
    error = pyqtSignal(str)
    unread = pyqtSignal(str)
    presence = pyqtSignal(str)
    disconnected = pyqtSignal()


class ChatWindow(QMainWindow):
    """One window per logged-in profile."""

    def __init__(self, session: ClientSession, store: ClientStore) -> None:
        super().__init__()
        self.session = session
        self.store = store
        self.bridge = SessionBridge()
        self._convo_unread: dict[str, int] = {}
        self._current_convo: str | None = None
        self._build_ui()
        self.bridge.ready.connect(self._on_ready)
        self.bridge.message.connect(self._on_message)
        self.bridge.ack.connect(lambda s: self._set_status(s))
        self.bridge.error.connect(lambda s: self._set_status("error: " + s))
        self.bridge.unread.connect(self._on_unread)
        self.bridge.presence.connect(self._set_status)
        self.bridge.disconnected.connect(lambda: self._set_status("connection lost - reconnecting"))

        cbs = ClientCallbacks(
            on_ready=self._cb_ready,
            on_message=self._cb_message,
            on_ack=self._cb_ack,
            on_error=self._cb_error,
            on_unread=self._cb_unread,
            on_presence=self._cb_presence,
            on_disconnected=self._cb_disconnected,
        )
        # The same ClientSession object is reused; re-point its callbacks.
        self.session.cb = cbs

    # -- UI construction ---------------------------------------------------

    def _build_ui(self) -> None:
        self.setWindowTitle(f"CSCP secure messaging - {self.session.username or '?'}")
        self.resize(860, 560)

        bar = QMenuBar(self)
        peer_menu = bar.addMenu("&E2EE")
        assert peer_menu is not None
        peer_menu.addAction("Add contact (paste public key)", self._pin_peer)
        peer_menu.addAction("Show my public key", self._show_own_key)
        self.setMenuBar(bar)

        self.conversations = QListWidget()
        self.conversations.currentItemChanged.connect(self._on_conversation_changed)
        self.conversations.setMinimumWidth(180)

        self.transcript = QTextBrowser()
        self.composer = QLineEdit()
        self.composer.setPlaceholderText("Type a message (Enter to send)...")
        self.composer.returnPressed.connect(self._send)
        send_button = QPushButton("Send")
        send_button.clicked.connect(self._send)

        composer_row = QHBoxLayout()
        composer_row.addWidget(self.composer, 1)
        composer_row.addWidget(send_button)

        chat_pane = QWidget()
        chat_layout = QVBoxLayout(chat_pane)
        chat_layout.addWidget(self.transcript, 1)
        chat_layout.addLayout(composer_row)

        splitter = QSplitter(self)
        splitter.addWidget(self.conversations)
        splitter.addWidget(chat_pane)
        splitter.setStretchFactor(1, 1)

        self.status = QLabel("connecting...")
        statusbar = self.statusBar()
        if statusbar is not None:
            statusbar.addWidget(self.status)

        central = QWidget(self)
        outer = QVBoxLayout(central)
        outer.addWidget(splitter, 1)
        outer.addWidget(self.status)
        self.setCentralWidget(central)

    # -- async callbacks -> Qt signals -------------------------------------

    async def _cb_ready(self, session: ClientSession) -> None:
        tls = "TLS 1.3" if session.transport is not None and session.transport.tls_active else "PLAIN"
        self.bridge.ready.emit(f"connected as {session.user_id} ({tls})")

    async def _cb_message(self, chat: ChatMessage) -> None:
        self.bridge.message.emit(chat)

    async def _cb_ack(self, ack) -> None:  # type: ignore[no-untyped-def]
        self.bridge.ack.emit(f"{self.session.delivery_status_text(ack)}: {ack.msg_id}")

    async def _cb_error(self, err) -> None:  # type: ignore[no-untyped-def]
        self.bridge.error.emit(f"server ({ErrorCode(err.code).name if err.code else '?'}): {err.reason}")

    async def _cb_unread(self, unread) -> None:  # type: ignore[no-untyped-def]
        self.bridge.unread.emit(str(dict(unread.convo_unread)))

    async def _cb_presence(self, presence) -> None:  # type: ignore[no-untyped-def]
        state = presence.state.name if hasattr(presence.state, "name") else str(presence.state)
        self.bridge.presence.emit(f"{presence.user_id} is {state}")

    async def _cb_disconnected(self) -> None:
        self.bridge.disconnected.emit()

    # -- Qt slots ----------------------------------------------------------

    def _on_ready(self, text: str) -> None:
        self._set_status(text)

    def _set_status(self, text: str) -> None:
        self.status.setText(text)

    def _on_unread(self, raw: str) -> None:
        import ast

        try:
            counts = ast.literal_eval(raw) if raw.startswith("{") else {}
        except (ValueError, SyntaxError):
            counts = {}
        self._convo_unread = counts
        self._refresh_conversation_labels()

    def _on_message(self, chat: ChatMessage) -> None:
        if chat.convo not in [self._row_key(i) for i in range(self.conversations.count())]:
            self._add_convo(chat.convo)
        self._maybe_select(chat.convo, chat)
        if chat.convo == self._current_convo:
            self._append_transcript(chat)
        else:
            self._convo_unread[chat.convo] = self._convo_unread.get(chat.convo, 0) + 1
            self._refresh_conversation_labels()

    def _on_conversation_changed(self, current: QListWidgetItem | None, _prev) -> None:  # type: ignore[no-untyped-def]
        if current is None:
            return
        convo = self._row_key(self.conversations.row(current))
        self._current_convo = convo
        asyncio.create_task(self._load_history(convo), name="ui-load-history")
        self._convo_unread.pop(convo, None)
        self._refresh_conversation_labels()
        asyncio.create_task(self.session.mark_read(*_split_convo(convo)), name="ui-mark-read")
        asyncio.create_task(self.session.sync_history(*_split_convo(convo)), name="ui-history-sync")

    def _send(self) -> None:
        peer = self._current_peer()
        text = self.composer.text().strip()
        if not peer or not text:
            return
        self.composer.clear()
        convo = convo_key("dm", self.session.user_id, peer)
        asyncio.create_task(self.session.send_text(peer, text), name="ui-send")
        local = ChatMessage(
            msg_id="local-" + peer,
            convo=convo,
            peer_id=peer,
            direction="sent",
            ts=0.0,
            text=text,
            encrypted=False,
            raw=b"",
        )
        if convo not in [self._row_key(i) for i in range(self.conversations.count())]:
            self._add_convo(convo)
        self._append_transcript(local)

    def _current_peer(self) -> str | None:
        if self._current_convo:
            kind, ids = _split_convo(self._current_convo)
            if kind == "dm":
                return _peer_of(ids, self.session.user_id)
        return None

    def _pin_peer(self) -> None:
        peer, ok1 = QInputDialog.getText(self, "Add E2EE contact", "Peer user id (e.g. u_bob):")
        if not ok1 or not peer.strip():
            return
        key_hex, ok2 = QInputDialog.getText(self, "Add E2EE contact", "Paste their X25519 public key (hex):")
        if not ok2 or not key_hex.strip():
            return
        try:
            key = bytes.fromhex(key_hex.strip())
        except ValueError:
            self._set_status("invalid hex public key")
            return
        crypto = self.session.crypto
        if not crypto.pin_peer(peer.strip(), key):
            self._set_status("key conflict: peer already pinned with a different key (TOFU)")
            return
        crypto.reset_thread(peer.strip())
        self._set_status(f"pinned E2EE key for {peer}")
        asyncio.create_task(self.store.save_peer(peer.strip(), key.hex()), name="ui-save-pin")

    def _show_own_key(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        QMessageBox.information(self, "My public key", self.session.crypto.own_public().hex())

    # -- helpers -----------------------------------------------------------

    def _row_key(self, row: int) -> str:
        item = self.conversations.item(row)
        return item.data(0x0100) if item is not None else ""

    def _add_convo(self, convo: str) -> None:
        item = QListWidgetItem(convo)
        item.setData(0x0100, convo)
        self.conversations.addItem(item)

    def _maybe_select(self, convo: str, chat: ChatMessage) -> None:
        if convo == self._current_convo or chat.direction == "sent":
            return
        _, ids = _split_convo(convo)
        self._set_status(f"new message from {_peer_of(ids, self.session.user_id)}")

    async def _load_history(self, convo: str) -> None:
        rows = await self.store.history(convo, limit=200)
        self.transcript.clear()
        for r in rows:
            self._append_row(f"{'→' if r.direction == 'sent' else '←'} {r.plaintext}")

    def _append_transcript(self, chat: ChatMessage) -> None:
        text = chat.text if chat.text is not None else "[ciphertext]"
        self._append_row(f"{'→' if chat.direction == 'sent' else '←'} {text}")

    def _append_row(self, line: str) -> None:
        fmt = QTextCharFormat()
        fmt.setForeground(QColor("#2b6cb0"))  # muted blue for local reads
        self.transcript.append(line)

    def _refresh_conversation_labels(self) -> None:
        for row in range(self.conversations.count()):
            item = self.conversations.item(row)
            if item is None:
                continue
            convo: str = item.data(0x0100) or ""
            count = self._convo_unread.get(convo, 0)
            item.setText(f"{convo}{f'  ●{count}' if count else ''}")

    async def sync_and_mark_current(self) -> None:
        if self._current_convo:
            await self.session.sync_history(*_split_convo(self._current_convo))


def _split_convo(convo: str) -> tuple[str, str]:
    """Split a storage key like ``dm:u_alice|u_bob`` into (kind, convo_id)."""
    kind, _, ids = convo.partition(":")
    return kind, ids


def _peer_of(ids: str, me: str) -> str:
    """Given ``u_alice|u_bob`` return the non-me member (fallback first)."""
    candidates = [p for p in ids.split("|") if p and p != me]
    return candidates[0] if candidates else ids.split("|")[0]