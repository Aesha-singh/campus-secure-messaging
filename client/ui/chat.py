"""Main chat window: conversations, channels, file transfer, diagnostics.

Networking concept demonstrated
-------------------------------
**Asynchronous GUI -- the event loop owns the network.**  The window runs on
the same qasync loop as the ``ClientSession``: socket callbacks and widget
signals are *both* events, so no thread locks are needed and the UI never
blocks the wire.  The status bar and the diagnostics dock surface live
transport facts -- connected/TLS, delivered-vs-queued, RTT/jitter/loss -- turning
the network's behaviour into visible evidence for the demo.

Feature surfaces added here:

* **File transfer** -- a progress panel per transfer, an accept dialog for
  incoming offers, and a "Send file" action (E2EE blob over the relay).
* **Channels** -- create/join rooms; room conversations share the list pane but
  route to the server-mediated group relay instead of E2EE DMs.
* **Diagnostics** -- active RTT probing with jitter/loss, so the user sees the
  path quality change (the same PING/PONG the protocol defines).
* **Discovery** -- a browser for ``_cscp._tcp`` services advertised over mDNS.
"""

from __future__ import annotations

import asyncio
import logging
import statistics
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QDockWidget,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from client.session import ChatMessage, ClientCallbacks, ClientSession, FileEvent, GroupMessage
from client.store import ClientStore
from protocol.constants import ErrorCode
from server.storage import convo_key

if TYPE_CHECKING:
    from client.discovery import ServerBrowser

log = logging.getLogger("cscp.client.ui")


class SessionBridge(QObject):
    """Qt-side reflection of asyncio callbacks (queued, thread-safe signals)."""

    ready = pyqtSignal(str)
    message = pyqtSignal(object)
    group = pyqtSignal(object)
    file = pyqtSignal(object)
    channel = pyqtSignal(object)
    rtt = pyqtSignal(float)
    ack = pyqtSignal(str)
    error = pyqtSignal(str)
    unread = pyqtSignal(str)
    presence = pyqtSignal(str)
    disconnected = pyqtSignal()


class TransfersPanel(QWidget):
    """Live progress rows, one per file transfer (in or out)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: dict[str, tuple[QLabel, QProgressBar]] = {}
        self._layout = QVBoxLayout(self)
        placeholder = QLabel("No active transfers")
        self._layout.addWidget(placeholder)
        self._placeholder: QLabel | None = placeholder

    def update_event(self, ev: FileEvent) -> None:
        if ev.transfer_id not in self._rows:
            if self._placeholder is not None:
                self._placeholder.hide()
                self._placeholder = None
            label = QLabel()
            bar = QProgressBar()
            bar.setRange(0, 100)
            self._layout.addWidget(label)
            self._layout.addWidget(bar)
            self._rows[ev.transfer_id] = (label, bar)
        label, bar = self._rows[ev.transfer_id]
        arrow = "→" if ev.direction == "out" else "←"
        enc = "E2EE" if ev.encrypted else "plain"
        label.setText(f"{arrow} {ev.name} ({ev.size} B, {enc}) [{ev.state}]")
        bar.setValue(int(ev.percent))
        if ev.state == "complete":
            label.setText(f"{label.text()}  saved: {ev.path}" if ev.path else label.text())
        if ev.state == "failed":
            label.setText(f"{label.text()}  error: {ev.error}")


class DiagnosticsPanel(QWidget):
    """Active round-trip probing: RTT, jitter (mean deviation), and loss."""

    def __init__(self, session: ClientSession, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.session = session
        self.samples: deque[float | None] = deque(maxlen=60)
        self._task: asyncio.Task[None] | None = None

        self.enable = QCheckBox("Probe continuously (1/s)")
        self.rtt_label = QLabel("RTT: -")
        self.jitter_label = QLabel("jitter: -")
        self.loss_label = QLabel("loss: -")
        self.manual = QPushButton("Ping x10")
        self.manual.clicked.connect(lambda: asyncio.create_task(self._burst(10), name="ui-ping-burst"))
        self.enable.toggled.connect(self._toggle)

        form = QFormLayout()
        form.addRow(self.enable)
        form.addRow("latency", self.rtt_label)
        form.addRow("variation", self.jitter_label)
        form.addRow("packet loss", self.loss_label)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.manual)
        layout.addStretch(1)

    def add_sample(self, rtt_ms: float | None) -> None:
        self.samples.append(rtt_ms)
        ok = [s for s in self.samples if s is not None]
        if ok:
            self.rtt_label.setText(f"RTT: {ok[-1]:.1f} ms (last) / {statistics.median(ok):.1f} ms (median)")
            if len(ok) >= 2:
                diffs = [abs(ok[i] - ok[i - 1]) for i in range(1, len(ok))]
                self.jitter_label.setText(f"jitter: {statistics.mean(diffs):.2f} ms (mean dev)")
        lost = sum(1 for s in self.samples if s is None)
        if self.samples:
            self.loss_label.setText(f"loss: {100.0 * lost / len(self.samples):.1f}% ({lost}/{len(self.samples)})")

    def _toggle(self, on: bool) -> None:
        if on and self._task is None:
            self._task = asyncio.create_task(self._continuous(), name="ui-diag")
        elif not on and self._task is not None:
            self._task.cancel()
            self._task = None

    async def _probe_once(self) -> float | None:
        try:
            return await self.session.ping(timeout=2.0)
        except (TimeoutError, ConnectionError):
            return None

    async def _burst(self, count: int) -> None:
        for _ in range(count):
            self.add_sample(await self._probe_once())
            await asyncio.sleep(0.05)

    async def _continuous(self) -> None:
        try:
            while True:
                self.add_sample(await self._probe_once())
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass


class DiscoveryDialog(QDialog):
    """Browse ``_cscp._tcp`` servers advertised over mDNS on the LAN."""

    def __init__(self, service_type: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Discovered CSCP servers")
        self.setMinimumWidth(420)
        self.service_type = service_type
        self.servers = QListWidget()
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"Browsing for {service_type} ..."))
        layout.addWidget(self.servers)
        layout.addWidget(buttons)
        self._browser: ServerBrowser | None = None

    async def _start(self) -> None:
        from client.discovery import ServerBrowser

        browser = ServerBrowser(service_type=self.service_type)
        self._browser = browser
        browser.on_found = lambda srv: self.servers.addItem(srv.label)
        try:
            await browser.start()
            await asyncio.sleep(5.0)
        finally:
            await browser.stop()

    async def _stop(self) -> None:
        if self._browser is not None:
            await self._browser.stop()
            self._browser = None


class ChatWindow(QMainWindow):
    """One window per logged-in profile."""

    def __init__(self, session: ClientSession, store: ClientStore) -> None:
        super().__init__()
        self.session = session
        self.store = store
        self.bridge = SessionBridge()
        self._convo_unread: dict[str, int] = {}
        self._channel_names: dict[str, str] = {}
        self._current_convo: str | None = None
        self._build_ui()
        self._connect_bridge()

        cbs = ClientCallbacks(
            on_ready=self._cb_ready,
            on_message=self._cb_message,
            on_group=self._cb_group,
            on_file=self._cb_file,
            on_channel=self._cb_channel,
            on_rtt=self._cb_rtt,
            on_ack=self._cb_ack,
            on_error=self._cb_error,
            on_unread=self._cb_unread,
            on_presence=self._cb_presence,
            on_disconnected=self._cb_disconnected,
        )
        self.session.cb = cbs

    # -- UI construction ---------------------------------------------------

    def _build_ui(self) -> None:
        self.setWindowTitle(f"CSCP secure messaging - {self.session.username or '?'}")
        self.resize(960, 620)

        bar = QMenuBar(self)
        peer_menu = bar.addMenu("&E2EE")
        assert peer_menu is not None
        peer_menu.addAction("Add contact (paste public key)", self._pin_peer)
        peer_menu.addAction("Show my public key", self._show_own_key)
        chan_menu = bar.addMenu("&Channels")
        assert chan_menu is not None
        chan_menu.addAction("Create channel...", self._create_channel)
        chan_menu.addAction("Join channel...", self._join_channel)
        chan_menu.addAction("Leave current channel", self._leave_channel)
        chan_menu.addAction("Refresh channel list", lambda: asyncio.create_task(self.session.list_channels()))
        net_menu = bar.addMenu("&Network")
        assert net_menu is not None
        net_menu.addAction("Discover servers (mDNS)", self._discover)
        self.setMenuBar(bar)

        self.conversations = QListWidget()
        self.conversations.currentItemChanged.connect(self._on_conversation_changed)
        self.conversations.setMinimumWidth(200)

        self.transcript = QTextBrowser()
        self.composer = QLineEdit()
        self.composer.setPlaceholderText("Type a message (Enter to send)...")
        self.composer.returnPressed.connect(self._send)
        send_button = QPushButton("Send")
        send_button.clicked.connect(self._send)
        self.file_button = QPushButton("Send file")
        self.file_button.clicked.connect(self._send_file)

        composer_row = QHBoxLayout()
        composer_row.addWidget(self.composer, 1)
        composer_row.addWidget(self.file_button)
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

        self.transfers = TransfersPanel()
        transfers_dock = QDockWidget("File transfers", self)
        transfers_dock.setWidget(self.transfers)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, transfers_dock)

        self.diagnostics = DiagnosticsPanel(self.session)
        diag_dock = QDockWidget("Network diagnostics", self)
        diag_dock.setWidget(self.diagnostics)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, diag_dock)

    def _connect_bridge(self) -> None:
        self.bridge.ready.connect(self._on_ready)
        self.bridge.message.connect(self._on_message)
        self.bridge.group.connect(self._on_group)
        self.bridge.file.connect(self._on_file)
        self.bridge.channel.connect(self._on_channel)
        self.bridge.ack.connect(lambda s: self._set_status(s))
        self.bridge.error.connect(lambda s: self._set_status("error: " + s))
        self.bridge.unread.connect(self._on_unread)
        self.bridge.presence.connect(self._set_status)
        self.bridge.disconnected.connect(lambda: self._set_status("connection lost - reconnecting"))

    # -- async callbacks -> Qt signals -------------------------------------

    async def _cb_ready(self, session: ClientSession) -> None:
        tls = "TLS 1.3" if session.transport is not None and session.transport.tls_active else "PLAIN"
        self.bridge.ready.emit(f"connected as {session.user_id} ({tls})")

    async def _cb_message(self, chat: ChatMessage) -> None:
        self.bridge.message.emit(chat)

    async def _cb_group(self, msg: GroupMessage) -> None:
        self.bridge.group.emit(msg)

    async def _cb_file(self, event: FileEvent) -> None:
        self.bridge.file.emit(event)

    async def _cb_channel(self, info) -> None:  # type: ignore[no-untyped-def]
        self.bridge.channel.emit(info)

    async def _cb_rtt(self, rtt_ms: float) -> None:
        # Emitted for every Pong; the diagnostics panel owns sampling so we only
        # forward bursts it starts itself.  (Kept for custom subscribers.)
        self.bridge.rtt.emit(rtt_ms)

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
        asyncio.create_task(self.session.list_channels(), name="ui-list-channels")

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
        self._ensure_convo(chat.convo)
        self._maybe_select(chat.convo, chat.direction)
        if chat.convo == self._current_convo:
            self._append_transcript(chat)
        else:
            self._bump_unread(chat.convo)

    def _on_group(self, msg: GroupMessage) -> None:
        convo = msg.convo
        self._ensure_convo(convo)
        self._maybe_select(convo, msg.direction)
        if convo == self._current_convo:
            prefix = "→" if msg.direction == "sent" else f"← {msg.sender_id}:"
            self._append_row(f"{prefix} {msg.text}")
        else:
            self._bump_unread(convo)

    def _on_file(self, ev: FileEvent) -> None:
        self.transfers.update_event(ev)
        if ev.direction == "in" and ev.state == "offered":
            self._prompt_incoming(ev)
        elif ev.state == "complete":
            self._set_status(f"transfer complete: {ev.name}")

    def _on_channel(self, info) -> None:  # type: ignore[no-untyped-def]
        convo = convo_key("channel", info.channel_id)
        self._channel_names[convo] = info.name
        self._ensure_convo(convo)
        self._refresh_conversation_labels()
        log.info(
            "channel_info",
            extra={"channel_id": info.channel_id, "role": info.role, "members": info.member_count},
        )

    def _prompt_incoming(self, ev: FileEvent) -> None:
        kind = "Encrypted (E2EE)" if ev.encrypted else "plaintext"
        answer = QMessageBox.question(
            self,
            "Incoming file",
            f"{ev.peer_id} is sending '{ev.name}' ({ev.size} bytes, {kind}).\nAccept?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer is QMessageBox.StandardButton.Yes:
            save_dir = QFileDialog.getExistingDirectory(self, "Save file to...", self.session.cfg.receive_dir)
            target = save_dir or self.session.cfg.receive_dir
            asyncio.create_task(self.session.accept_file(ev.transfer_id, target), name="ui-accept-file")
            self._set_status(f"accepting {ev.name} -> {target}")
        else:
            asyncio.create_task(self.session.accept_file(ev.transfer_id, accepted=False), name="ui-decline-file")

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
        self.file_button.setEnabled(self._current_peer() is not None)

    def _send(self) -> None:
        text = self.composer.text().strip()
        if not text or not self._current_convo:
            return
        kind, ids = _split_convo(self._current_convo)
        self.composer.clear()
        if kind == "channel":
            self._append_row(f"→ {text}")
            asyncio.create_task(self.session.send_channel(ids, text), name="ui-send-channel")
            return
        peer = self._current_peer()
        if not peer:
            return
        asyncio.create_task(self.session.send_text(peer, text), name="ui-send")
        local = ChatMessage(
            msg_id="local-" + peer,
            convo=self._current_convo,
            peer_id=peer,
            direction="sent",
            ts=0.0,
            text=text,
            encrypted=False,
            raw=b"",
        )
        self._append_transcript(local)

    def _send_file(self) -> None:
        peer = self._current_peer()
        if not peer:
            self._set_status("select a direct-message conversation to send a file")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Send file")
        if not path:
            return
        asyncio.create_task(self.session.send_file(peer, Path(path)), name="ui-send-file")
        self._set_status(f"offering {Path(path).name} to {peer}")

    def _create_channel(self) -> None:
        name, ok = QInputDialog.getText(self, "Create channel", "Channel name:")
        if not ok or not name.strip():
            return
        kind, ok2 = QInputDialog.getItem(
            self, "Create channel", "Kind:", ["public", "private", "course", "club"], 0, False
        )
        if not ok2:
            return
        asyncio.create_task(self.session.create_channel(name.strip(), kind), name="ui-create-channel")

    def _join_channel(self) -> None:
        known = ", ".join(sorted({c for c in self._channel_names.values()}))
        channel_id, ok = QInputDialog.getText(
            self, "Join channel", f"Channel id:{f' (known: {known})' if known else ''}"
        )
        if not ok or not channel_id.strip():
            return
        asyncio.create_task(self.session.join_channel(channel_id.strip()), name="ui-join-channel")

    def _leave_channel(self) -> None:
        if not self._current_convo:
            return
        kind, ids = _split_convo(self._current_convo)
        if kind != "channel":
            self._set_status("current conversation is not a channel")
            return
        asyncio.create_task(self.session.leave_channel(ids), name="ui-leave-channel")

    def _discover(self) -> None:
        dialog = DiscoveryDialog(self.session.cfg.discovery_service_type, self)
        asyncio.create_task(dialog._start(), name="ui-discovery")
        dialog.finished.connect(lambda _: asyncio.create_task(dialog._stop(), name="ui-discovery-stop"))
        dialog.show()

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
        QMessageBox.information(self, "My public key", self.session.crypto.own_public().hex())

    # -- helpers -----------------------------------------------------------

    def _row_key(self, row: int) -> str:
        item = self.conversations.item(row)
        return item.data(0x0100) if item is not None else ""

    def _ensure_convo(self, convo: str) -> None:
        if convo in [self._row_key(i) for i in range(self.conversations.count())]:
            return
        item = QListWidgetItem(self._convo_label(convo))
        item.setData(0x0100, convo)
        self.conversations.addItem(item)

    def _add_convo(self, convo: str) -> None:
        self._ensure_convo(convo)

    def _convo_label(self, convo: str) -> str:
        if convo in self._channel_names:
            return f"#{self._channel_names[convo]}"
        return convo

    def _maybe_select(self, convo: str, direction: str) -> None:
        if convo == self._current_convo or direction == "sent":
            return
        self._set_status(f"new message in {self._convo_label(convo)}")

    def _bump_unread(self, convo: str) -> None:
        self._convo_unread[convo] = self._convo_unread.get(convo, 0) + 1
        self._refresh_conversation_labels()

    async def _load_history(self, convo: str) -> None:
        rows = await self.store.history(convo, limit=200)
        self.transcript.clear()
        for r in rows:
            self._append_row(f"{'→' if r.direction == 'sent' else '←'} {r.plaintext}")

    def _append_transcript(self, chat: ChatMessage) -> None:
        text = chat.text if chat.text is not None else "[ciphertext]"
        self._append_row(f"{'→' if chat.direction == 'sent' else '←'} {text}")

    def _append_row(self, line: str) -> None:
        self.transcript.append(line)

    def _refresh_conversation_labels(self) -> None:
        for row in range(self.conversations.count()):
            item = self.conversations.item(row)
            if item is None:
                continue
            convo: str = item.data(0x0100) or ""
            count = self._convo_unread.get(convo, 0)
            label = self._convo_label(convo)
            item.setText(f"{label}{f'  ●{count}' if count else ''}")

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
