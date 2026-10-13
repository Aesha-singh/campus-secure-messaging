"""Sign-in dialog for the desktop client.

Networking concept demonstrated
-------------------------------
**Presentation vs transport separation.**  The dialog only *collects*
credentials and knobs (host, port, TOTP) and hands them to the asyncio
transport layer; the widget never speaks the protocol.  Keeping the GUI off
the wire makes the session logic unit-testable headlessly -- the same reason
applications route all I/O through one core service.
"""

from __future__ import annotations

from dataclasses import dataclass

from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QSpinBox,
    QVBoxLayout,
)


@dataclass(slots=True)
class LoginValues:
    host: str
    port: int
    username: str
    password: str
    totp: str
    require_tls: bool


class LoginDialog(QDialog):
    """Collect the connection + credential form before creating a session."""

    def __init__(self, parent=None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(parent)
        self.setWindowTitle("CSCP - sign in to campus secure messaging")
        self.setMinimumWidth(380)

        self.host_edit = QLineEdit("127.0.0.1")
        self.port_edit = QSpinBox()
        self.port_edit.setRange(1, 65535)
        self.port_edit.setValue(9443)
        self.username_edit = QLineEdit("alice")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.totp_edit = QLineEdit()
        self.totp_edit.setPlaceholderText("6-digit code (if the account has 2FA)")
        self.tls_check = QCheckBox("Require TLS 1.3 (mTLS)")
        self.tls_check.setChecked(False)

        form = QFormLayout()
        form.addRow("Host", self.host_edit)
        form.addRow("Port", self.port_edit)
        form.addRow("Username", self.username_edit)
        form.addRow("Password", self.password_edit)
        form.addRow("TOTP code", self.totp_edit)
        form.addRow("", self.tls_check)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def values(self) -> LoginValues:
        return LoginValues(
            host=self.host_edit.text().strip(),
            port=self.port_edit.value(),
            username=self.username_edit.text().strip(),
            password=self.password_edit.text(),
            totp=self.totp_edit.text().strip() or None,  # type: ignore[arg-type]
            require_tls=self.tls_check.isChecked(),
        )