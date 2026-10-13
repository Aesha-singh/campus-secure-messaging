"""Headless GUI tests for the transfers + diagnostics panels and channel routing.

These exercise widget logic without a network so they stay deterministic; the
full wire path is covered by ``test_session_features.py`` and ``test_ui_smoke``.
"""

from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from client.session import FileEvent  # noqa: E402
from client.ui.chat import DiagnosticsPanel, TransfersPanel  # noqa: E402


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    return QApplication.instance() or QApplication(sys.argv[:1])


def test_transfers_panel_tracks_progress(qapp: QApplication) -> None:
    panel = TransfersPanel()
    panel.update_event(
        FileEvent("f1", "u_bob", "notes.pdf", 2000, "out", "offered", total=2028, encrypted=True)
    )
    assert "f1" in panel._rows
    _, bar = panel._rows["f1"]
    assert bar.value() == 0

    panel.update_event(
        FileEvent("f1", "u_bob", "notes.pdf", 2000, "out", "progress", received=1014, total=2028, encrypted=True)
    )
    assert 49 <= bar.value() <= 51

    panel.update_event(
        FileEvent("f1", "u_bob", "notes.pdf", 2000, "out", "complete", received=2028, total=2028, path="notes.pdf")
    )
    assert bar.value() == 100


def test_transfers_panel_percent_edge_cases(qapp: QApplication) -> None:
    ev = FileEvent("f2", "u_bob", "x", 0, "in", "offered", total=28)
    assert ev.percent == 0.0


class _StubSession:
    def __init__(self, results: list[float | None]) -> None:
        self._results = results
        self.calls = 0

    async def ping(self, timeout: float = 2.0) -> float:  # noqa: ASYNC109 -- mirrors the real signature
        value = self._results[self.calls % len(self._results)]
        self.calls += 1
        if value is None:
            raise TimeoutError
        return value


async def test_diagnostics_panel_computes_stats(qapp: QApplication) -> None:
    panel = DiagnosticsPanel(_StubSession([10.0, 20.0, None, 30.0]))  # type: ignore[arg-type]
    await panel._burst(4)
    assert "RTT" in panel.rtt_label.text()
    assert "jitter" in panel.jitter_label.text()
    # 1 of 4 probes timed out -> 25% loss
    assert "25.0%" in panel.loss_label.text()
