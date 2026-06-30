"""
ui/console.py
─────────────
CollapsibleConsole — aşağı sistem konsolu paneli.
"""

from __future__ import annotations

from PyQt6.QtCore    import Qt
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from core.config   import C
from ui.primitives import Btn, Log


class CollapsibleConsole(QWidget):
    COLLAPSED = 28
    EXPANDED  = 140

    def __init__(self, parent=None):
        super().__init__(parent)
        self._open = True
        self.setFixedHeight(self.EXPANDED)
        self.setStyleSheet(
            f"background:{C.SURF0}; border-top:1px solid {C.BDR0};"
        )

        vl = QVBoxLayout(self)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        # ── Header bar ────────────────────────────────────────────────────────
        hdr = QWidget(); hdr.setFixedHeight(self.COLLAPSED)
        hdr.setStyleSheet(
            f"background:{C.SURF2}; border-bottom:1px solid {C.BDR0};"
        )
        hdr.setCursor(Qt.CursorShape.PointingHandCursor)
        hl = QHBoxLayout(hdr); hl.setContentsMargins(14, 0, 10, 0); hl.setSpacing(6)

        for col in (C.RED, C.AMBER, C.GREEN):
            d = QLabel("●")
            d.setStyleSheet(f"color:{col};font-size:7px;")
            hl.addWidget(d)
        hl.addSpacing(6)

        from ui.primitives import make_label
        hl.addWidget(make_label("System Console", 10, C.T2, bold=True))
        hl.addStretch()

        bcl      = Btn("Clear", "ghost", 46, 20)
        self._tog = Btn("▼",    "ghost", 32, 20)
        hl.addWidget(bcl)
        hl.addSpacing(4)
        hl.addWidget(self._tog)

        hdr.mousePressEvent = lambda _: self.toggle()
        self._tog.clicked.connect(self.toggle)

        # ── Log ───────────────────────────────────────────────────────────────
        self._log = Log()
        bcl.clicked.connect(lambda: (self._log.clear(), self._log.sys("cleared")))

        vl.addWidget(hdr)
        vl.addWidget(self._log)

    def toggle(self) -> None:
        self._open = not self._open
        self.setFixedHeight(
            self.EXPANDED if self._open else self.COLLAPSED
        )
        self._log.setVisible(self._open)
        self._tog.setText("▼" if self._open else "▶")

    @property
    def log(self) -> Log:
        return self._log