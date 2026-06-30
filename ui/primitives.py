"""
ui/primitives.py
────────────────
Əsas UI komponentləri:
  StatusLight, Btn, Field, Log
  _hline, _label, _chip  (factory funksiyaları)

Hamısı theme-dən (core.config.C) istifadə edir.
"""

from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore    import Qt, QTimer
from PyQt6.QtGui     import QBrush, QColor, QPainter, QTextCursor
from PyQt6.QtWidgets import QFrame, QLabel, QLineEdit, QPushButton, QTextEdit, QWidget

from core.config import C


# ══════════════════════════════════════════════════════════════════════════════
class StatusLight(QWidget):
    """Animasiyalı LED göstəricisi. setState(int) ilə idarə olunur."""

    OFF     = 0
    ON      = 1
    ERR     = 2
    PENDING = 3

    _DOT  = {OFF: C.T3,   ON: C.GREEN, ERR: C.RED,   PENDING: C.AMBER}
    _GLOW = {OFF: None,   ON: C.GREEN, ERR: C.RED,   PENDING: C.AMBER}

    def __init__(self, size: int = 8, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._st  = self.OFF
        self._ph  = 0.0
        self._dir = 1
        self._t   = QTimer(self)
        self._t.setInterval(40)
        self._t.timeout.connect(self._tick)

    def setState(self, s: int) -> None:
        self._st = s
        if s in (self.ON, self.ERR, self.PENDING):
            self._t.start()
        else:
            self._t.stop()
            self._ph = 0
            self.update()

    def _tick(self) -> None:
        self._ph = max(0.0, min(1.0, self._ph + 0.04 * self._dir))
        if self._ph in (0.0, 1.0):
            self._dir *= -1
        self.update()

    def paintEvent(self, _) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        sz = self.width()
        gc = self._GLOW[self._st]
        if gc and self._ph > 0.02:
            g = QColor(gc)
            g.setAlpha(int(55 * self._ph))
            p.setBrush(QBrush(g))
            r  = int(sz // 2 + self._ph * 3)
            cx = sz // 2
            p.drawEllipse(cx - r, cx - r, r * 2, r * 2)
        p.setBrush(QBrush(QColor(self._DOT[self._st])))
        p.drawEllipse(1, 1, sz - 2, sz - 2)


# ══════════════════════════════════════════════════════════════════════════════
class Btn(QPushButton):
    """
    Rəngli düymə. variant = "success" | "danger" | "primary" | "ghost" | "amber"
    """

    _STYLES: dict[str, tuple[str, str, str]] = {
        "success": (C.GREEN,  C.GREEN_B, C.T0),
        "danger":  (C.RED,    C.RED_B,   C.T0),
        "primary": (C.BLUE,   C.BLUE_B,  C.T0),
        "ghost":   (C.BDR2,   C.SURF2,   C.T1),
        "amber":   (C.AMBER,  C.AMBER_B, C.T0),
    }

    def __init__(self, label: str, variant: str = "primary",
                 w: int | None = None, h: int = 26, parent=None):
        super().__init__(label, parent)
        self._v   = variant
        self._hov = False
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(h)
        if w:
            self.setFixedWidth(w)
        self._draw()

    def _draw(self) -> None:
        ac, bg, tc = self._STYLES[self._v]
        fill = ac if self._hov else bg
        self.setStyleSheet(f"""
            QPushButton {{
                background:{fill}; color:{tc};
                border:1px solid {ac}55; border-radius:4px;
                padding:0 12px; font-size:11px; font-weight:600;
            }}
            QPushButton:pressed  {{ background:{ac}; border-color:{ac}; }}
            QPushButton:disabled {{ background:{C.SURF1}; color:{C.T3}; border-color:{C.BDR0}; }}
        """)

    def enterEvent(self, e):
        self._hov = True
        self._draw()
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._hov = False
        self._draw()
        super().leaveEvent(e)


# ══════════════════════════════════════════════════════════════════════════════
class Field(QLineEdit):
    """Stilizə edilmiş input sahəsi."""

    def __init__(self, val: str = "", w: int | None = None, parent=None):
        super().__init__(val, parent)
        if w:
            self.setFixedWidth(w)
        self.setFixedHeight(24)
        self.setStyleSheet(f"""
            QLineEdit {{
                background:{C.SURF0}; color:{C.T0};
                border:1px solid {C.BDR1}; border-radius:4px;
                padding:0 8px; font-size:11px;
            }}
            QLineEdit:focus {{ border-color:{C.BLUE}; background:{C.SURF1}; }}
            QLineEdit:hover {{ border-color:{C.BDR2}; }}
        """)


# ══════════════════════════════════════════════════════════════════════════════
class Log(QTextEdit):
    """
    Rəngli log paneli.
    ok / err / warn / info / sys / svc metodları ilə istifadə edin.
    """

    _ICONS: dict[str, str] = {
        "✓": C.GREEN, "✗": C.RED, "!": C.AMBER, "→": C.BLUE, "·": C.T2,
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setStyleSheet(f"""
            QTextEdit {{
                background:{C.BASE}; color:{C.TCO}; border:none;
                padding:6px 12px;
                font-family:'JetBrains Mono','Cascadia Code','Consolas',monospace;
                font-size:10px;
            }}
        """)
        self._append("·", "console ready", C.T2)

    def _ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _append(self, icon: str, msg: str, col: str) -> None:
        self.moveCursor(QTextCursor.MoveOperation.End)
        self.insertHtml(
            f'<span style="color:{C.T3};font-size:9px;">{self._ts()}</span>'
            f'&nbsp;&nbsp;<span style="color:{col};">{icon}</span>'
            f'&nbsp;<span style="color:{col};">{msg}</span><br>'
        )
        self.moveCursor(QTextCursor.MoveOperation.End)

    def ok(self,   m: str) -> None: self._append("✓", m, C.GREEN)
    def err(self,  m: str) -> None: self._append("✗", m, C.RED)
    def warn(self, m: str) -> None: self._append("!", m, C.AMBER)
    def info(self, m: str) -> None: self._append("→", m, C.BLUE)
    def sys(self,  m: str) -> None: self._append("·", m, C.T2)
    def svc(self,  m: str) -> None: self._append("·", m, C.TCO)


# ══════════════════════════════════════════════════════════════════════════════
# Factory helpers
# ══════════════════════════════════════════════════════════════════════════════

def hline() -> QFrame:
    """1px horizontal separator."""
    f = QFrame()
    f.setFrameShape(QFrame.Shape.HLine)
    f.setFixedHeight(1)
    f.setStyleSheet(f"background:{C.BDR0}; border:none;")
    return f


def make_label(text: str, size: int = 11, color: str | None = None,
               bold: bool = False, spacing: float | None = None) -> QLabel:
    lbl = QLabel(text)
    s   = f"color:{color or C.T1}; font-size:{size}px;"
    if bold:    s += " font-weight:700;"
    if spacing: s += f" letter-spacing:{spacing}px;"
    lbl.setStyleSheet(s)
    return lbl


def make_chip(text: str, color: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"background:{color}18; color:{color}; border:1px solid {color}35;"
        f" border-radius:3px; padding:1px 6px; font-size:9px; font-weight:700;"
    )
    return lbl