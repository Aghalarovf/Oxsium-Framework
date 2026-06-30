"""
ui/sidebar.py
─────────────
Sidebar UI komponentləri:
  SidebarBtn          — tək servis düyməsi (icon + StatusLight)
  SidebarActionBtn    — Start All / Stop All düymələri
  Sidebar             — tam sidebar paneli

Hər SidebarBtn bərabər stretch alır → hamısı Start/Stop-a qədər bərabər yayılır.
"""

from __future__ import annotations

from PyQt6.QtCore    import Qt, pyqtSignal
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

from core.config   import C
from ui.primitives import StatusLight


# ══════════════════════════════════════════════════════════════════════════════
class SidebarBtn(QWidget):
    clicked = pyqtSignal(int)

    def __init__(self, icon: str, tip: str, idx: int, col: str, parent=None):
        super().__init__(parent)
        self._idx = idx
        self._col = col
        self._sel = False

        # Genişlik sabit, hündürlük elastik (Sidebar stretch ilə idarə edir)
        self.setFixedWidth(C.SB_W)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(tip)

        vl = QVBoxLayout(self)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(4)
        vl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._icon_lbl = QLabel(icon)
        self._icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon_lbl.setFixedSize(32, 26)

        self._light = StatusLight(6)
        lw = QWidget(); lw.setFixedSize(C.SB_W, 8)
        ll = QHBoxLayout(lw); ll.setContentsMargins(0, 0, 0, 0)
        ll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ll.addWidget(self._light)

        vl.addWidget(self._icon_lbl, 0, Qt.AlignmentFlag.AlignCenter)
        vl.addWidget(lw, 0, Qt.AlignmentFlag.AlignCenter)
        self._refresh()

    def _refresh(self) -> None:
        if self._sel:
            self.setStyleSheet(
                f"SidebarBtn{{background:{C.SB_SEL};"
                f"border-right:2px solid {self._col};}}"
            )
            self._icon_lbl.setStyleSheet(
                f"color:{C.T0};font-size:16px;background:transparent;"
            )
        else:
            self.setStyleSheet(
                "SidebarBtn{background:transparent;border-right:2px solid transparent;}"
            )
            self._icon_lbl.setStyleSheet(
                f"color:{C.T2};font-size:16px;background:transparent;"
            )

    def setSelected(self, v: bool) -> None:
        self._sel = v
        self._refresh()

    def light(self) -> StatusLight:
        return self._light

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._idx)
        super().mousePressEvent(e)


# ══════════════════════════════════════════════════════════════════════════════
class SidebarActionBtn(QWidget):
    """Start All / Stop All üçün kiçik icon düyməsi."""

    clicked = pyqtSignal()

    def __init__(self, icon: str, color: str, tip: str, parent=None):
        super().__init__(parent)
        self.setFixedSize(C.SB_W, 40)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(tip)
        self._col = color
        self._hov = False

        vl = QVBoxLayout(self)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl = QLabel(icon)
        self._lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl.setStyleSheet(
            f"color:{color};font-size:14px;background:transparent;"
        )
        vl.addWidget(self._lbl)
        self._refresh()

    def _refresh(self) -> None:
        self.setStyleSheet(
            f"background:{self._col}18;" if self._hov else "background:transparent;"
        )

    def enterEvent(self, e):
        self._hov = True;  self._refresh(); super().enterEvent(e)

    def leaveEvent(self, e):
        self._hov = False; self._refresh(); super().leaveEvent(e)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(e)

    def setEnabled(self, v: bool) -> None:
        super().setEnabled(v)
        alpha = "ff" if v else "44"
        self._lbl.setStyleSheet(
            f"color:{self._col}{alpha};font-size:14px;background:transparent;"
        )


# ══════════════════════════════════════════════════════════════════════════════
class Sidebar(QWidget):
    """
    Sol panel — servis ikonları + Start All / Stop All.

    Hər SidebarBtn bərabər stretch(1) alır → pəncərə böyüdükcə/kiçildikcə
    hamısı bərabər paylaşır və Start/Stop-a qədər dolu olur.
    """

    service_selected = pyqtSignal(int)

    def __init__(self, entries: list[tuple[str, str, str]], parent=None):
        super().__init__(parent)
        self.setFixedWidth(C.SB_W)
        self.setStyleSheet(
            f"background:{C.SB_BG}; border-right:1px solid {C.BDR0};"
        )

        vl = QVBoxLayout(self)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        self._btns: list[SidebarBtn] = []
        for i, (icon, tip, col) in enumerate(entries):
            b = SidebarBtn(icon, tip, i, col)
            b.clicked.connect(self._on_click)
            self._btns.append(b)
            # Hər düymə bərabər stretch alır
            vl.addWidget(b, stretch=1)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background:{C.BDR0};border:none;")
        vl.addWidget(sep)

        # Start All / Stop All — sabit hündürlük, ən aşağıda
        self.btn_start_all = SidebarActionBtn("▶", C.GREEN, "Start All")
        self.btn_stop_all  = SidebarActionBtn("■", C.RED,   "Stop All")
        vl.addWidget(self.btn_start_all)
        vl.addWidget(self.btn_stop_all)
        vl.addSpacing(6)

        if self._btns:
            self._btns[0].setSelected(True)

    def _on_click(self, idx: int) -> None:
        for b in self._btns:
            b.setSelected(False)
        self._btns[idx].setSelected(True)
        self.service_selected.emit(idx)

    def light(self, idx: int) -> StatusLight:
        return self._btns[idx].light()