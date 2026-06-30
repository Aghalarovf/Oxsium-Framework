"""
ui/main_window.py
─────────────────
MainWin — əsas pəncərə.

Bütün controller-ləri SERVICE_DEFS-dən avtomatik qurur.
Yeni servis əlavə etmək üçün yalnız core/config.py-ı dəyişmək kifayətdir.
"""

from __future__ import annotations

import os

from PyQt6.QtCore    import Qt
from PyQt6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel,
    QMainWindow, QVBoxLayout, QWidget,
)

from core.config          import (
    C, FILES, DEFAULT_PORTS, PYTHON, ROOT,
    SERVICE_DEFS, SIDEBAR_ENTRIES, VENV_PYTHON,
)
from core.service_controller import ServiceController
from core.web_controller     import WebController, _stop_http
from ui.primitives           import make_label
from ui.sidebar              import Sidebar
from ui.detail_panel         import ServiceDetailPanel
from ui.console              import CollapsibleConsole


class MainWin(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Oxsium Framework  —  Control Panel")
        self.setMinimumSize(860, 620)
        self.resize(1060, 760)

        self._ctrls: list = []
        self._build()

        # Mərkəzlə
        g = self.geometry()
        s = QApplication.primaryScreen().availableGeometry()
        self.move(
            (s.width()  - g.width())  // 2,
            (s.height() - g.height()) // 2,
        )

    # ── build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        root_w = QWidget()
        root_w.setStyleSheet(f"background:{C.BASE};")
        self.setCentralWidget(root_w)
        ml = QVBoxLayout(root_w)
        ml.setContentsMargins(0, 0, 0, 0)
        ml.setSpacing(0)

        # ── Title bar ─────────────────────────────────────────────────────────
        tb = QWidget(); tb.setFixedHeight(42)
        tb.setStyleSheet(
            f"background:{C.SURF0}; border-bottom:1px solid {C.BDR0};"
        )
        tl = QHBoxLayout(tb); tl.setContentsMargins(14, 0, 16, 0); tl.setSpacing(10)

        logo = QLabel("◈"); logo.setFixedSize(26, 26)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet(
            f"color:{C.BLUE};font-size:14px;background:{C.BLUE_B};"
            f"border:1px solid {C.BLUE}40;border-radius:5px;"
        )
        tl.addWidget(logo)
        tl.addWidget(make_label("Oxsium Framework", 13, C.T0, bold=True))
        tl.addWidget(make_label("·", 12, C.T3))
        tl.addWidget(make_label("Control Panel  v3.0", 11, C.T2))
        tl.addStretch()

        venv_ok = VENV_PYTHON.exists()
        ep = QLabel("● venv" if venv_ok else "● sys-python")
        ep.setStyleSheet(
            f"color:{C.GREEN if venv_ok else C.AMBER};font-size:9px;font-weight:600;"
        )
        tl.addWidget(ep)
        ml.addWidget(tb)

        # ── Body ──────────────────────────────────────────────────────────────
        body = QWidget(); body.setStyleSheet(f"background:{C.BASE};")
        bl = QHBoxLayout(body); bl.setContentsMargins(0, 0, 0, 0); bl.setSpacing(0)

        # Controller-ləri SERVICE_DEFS-dən avtomatik qur
        for key, name, hint, file_key, port_key, tag, col in SERVICE_DEFS:
            self._ctrls.append(
                ServiceController(
                    key     = key,
                    name    = name,
                    hint    = hint,
                    fpath   = FILES[file_key],
                    port    = DEFAULT_PORTS[port_key],
                    tag     = tag,
                    tag_col = col,
                )
            )
        self._ctrls.append(WebController())

        # Console
        self._console = CollapsibleConsole()
        glog = self._console.log

        # Sidebar
        self._sidebar = Sidebar(SIDEBAR_ENTRIES)
        self._sidebar.service_selected.connect(self._on_select)
        self._sidebar.btn_start_all.clicked.connect(self._start_all)
        self._sidebar.btn_stop_all.clicked.connect(self._stop_all)

        # Sidebar işıqlarını controller state-inə wire et
        for i, ctrl in enumerate(self._ctrls):
            light = self._sidebar.light(i)
            def _make(lt, ct):
                def _cb(s): lt.setState(s)
                ct.on_state = _cb
            _make(light, ctrl)

        # Detail panel
        self._detail = ServiceDetailPanel(glog)
        bl.addWidget(self._sidebar)
        bl.addWidget(self._detail, 1)
        ml.addWidget(body, 1)
        ml.addWidget(self._console)

        # ── Footer ────────────────────────────────────────────────────────────
        ft = QWidget(); ft.setFixedHeight(22)
        ft.setStyleSheet(
            f"background:{C.SURF0}; border-top:1px solid {C.BDR0};"
        )
        fl = QHBoxLayout(ft); fl.setContentsMargins(14, 0, 14, 0); fl.setSpacing(14)

        py_l = make_label(str(PYTHON), 9, C.T3); py_l.setToolTip(str(PYTHON))
        wd_l = make_label(str(ROOT),   9, C.T3); wd_l.setToolTip(str(ROOT))
        fl.addWidget(py_l)

        s2 = QFrame(); s2.setFrameShape(QFrame.Shape.VLine)
        s2.setFixedWidth(1); s2.setFixedHeight(14)
        s2.setStyleSheet(f"background:{C.BDR1};border:none;")
        fl.addWidget(s2, 0, Qt.AlignmentFlag.AlignVCenter)
        fl.addWidget(wd_l)
        fl.addStretch()
        fl.addWidget(make_label("Oxsium v3.0", 9, C.T4))
        ml.addWidget(ft)

        # İlk sərvis seç
        self._on_select(0)

    # ── actions ───────────────────────────────────────────────────────────────

    def _on_select(self, idx: int) -> None:
        ctrl = self._ctrls[idx]
        # load_service on_state/on_log-u set edir (detail panel üçün)
        self._detail.load_service(ctrl)
        # Sidebar light-ı da on_state-ə əlavə et
        light = self._sidebar.light(idx)
        detail_on_state = ctrl.on_state
        def _combined(s: int):
            light.setState(s)
            if detail_on_state:
                detail_on_state(s)
        ctrl.on_state = _combined

    def _start_all(self) -> None:
        glog = self._console.log
        glog.info("Starting all services...")
        for ctrl in self._ctrls:
            if isinstance(ctrl, ServiceController):
                try:
                    port = int(ctrl.port_def)
                except (ValueError, TypeError):
                    port = ctrl.port_def
                ctrl.start("0.0.0.0", port, glog)

    def _stop_all(self) -> None:
        glog = self._console.log
        glog.warn("Stopping all services...")
        self._sidebar.btn_start_all.setEnabled(False)
        self._sidebar.btn_stop_all.setEnabled(False)
        for ctrl in self._ctrls:
            ctrl.stop(glog)
        self._sidebar.btn_start_all.setEnabled(True)
        self._sidebar.btn_stop_all.setEnabled(True)
        glog.ok("All services stopped.")

    def closeEvent(self, e) -> None:
        e.ignore()
        for ctrl in self._ctrls:
            try:
                ctrl.kill_nowait()
            except Exception:
                pass
        try:
            _stop_http()
        except Exception:
            pass
        os._exit(0)