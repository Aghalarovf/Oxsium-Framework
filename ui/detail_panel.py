"""
ui/detail_panel.py
──────────────────
ServiceDetailPanel — sağ panel; seçilmiş servisin detallarını göstərir.

Hər servisin öz Log widget-i var (_logs dict).
load_service() çağırıldıqda köhnə log gizlənir, yenisi göstərilir.
"""

from __future__ import annotations

from PyQt6.QtCore    import Qt
from PyQt6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel,
    QStackedWidget, QVBoxLayout, QWidget,
)

from core.config   import C, ROOT, SQLITE_DB_PATH
from ui.primitives import Btn, Field, Log, StatusLight, hline, make_chip, make_label


class ServiceDetailPanel(QWidget):
    def __init__(self, glog: Log, parent=None):
        super().__init__(parent)
        self._glog  = glog
        self._ctrl  = None
        # key -> Log  (hər servisin öz log widget-i)
        self._logs: dict[str, Log] = {}
        self._build()

    # ── build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        vl = QVBoxLayout(self)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        # ── Header ────────────────────────────────────────────────────────────
        hdr = QWidget(); hdr.setFixedHeight(46)
        hdr.setStyleSheet(
            f"background:{C.SURF1}; border-bottom:1px solid {C.BDR0};"
        )
        hl = QHBoxLayout(hdr); hl.setContentsMargins(18, 0, 18, 0); hl.setSpacing(10)

        self._h_icon  = QLabel("◈"); self._h_icon.setFixedWidth(20)
        self._h_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._h_icon.setStyleSheet(f"color:{C.BLUE};font-size:14px;")

        self._h_name  = make_label("Select a service", 13, C.T0, bold=True)
        self._h_hint  = make_label("", 11, C.T2)
        self._h_badge = make_chip("", C.BLUE); self._h_badge.hide()
        self._h_light = StatusLight(8)

        hl.addWidget(self._h_icon)
        hl.addWidget(self._h_name)
        hl.addWidget(self._h_hint)
        hl.addWidget(self._h_badge)
        hl.addStretch()
        hl.addWidget(self._h_light)
        vl.addWidget(hdr)

        # ── Config row ────────────────────────────────────────────────────────
        cfg = QWidget(); cfg.setFixedHeight(80)
        cfg.setStyleSheet(f"background:{C.SURF0};")
        cl = QHBoxLayout(cfg); cl.setContentsMargins(18, 12, 18, 12); cl.setSpacing(0)

        grid = QGridLayout(); grid.setSpacing(4)
        grid.addWidget(make_label("HOST", 9, C.T2, bold=True, spacing=0.8), 0, 0)
        self._f_ip = Field("0.0.0.0", w=130)
        grid.addWidget(self._f_ip, 1, 0)

        sp = QWidget(); sp.setFixedWidth(16)
        grid.addWidget(sp, 0, 1)

        grid.addWidget(make_label("PORT", 9, C.T2, bold=True, spacing=0.8), 0, 2)
        self._f_port = Field("", w=72)
        grid.addWidget(self._f_port, 1, 2)

        sp2 = QWidget(); sp2.setFixedWidth(16)
        grid.addWidget(sp2, 0, 3)

        self._db_label = make_label("DB PATH", 9, C.T2, bold=True, spacing=0.8)
        grid.addWidget(self._db_label, 0, 4)
        self._f_dbpath = Field("", w=220)
        grid.addWidget(self._f_dbpath, 1, 4)
        self._db_label.hide()
        self._f_dbpath.hide()

        cl.addLayout(grid); cl.addSpacing(24)

        vsep = QFrame(); vsep.setFrameShape(QFrame.Shape.VLine)
        vsep.setFixedWidth(1); vsep.setFixedHeight(40)
        vsep.setStyleSheet(f"background:{C.BDR0};border:none;")
        cl.addWidget(vsep, 0, Qt.AlignmentFlag.AlignVCenter); cl.addSpacing(24)

        self._fstat = make_label("", 10, C.T2)
        self._fstat.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        cl.addWidget(self._fstat, 0, Qt.AlignmentFlag.AlignVCenter)
        cl.addStretch()

        self._path_lbl = make_label("", 9, C.TPATH)
        self._path_lbl.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        cl.addWidget(self._path_lbl, 0, Qt.AlignmentFlag.AlignVCenter)
        vl.addWidget(cfg)
        vl.addWidget(hline())

        # ── Button row ────────────────────────────────────────────────────────
        br = QWidget(); br.setFixedHeight(44)
        br.setStyleSheet(
            f"background:{C.SURF1}; border-bottom:1px solid {C.BDR0};"
        )
        bl = QHBoxLayout(br); bl.setContentsMargins(18, 0, 18, 0); bl.setSpacing(6)

        self._b_start = Btn("▶  Start", "success", 88)
        self._b_stop  = Btn("■  Stop",  "danger",  80)
        self._b_file  = Btn("Open File","ghost",   84)
        self._b_start.clicked.connect(self._on_start)
        self._b_stop.clicked.connect(self._on_stop)
        self._b_file.clicked.connect(self._on_open)

        bl.addWidget(self._b_start)
        bl.addWidget(self._b_stop)
        bl.addSpacing(6)
        bl.addWidget(self._b_file)
        bl.addStretch()
        self._pid_lbl = make_label("", 10, C.T2)
        bl.addWidget(self._pid_lbl)
        vl.addWidget(br)

        # ── Log header ────────────────────────────────────────────────────────
        lh = QWidget(); lh.setFixedHeight(28)
        lh.setStyleSheet(
            f"background:{C.SURF2}; border-bottom:1px solid {C.BDR0};"
        )
        ll = QHBoxLayout(lh); ll.setContentsMargins(18, 0, 10, 0); ll.setSpacing(6)
        ll.addWidget(make_label("SERVICE LOG", 9, C.T3, bold=True, spacing=1.0))
        ll.addStretch()
        self._bcl = Btn("Clear", "ghost", 50, h=20)
        self._bcl.clicked.connect(self._on_clear)
        ll.addWidget(self._bcl)
        vl.addWidget(lh)

        # ── Log stack — hər servis üçün ayrı Log widget ───────────────────────
        self._log_stack = QStackedWidget()
        vl.addWidget(self._log_stack, 1)

    # ── log per service ───────────────────────────────────────────────────────

    def _get_log(self, key: str) -> Log:
        """key üçün Log widget-i yarat (yoxdursa) və qaytar."""
        if key not in self._logs:
            log = Log()
            self._logs[key] = log
            self._log_stack.addWidget(log)
        return self._logs[key]

    def _current_log(self) -> Log | None:
        if self._ctrl:
            return self._logs.get(self._ctrl.key)
        return None

    # ── load ──────────────────────────────────────────────────────────────────

    def load_service(self, ctrl) -> None:
        self._ctrl = ctrl

        self._h_name.setText(ctrl.name)
        self._h_hint.setText(ctrl.hint)
        self._h_badge.setText(ctrl.tag)
        self._h_badge.setStyleSheet(
            f"background:{ctrl.tag_col}18; color:{ctrl.tag_col};"
            f"border:1px solid {ctrl.tag_col}35; border-radius:3px;"
            f"padding:1px 6px; font-size:9px; font-weight:700;"
        )
        self._h_badge.show()
        self._h_icon.setStyleSheet(f"color:{ctrl.tag_col};font-size:14px;")
        self._f_port.setText(str(ctrl.port_def))
        self._f_ip.setText("0.0.0.0")

        exists = ctrl.fpath.exists()
        self._fstat.setText("● file found" if exists else "● file missing")
        self._fstat.setStyleSheet(
            f"color:{C.GREEN if exists else C.RED};font-size:10px;font-weight:600;"
        )
        try:
            rel = str(ctrl.fpath.relative_to(ROOT))
        except ValueError:
            rel = str(ctrl.fpath)
        self._path_lbl.setText(rel)
        self._path_lbl.setToolTip(str(ctrl.fpath))

        # Bu servisin log widget-ini aktivləşdir
        slog = self._get_log(ctrl.key)
        self._log_stack.setCurrentWidget(slog)

        # Callbacks — yalnız bu servisin logları bu Log-a yazılır
        ctrl.on_state = self._on_state
        ctrl.on_log   = self._on_log

        # Web vs normal
        if ctrl.key == "web":
            self._b_start.setText("◉  Open")
            self._b_file.setText("Open URL")
        else:
            self._b_start.setText("▶  Start")
            self._b_file.setText("Open File")

        # DB Path sahəsi yalnız sqlite_reader üçün göstərilir
        if ctrl.key == "sqlite_reader":
            self._f_dbpath.setText(str(getattr(ctrl, "db_path", SQLITE_DB_PATH)))
            self._db_label.show()
            self._f_dbpath.show()
        else:
            self._db_label.hide()
            self._f_dbpath.hide()

        self._on_state(1 if ctrl.running else 0)

    # ── callbacks ─────────────────────────────────────────────────────────────

    def _on_state(self, s: int) -> None:
        self._h_light.setState(s)
        running = self._ctrl.running if self._ctrl else False
        pending = (s == StatusLight.PENDING)
        self._b_start.setEnabled(not running and not pending)
        self._b_stop.setEnabled(running or pending)

    def _on_log(self, icon: str, msg: str, col: str) -> None:
        """Aktiv servisin log widget-inə yaz."""
        if self._ctrl:
            self._get_log(self._ctrl.key)._append(icon, msg, col)

    def _on_clear(self) -> None:
        log = self._current_log()
        if log:
            log.clear()
            log.sys("cleared")

    # ── actions ───────────────────────────────────────────────────────────────

    def _on_start(self) -> None:
        if not self._ctrl:
            return
        try:
            port = int(self._f_port.text())
        except ValueError:
            port = self._ctrl.port_def
        ip = self._f_ip.text().strip() or "0.0.0.0"
        if self._ctrl.key == "sqlite_reader":
            db_path = self._f_dbpath.text().strip()
            if db_path:
                self._ctrl.db_path = db_path
        self._ctrl.start(ip, port, self._glog)

    def _on_stop(self) -> None:
        if not self._ctrl:
            return
        self._ctrl.stop(self._glog)

    def _on_open(self) -> None:
        if not self._ctrl:
            return
        self._ctrl.open_file()