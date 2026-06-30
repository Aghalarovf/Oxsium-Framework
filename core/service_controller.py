"""
core/service_controller.py
──────────────────────────
ServiceController — bir servisin bütün state-i.

Yeni komanda növü əlavə etmək üçün yalnız CMD_BUILDERS dict-inə
bir lambda/funksiya əlavə edin — başqa heç nəyi dəyişmək lazım deyil.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

from PyQt6.QtCore import QTimer

from .config   import PYTHON, ROOT, C, SQLITE_DB_PATH
from .env_utils import build_env
from .service_runner import ServiceRunner


def _cmd_connection(fp: Path):
    def _f(h: str, p: int):
        return (
            [str(PYTHON), "-u", str(fp)],
            {"PORT": str(p), "HOST": h, "FLASK_ENV": "development"},
        )
    return _f

def _cmd_root(fp: Path):
    return lambda h, p: [str(PYTHON), "-u", str(fp), "server",
                         "--port", str(p), "--ip-address", h]

def _cmd_certificate(fp: Path):
    return lambda h, p: [str(PYTHON), "-u", str(fp)]

def _cmd_server_api(fp: Path):
    return lambda h, p: [str(PYTHON), "-u", str(fp), "--host", h, "--port", str(p)]

def _cmd_sqlite_reader(fp: Path, ctrl=None):
    def _f(h: str, p: int):
        db = str(ctrl.db_path) if ctrl is not None else str(SQLITE_DB_PATH)
        return [str(PYTHON), "-u", str(fp), db, "--port", str(p)]
    return _f


CMD_BUILDERS: dict[str, Callable[[Path], Callable]] = {
    "connection":    _cmd_connection,
    "root":          _cmd_root,
    "certificate":   _cmd_certificate,
    "server_api":    _cmd_server_api,
    "sqlite_reader": _cmd_sqlite_reader,
}



# ══════════════════════════════════════════════════════════════════════════════
class ServiceController:
    """
    Bir servisin tam state-i:
      - start / stop / kill_nowait
      - on_state / on_log callback-ləri (UI tərəfindən set edilir)
    """

    def __init__(
        self,
        key:     str,
        name:    str,
        hint:    str,
        fpath:   Path,
        port:    int,
        tag:     str,
        tag_col: str,
    ):
        self.key      = key
        self.name     = name
        self.hint     = hint
        self.fpath    = fpath
        self.port_def = port
        self.tag      = tag
        self.tag_col  = tag_col

        # sqlite_reader üçün oxunacaq .db faylının yolu (UI-dan dəyişdirilə bilər)
        self.db_path: Path = SQLITE_DB_PATH

        # Komanda funksiyasını avtomatik seç
        builder = CMD_BUILDERS.get(key)
        if builder is None:
            raise ValueError(f"ServiceController: '{key}' üçün CMD_BUILDERS-də qeyd yoxdur.")
        if key == "sqlite_reader":
            self._cmd_fn: Callable = builder(fpath, self)
        else:
            self._cmd_fn: Callable = builder(fpath)

        self._runner: Optional[ServiceRunner] = None
        self._glog                            = None   # set by MainWin
        self._last_url: Optional[str]         = None   # web-based servislər üçün (sqlite_reader)

        self._poll = QTimer()
        self._poll.setInterval(2000)
        self._poll.timeout.connect(self._on_poll)

        # UI callbacks
        self.on_state: Optional[Callable[[int], None]] = None
        self.on_log:   Optional[Callable[[str, str, str], None]] = None

    # ── public ────────────────────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return (
            self._runner is not None
            and self._runner.isRunning()
            and self._runner._proc is not None
            and self._runner._proc.poll() is None
        )

    def start(self, host: str, port: int, glog) -> None:
        self._glog = glog

        if not self.fpath.exists():
            self._emit_log("✗", f"File not found: {self.fpath}", C.RED)
            glog.err(f"[{self.key.upper()}] File not found: {self.fpath}")
            self._set_state(2)  # ERR
            return

        if self._runner and self._runner.isRunning():
            return

        try:
            result  = self._cmd_fn(host, port)
            cmd, ex = result if isinstance(result, tuple) else (result, {})
        except Exception as exc:
            glog.err(f"[{self.key.upper()}] cmd_fn error: {exc}")
            self._set_state(2)
            return

        self._emit_log("→", "$ " + " ".join(str(x) for x in cmd), C.BLUE)
        glog.info(f"[{self.key.upper()}] Starting...")
        self._set_state(3)  # PENDING

        if self.key == "sqlite_reader":
            # sqlite_reader.py həmişə 127.0.0.1-ə bind olunur (host param onun
            # üçün artıq yoxdur) - bu URL yalnız log mesajı üçün saxlanılır,
            # heç bir brauzer açılmır.
            self._last_url = f"http://127.0.0.1:{port}"

        self._runner = ServiceRunner(cmd, ROOT, build_env(ex))
        self._runner.started.connect(self._on_started)
        self._runner.failed.connect(self._on_failed)
        self._runner.log_line.connect(self._on_log_line)
        self._runner.finished_clean.connect(self._on_crashed)
        self._runner.start()

    def stop(self, glog) -> None:
        self._glog = glog
        self._poll.stop()
        if self._runner:
            self._runner.stop()
            self._runner.wait(800)
            self._runner = None
        self._set_state(0)  # OFF
        self._emit_log("!", "Stopped.", C.AMBER)
        glog.warn(f"[{self.key.upper()}] Stopped.")

    def kill_nowait(self) -> None:
        """closeEvent üçün — block etmədən öldür."""
        if self._runner:
            self._runner.stop()

    def open_file(self) -> None:
        try:
            if os.name == "nt":
                os.startfile(str(self.fpath))
            elif sys.platform == "darwin":
                subprocess.Popen(["open",     str(self.fpath)])
            else:
                subprocess.Popen(["xdg-open", str(self.fpath)])
        except Exception:
            pass

    # ── private ───────────────────────────────────────────────────────────────

    def _set_state(self, s: int) -> None:
        if self.on_state:
            self.on_state(s)

    def _emit_log(self, icon: str, msg: str, col: str) -> None:
        if self.on_log:
            self.on_log(icon, msg, col)

    def _on_started(self, pid: int) -> None:
        self._emit_log("✓", f"Running — PID {pid}", C.GREEN)
        if self._glog:
            self._glog.ok(f"[{self.key.upper()}] Running — PID {pid}")
        if self.key == "sqlite_reader" and self._last_url:
            self._emit_log("·", f"API listening at {self._last_url}", C.TCO)
        self._set_state(1)  # ON
        self._poll.start()

    def _on_failed(self, msg: str) -> None:
        self._emit_log("✗", f"Failed: {msg}", C.RED)
        if self._glog:
            self._glog.err(f"[{self.key.upper()}] Failed: {msg}")
        self._set_state(2)  # ERR

    def _on_log_line(self, line: str) -> None:
        self._emit_log("·", line, C.TCO)

    def _on_poll(self) -> None:
        if not self.running:
            self._poll.stop()
            self._runner = None
            self._set_state(2)  # ERR
            self._emit_log("✗", "Process exited unexpectedly!", C.RED)
            if self._glog:
                self._glog.err(f"[{self.key.upper()}] Crashed!")

    def _on_crashed(self) -> None:
        self._poll.stop()
        self._runner = None
        self._set_state(2)
        self._emit_log("✗", "Process exited.", C.RED)
        if self._glog:
            self._glog.err(f"[{self.key.upper()}] Exited.")