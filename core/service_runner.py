"""
core/service_runner.py
──────────────────────
ServiceRunner — tək QThread; prosesi açır, stdout oxuyur.

stop() çağırıldıqda:
  1. Proses terminate/kill olunur.
  2. stdout bağlanır.
  3. run() içindəki for-loop öz-özünə çıxır → thread biter.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal


class ServiceRunner(QThread):
    started        = pyqtSignal(int)   # pid
    failed         = pyqtSignal(str)   # xəta mesajı
    log_line       = pyqtSignal(str)   # stdout sətri
    finished_clean = pyqtSignal()      # proses öz-özünə dayandı

    def __init__(self, cmd: list, cwd: Path, env: dict, parent=None):
        super().__init__(parent)
        self._cmd  = cmd
        self._cwd  = cwd
        self._env  = env
        self._proc: subprocess.Popen | None = None

    # ── public ────────────────────────────────────────────────────────────────

    def stop(self) -> None:
        """
        UI thread-dən çağırılır.
        Prosesi öldürür, stdout-u bağlayır → run() for-loop öz-özünə çıxır.
        """
        proc = self._proc
        if proc is None:
            return

        try:
            if proc.poll() is None:
                if os.name == "nt":
                    proc.kill()
                else:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
        except Exception:
            pass

        try:
            if proc.stdout and not proc.stdout.closed:
                proc.stdout.close()
        except Exception:
            pass

    # ── QThread.run ───────────────────────────────────────────────────────────

    def run(self) -> None:
        flags = ({"creationflags": subprocess.CREATE_NO_WINDOW}
                 if os.name == "nt"
                 else {"start_new_session": True})

        try:
            self._proc = subprocess.Popen(
                self._cmd,
                cwd=str(self._cwd),
                env=self._env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                **flags,
            )
        except Exception as exc:
            self.failed.emit(str(exc))
            return

        self.started.emit(self._proc.pid)

        # stdout oxu — stop() stdout-u bağlayana qədər davam edir
        try:
            for raw in self._proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue
                self.log_line.emit(line)
        except Exception:
            pass

        # Proses öz-özünə dayandısa (crash / normal çıxış)
        if self._proc and self._proc.poll() is not None:
            self.finished_clean.emit()