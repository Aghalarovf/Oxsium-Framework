"""
core/web_controller.py
──────────────────────
WebController — lokal HTTP static server (Oxsium-Framework.html üçün).

Standalone modul; ServiceController-dan fərqli olaraq subprocess yox,
threading istifadə edir.

HTTP logları terminala yox, UI-a göndərilir (_SilentHandler).
"""

from __future__ import annotations

import http.server
import os
import socketserver
import threading
import webbrowser
from pathlib import Path
from typing import Callable, Optional

from PyQt6.QtCore import QTimer

from .config import C, DEFAULT_PORTS, FILES


# ── Silent HTTP handler ────────────────────────────────────────────────────────
# log_message / log_error override edilir → terminal çıxışı tamamilə gizlənir.
# Bütün 200, 404, xəta mesajları terminala getmir.

class _SilentHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):  # type: ignore[override]
        pass

    def log_error(self, fmt, *args):    # type: ignore[override]
        pass


# ── Module-level server state ──────────────────────────────────────────────────
_http_srv: socketserver.TCPServer | None = None
_http_thd: threading.Thread       | None = None


def _start_http(port: int, html: Path) -> bool:
    """HTTP server-i başladır. Artıq işləyirsə True qaytarır."""
    global _http_srv, _http_thd
    if _http_srv:
        return True
    try:
        os.chdir(str(html.parent))
        socketserver.TCPServer.allow_reuse_address = True
        _http_srv = socketserver.TCPServer(
            ("0.0.0.0", port),
            _SilentHandler,
        )
        _http_thd = threading.Thread(target=_http_srv.serve_forever, daemon=True)
        _http_thd.start()
        return True
    except Exception:
        return False


def _stop_http() -> None:
    """HTTP server-i dayandırır."""
    global _http_srv, _http_thd
    if _http_srv:
        try:
            _http_srv.shutdown()
        except Exception:
            pass
        _http_srv = None
    _http_thd = None


# ══════════════════════════════════════════════════════════════════════════════
class WebController:
    """
    Web Viewer servisinin controller-i.
    ServiceController ilə eyni interfeysə malikdir:
    start / stop / kill_nowait / open_file / running / on_state / on_log
    """

    def __init__(self):
        self.key      = "web"
        self.name     = "Web Viewer"
        self.hint     = "Local HTTP server"
        self.fpath    = FILES["html"]
        self.port_def = DEFAULT_PORTS["http"]
        self.tag      = "HTTP"
        self.tag_col  = C.TEAL
        self._up      = False
        self._url     = ""

        # UI callbacks
        self.on_state: Optional[Callable[[int], None]]           = None
        self.on_log:   Optional[Callable[[str, str, str], None]] = None

    # ── public ────────────────────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._up

    def start(self, host: str, port: int, glog) -> None:
        if not self.fpath.exists():
            if self.on_log:
                self.on_log("✗", "HTML file not found", C.RED)
            glog.err("[WEB] HTML file not found")
            return

        if _start_http(port, self.fpath):
            self._url = f"http://127.0.0.1:{port}/Oxsium-Framework.html"
            self._up  = True
            if self.on_log:
                self.on_log("✓", f"Serving → {self._url}", C.GREEN)
            glog.ok(f"[WEB] Serving :{port}  → {self._url}")
            if self.on_state:
                self.on_state(1)
            QTimer.singleShot(1400, lambda: webbrowser.open(self._url, new=1))
        else:
            if self.on_log:
                self.on_log("✗", "HTTP server failed", C.RED)
            glog.err("[WEB] HTTP server failed.")
            if self.on_state:
                self.on_state(2)

    def stop(self, glog) -> None:
        _stop_http()
        self._up  = False
        self._url = ""
        if self.on_state:
            self.on_state(0)
        if self.on_log:
            self.on_log("!", "Server stopped.", C.AMBER)
        glog.warn("[WEB] Server stopped.")

    def kill_nowait(self) -> None:
        """closeEvent üçün — block etmədən dayandır."""
        _stop_http()
        self._up = False

    def open_file(self) -> None:
        if self._url:
            webbrowser.open(self._url, new=1)