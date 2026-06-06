"""
Oxsium Framework — NiceGUI Service Launcher
Run: python launcher.py   (works with venv or system Python)
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

# ── Auto-install nicegui into whichever Python is running this script ─────────
def _ensure_nicegui():
    if importlib.util.find_spec("nicegui") is not None:
        return  # already installed
    print("  [SETUP] nicegui not found — installing into current Python...")
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "nicegui", "--quiet"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print("  [SETUP] nicegui installed successfully.\n")

_ensure_nicegui()

from nicegui import app, ui  # noqa: E402

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
VENV_PYTHON = (
    ROOT / "oxsium"
    / ("Scripts" if os.name == "nt" else "bin")
    / ("python.exe" if os.name == "nt" else "python")
)
PYTHON = VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable)

CONNECTION_PY = ROOT / "Main" / "connect" / "connection.py"
DECISION_PY   = ROOT / "Main" / "Decision Engine" / "Helpers" / "root_principal.py"
HTML_FILE     = ROOT / "Main" / "Oxsium-Framework.html"


# ── Helpers ───────────────────────────────────────────────────────────────────
def _load_port(filepath: Path, attr: str, fallback: int) -> int:
    try:
        spec = importlib.util.spec_from_file_location(filepath.stem, filepath)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return int(getattr(mod, attr, fallback))
    except Exception:
        return fallback


def get_venv_env() -> dict:
    env = os.environ.copy()
    if os.name == "nt":
        env["PATH"] = str(ROOT / "oxsium" / "Scripts") + os.pathsep + env.get("PATH", "")
    else:
        env["PATH"] = str(ROOT / "oxsium" / "bin") + os.pathsep + env.get("PATH", "")
    env["VIRTUAL_ENV"] = str(ROOT / "oxsium")
    return env


def _launch_kwargs() -> dict:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {}


# ── Service state ─────────────────────────────────────────────────────────────
class Service:
    def __init__(self, name: str, script: Path, default_port: int, port_attr: str):
        self.name         = name
        self.script       = script
        self.default_port = default_port
        self.port_attr    = port_attr
        self.proc: subprocess.Popen | None = None
        self.logs: list[str] = []
        self.status  = "stopped"   # stopped | running | error
        self._log_cb = None        # ui callback registered later

    # public port (may be overridden by UI)
    @property
    def port(self) -> int:
        return self._port if hasattr(self, "_port") else self.default_port

    @port.setter
    def port(self, v: int):
        self._port = v

    def add_log(self, line: str):
        ts = time.strftime("%H:%M:%S")
        self.logs.append(f"[{ts}]  {line}")
        if len(self.logs) > 500:
            self.logs = self.logs[-400:]
        if self._log_cb:
            self._log_cb()

    def start(self, ip: str):
        if self.proc and self.proc.poll() is None:
            return
        if not self.script.exists():
            self.status = "error"
            self.add_log(f"ERROR: script not found → {self.script}")
            return

        cmd = [str(PYTHON), str(self.script)]
        if self.name == "Decision Engine":
            cmd += ["server", "--ip", ip, "--port", str(self.port)]
        else:
            cmd += ["--ip", ip, "--port", str(self.port)]

        self.add_log(f"Starting: {' '.join(cmd)}")
        try:
            self.proc = subprocess.Popen(
                cmd,
                cwd=str(ROOT),
                env=get_venv_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                **_launch_kwargs(),
            )
            self.status = "running"
            self.add_log(f"PID {self.proc.pid} — listening on {ip}:{self.port}")
            threading.Thread(target=self._tail, daemon=True).start()
            threading.Thread(target=self._watch, daemon=True).start()
        except Exception as exc:
            self.status = "error"
            self.add_log(f"LAUNCH ERROR: {exc}")

    def _tail(self):
        try:
            for line in self.proc.stdout:
                self.add_log(line.rstrip())
        except Exception:
            pass

    def _watch(self):
        code = self.proc.wait()
        if self.status == "running":
            self.status = "error" if code != 0 else "stopped"
            self.add_log(f"Process exited — code {code}")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.add_log("Stopping…")
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            self.add_log("Stopped.")
        self.status = "stopped"
        self.proc = None


SERVICES = [
    Service("Connection API",  CONNECTION_PY, _load_port(CONNECTION_PY, "PORT", 5000), "PORT"),
    Service("Decision Engine", DECISION_PY,   _load_port(DECISION_PY,   "PORT", 5100), "PORT"),
]


# ── UI ────────────────────────────────────────────────────────────────────────
def build_ui():
    # global dark theme + Oxsium palette
    ui.add_head_html("""
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
      :root {
        --bg-deep:   #0a0a0a;
        --bg-base:   #111111;
        --bg-panel:  #1a1a1a;
        --bg-card:   #1f1f1f;
        --bg-input:  #141414;
        --border:    #2a2a2a;
        --border-hi: #3d3d3d;
        --accent:    #cc1a1a;
        --accent-d:  #7a0f0f;
        --accent-g:  rgba(204,26,26,.13);
        --green:     #4caf50;
        --amber:     #9e9e9e;
        --red:       #cc1a1a;
        --text-pri:  #d4d4d4;
        --text-sec:  #7a7a7a;
        --text-hi:   #f5f5f5;
        --mono:      'Share Tech Mono', monospace;
        --head:      'Rajdhani', sans-serif;
        --ui:        'Space Mono', monospace;
      }
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body, .nicegui-content { background: var(--bg-deep) !important; }

      /* topbar */
      .ox-topbar {
        background: var(--bg-base);
        border-bottom: 1px solid var(--border);
        padding: 0 24px;
        height: 52px;
        display: flex;
        align-items: center;
        gap: 14px;
        position: sticky; top: 0; z-index: 100;
      }
      .ox-logo-mark {
        width: 32px; height: 32px;
        background: var(--accent);
        clip-path: polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);
        display: flex; align-items: center; justify-content: center;
        font-family: var(--head); font-weight: 700; font-size: 13px;
        color: #fff; letter-spacing: 1px; flex-shrink: 0;
      }
      .ox-title {
        font-family: var(--head);
        font-size: 18px; font-weight: 700;
        color: var(--text-hi); letter-spacing: 2px;
        text-transform: uppercase;
      }
      .ox-sub {
        font-family: var(--mono);
        font-size: 10px; color: var(--text-sec);
        letter-spacing: 1px;
        border-left: 2px solid var(--border);
        padding-left: 12px;
        margin-left: 4px;
      }
      .ox-badge {
        margin-left: auto;
        font-family: var(--mono);
        font-size: 9px; color: var(--accent);
        border: 1px solid var(--accent-d);
        padding: 2px 8px; border-radius: 3px;
        letter-spacing: 1.5px; text-transform: uppercase;
        background: var(--accent-g);
      }

      /* global controls bar */
      .ox-ctrl-bar {
        background: var(--bg-panel);
        border-bottom: 1px solid var(--border);
        padding: 10px 24px;
        display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
      }
      .ox-ctrl-label {
        font-family: var(--head);
        font-size: 11px; font-weight: 700; letter-spacing: 1.5px;
        color: var(--text-sec); text-transform: uppercase;
      }

      /* service grid */
      .ox-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(520px, 1fr));
        gap: 20px;
        padding: 20px 24px;
      }

      /* service card */
      .ox-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 6px;
        overflow: hidden;
        display: flex; flex-direction: column;
        transition: border-color .2s;
      }
      .ox-card.running  { border-color: rgba(76,175,80,.35); }
      .ox-card.error    { border-color: rgba(204,26,26,.5); }

      .ox-card-header {
        padding: 14px 16px 12px;
        border-bottom: 1px solid var(--border);
        display: flex; align-items: center; gap: 12px;
        background: var(--bg-panel);
      }
      .ox-status-dot {
        width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
        background: var(--text-sec);
        transition: background .3s;
      }
      .ox-status-dot.running { background: var(--green); box-shadow: 0 0 6px var(--green); animation: pulse 2s infinite; }
      .ox-status-dot.error   { background: var(--red);   box-shadow: 0 0 6px var(--red); }

      @keyframes pulse {
        0%,100% { opacity: 1; } 50% { opacity: .5; }
      }

      .ox-svc-name {
        font-family: var(--head);
        font-size: 15px; font-weight: 700; letter-spacing: 1.2px;
        color: var(--text-hi); text-transform: uppercase;
      }
      .ox-svc-status {
        font-family: var(--mono);
        font-size: 10px; color: var(--text-sec); margin-top: 1px;
      }
      .ox-svc-status.running { color: var(--green); }
      .ox-svc-status.error   { color: var(--red); }

      /* port / ip row */
      .ox-config-row {
        display: flex; align-items: center; gap: 8px;
        padding: 10px 16px; border-bottom: 1px solid var(--border);
        background: var(--bg-base);
        flex-wrap: wrap;
      }
      .ox-config-label {
        font-family: var(--mono);
        font-size: 10px; color: var(--text-sec);
        letter-spacing: .8px; width: 36px; text-align: right;
        text-transform: uppercase;
      }
      /* override NiceGUI input */
      .ox-config-row .q-field { min-width: 0 !important; }
      .ox-config-row .q-field__control { background: var(--bg-input) !important; }
      .ox-config-row .q-field__native { color: var(--text-hi) !important; font-family: var(--mono) !important; font-size: 12px !important; }

      /* log area */
      .ox-log-header {
        padding: 7px 16px;
        background: var(--bg-base);
        border-bottom: 1px solid var(--border);
        display: flex; align-items: center; gap: 8px;
      }
      .ox-log-title {
        font-family: var(--head); font-size: 10px; font-weight: 700;
        color: var(--text-sec); letter-spacing: 1.5px; text-transform: uppercase;
      }
      .ox-log-count {
        margin-left: auto;
        font-family: var(--mono); font-size: 9px; color: var(--text-dim, #555);
      }
      .ox-log-box {
        flex: 1; min-height: 220px; max-height: 320px;
        overflow-y: auto;
        padding: 12px 16px;
        background: var(--bg-deep);
        font-family: var(--mono); font-size: 11px; line-height: 1.65;
        color: #888;
        white-space: pre-wrap; word-break: break-all;
      }
      .ox-log-box::-webkit-scrollbar { width: 4px; }
      .ox-log-box::-webkit-scrollbar-track { background: transparent; }
      .ox-log-box::-webkit-scrollbar-thumb { background: var(--border-hi); border-radius: 2px; }

      .ox-log-line { display: block; }
      .ox-log-line .ts { color: var(--text-dim, #444); }
      .ox-log-line .body { color: #9e9e9e; }
      .ox-log-line.err .body  { color: var(--red); }
      .ox-log-line.warn .body { color: #a5855a; }
      .ox-log-line.ok .body   { color: var(--green); }

      /* card footer */
      .ox-card-footer {
        padding: 10px 16px;
        border-top: 1px solid var(--border);
        background: var(--bg-panel);
        display: flex; align-items: center; gap: 8px;
      }

      /* buttons */
      .ox-btn {
        font-family: var(--head); font-weight: 700; font-size: 12px;
        letter-spacing: 1.2px; text-transform: uppercase;
        border: 1px solid; border-radius: 4px;
        padding: 5px 16px; cursor: pointer;
        transition: background .15s, color .15s;
        background: transparent;
      }
      .ox-btn-run  { color: var(--green); border-color: rgba(76,175,80,.4); }
      .ox-btn-run:hover { background: rgba(76,175,80,.1); }
      .ox-btn-stop { color: var(--red);   border-color: rgba(204,26,26,.4); }
      .ox-btn-stop:hover { background: rgba(204,26,26,.1); }
      .ox-btn-clear { color: var(--text-sec); border-color: var(--border); font-size: 10px; padding: 4px 10px; }
      .ox-btn-clear:hover { background: var(--bg-hover, #202020); }
      .ox-btn-all  { color: var(--text-hi); border-color: var(--border-hi); }
      .ox-btn-all:hover { background: rgba(255,255,255,.05); }
      .ox-btn-all-stop { color: var(--amber); border-color: rgba(158,158,158,.3); }
      .ox-btn-all-stop:hover { background: rgba(158,158,158,.07); }

      /* info strip */
      .ox-info-strip {
        padding: 8px 24px;
        background: var(--bg-panel);
        border-top: 1px solid var(--border);
        display: flex; gap: 24px; flex-wrap: wrap;
      }
      .ox-info-item {
        font-family: var(--mono); font-size: 10px; color: var(--text-sec);
        display: flex; gap: 6px; align-items: center;
      }
      .ox-info-item span { color: var(--text-pri); }
    </style>
    """)

    # ── Topbar ─────────────────────────────────────────────────────────────
    with ui.element("div").classes("ox-topbar"):
        ui.element("div").classes("ox-logo-mark").style("font-size:11px").bind_text_from({}, "OX")
        ui.html('<div class="ox-logo-mark">OX</div><div class="ox-title">Oxsium Framework</div>')
        ui.html('<div class="ox-sub">Service Launcher v2</div>')
        ui.html('<div class="ox-badge">Control Panel</div>')

    # shared IP input value
    shared_ip = {"value": "0.0.0.0"}

    # ── Global controls ────────────────────────────────────────────────────
    with ui.element("div").classes("ox-ctrl-bar"):
        ui.html('<span class="ox-ctrl-label">Global IP</span>')
        global_ip = ui.input(value="0.0.0.0").style(
            "width:150px; background:#141414; border:1px solid #2a2a2a; "
            "border-radius:4px; padding:4px 8px; color:#d4d4d4; "
            "font-family:'Share Tech Mono',monospace; font-size:12px;"
        ).props("dense outlined dark")
        global_ip.style("margin-right:8px")

        def start_all():
            for svc in SERVICES:
                svc.port = svc._port if hasattr(svc, "_port") else svc.default_port
                svc.start(global_ip.value)
            refresh_all()

        def stop_all():
            for svc in SERVICES:
                svc.stop()
            refresh_all()

        ui.button("▶  Start All", on_click=start_all).props("flat").style(
            "font-family:'Rajdhani',sans-serif; font-weight:700; font-size:12px; "
            "letter-spacing:1.2px; color:#4caf50; border:1px solid rgba(76,175,80,.4); "
            "border-radius:4px; padding:4px 14px; text-transform:uppercase;"
        )
        ui.button("■  Stop All", on_click=stop_all).props("flat").style(
            "font-family:'Rajdhani',sans-serif; font-weight:700; font-size:12px; "
            "letter-spacing:1.2px; color:#9e9e9e; border:1px solid rgba(158,158,158,.3); "
            "border-radius:4px; padding:4px 14px; text-transform:uppercase;"
        )

    # ── Service cards ──────────────────────────────────────────────────────
    card_refresh_fns: list = []

    with ui.element("div").classes("ox-grid"):
        for svc in SERVICES:
            _build_service_card(svc, global_ip, card_refresh_fns)

    def refresh_all():
        for fn in card_refresh_fns:
            fn()

    # auto-refresh every 1 s
    ui.timer(1.0, refresh_all)

    # ── Info strip ─────────────────────────────────────────────────────────
    ui.html(f"""
    <div class="ox-info-strip">
      <div class="ox-info-item">Python <span>{PYTHON}</span></div>
      <div class="ox-info-item">Venv <span>{'found' if VENV_PYTHON.exists() else 'not found — using system Python'}</span></div>
      <div class="ox-info-item">Connection Script <span>{'✓' if CONNECTION_PY.exists() else '✗ missing'}</span></div>
      <div class="ox-info-item">Decision Script <span>{'✓' if DECISION_PY.exists() else '✗ missing'}</span></div>
    </div>
    """)


def _build_service_card(svc: Service, global_ip_input, refresh_list: list):
    """Builds one service card and registers its refresh function."""

    card_el     = ui.element("div").classes("ox-card")
    header_el   = None
    dot_el      = None
    status_el   = None
    log_el      = None
    port_input  = None

    with card_el:
        # header
        with ui.element("div").classes("ox-card-header") as header_el:
            dot_el = ui.element("div").classes("ox-status-dot")
            with ui.element("div"):
                ui.html(f'<div class="ox-svc-name">{svc.name}</div>')
                status_el = ui.element("div").classes("ox-svc-status").style("font-family:'Share Tech Mono',monospace; font-size:10px; color:#7a7a7a;")
                with status_el:
                    ui.label("● STOPPED")

        # config row
        with ui.element("div").classes("ox-config-row"):
            ui.html('<span class="ox-config-label">PORT</span>')
            port_input = ui.number(value=svc.default_port, min=1, max=65535).style(
                "width:90px; background:#141414; border:1px solid #2a2a2a; "
                "border-radius:4px; padding:3px 8px; color:#f5f5f5; "
                "font-family:'Share Tech Mono',monospace; font-size:12px;"
            ).props("dense outlined dark")

            ui.html('<span class="ox-config-label" style="margin-left:12px;">IP</span>')
            ui.html(f'<span style="font-family:\'Share Tech Mono\',monospace; font-size:11px; color:#7a7a7a;">→ uses global IP</span>')

        # log header
        with ui.element("div").classes("ox-log-header"):
            ui.html('<span class="ox-log-title">Output Log</span>')
            log_count_el = ui.element("span").classes("ox-log-count")
            with log_count_el:
                ui.label("0 lines")

        # log body
        log_el = ui.element("div").classes("ox-log-box")

        # footer buttons
        with ui.element("div").classes("ox-card-footer"):
            def make_start(s=svc, pi=port_input):
                def _start():
                    s.port = int(pi.value or s.default_port)
                    s.start(global_ip_input.value)
                return _start

            def make_stop(s=svc):
                def _stop():
                    s.stop()
                return _stop

            def make_clear(s=svc):
                def _clear():
                    s.logs.clear()
                return _clear

            ui.button("▶ Start", on_click=make_start()).props("flat").style(
                "font-family:'Rajdhani',sans-serif; font-weight:700; font-size:12px; "
                "letter-spacing:1.2px; color:#4caf50; border:1px solid rgba(76,175,80,.4); "
                "border-radius:4px; padding:4px 14px; text-transform:uppercase;"
            )
            ui.button("■ Stop", on_click=make_stop()).props("flat").style(
                "font-family:'Rajdhani',sans-serif; font-weight:700; font-size:12px; "
                "letter-spacing:1.2px; color:#cc1a1a; border:1px solid rgba(204,26,26,.4); "
                "border-radius:4px; padding:4px 14px; text-transform:uppercase;"
            )
            ui.element("div").style("flex:1")
            ui.button("Clear", on_click=make_clear()).props("flat").style(
                "font-family:'Rajdhani',sans-serif; font-weight:600; font-size:10px; "
                "letter-spacing:1px; color:#7a7a7a; border:1px solid #2a2a2a; "
                "border-radius:4px; padding:3px 10px; text-transform:uppercase;"
            )

    # ── refresh closure ────────────────────────────────────────────────────
    def refresh():
        st = svc.status
        # card border class
        card_el._props["class"] = f"ox-card {st}"

        # dot
        dot_el._props["class"] = f"ox-status-dot {st}"

        # status text + color
        status_el.clear()
        color_map = {"running": "#4caf50", "error": "#cc1a1a", "stopped": "#7a7a7a"}
        label_map = {"running": "● RUNNING", "error": "● ERROR",   "stopped": "● STOPPED"}
        with status_el:
            ui.label(label_map.get(st, st.upper())).style(
                f"font-family:'Share Tech Mono',monospace; font-size:10px; color:{color_map.get(st,'#7a7a7a')};"
            )

        # logs
        log_el.clear()
        with log_el:
            for line in svc.logs[-300:]:
                low = line.lower()
                cls = "err" if any(k in low for k in ("error","xeta","traceback","critical","fail")) \
                     else "ok" if any(k in low for k in ("start","listen","pid","ok","success","running")) \
                     else "warn" if any(k in low for k in ("warn","xeberdarl")) \
                     else ""
                # split timestamp from body
                if line.startswith("[") and "]" in line:
                    ts, body = line.split("]", 1)
                    html_line = (
                        f'<span class="ts">{ts}]</span>'
                        f'<span class="body">{body}</span>'
                    )
                else:
                    html_line = f'<span class="body">{line}</span>'
                ui.html(f'<span class="ox-log-line {cls}">{html_line}</span>')

        # line count
        log_count_el.clear()
        with log_count_el:
            ui.label(f"{len(svc.logs)} lines").style(
                "font-family:'Share Tech Mono',monospace; font-size:9px; color:#444;"
            )

        # auto-scroll via JS
        ui.run_javascript(
            f"var el=document.querySelectorAll('.ox-log-box')[{SERVICES.index(svc)}];"
            "if(el) el.scrollTop=el.scrollHeight;"
        )

    refresh_list.append(refresh)


# ── Entry point ───────────────────────────────────────────────────────────────
@ui.page("/")
def index():
    build_ui()


if __name__ in ("__main__", "__mp_main__"):
    ui.run(
        title="Oxsium Framework — Launcher",
        favicon="🔺",
        dark=True,
        port=8080,
        reload=False,
        show=True,
    )