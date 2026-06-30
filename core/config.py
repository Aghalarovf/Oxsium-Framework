"""
core/config.py
──────────────
Bütün sabit dəyərlər: yollar, portlar, rənglər, QSS.
Yeni servis əlavə etmək üçün yalnız FILES, DEFAULT_PORTS
və SERVICE_DEFS-i genişləndirmək kifayətdir.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT        = Path(__file__).resolve().parent.parent
VENV_PYTHON = (ROOT / "oxsium"
               / ("Scripts" if os.name == "nt" else "bin")
               / ("python.exe" if os.name == "nt" else "python"))
PYTHON      = VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable)

FILES: dict[str, Path] = {
    "connection":    ROOT / "Main" / "connect"             / "connection.py",
    "root":          ROOT / "Main" / "Decision Engine"     / "Helpers" / "root_principal.py",
    "certificate":   ROOT / "Main" / "Certificate Service" / "connect_certificate.py",
    "server_api":    ROOT / "Main" / "Agent Generator"     / "server_api.py",
    "sqlite_reader": ROOT / "Main" / "SQLite Engine"              / "sqlite_reader.py",
    "html":          ROOT / "Main" / "Oxsium-Framework.html",
}

DEFAULT_PORTS: dict[str, int] = {
    "connection":    30100,
    "root":          30101,
    "certificate":   30102,
    "server_api":    30103,
    "sqlite_reader": 30104,
    "http":          30200,
}

# setproctitle ilə hər servisin proses adı (bax: əlaqəli servis skriptləri)
PROC_TITLES: dict[str, str] = {
    "connection":    "Oxsium:LDAP Engine",
    "root":          "Oxsium:Decision Engine",
    "certificate":   "Oxsium:AD CS Enumeration",
    "server_api":    "Oxsium:Central Server",
    "sqlite_reader": "Oxsium:DB Server",
    "web":           "Oxsium:Web Panel",
}

# sqlite_reader-in oxuyacağı domain_data.db faylının yolu.
# Lazım gəldikdə UI-dan dəyişdirilə bilər (bax: ui/detail_panel.py — DB Path sahəsi).
SQLITE_DB_PATH: Path = ROOT / "Main" / "Domain Object" / "domain_data.db"


# ── Colour palette ─────────────────────────────────────────────────────────────
class C:
    BASE    = "#0B0F18"; SURF0   = "#0E1420"; SURF1   = "#121926"
    SURF2   = "#16202E"; SURF3   = "#1A2535"
    BDR0    = "#1C2535"; BDR1    = "#222E42"; BDR2    = "#2A3A54"
    BLUE    = "#4A85D4"; BLUE_B  = "#162240"
    GREEN   = "#3AAF78"; GREEN_B = "#0F2E1C"
    RED     = "#C45060"; RED_B   = "#3A1018"
    AMBER   = "#C4904A"; AMBER_B = "#3A2810"
    PURPLE  = "#8878D4"; TEAL    = "#3AACAC"
    T0      = "#D8E5F5"; T1      = "#8AA4C0"; T2  = "#526A84"
    T3      = "#2E4258"; T4      = "#1A2E42"
    TCO     = "#3A8AC0"; TPATH   = "#324E6A"
    SB_BG   = "#090D14"; SB_SEL  = "#131C2A"; SB_W = 52


# ── Global stylesheet ──────────────────────────────────────────────────────────
QSS = f"""
* {{ font-family: 'Segoe UI','SF Pro Text',Arial,sans-serif; font-size:12px; outline:none; }}
QWidget     {{ background: transparent; color: {C.T0}; }}
QMainWindow {{ background: {C.BASE}; }}
QScrollBar:vertical   {{ background:{C.BASE}; width:4px; border:none; margin:0; }}
QScrollBar::handle:vertical        {{ background:{C.BDR2}; border-radius:2px; min-height:24px; }}
QScrollBar::handle:vertical:hover  {{ background:{C.BLUE}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}
QScrollBar:horizontal {{ height:0; }}
QToolTip {{ background:{C.SURF3}; color:{C.T0}; border:1px solid {C.BDR2};
            padding:4px 8px; border-radius:4px; font-size:11px; }}
"""


# ── Service definitions ────────────────────────────────────────────────────────
# Yeni servis əlavə etmək istəyirsinizsə, yalnız bu siyahıya bir sətir əlavə edin.
# Format: (key, name, hint, file_key, port_key, tag, tag_colour)
#
# cmd_fn avtomatik olaraq key-ə görə seçilir (bax core/service_controller.py).
# Əgər xüsusi komanda lazımdırsa, ServiceController.CMD_BUILDERS dict-inə əlavə edin.

SERVICE_DEFS: list[tuple] = [
    # key             name             hint                         file_key        port_key        tag      colour
    ("connection",    "Connection",     "LDAP / Active Directory",   "connection",    "connection",    "LDAP",  C.BLUE),
    ("root",          "Root Principal", "Decision Engine · Helpers", "root",          "root",          "ENGINE",C.PURPLE),
    ("certificate",   "Certificate",    "PKI / SSL / TLS",           "certificate",   "certificate",   "PKI",   C.AMBER),
    ("server_api",    "Server API",     "REST Gateway",              "server_api",    "server_api",    "REST",  C.TEAL),
    ("sqlite_reader", "DB Reader",      "SQLite Domain Data Viewer", "sqlite_reader", "sqlite_reader", "DB",    C.GREEN),
]

# Sidebar icon / tooltip / colour (SERVICE_DEFS ilə eyni sırada + web)
SIDEBAR_ENTRIES: list[tuple[str, str, str]] = [
    ("⇌", "Connection  (LDAP/AD)",            C.BLUE),
    ("⚙", "Root Principal  (Decision Engine)", C.PURPLE),
    ("⊕", "Certificate  (PKI/SSL/TLS)",        C.AMBER),
    ("⊞", "Server API  (REST Gateway)",         C.TEAL),
    ("⛁", "DB Reader  (SQLite Domain Data)",    C.GREEN),
    ("◉", "Web Viewer  (HTTP Server)",          C.TEAL),
]