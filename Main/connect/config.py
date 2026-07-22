import os
import logging
import warnings
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

DEBUG_MODE: bool = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")


class Config:
    PROJECT_ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    DOMAIN_OBJECT_DIR = Path(
        os.getenv(
            "DOMAIN_OBJECT_DIR",
            str(PROJECT_ROOT / "Domain Object")
        )
    )

    DOMAIN_ACES_PARQUET = DOMAIN_OBJECT_DIR / "domain_aces.parquet"
    DOMAIN_ACES_JSON = DOMAIN_OBJECT_DIR / "domain_aces.json"
    DOMAIN_EXTENDED_RIGHTS_JSON = DOMAIN_OBJECT_DIR / "domain_extended_rights.json"
    DOMAIN_DANGEROUS_ACE_JSON = DOMAIN_OBJECT_DIR / "domain_dangerous_ace.json"

    DOMAIN_USERS_JSON = DOMAIN_OBJECT_DIR / "domain_users.json"
    DOMAIN_COMPUTERS_JSON = DOMAIN_OBJECT_DIR / "domain_computers.json"
    DOMAIN_GROUPS_JSON = DOMAIN_OBJECT_DIR / "domain_groups.json"

    PROTO_PORTS: dict[str, int] = {
        "kerberos": 88,
        "ldap":   389,
        "ldaps":  636,
        "rpc":    135,
        "agent":  445,
        "beacon": 22,
    }

    DEFAULT_PORTS: dict[str, int] = {
        "api":           int(os.getenv("API_PORT", 5000)),
        "sqlite_reader": int(os.getenv("SQLITE_READER_PORT", 8800)),
    }

    LDAP_CONNECT_TIMEOUT: int = int(os.getenv("LDAP_CONNECT_TIMEOUT", 15))
    LDAP_RECEIVE_TIMEOUT: int = int(os.getenv("LDAP_RECEIVE_TIMEOUT", 120))
    PORT_CHECK_TIMEOUT:   int = int(os.getenv("PORT_CHECK_TIMEOUT",   2))
    LDAP_PAGE_SIZE:       int = int(os.getenv("LDAP_PAGE_SIZE",       200))
    DOMAIN_LEVEL_MAP: dict[str, str] = {
        "0": "2000", "2": "2003", "3": "2008",
        "4": "2008 R2", "5": "2012", "6": "2012 R2", "7": "2016+",
    }
    RATE_LIMIT_CONNECT: str = os.getenv("RATE_LIMIT_CONNECT", "120 per minute")
    RATE_LIMIT_ENUM:    str = os.getenv("RATE_LIMIT_ENUM",    "120 per minute")
    RATE_LIMIT_TEST:    str = os.getenv("RATE_LIMIT_TEST",    "120 per minute")
    RATE_LIMIT_ACL:     str = os.getenv("RATE_LIMIT_ACL",     "60 per minute")
    RATE_LIMIT_TOOLS:   str = os.getenv("RATE_LIMIT_TOOLS",   "120 per minute")
    RATE_LIMIT_DCSYNC:  str = os.getenv("RATE_LIMIT_DCSYNC",  "60 per minute")


# ─── Log format ───────────────────────────────────────────────────────────────
# Faylda modul adı da görünsün ki, xətanın haradan gəldiyi bəlli olsun.
_LOG_FORMAT_FILE    = "%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s"
_LOG_FORMAT_CONSOLE = "%(asctime)s  %(levelname)-8s  %(message)s"
_LOG_DATEFMT = "%H:%M:%S"

_LOG_FILE_PATH = Path(os.getenv("CONNECTION_LOG_PATH", str(Config.PROJECT_ROOT / "Logs" / "connection.log")))
_LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

if not DEBUG_MODE:
    warnings.filterwarnings("ignore", category=DeprecationWarning)

# ─── Konsol handler ───────────────────────────────────────────────────────────
# DEBUG_MODE=false olduqda konsola yalnız CRITICAL səviyyəsi çıxır;
# bütün digər məlumatlar faylda olur.
_console_handler = logging.StreamHandler()
_console_handler.setLevel(logging.DEBUG if DEBUG_MODE else logging.CRITICAL)
_console_handler.setFormatter(logging.Formatter(_LOG_FORMAT_CONSOLE, datefmt=_LOG_DATEFMT))

# ─── Root logger-i birbaşa konfiqurasiya et ───────────────────────────────────
# logging.basicConfig() yalnız root-un heç bir handler-i olmadıqda işləyir.
# Buna görə birbaşa root logger-ə handler əlavə edirik — bu həmişə işləyir,
# hətta başqa kitabxana basicConfig-i əvvəlcədən çağırmış olsa belə.
_root_logger = logging.getLogger()
_root_logger.setLevel(logging.DEBUG)

# Mövcud handler-ləri sil — köhnə, yarımçıq konfiqurasiyaların qarışmasının
# qarşısını alır (məsələn Flask-ın özü basicConfig çağırır).
for _h in _root_logger.handlers[:]:
    _root_logger.removeHandler(_h)

# Konsol handler-i root-a qoş
_root_logger.addHandler(_console_handler)

# ─── Fayl handler — ROOT logger-ə qoşulur ────────────────────────────────────
# Root-a qoşmaq vacibdir: ldap3, impacket kimi kitabxanalar öz logger-lərini
# istifadə edir, onlar ad_api logger-indən keçmir. Root-a qoşsaq hamısı
# connection.log-a düşər.
try:
    _file_handler = logging.FileHandler(_LOG_FILE_PATH, encoding="utf-8")
    _file_handler.setLevel(logging.DEBUG)
    _file_handler.setFormatter(logging.Formatter(_LOG_FORMAT_FILE, datefmt=_LOG_DATEFMT))
    _root_logger.addHandler(_file_handler)

except Exception as _log_exc:
    logging.getLogger().critical("Could not attach file handler for connection.log: %s", _log_exc)

# ─── Küylü kitabxana logger-ləri ─────────────────────────────────────────────
# Bu logger-lər çox verbose məlumat verir; WARNING-ə qoyuruq ki,
# log oxuna bilsin, amma xətaları itirməyək.
logging.getLogger("werkzeug").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("charset_normalizer").setLevel(logging.WARNING)

# ldap3-ün öz logger-ini DEBUG-da saxlayırıq — LDAP protokol xətaları
# connection.log-a düşsün.
logging.getLogger("ldap3").setLevel(logging.DEBUG)

# ─── Əsas tətbiq logger-i ─────────────────────────────────────────────────────
logger = logging.getLogger("ad_api")
logger.setLevel(logging.DEBUG)

# Flask tətbiq logger-i də faylda görünsün.
_flask_logger = logging.getLogger("flask.app")
_flask_logger.setLevel(logging.DEBUG)
_flask_logger.propagate = True  