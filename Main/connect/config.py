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


_LOG_FORMAT  = "%(asctime)s  %(levelname)-8s  %(message)s"
_LOG_DATEFMT = "%H:%M:%S"

_LOG_FILE_PATH = Path(os.getenv("CONNECTION_LOG_PATH", str(Config.PROJECT_ROOT / "connection.log")))

_console_handler = logging.StreamHandler()
_console_handler.setLevel(logging.DEBUG if DEBUG_MODE else logging.CRITICAL)
_console_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))

logging.basicConfig(handlers=[_console_handler], level=logging.DEBUG)

logging.getLogger("werkzeug").setLevel(logging.ERROR)

if not DEBUG_MODE:
    warnings.filterwarnings("ignore", category=DeprecationWarning)

logger = logging.getLogger("ad_api")
logger.setLevel(logging.DEBUG)

try:
    _file_handler = logging.FileHandler(_LOG_FILE_PATH, encoding="utf-8")
    _file_handler.setLevel(logging.DEBUG)
    _file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
    logger.addHandler(_file_handler)

    if not DEBUG_MODE:
        _flask_file_handler = logging.FileHandler(_LOG_FILE_PATH, encoding="utf-8")
        _flask_file_handler.setLevel(logging.DEBUG)
        _flask_file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT))
        _flask_logger = logging.getLogger("flask.app")
        _flask_logger.addHandler(_flask_file_handler)
        _flask_logger.setLevel(logging.DEBUG)
        _flask_logger.propagate = False

except Exception as _log_exc:
    logging.getLogger().critical("Could not attach file handler for connection.log: %s", _log_exc)