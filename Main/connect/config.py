import os
import logging
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── Project root və data directories ──────────────────────────────────
    # PROJECT_ROOT = /Main (connect/config.py-dən iki səviyyə yuxarı)
    PROJECT_ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Domain Object qovluğunun yolu environment variable-dən və ya default-dən oxunur
    # DOMAIN_OBJECT_DIR={PROJECT_ROOT}/Domain Object = /Main/Domain Object
    DOMAIN_OBJECT_DIR = Path(
        os.getenv(
            "DOMAIN_OBJECT_DIR",
            str(PROJECT_ROOT / "Domain Object")
        )
    )
    
    # ACL output files
    DOMAIN_ACES_PARQUET = DOMAIN_OBJECT_DIR / "domain_aces.parquet"
    DOMAIN_ACES_JSON = DOMAIN_OBJECT_DIR / "domain_aces.json"
    DOMAIN_EXTENDED_RIGHTS_JSON = DOMAIN_OBJECT_DIR / "domain_extended_rights.json"
    DOMAIN_DANGEROUS_ACE_JSON = DOMAIN_OBJECT_DIR / "domain_dangerous_ace.json"
    
    # Legacy paths (compatibility)
    DOMAIN_USERS_JSON = DOMAIN_OBJECT_DIR / "domain_users.json"
    DOMAIN_COMPUTERS_JSON = DOMAIN_OBJECT_DIR / "domain_computers.json"
    DOMAIN_GROUPS_JSON = DOMAIN_OBJECT_DIR / "domain_groups.json"

    PROTO_PORTS: dict[str, int] = {
        "kerberos": 88,
        "winrm":  5985,
        "psexec": 445,
        "smb":    445,
        "ssh":    22,
        "ldap":   389,
        "ldaps":  636,
    }
    LDAP_CONNECT_TIMEOUT: int = int(os.getenv("LDAP_CONNECT_TIMEOUT", 5))
    LDAP_RECEIVE_TIMEOUT: int = int(os.getenv("LDAP_RECEIVE_TIMEOUT", 10))
    PORT_CHECK_TIMEOUT:   int = int(os.getenv("PORT_CHECK_TIMEOUT",   2))
    LDAP_PAGE_SIZE:       int = int(os.getenv("LDAP_PAGE_SIZE",       500))
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


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ad_api")