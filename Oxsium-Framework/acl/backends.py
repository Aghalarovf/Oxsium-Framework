import re
from datetime import datetime, timezone

from .models import LdapConfig, LdapBackend, SecurityDescriptorParser  # noqa: F401


# ══════════════════════════════════════════════════════════════════════════════
# SRP: Köməkçi funksiyalar
# ══════════════════════════════════════════════════════════════════════════════

def is_ntlm_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}", value or ""))


def domain_to_dn(domain: str) -> str:
    if not domain or not domain.strip():
        raise ValueError(f"Yanlış domain dəyəri: {domain!r}")
    return ",".join(f"DC={p}" for p in domain.strip().split("."))


def get_bind_user(username: str, domain: str) -> str:
    if "@" in username or "\\" in username:
        return username
    return f"{domain.split('.')[0].upper()}\\{username}"


def normalize_value(value):
    if hasattr(value, "value"):
        value = value.value
    if isinstance(value, list):
        return value[0] if value else None
    return value


def ldap_ts_to_iso(value) -> str | None:
    v = normalize_value(value)
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.replace(tzinfo=v.tzinfo or timezone.utc).isoformat()
    try:
        ticks = int(str(v))
    except (ValueError, TypeError):
        return str(v)
    if ticks in (0, 9_223_372_036_854_775_807):
        return None
    try:
        return datetime.fromtimestamp(
            (ticks - 116_444_736_000_000_000) / 10_000_000, tz=timezone.utc
        ).isoformat()
    except (OSError, OverflowError, ValueError):
        return str(v)


# ══════════════════════════════════════════════════════════════════════════════
# DIP: Konkret tətbiqlər — yalnız burada xarici asılılıqlar var
# ══════════════════════════════════════════════════════════════════════════════

class ImpacketParser:
    """SRP + DIP: impacket DACL parse məsuliyyəti burada cəmləşib."""

    def __init__(self) -> None:
        try:
            from impacket.ldap.ldaptypes import (
                ACCESS_ALLOWED_OBJECT_ACE,
                SR_SECURITY_DESCRIPTOR,
            )
            self._SR_SD   = SR_SECURITY_DESCRIPTOR
            self._OBJ_ACE = ACCESS_ALLOWED_OBJECT_ACE
        except ImportError as e:
            raise ImportError(f"impacket not installed: {e}") from e

    def parse(self, raw_sd: bytes) -> object:
        return self._SR_SD(data=raw_sd)["Dacl"]

    def is_object_ace(self, ace_data: object) -> bool:
        return isinstance(ace_data, self._OBJ_ACE)


class Ldap3Backend:
    """SRP + DIP: ldap3 bağlantı məsuliyyəti burada cəmləşib."""

    def __init__(self, ip: str, bind_user: str, password: str,
                 auth_type: str, cfg: LdapConfig) -> None:
        from ldap3 import ALL, Server, Connection
        server = Server(ip, get_info=ALL, connect_timeout=cfg.connect_timeout)
        self._conn = Connection(
            server,
            user=bind_user,
            password=password,
            authentication=auth_type,
            auto_bind=True,
            receive_timeout=cfg.receive_timeout,
        )

    def search(self, base: str, ldap_filter: str, **kwargs) -> None:
        self._conn.search(base, ldap_filter, **kwargs)

    @property
    def entries(self) -> list:
        return self._conn.entries

    @property
    def result(self) -> dict | None:
        return self._conn.result

    def unbind(self) -> None:
        self._conn.unbind()