import random
import re
import time
from datetime import datetime, timezone

from .models import LdapConfig, LdapBackend, SecurityDescriptorParser  # noqa: F401


def is_ntlm_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}", value or ""))


def domain_to_dn(domain: str) -> str:
    if not domain or not domain.strip():
        raise ValueError(f"Invalid domain value: {domain!r}")
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


_RETRYABLE_EXCEPTIONS_CACHE: tuple[type[BaseException], ...] | None = None


def _get_retryable_exceptions() -> tuple[type[BaseException], ...]:
    global _RETRYABLE_EXCEPTIONS_CACHE
    if _RETRYABLE_EXCEPTIONS_CACHE is not None:
        return _RETRYABLE_EXCEPTIONS_CACHE

    exceptions: list[type[BaseException]] = [ConnectionError, TimeoutError, OSError]
    try:
        from ldap3.core.exceptions import (
            LDAPSocketOpenError,
            LDAPSocketSendError,
            LDAPSocketReceiveError,
            LDAPTimeoutError,
        )
        exceptions = [
            LDAPSocketOpenError, LDAPSocketSendError,
            LDAPSocketReceiveError, LDAPTimeoutError,
            *exceptions,
        ]
    except ImportError:
        pass

    _RETRYABLE_EXCEPTIONS_CACHE = tuple(exceptions)
    return _RETRYABLE_EXCEPTIONS_CACHE


def search_with_retry(
    conn: "LdapBackend",
    base: str,
    ldap_filter: str,
    max_retries: int = 1,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
    **kwargs,
) -> None:
    retryable = _get_retryable_exceptions()
    attempt = 0
    while True:
        try:
            conn.search(base, ldap_filter, **kwargs)
            return
        except retryable:
            attempt += 1
            if attempt > max_retries:
                raise
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay += random.uniform(0, delay * 0.25)
            time.sleep(delay)


class ImpacketParser:
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
    def __init__(self, ip: str, bind_user: str, password: str,
                 auth_type: str, cfg: LdapConfig) -> None:
        from ldap3 import ALL, Server, Connection
        from ldap3.core.exceptions import LDAPBindError, LDAPInvalidCredentialsResult

        server = Server(ip, get_info=ALL, connect_timeout=cfg.connect_timeout)
        self._conn = Connection(
            server,
            user=bind_user,
            password=password,
            authentication=auth_type,
            auto_bind=True,
            receive_timeout=cfg.receive_timeout,
        )
        if not self._conn.bound:
            result_code = (self._conn.result or {}).get("result")
            description = (self._conn.result or {}).get("description", "")
            if result_code == 49 or description == "invalidCredentials":
                raise LDAPInvalidCredentialsResult(
                    f"LDAP authentication failed (bind_user={bind_user!r}): "
                    f"{self._conn.result}"
                )
            raise LDAPBindError(
                f"LDAP bind failed (bind_user={bind_user!r}): "
                f"{self._conn.result}"
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


def make_conn_factory(ip: str, bind_user: str, password: str,
                       auth_type: str, cfg: LdapConfig):
    def factory() -> Ldap3Backend:
        return Ldap3Backend(ip, bind_user, password, auth_type, cfg)
    return factory