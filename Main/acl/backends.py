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
    return f"{username}@{domain}"


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
    def __init__(self, ip: str = None, bind_user: str = None, password: str = None,
                 auth_type: str = None, cfg: LdapConfig = None, use_ssl: bool = False,
                 _conn=None,
                 # Alt-auth params: pass these when Kerberos ccache or certificate
                 # (PFX) is in use so every code path — including parallel workers
                 # spawned by make_conn_factory — authenticates via GSSAPI/EXTERNAL
                 # rather than falling back to an empty SIMPLE bind (error 49/9).
                 ccache_bytes: bytes | None = None,
                 pfx_bytes: bytes | None = None,
                 pfx_password: str | None = None,
                 dc_host: str | None = None,
                 # Separate username / domain required for the alt-auth path because
                 # LdapSession expects them split; bind_user (user@domain) is kept
                 # for the SIMPLE/NTLM path.
                 username: str | None = None,
                 domain: str | None = None) -> None:
        if _conn is not None:
            self._conn = _conn
            return

        from ldap3.core.exceptions import LDAPBindError, LDAPInvalidCredentialsResult

        # ── Alt-auth (ccache / PFX) path ────────────────────────────────────
        # open_standalone_connection handles GSSAPI (ccache) and EXTERNAL
        # (certificate / PFX) authentication via LdapSession.  It never tries
        # a plaintext SIMPLE bind, so it works even when the DC enforces
        # LDAP signing / channel binding.
        if ccache_bytes or pfx_bytes:
            if not username or not domain:
                raise ValueError(
                    "username and domain are required when ccache_bytes or "
                    "pfx_bytes are provided"
                )
            from connect.ldap_core import open_standalone_connection
            conn, _base_dn = open_standalone_connection(
                ip, username, password or "", domain, cfg,
                use_ssl=use_ssl,
                ccache_bytes=ccache_bytes,
                pfx_bytes=pfx_bytes,
                pfx_password=pfx_password,
                dc_host=dc_host,
            )
            self._conn = conn
            return

        # ── SIMPLE / NTLM path ───────────────────────────────────────────────
        # Route through _open_ldap_connection (StartTLS-first, LDAPS fallback)
        # instead of a raw ldap3.Connection(auto_bind=True) call, so DCs that
        # enforce LDAP signing don't reject the bind.
        from connect.ldap_core import _open_ldap_connection

        self._conn = _open_ldap_connection(
            ldap_target=ip,
            bind_user=bind_user,
            bind_secret=password,
            auth_type=auth_type,
            use_ssl=use_ssl,
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

    @classmethod
    def from_connection(cls, conn) -> "Ldap3Backend":
        return cls(_conn=conn)

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
                       auth_type: str, cfg: LdapConfig, use_ssl: bool = False,
                       ccache_bytes: bytes | None = None,
                       pfx_bytes: bytes | None = None,
                       pfx_password: str | None = None,
                       dc_host: str | None = None,
                       username: str | None = None,
                       domain: str | None = None):
    """Return a zero-argument callable that opens a fresh Ldap3Backend.

    Each parallel ACL worker calls factory() to get its own connection.
    When ccache_bytes or pfx_bytes are supplied the factory produces
    GSSAPI/EXTERNAL connections; without them it falls back to the
    SIMPLE/NTLM path.  The caller must supply username + domain when
    passing alt-auth credentials (they are forwarded to open_standalone_connection).
    """
    def factory() -> Ldap3Backend:
        return Ldap3Backend(
            ip, bind_user, password, auth_type, cfg,
            use_ssl=use_ssl,
            ccache_bytes=ccache_bytes,
            pfx_bytes=pfx_bytes,
            pfx_password=pfx_password,
            dc_host=dc_host,
            username=username,
            domain=domain,
        )
    return factory