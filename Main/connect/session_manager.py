"""Shared LDAP session manager.

Instead of every collector module (users, computers, groups, ous, gpos,
trusts, acl ...) opening its own separate LDAP connection, /api/connect
opens ONE connection and stores it here. All subsequent enumeration
endpoints reuse that same connection through `get_active_session()`.

If no matching shared session exists (e.g. a caller hits /api/users
directly without calling /api/connect first, or the session died),
callers fall back to opening their own connection as before.
"""
import logging
import threading

from connect.ldap_session import LdapSession

logger = logging.getLogger("ad_api")

_lock = threading.Lock()
_session: LdapSession | None = None
_session_key: tuple | None = None


def _make_key(ip: str, domain: str, username: str) -> tuple:
    return (
        str(ip or "").strip().lower(),
        str(domain or "").strip().lower(),
        str(username or "").strip().lower(),
    )


def _is_session_alive(session: LdapSession) -> bool:
    if session is None or session.conn is None:
        return False
    try:
        # ldap3-ün conn.closed xassəsi həmişə etibarlı deyil —
        # bəzən aktiv bağlantını "closed" kimi göstərir.
        # Əlavə olaraq conn.bound-u yoxlayırıq.
        conn = session.conn
        if conn.closed:
            return False
        # bound=True varsa bağlantı qurulub və autentifikasiya edilib
        if hasattr(conn, "bound") and not conn.bound:
            return False
        return True
    except Exception:
        return False


def set_active_session(session: LdapSession, ip: str, domain: str, username: str) -> None:
    """Register a freshly-opened session as the shared connection, closing
    whatever was previously active."""
    global _session, _session_key
    with _lock:
        if _session is not None and _session is not session:
            try:
                _session.close()
            except Exception:
                logger.warning("session_manager: failed to close previous session", exc_info=True)
        _session = session
        _session_key = _make_key(ip, domain, username)
        logger.info("session_manager: active LDAP session set for %s", _session_key)


def get_active_session(ip: str, domain: str, username: str) -> LdapSession | None:
    """Return the shared session if it matches ip/domain/username and is
    still alive, otherwise None (caller should fall back)."""
    with _lock:
        if _session is None:
            return None
        if _session_key != _make_key(ip, domain, username):
            return None
        if not _is_session_alive(_session):
            logger.warning("session_manager: cached session is no longer alive, dropping it")
            return None
        return _session


def clear_active_session() -> None:
    global _session, _session_key
    with _lock:
        if _session is not None:
            try:
                _session.close()
            except Exception:
                logger.warning("session_manager: failed to close session on clear", exc_info=True)
        _session = None
        _session_key = None