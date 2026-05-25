import logging
import socket
import platform

from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPBindError, LDAPInvalidCredentialsResult

from connect.config import Config
from connect.utils import is_ntlm_hash, get_netbios_bind_user, build_ldap_bind_users
from connect.network import check_port, _tcp_probe
from connect.ldap_core import _collect_ldap_environment_for_target

logger = logging.getLogger("ad_api")


def _is_ldap_refused_error(err: Exception) -> bool:
    msg = str(err).lower()
    return any(token in msg for token in (
        "winerror 10061",
        "actively refused",
        "connection refused",
        "socket connection error while opening",
        "refused",
    ))


def _ldap_port_status(ip: str) -> list[dict]:
    ports = []
    for port in (389, 636):
        result = _tcp_probe(ip, port, timeout=Config.LDAP_CONNECT_TIMEOUT)
        ports.append({"port": port, "result": result, "port_open": result == "open"})
    return ports


def _ldap_refused_message(ip: str, base_message: str | None = None) -> dict:
    ports = _ldap_port_status(ip)
    open_ports = [str(item["port"]) for item in ports if item["port_open"]]
    closed_ports = [str(item["port"]) for item in ports if not item["port_open"]]

    if closed_ports and not open_ports:
        message = f"LDAP connection refused; ports {', '.join(closed_ports)} are closed"
    elif open_ports and closed_ports:
        message = f"LDAP connection refused; port {', '.join(open_ports)} is open but port {', '.join(closed_ports)} is closed"
    else:
        message = base_message or "LDAP connection refused"

    return {
        "success": False,
        "error": message,
        "ports": ports,
        "host_up": any(item["result"] == "open" for item in ports),
        "port_open": any(item["port_open"] for item in ports),
        "reachable": any(item["port_open"] for item in ports),
        "code": 503,
    }


# ---------------------------------------------------------------------------
# LDAP / LDAPS
# ---------------------------------------------------------------------------

def connect_ldap(ip: str, user: str, password: str, domain: str, use_ssl: bool = False) -> dict:
    tag = "ldaps" if use_ssl else "ldap"
    logger.info("%s connection: user=%s ip=%s", tag.upper(), get_netbios_bind_user(user, domain), ip)
    try:
        result = _collect_ldap_environment_for_target(ip, user, password, domain, use_ssl=use_ssl)
        if not result.get("success"):
            return result
        env = result["data"]
        return {
            "success":          True,
            "domain":           domain,
            "username":         user.split("\\")[-1].split("@")[0].upper(),
            "dc":               env.get("dc", ip),
            "dnsHostName":      env.get("dnsHostName", env.get("dc", ip)),
            "os_version":       env.get("os_version", "Windows Server"),
            "domain_level":     env.get("domain_level", "Unknown"),
            "kerberos_enabled": bool(env.get("kerberos_enabled", True)),
            "smb_enabled":      env.get("smb_enabled"),
            "counts":           env.get("counts", {}),
            "protocol_used":    tag,
        }
    except (LDAPInvalidCredentialsResult, LDAPBindError):
        return {
            "success": False,
            "error": (
                f"LDAP bind failed for {user}; tried UPN, NETBIOS, and raw username formats. "
                f"Verify the AD logon name or try user@domain / DOMAIN\\user."
            ),
            "code": 401,
        }
    except Exception as e:
        logger.exception("LDAP environment probe failed for %s@%s", get_netbios_bind_user(user, domain), ip)
        if _is_ldap_refused_error(e):
            return _ldap_refused_message(ip, str(e))
        return {"success": False, "error": str(e)}


def connect_ldap_fast(ip: str, user: str, password: str, domain: str, use_ssl: bool = False) -> dict:
    auth_type   = "SIMPLE"
    bind_secret = password
    if is_ntlm_hash(password):
        bind_secret = f"00000000000000000000000000000000:{password}"
        auth_type   = "NTLM"

    server = Server(
        ip,
        port=636 if use_ssl else 389,
        use_ssl=use_ssl,
        get_info=ALL,
        connect_timeout=Config.LDAP_CONNECT_TIMEOUT,
    )

    last_error = None
    try:
        for bind_user in build_ldap_bind_users(user, domain):
            try:
                conn = Connection(
                    server,
                    user=bind_user,
                    password=bind_secret,
                    authentication=auth_type,
                    auto_bind=True,
                    receive_timeout=Config.LDAP_RECEIVE_TIMEOUT,
                )
                conn.unbind()
                return {
                    "success":          True,
                    "domain":           domain,
                    "username":         user.split("\\")[-1].split("@")[0].upper(),
                    "dc":               ip,
                    "dnsHostName":      ip,
                    "os_version":       "Unknown",
                    "domain_level":     "Unknown",
                    "kerberos_enabled": True,
                    "smb_enabled":      check_port(ip, 445),
                    "counts": {
                        "users": 0, "computers": 0, "groups": 0,
                        "ous": 0,   "gpos": 0,      "trusts": 0,
                    },
                    "protocol_used": "ldaps" if use_ssl else "ldap",
                }
            except (LDAPInvalidCredentialsResult, LDAPBindError) as exc:
                last_error = exc
                continue
    except Exception as e:
        logger.exception("LDAP fast connect failed for %s", user)
        if _is_ldap_refused_error(e):
            return _ldap_refused_message(ip, str(e))
        return {"success": False, "error": str(e)}

    return {
        "success": False,
        "error": (
            f"LDAP bind failed for {user}; tried UPN, NETBIOS, and raw username formats. "
            f"Verify the AD logon name or try user@domain / DOMAIN\\user."
        ),
        "code": 401,
        "last_error": str(last_error) if last_error else None,
    }


# ---------------------------------------------------------------------------
# Local
# ---------------------------------------------------------------------------

def connect_local() -> dict:
    try:
        import getpass
        username   = getpass.getuser().upper()
        host       = socket.gethostname()
        os_version = f"{platform.system()} {platform.release()}"
        domain     = __import__("os").environ.get("USERDOMAIN", "LOCAL")

        return {
            "success":          True,
            "username":         username,
            "dc":               host,
            "dnsHostName":      host,
            "os_version":       os_version,
            "domain_level":     domain,
            "kerberos_enabled": False,
            "smb_enabled":      check_port("127.0.0.1", 445),
            "protocol_used":    "local",
            "counts": {
                "users": 0, "computers": 0, "groups": 0,
                "ous": 0,   "gpos": 0,      "trusts": 0,
            },
        }
    except Exception as e:
        return {"success": False, "error": f"Local session attach failed: {e}"}


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

PROTOCOL_HANDLERS = {
    "ldap":   lambda ip, u, p, d: connect_ldap(ip, u, p, d, use_ssl=False),
    "ldaps":  lambda ip, u, p, d: connect_ldap(ip, u, p, d, use_ssl=True),
    "rpc":    lambda ip, u, p, d: connect_ldap(ip, u, p, d, use_ssl=False),
    "agent":  lambda ip, u, p, d: connect_ldap(ip, u, p, d, use_ssl=False),
    "beacon": lambda ip, u, p, d: connect_ldap(ip, u, p, d, use_ssl=False),
    "local":  lambda *_: connect_local(),
}