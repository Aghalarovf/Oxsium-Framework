import logging
import socket
import platform

from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPInvalidCredentialsResult

from connect.config import Config
from connect.utils import is_ntlm_hash, get_netbios_bind_user
from connect.network import check_port
from connect.ldap_core import _collect_ldap_environment

logger = logging.getLogger("ad_api")


# ---------------------------------------------------------------------------
# LDAP / LDAPS
# ---------------------------------------------------------------------------

def connect_ldap(ip: str, user: str, password: str, domain: str, use_ssl: bool = False) -> dict:
    tag = "ldaps" if use_ssl else "ldap"
    logger.info("%s connection: user=%s ip=%s", tag.upper(), get_netbios_bind_user(user, domain), ip)
    try:
        env = _collect_ldap_environment(ip, user, password, domain, use_ssl=use_ssl)
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
    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": f"Invalid credentials for {get_netbios_bind_user(user, domain)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def connect_ldap_fast(ip: str, user: str, password: str, domain: str, use_ssl: bool = False) -> dict:
    bind_user   = get_netbios_bind_user(user, domain)
    auth_type   = "SIMPLE"
    bind_secret = password
    if is_ntlm_hash(password):
        bind_secret = f"00000000000000000000000000000000:{password}"
        auth_type   = "NTLM"

    try:
        server = Server(
            ip,
            port=636 if use_ssl else 389,
            use_ssl=use_ssl,
            get_info=ALL,
            connect_timeout=Config.LDAP_CONNECT_TIMEOUT,
        )
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
    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": f"Invalid credentials for {bind_user}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# WinRM
# ---------------------------------------------------------------------------

def connect_winrm(ip: str, user: str, password: str, domain: str) -> dict:
    if is_ntlm_hash(password):
        return {"success": False, "error": "WinRM does not support Pass-the-Hash. Please use SMB (psexec) instead."}

    try:
        import winrm
    except ImportError:
        return {"success": False, "error": "pywinrm not installed"}

    if not check_port(ip, 5985):
        return {"success": False, "error": "WinRM port (5985) is closed"}

    try:
        bind_user = get_netbios_bind_user(user, domain)
        session   = winrm.Session(f"http://{ip}:5985/wsman", auth=(bind_user, password), transport="ntlm")
        r         = session.run_cmd("whoami")
        if r.status_code != 0:
            return {"success": False, "error": r.std_err.decode().strip()}
        return {
            "success":      True,
            "domain":       domain,
            "username":     user.upper(),
            "dc":           ip,
            "dnsHostName":  ip,
            "smb_enabled":  check_port(ip, 445),
            "whoami":       r.std_out.decode().strip(),
            "protocol_used": "winrm",
        }
    except Exception as e:
        return {"success": False, "error": f"WinRM: {e}"}


# ---------------------------------------------------------------------------
# SMB / PsExec
# ---------------------------------------------------------------------------

def connect_smb(ip: str, user: str, password: str, domain: str) -> dict:
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        return {"success": False, "error": "impacket not installed"}

    if not check_port(ip, 445):
        return {"success": False, "error": "SMB port (445) is closed"}

    try:
        smb = SMBConnection(ip, ip, timeout=Config.LDAP_CONNECT_TIMEOUT)
        if is_ntlm_hash(password):
            smb.login(user, '', domain, lmhash='00000000000000000000000000000000', nthash=password)
        else:
            smb.login(user, password, domain)

        server_name = smb.getServerName()
        smb.logoff()
        fqdn = (
            f"{server_name}.{domain}"
            if server_name and "." not in server_name and domain
            else (server_name or ip)
        )
        return {
            "success":       True,
            "domain":        domain,
            "username":      user.upper(),
            "dc":            fqdn,
            "dnsHostName":   fqdn,
            "smb_enabled":   True,
            "protocol_used": "smb",
        }
    except Exception as e:
        return {"success": False, "error": f"SMB: {e}"}


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

def connect_ssh(ip: str, user: str, password: str, domain: str) -> dict:
    if is_ntlm_hash(password):
        return {"success": False, "error": "SSH does not support NTLM Hashes."}

    try:
        import paramiko
    except ImportError:
        return {"success": False, "error": "paramiko not installed"}

    if not check_port(ip, 22):
        return {"success": False, "error": "SSH port (22) is closed"}

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=22, username=user, password=password, timeout=Config.LDAP_CONNECT_TIMEOUT)
        _, stdout, _ = client.exec_command("hostname && whoami")
        lines = stdout.read().decode().strip().splitlines()
        client.close()
        return {
            "success":       True,
            "domain":        domain,
            "username":      user.upper(),
            "dc":            lines[0] if lines else ip,
            "dnsHostName":   lines[0] if lines else ip,
            "smb_enabled":   check_port(ip, 445),
            "whoami":        lines[1] if len(lines) > 1 else user,
            "protocol_used": "ssh",
        }
    except Exception as e:
        return {"success": False, "error": f"SSH: {e}"}


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
    "winrm":  connect_winrm,
    "psexec": connect_smb,
    "smb":    connect_smb,
    "ssh":    connect_ssh,
    "local":  lambda *_: connect_local(),
}