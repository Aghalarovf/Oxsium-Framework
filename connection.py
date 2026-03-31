import os
import re
import socket
import subprocess
import platform
import logging
import ipaddress
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import (
    LDAPSocketOpenError, LDAPInvalidCredentialsResult,
)
from dotenv import load_dotenv

import users
import computers
import ou
import gpo
import groups
import trust
import local_ad

load_dotenv()

class Config:
    PROTO_PORTS: dict[str, int] = {
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
    RATE_LIMIT_CONNECT: str = os.getenv("RATE_LIMIT_CONNECT", "10 per minute")
    RATE_LIMIT_TEST:    str = os.getenv("RATE_LIMIT_TEST",    "30 per minute")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ad_api")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}},
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"])

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["10000 per day", "1000 per hour"],
    storage_uri=os.getenv("REDIS_URL", "memory://"),
)

def is_ntlm_hash(password: str) -> bool:
    return bool(re.match(r"^[a-fA-F0-9]{32}$", password))

def get_netbios_bind_user(username: str, domain: str) -> str:
    if "\\" in username or "@" in username:
        return username
    netbios = domain.split('.')[0].upper()
    return f"{netbios}\\{username}"

def domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_domain(domain: str) -> bool:
    return bool(re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", domain))

def validate_username(username: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9@.\\\-_]{1,128}$", username))

def check_port(ip: str, port: int, timeout: int = Config.PORT_CHECK_TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def require_json_fields(*fields):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            data = request.get_json(silent=True)
            if not data:
                return jsonify({"error": "JSON body is required"}), 400
            missing = [fld for fld in fields if not data.get(fld)]
            if missing:
                return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400
            g.req = data
            return f(*args, **kwargs)
        return wrapper
    return decorator


def is_local_request(data: dict | None) -> bool:
    if not data:
        return False
    return str(data.get("mode", "")).lower() == "local"


def get_enumeration_request_data():
    req = request.get_json(silent=True)
    if not req:
        return None, (jsonify({"error": "JSON body is required"}), 400)

    if is_local_request(req):
        return req, None

    missing = [fld for fld in ("ip", "domain", "username", "password") if not req.get(fld)]
    if missing:
        return None, (jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400)

    ip = req["ip"]
    domain = req["domain"]
    username = req["username"]
    if not validate_ip(ip) or not validate_domain(domain) or not validate_username(username):
        return None, (jsonify({"error": "Invalid IP, Domain, or Username"}), 400)

    return req, None


def _build_ldap_targets(req: dict) -> list[str]:
    protocol = str(req.get("protocol", "")).lower()
    ip = str(req.get("ip", "")).strip()
    domain = str(req.get("domain", "")).strip()
    ldap_host = str(req.get("ldap_host", "")).strip()
    dc = str(req.get("dc", "")).strip()

    targets: list[str] = []

    # If caller explicitly provides LDAP host/DC, always prefer it.
    for candidate in (ldap_host, dc):
        if candidate:
            targets.append(candidate)

    # For LDAP/LDAPS direct sessions, user IP is usually a DC.
    if protocol in ("ldap", "ldaps") and ip:
        targets.append(ip)

    # For WinRM/SMB/SSH sessions, connected IP is often a client member.
    # Prefer domain DNS name so LDAP resolves to a domain controller.
    if domain:
        targets.append(domain)

    # Keep IP as final fallback.
    if ip:
        targets.append(ip)

    # De-duplicate while preserving order.
    deduped: list[str] = []
    for t in targets:
        if t not in deduped:
            deduped.append(t)
    return deduped


def _is_retryable_ldap_error(message: str) -> bool:
    msg = (message or "").lower()
    retry_markers = (
        "socket",
        "connection",
        "timeout",
        "timed out",
        "can't contact",
        "server unavailable",
        "refused",
        "unreachable",
        "invalid server address",
    )
    return any(m in msg for m in retry_markers)


def _run_enumeration_with_target_fallback(req: dict, enum_fn):
    last_result = None
    targets = _build_ldap_targets(req)

    for target in targets:
        result = enum_fn(target, req["domain"], req["username"], req["password"], Config)
        if result.get("success"):
            if target != req.get("ip"):
                result.setdefault("meta", {})
                result["meta"]["ldap_target"] = target
            return result

        last_result = result
        # Stop on hard failures (invalid credentials, auth failures, etc.).
        if not _is_retryable_ldap_error(result.get("error", "")):
            break

    return last_result or {"success": False, "error": "Enumeration failed", "code": 500}

SEARCH_QUERIES: dict[str, str] = {
    "users":     "(&(objectClass=user)(objectCategory=person))",
    "computers": "(objectClass=computer)",
    "groups":    "(objectClass=group)",
    "ous":       "(objectClass=organizationalUnit)",
    "gpos":      "(objectClass=groupPolicyContainer)",
    "trusts":    "(objectClass=trustedDomain)",
}

def connect_ldap(ip: str, user: str, password: str, domain: str, use_ssl: bool = False) -> dict:
    base_dn = domain_to_dn(domain)
    bind_user = get_netbios_bind_user(user, domain)
    port = 636 if use_ssl else 389
    tag = "LDAPS" if use_ssl else "LDAP"

    auth_type = "SIMPLE"
    if is_ntlm_hash(password):
        password = f"00000000000000000000000000000000:{password}"
        auth_type = "NTLM"

    logger.info("%s connection: user=%s ip=%s", tag, bind_user, ip)
    try:
        server = Server(ip, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=Config.LDAP_CONNECT_TIMEOUT)
        conn = Connection(server, user=bind_user, password=password, authentication=auth_type,
                          auto_bind=True, receive_timeout=Config.LDAP_RECEIVE_TIMEOUT)

        counts: dict[str, int] = {}
        for key, query in SEARCH_QUERIES.items():
            conn.search(base_dn, query, search_scope=SUBTREE, paged_size=Config.LDAP_PAGE_SIZE)
            counts[key] = len(conn.entries)

        dc_name, func_level = ip, "0"
        if server.info and server.info.other:
            dns = server.info.other.get("dnsHostName")
            if dns: dc_name = str(dns[0]) if isinstance(dns, list) else str(dns)
            raw = server.info.other.get("domainFunctionality", ["0"])
            func_level = str(raw[0]) if isinstance(raw, list) else str(raw)

        conn.unbind()
        return {
            "success":          True,
            "domain":           domain,
            "username":         user.split("\\")[-1].split("@")[0].upper(),
            "dc":               dc_name,
            "os_version":       f"Windows Server ({Config.DOMAIN_LEVEL_MAP.get(func_level, 'Unknown')})",
            "domain_level":     f"Level {func_level}",
            "kerberos_enabled": True,
            "counts":           counts,
            "protocol_used":    tag.lower(),
        }
    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": f"Invalid credentials for {bind_user}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

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
        session = winrm.Session(f"http://{ip}:5985/wsman", auth=(bind_user, password), transport="ntlm")
        r = session.run_cmd("whoami")
        if r.status_code != 0: 
            return {"success": False, "error": r.std_err.decode().strip()}
        return {
            "success": True, "domain": domain, "username": user.upper(), "dc": ip,
            "whoami": r.std_out.decode().strip(), "protocol_used": "winrm", "counts": {}
        }
    except Exception as e: 
        return {"success": False, "error": f"WinRM: {e}"}

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
        return {
            "success": True, "domain": domain, "username": user.upper(), "dc": server_name or ip,
            "protocol_used": "smb", "counts": {}
        }
    except Exception as e: 
        return {"success": False, "error": f"SMB: {e}"}

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
        return {"success": True, "domain": domain, "username": user.upper(), "dc": lines[0] if lines else ip,
                "whoami": lines[1] if len(lines)>1 else user, "protocol_used": "ssh", "counts": {}}
    except Exception as e: 
        return {"success": False, "error": f"SSH: {e}"}

def connect_local() -> dict:
    try:
        import getpass

        username = getpass.getuser().upper()
        host = socket.gethostname()
        os_version = f"{platform.system()} {platform.release()}"
        domain = os.environ.get("USERDOMAIN", "LOCAL")

        return {
            "success": True,
            "username": username,
            "dc": host,
            "os_version": os_version,
            "domain_level": domain,
            "kerberos_enabled": False,
            "protocol_used": "local",
            "counts": {},
        }
    except Exception as e:
        return {"success": False, "error": f"Local session attach failed: {e}"}


def run_local_command(command: str) -> dict:
    try:
        if platform.system().lower() == 'windows':
            proc = subprocess.run([
                'powershell', '-NoProfile', '-Command', command
            ], capture_output=True, text=True, timeout=30)
        else:
            proc = subprocess.run(command, capture_output=True, text=True, shell=True, timeout=30)
        return {
            'success': True,
            'output': proc.stdout or '',
            'stderr': proc.stderr or '',
            'exit_code': proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Local command timed out'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def run_winrm_command(ip: str, user: str, password: str, domain: str, command: str) -> dict:
    try:
        import winrm
    except ImportError:
        return {'success': False, 'error': 'pywinrm not installed'}

    if not check_port(ip, 5985):
        return {'success': False, 'error': 'WinRM port (5985) is closed'}

    try:
        bind_user = get_netbios_bind_user(user, domain)
        session = winrm.Session(f'http://{ip}:5985/wsman', auth=(bind_user, password), transport='ntlm')
        result = session.run_ps(command)
        stdout = result.std_out.decode(errors='ignore').strip()
        stderr = result.std_err.decode(errors='ignore').strip()
        if result.status_code != 0:
            return {'success': False, 'error': stderr or f'Command failed with code {result.status_code}', 'output': stdout}
        return {'success': True, 'output': stdout, 'stderr': stderr}
    except Exception as e:
        return {'success': False, 'error': f'WinRM shell error: {e}'}


def run_ssh_command(ip: str, user: str, password: str, command: str) -> dict:
    try:
        import paramiko
    except ImportError:
        return {'success': False, 'error': 'paramiko not installed'}

    if not check_port(ip, 22):
        return {'success': False, 'error': 'SSH port (22) is closed'}

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=22, username=user, password=password, timeout=Config.LDAP_CONNECT_TIMEOUT)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode(errors='ignore').strip()
        error = stderr.read().decode(errors='ignore').strip()
        client.close()
        return {'success': True, 'output': output, 'stderr': error}
    except Exception as e:
        return {'success': False, 'error': f'SSH shell error: {e}'}

PROTOCOL_HANDLERS = {
    "ldap":   lambda ip, u, p, d: connect_ldap(ip, u, p, d, use_ssl=False),
    "ldaps":  lambda ip, u, p, d: connect_ldap(ip, u, p, d, use_ssl=True),
    "winrm":  connect_winrm,
    "psexec": connect_smb,
    "smb":    connect_smb,
    "ssh":    connect_ssh,
    "local":  lambda *_: connect_local(),
}

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0", "protocols": list(PROTOCOL_HANDLERS.keys())})

@app.route("/api/test", methods=["POST"])
@require_json_fields("ip", "protocol")
def test_connection():
    req = g.req
    ip, proto = req["ip"], req.get("protocol", "ldap").lower()
    if not validate_ip(ip): 
        return jsonify({"error": "Invalid IP format"}), 400
    if proto not in Config.PROTO_PORTS: 
        return jsonify({"error": f"Unknown protocol: {proto}"}), 400
    port = Config.PROTO_PORTS[proto]
    return jsonify({"reachable": check_port(ip, port), "port": port, "protocol": proto})

@app.route("/api/connect", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_CONNECT)
def connect():
    req = request.get_json(silent=True)
    if not req:
        return jsonify({"error": "JSON body is required"}), 400

    mode = req.get("mode", "remote").lower()
    if mode == "local":
        result = connect_local()
        return jsonify(result) if result.get("success") else (jsonify(result), 500)

    missing = [fld for fld in ("ip", "username", "password", "domain") if not req.get(fld)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    ip = req["ip"]
    username = req["username"]
    password = req["password"]
    domain = req["domain"]
    proto = req.get("protocol", "ldap").lower()

    if not validate_ip(ip) or not validate_domain(domain) or not validate_username(username):
        return jsonify({"error": "Invalid input formats"}), 400
    if proto not in PROTOCOL_HANDLERS:
        return jsonify({"error": f"Unsupported protocol: {proto}"}), 400

    result = PROTOCOL_HANDLERS[proto](ip, username, password, domain)
    status = 401 if any(k in result.get("error", "") for k in ("password", "Authentication", "credentials")) else 500
    return jsonify(result) if result.get("success") else (jsonify(result), status)

@app.route("/api/users", methods=["POST"])
@limiter.limit("5 per minute")
def list_users():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response

    if is_local_request(req):
        result = local_ad.get_local_domain_users(Config)
    else:
        result = _run_enumeration_with_target_fallback(req, users.get_domain_users)
    if result.get("success"):
        return jsonify(result), 200

    status = result.get("code", 500)
    if status not in (400, 401, 403, 404, 500, 503):
        status = 500
    return jsonify(result), status

@app.route("/api/computers", methods=["POST"])
@limiter.limit("5 per minute")
def list_computers():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response

    if is_local_request(req):
        result = local_ad.get_local_domain_computers(Config)
    else:
        result = _run_enumeration_with_target_fallback(req, computers.get_domain_computers)
    if result.get("success"):
        return jsonify(result), 200

    status = result.get("code", 500)
    if status not in (400, 401, 403, 404, 500, 503):
        status = 500
    return jsonify(result), status

@app.route("/api/ous", methods=["POST"])
@limiter.limit("5 per minute")
def list_ous():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response

    if is_local_request(req):
        result = local_ad.get_local_domain_ous(Config)
    else:
        result = _run_enumeration_with_target_fallback(req, ou.get_domain_ous)
    if result.get("success"):
        return jsonify(result), 200

    status = result.get("code", 500)
    if status not in (400, 401, 403, 404, 500, 503):
        status = 500
    return jsonify(result), status

@app.route("/api/gpo", methods=["POST"])
@limiter.limit("5 per minute")
def list_gpos():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response

    if is_local_request(req):
        result = local_ad.get_local_domain_gpos(Config)
    else:
        result = _run_enumeration_with_target_fallback(req, gpo.get_domain_gpos)
    if result.get("success"):
        return jsonify(result), 200

    status = result.get("code", 500)
    if status not in (400, 401, 403, 404, 500, 503):
        status = 500
    return jsonify(result), status


@app.route("/api/groups", methods=["POST"])
@limiter.limit("5 per minute")
def list_groups():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response

    if is_local_request(req):
        result = local_ad.get_local_domain_groups(Config)
    else:
        result = _run_enumeration_with_target_fallback(req, groups.get_domain_groups)
    if result.get("success"):
        return jsonify(result), 200

    status = result.get("code", 500)
    if status not in (400, 401, 403, 404, 500, 503):
        status = 500
    return jsonify(result), status


@app.route("/api/trusts", methods=["POST"])
@limiter.limit("5 per minute")
def list_trusts():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response

    if is_local_request(req):
        result = local_ad.get_local_domain_trusts(Config)
    else:
        result = _run_enumeration_with_target_fallback(req, trust.get_domain_trusts)
    if result.get("success"):
        return jsonify(result), 200

    status = result.get("code", 500)
    if status not in (400, 401, 403, 404, 500, 503):
        status = 500
    return jsonify(result), status

@app.route("/api/shell", methods=["POST"])
def shell_command():
    req = request.get_json(silent=True)
    if not req:
        return jsonify({"error": "JSON body is required"}), 400

    command = req.get("command", "").strip()
    mode = req.get("mode", "remote").lower()
    protocol = req.get("protocol", "winrm").lower()

    if not command:
        return jsonify({"error": "Command is required"}), 400

    if mode == "local":
        result = run_local_command(command)
        return jsonify(result) if result.get("success") else (jsonify(result), 500)

    ip = req.get("ip")
    domain = req.get("domain")
    user = req.get("username")
    password = req.get("password")
    if not ip or not user or not password or not domain:
        return jsonify({"error": "Missing shell connection fields"}), 400
    if protocol == "winrm":
        result = run_winrm_command(ip, user, password, domain, command)
    elif protocol == "ssh":
        result = run_ssh_command(ip, user, password, command)
    else:
        return jsonify({"success": False, "error": f"Shell is not supported for protocol: {protocol}"}), 400

    return jsonify(result) if result.get("success") else (jsonify(result), 500)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
