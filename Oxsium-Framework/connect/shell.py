import json
import platform
import subprocess

from connect.config import Config
from connect.utils import is_ntlm_hash, get_netbios_bind_user
from connect.network import check_port


# ---------------------------------------------------------------------------
# PowerShell profile script (run on the remote host to gather AD context)
# ---------------------------------------------------------------------------

_POWERSHELL_PROFILE_SCRIPT = r'''
$domainFqdn = $null
$domainLevelRaw = $null
try {
    $root = [ADSI]"LDAP://RootDSE"
    $dn = [string]$root.defaultNamingContext
    if ($dn) {
        $domainFqdn = ($dn -replace '^DC=', '' -replace ',DC=', '.')
    }
    if ($root.domainFunctionality -ne $null) {
        $domainLevelRaw = [string]$root.domainFunctionality
    }
} catch {}

$dcName = $null
$dcIp = $null
try {
    $dcName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
} catch {}
if (-not $dcName) {
    try {
        $ls = $env:LOGONSERVER
        if ($ls) { $dcName = $ls.TrimStart('\\') }
    } catch {}
}
if ($dcName) {
    try {
        $addr = [System.Net.Dns]::GetHostAddresses($dcName) |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            Select-Object -First 1
        if ($addr) { $dcIp = $addr.IPAddressToString }
    } catch {}
}

$sessionUser = $null
try { $sessionUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch {}
if ($sessionUser -and $sessionUser.Contains('\\')) {
    $sessionUser = $sessionUser.Split('\\')[-1]
}

$osVersion = $null
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($os) { $osVersion = "{0} ({1})" -f $os.Caption, $os.Version }
} catch {}

[ordered]@{
    domain = $domainFqdn
    session_user = $sessionUser
    dc_name = $dcName
    dc_ip = $dcIp
    os_version = $osVersion
    domain_level_raw = $domainLevelRaw
} | ConvertTo-Json -Compress
'''.strip()


# ---------------------------------------------------------------------------
# Local / remote command runners
# ---------------------------------------------------------------------------

def run_local_command(command: str) -> dict:
    try:
        if platform.system().lower() == 'windows':
            proc = subprocess.run(
                ['powershell', '-NoProfile', '-Command', command],
                capture_output=True, text=True, timeout=30,
            )
        else:
            proc = subprocess.run(
                command, capture_output=True, text=True, shell=True, timeout=30,
            )
        return {
            'success':   True,
            'output':    proc.stdout or '',
            'stderr':    proc.stderr or '',
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
        session   = winrm.Session(f'http://{ip}:5985/wsman', auth=(bind_user, password), transport='ntlm')
        result    = session.run_ps(command)
        stdout    = result.std_out.decode(errors='ignore').strip()
        stderr    = result.std_err.decode(errors='ignore').strip()
        if result.status_code != 0:
            return {
                'success': False,
                'error':   stderr or f'Command failed with code {result.status_code}',
                'output':  stdout,
            }
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
        error  = stderr.read().decode(errors='ignore').strip()
        client.close()
        return {'success': True, 'output': output, 'stderr': error}
    except Exception as e:
        return {'success': False, 'error': f'SSH shell error: {e}'}


# ---------------------------------------------------------------------------
# PowerShell profile collection & application
# ---------------------------------------------------------------------------

def _parse_json_object_output(raw: str) -> dict:
    text = (raw or "").strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        pass
    first = text.find("{")
    last  = text.rfind("}")
    if first != -1 and last != -1 and last > first:
        snippet = text[first:last + 1]
        try:
            parsed = json.loads(snippet)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _format_domain_level(raw_value: str | None) -> str | None:
    if raw_value is None:
        return None
    raw = str(raw_value).strip()
    if not raw:
        return None
    return f"Level {raw} ({Config.DOMAIN_LEVEL_MAP.get(raw, 'Unknown')})"


def _collect_powershell_profile(req: dict, result: dict) -> dict:
    mode  = str(req.get("mode", "remote")).lower()
    proto = str(req.get("protocol", result.get("protocol_used", ""))).lower()

    if mode == "local" or result.get("protocol_used") == "local" or proto == "local":
        ps_result = run_local_command(_POWERSHELL_PROFILE_SCRIPT)
        if ps_result.get("success"):
            return _parse_json_object_output(ps_result.get("output", ""))
        return {}

    ip       = str(req.get("ip", "")).strip()
    user     = str(req.get("username", "")).strip()
    password = str(req.get("password", ""))
    domain   = str(req.get("domain", result.get("domain", ""))).strip()

    # Prefer WinRM PowerShell profile even if session protocol is SMB/LDAP/SSH.
    if ip and user and password and domain and not is_ntlm_hash(password):
        winrm_res = run_winrm_command(ip, user, password, domain, _POWERSHELL_PROFILE_SCRIPT)
        if winrm_res.get("success"):
            return _parse_json_object_output(winrm_res.get("output", ""))

    # Optional SSH fallback for Windows OpenSSH endpoints.
    if proto == "ssh" and ip and user and password:
        compact_cmd = _POWERSHELL_PROFILE_SCRIPT.replace('"', '`"').replace("\n", "; ")
        ssh_res = run_ssh_command(
            ip, user, password,
            f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{compact_cmd}"',
        )
        if ssh_res.get("success"):
            return _parse_json_object_output(ssh_res.get("output", ""))

    return {}


def _apply_powershell_profile(result: dict, profile: dict) -> None:
    if not isinstance(profile, dict) or not profile:
        return

    domain = str(profile.get("domain") or "").strip()
    if domain:
        result["domain"] = domain

    session_user = str(profile.get("session_user") or "").strip()
    if session_user:
        result["username"] = session_user.split("\\")[-1].split("@")[0].upper()

    dc_ip   = str(profile.get("dc_ip")   or "").strip()
    dc_name = str(profile.get("dc_name") or "").strip()
    if dc_ip:
        result["dc"] = dc_ip
    if dc_name:
        result["dnsHostName"] = dc_name
        if not dc_ip:
            result["dc"] = dc_name

    os_version = str(profile.get("os_version") or "").strip()
    if os_version:
        result["os_version"] = os_version

    domain_level = _format_domain_level(profile.get("domain_level_raw"))
    if domain_level:
        result["domain_level"] = domain_level

    result.setdefault("meta", {})
    result["meta"]["profile_source"] = "powershell"