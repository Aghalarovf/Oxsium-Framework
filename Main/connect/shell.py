import json
import platform
import subprocess

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