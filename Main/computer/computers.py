import os
import re
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone, timedelta
from ldap3 import Server, Connection, ALL, SUBTREE, Attribute
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPSocketOpenError

from connect.ldap_core import open_standalone_connection
try:
    pass  
except ImportError:
    pass  
try:
    from impacket.ldap import ldaptypes as _ldaptypes
    _IMPACKET_OK = True
except ImportError:
    _IMPACKET_OK = False


def is_ntlm_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}", value))


def domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def get_bind_user(username: str, domain: str) -> str:
    if "@" in username or "\\" in username:
        return username
    return f"{username}@{domain}"


def normalize_value(value):
    if isinstance(value, Attribute):
        value = value.value
    if isinstance(value, list):
        return value[0] if value else None
    return value


def normalize_values(value):
    if isinstance(value, Attribute):
        value = value.value
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if value is None:
        return []
    return [str(value)]


def safe_int(value, default=0):
    value = normalize_value(value)
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (ValueError, TypeError):
        return default


def parse_user_account_control(raw_value):
    uac = safe_int(raw_value, 0)
    return {
        "disabled": bool(uac & 0x0002),
        "trusted_for_delegation": bool(uac & 0x80000),
        "trusted_to_auth_for_delegation": bool(uac & 0x1000000),
        "workstation_trust_account": bool(uac & 0x1000),
        "server_trust_account": bool(uac & 0x2000),
    }


def ldap_timestamp_to_iso(value):
    normalized = normalize_value(value)
    if normalized is None:
        return None
    if isinstance(normalized, str) and not normalized.isdigit():
        return normalized
    try:
        ticks = int(str(normalized))
    except (ValueError, TypeError):
        return str(normalized)
    if ticks in (0, 9223372036854775807):
        return None
    unix_seconds = (ticks - 116444736000000000) / 10000000
    try:
        dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        return dt.isoformat()
    except (OSError, OverflowError, ValueError):
        return str(normalized)


def parse_iso_datetime(value):
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except Exception:
        return None


def _normalize_sd_raw(value):
    value = normalize_value(value)
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    return b""


def _security_descriptor_to_sddl(sd_raw: bytes) -> str:
    if not sd_raw or os.name != "nt":
        return ""
    try:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        convert_fn = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
        convert_fn.argtypes = [
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(wintypes.DWORD),
        ]
        convert_fn.restype = wintypes.BOOL

        local_free = kernel32.LocalFree
        local_free.argtypes = [wintypes.HLOCAL]
        local_free.restype = wintypes.HLOCAL

        sd_buf = ctypes.create_string_buffer(sd_raw)
        out_str = wintypes.LPWSTR()
        out_len = wintypes.DWORD(0)
        SDDL_REVISION_1 = 1
        OWNER_GROUP_DACL = 0x00000007

        ok = convert_fn(
            ctypes.cast(sd_buf, wintypes.LPVOID),
            SDDL_REVISION_1,
            OWNER_GROUP_DACL,
            ctypes.byref(out_str),
            ctypes.byref(out_len),
        )
        if not ok or not out_str.value:
            return ""
        sddl = str(out_str.value)
        local_free(ctypes.cast(out_str, wintypes.HLOCAL))
        return sddl
    except Exception:
        return ""


def _extract_sid_tokens_from_sddl(sddl: str) -> list[str]:
    if not sddl:
        return []
    sids = re.findall(r";;;(S-\d-\d+(?:-\d+)+)", sddl)
    seen = set()
    out = []
    for sid in sids:
        if sid not in seen:
            seen.add(sid)
            out.append(sid)
    return out


def _extract_rbcd_sids(sd_raw: bytes, sddl: str) -> list[str]:
    sids = []
    if _IMPACKET_OK and sd_raw:
        try:
            sd = _ldaptypes.SR_SECURITY_DESCRIPTOR()
            sd.fromString(sd_raw)
            if sd["Dacl"]:
                for ace in sd["Dacl"].aces:
                    try:
                        sid = str(ace["Ace"]["Sid"].formatCanonical())
                        if sid:
                            sids.append(sid)
                    except Exception:
                        continue
        except Exception:
            pass

    if not sids and sddl:
        sids = _extract_sid_tokens_from_sddl(sddl)

    seen = set()
    out = []
    for sid in sids:
        if sid and sid not in seen:
            seen.add(sid)
            out.append(sid)
    return out


def _normalize_laps_values(attr_name: str, raw_value) -> list[str]:
    values = raw_value if isinstance(raw_value, list) else [raw_value]
    normalized = []
    for item in values:
        if item is None:
            continue
        if isinstance(item, (bytes, bytearray, memoryview)):
            b = bytes(item)
            if not b:
                continue
            normalized.append(b.hex())
            continue

        text = str(item).strip()
        if not text:
            continue

        if attr_name in ("ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime"):
            converted = ldap_timestamp_to_iso(text)
            normalized.append(converted if converted else text)
        else:
            normalized.append(text)
    return normalized


def _parse_isaclprotected(sd_raw: bytes) -> bool:

    if not sd_raw or len(sd_raw) < 4:
        return False
    try:
        # SD struktur: Revision(1) + Sbz1(1) + Control(2) + ...
        control = int.from_bytes(sd_raw[2:4], byteorder="little")
        SE_DACL_PROTECTED = 0x1000
        return bool(control & SE_DACL_PROTECTED)
    except Exception:
        return False


def _parse_sid_history(raw_values) -> list[str]:

    if not raw_values:
        return []
    if not isinstance(raw_values, list):
        raw_values = [raw_values]
    result = []
    for item in raw_values:
        if item is None:
            continue
        try:
            if _IMPACKET_OK:
                from impacket.ldap import ldaptypes as _lt
                sid_obj = _lt.LDAP_SID(data=bytes(item) if not isinstance(item, bytes) else item)
                result.append(sid_obj.formatCanonical())
            else:
                # impacket yoxdursa raw hex kimi saxla
                result.append(bytes(item).hex() if not isinstance(item, bytes) else item.hex())
        except Exception:
            try:
                result.append(str(item))
            except Exception:
                pass
    return result


def _extract_domainsid_from_sid(sid_str: str) -> str:

    if not sid_str:
        return ""
    parts = sid_str.split("-")
    if len(parts) >= 8 and parts[2] == "5" and parts[3] == "21":
        return "-".join(parts[:-1])
    return ""


def _is_potential_privileged_by_rid(primary_group_id: int) -> bool:
    potential_privileged_rids = {548, 549, 551, 520, 550, 569, 578, 582, 526, 527, 553, 557}
    return int(primary_group_id) in potential_privileged_rids



def get_domain_computers(ip, domain, username, password, config, conn=None, base_dn=None):
    owns_connection = conn is None

    if not owns_connection:
        base_dn = base_dn or domain_to_dn(domain)

    try:
        if owns_connection:
            conn, base_dn = open_standalone_connection(ip, username, password, domain, config)

        laps_attr_names = [
            "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-PasswordHistory",
            "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory", "msLAPS-EncryptedDSRoot",
            "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime",
        ]

        attrs = [
            "sAMAccountName", "distinguishedName", "displayName",
            "objectSid", "dnsHostName", "description",
            "userAccountControl", "servicePrincipalName",
            "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack",
            "pwdLastSet", "whenCreated", "whenChanged",
            "lastLogonTimestamp", "location", "physicalLocationObject",
            "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "primaryGroupID",
            "nTSecurityDescriptor", 
            "sIDHistory",         
            *laps_attr_names,
        ]

        requested_attrs = list(attrs)
        while True:
            try:
                conn.search(
                    base_dn,
                    "(&(objectClass=computer))",
                    search_scope=SUBTREE,
                    attributes=requested_attrs,
                    paged_size=getattr(config, "LDAP_PAGE_SIZE", 500),
                )
                break
            except Exception as search_exc:
                error_text = str(search_exc)
                if "invalid attribute type" not in error_text.lower():
                    raise

                invalid_match = re.search(r"invalid\s+attribute\s+type\s*[:=]?\s*([A-Za-z0-9\-]+)", error_text, re.IGNORECASE)
                invalid_attr = invalid_match.group(1) if invalid_match else None

                if not invalid_attr:
                    invalid_attr = next(
                        (name for name in requested_attrs if name.lower() in error_text.lower()),
                        None,
                    )

                if not invalid_attr:
                    invalid_attr = next((name for name in requested_attrs if name in laps_attr_names), None)

                if not invalid_attr:
                    raise

                filtered_attrs = [name for name in requested_attrs if name.lower() != invalid_attr.lower()]
                if len(filtered_attrs) == len(requested_attrs):
                    raise
                requested_attrs = filtered_attrs

        computers = []
        stale_cutoff = datetime.now(timezone.utc) - timedelta(days=45)
        for entry in conn.entries:
            uac_raw = entry.userAccountControl.value if entry.userAccountControl else 0
            user_account_control = parse_user_account_control(uac_raw)
            
            def get_attr(attr_name, is_list=False):
                attr = getattr(entry, attr_name, None)
                if not attr: return [] if is_list else None
                return attr.values if is_list else attr.value

            sam_name = str(get_attr("sAMAccountName") or "")
            dns_name = str(get_attr("dnsHostName") or "")
            spn_list = get_attr("servicePrincipalName", is_list=True) or []
            if not isinstance(spn_list, list): spn_list = [str(spn_list)]
            allowed_to_delegate = get_attr("msDS-AllowedToDelegateTo", is_list=True) or []
            if not isinstance(allowed_to_delegate, list):
                allowed_to_delegate = [str(allowed_to_delegate)]

            rbcd_raw = _normalize_sd_raw(get_attr("msDS-AllowedToActOnBehalfOfOtherIdentity"))
            rbcd_enabled = bool(rbcd_raw)
            rbcd_sddl = _security_descriptor_to_sddl(rbcd_raw) if rbcd_enabled else ""
            rbcd_principals = _extract_rbcd_sids(rbcd_raw, rbcd_sddl) if rbcd_enabled else []

            ntsd_raw = _normalize_sd_raw(get_attr("nTSecurityDescriptor"))
            isaclprotected = _parse_isaclprotected(ntsd_raw)

            sid_history_raw = get_attr("sIDHistory", is_list=True) or []
            sid_history = _parse_sid_history(sid_history_raw)

            own_sid = str(get_attr("objectSid") or "")
            domainsid = _extract_domainsid_from_sid(own_sid)


            laps_attributes = {
                attr_name: _normalize_laps_values(attr_name, get_attr(attr_name, is_list=True))
                for attr_name in laps_attr_names
            }
            has_laps = any(laps_attributes[attr_name] for attr_name in laps_attr_names)

            has_spn = len(spn_list) > 0

            pwd_last_set = ldap_timestamp_to_iso(get_attr("pwdLastSet"))
            last_logon = ldap_timestamp_to_iso(get_attr("lastLogonTimestamp"))
            pwd_dt = parse_iso_datetime(pwd_last_set)
            logon_dt = parse_iso_datetime(last_logon)
            stale_by_pwd = pwd_dt is None or pwd_dt < stale_cutoff
            stale_by_logon = logon_dt is None or logon_dt < stale_cutoff
            is_stale = bool(stale_by_pwd and stale_by_logon)

            dn_value = str(get_attr("distinguishedName") or "")
            primary_group_id = safe_int(get_attr("primaryGroupID"), 0)
            potential_privileged = _is_potential_privileged_by_rid(primary_group_id)
            is_domain_controller = (
                "OU=Domain Controllers" in dn_value or
                primary_group_id == 516 or
                user_account_control["server_trust_account"]
            )

            os_name = str(get_attr("operatingSystem") or "")
            os_bucket = "unknown"
            if "server" in os_name.lower():
                os_bucket = "server"
            elif os_name:
                os_bucket = "workstation"

            risk_controls = []
            if user_account_control["trusted_for_delegation"]:
                risk_controls.append("Unconstrained Delegation")
            if len(allowed_to_delegate) > 0:
                risk_controls.append("Constrained Delegation")
            if rbcd_enabled:
                risk_controls.append("RBCD Enabled")
            if has_laps:
                risk_controls.append("LAPS Enabled")
            if is_domain_controller:
                risk_controls.append("Domain Controller")
            if is_stale:
                risk_controls.append("Stale Account")
            if sid_history:
                risk_controls.append("SID History Present")
            if isaclprotected:
                risk_controls.append("ACL Protected")

            smb_signing_required = None
            smb_version = None

            os_service_pack = str(get_attr("operatingSystemServicePack") or "")

            is_ip_only = None
            ipv4_addresses_reserved = []
            ipv6_addresses_reserved = []

            computers.append({
                "computer_name": sam_name,
                "dns_name": dns_name,
                "is_ip_only": is_ip_only,
                "ipv4_addresses": ipv4_addresses_reserved,
                "ipv6_addresses": ipv6_addresses_reserved,
                "dn": dn_value,
                "display_name": str(get_attr("displayName") or ""),
                "sid": own_sid,
                "primary_group_id": primary_group_id,
                "description": str(get_attr("description") or ""),
                "disabled": user_account_control["disabled"],
                "os": os_name,
                "os_version": str(get_attr("operatingSystemVersion") or ""),
                "os_service_pack": os_service_pack,
                "os_bucket": os_bucket,
                "spn": [str(s) for s in spn_list],
                "has_spn": has_spn,
                "trusted_for_delegation": user_account_control["trusted_for_delegation"],
                "trusted_to_auth_for_delegation": user_account_control["trusted_to_auth_for_delegation"],
                "unconstrained_delegation": user_account_control["trusted_for_delegation"],
                "constrained_delegation": len(allowed_to_delegate) > 0,
                "allowed_to_delegate_to": [str(s) for s in allowed_to_delegate],
                "rbcd_enabled": rbcd_enabled,
                "rbcd_sddl": rbcd_sddl,
                "rbcd_principals": rbcd_principals,
                "has_laps": has_laps,
                "haslaps": has_laps,                   # BloodHound canonical alias
                "laps_attributes": laps_attributes,
                "is_workstation": user_account_control["workstation_trust_account"],
                "is_server": user_account_control["server_trust_account"],
                "is_domain_controller": is_domain_controller,
                "potential_privileged": potential_privileged,
                "is_stale": is_stale,
                "stale_by_pwd": stale_by_pwd,
                "stale_by_logon": stale_by_logon,
                "location": str(get_attr("location") or ""),
                "when_created": ldap_timestamp_to_iso(get_attr("whenCreated")),
                "when_changed": ldap_timestamp_to_iso(get_attr("whenChanged")),
                "last_logon": last_logon,
                "pwd_last_set": pwd_last_set,
                "isaclprotected": isaclprotected,       
                "domainsid": domainsid,                 
                "sid_history": sid_history,             
                "smb_port_open": False,
                "smb_signing_required": smb_signing_required,
                "smb_version": smb_version,
                "admin_to": [],                        
                "sessions": [],                       
                "risk_controls": risk_controls,
            })

        if owns_connection:
            conn.unbind()

        smb_info = {"smb_port_open": False, "smb_signing_required": None, "smb_version": None}

        matched_comp = None

        if matched_comp is None:
            for comp in computers:
                if comp.get("is_domain_controller"):
                    matched_comp = comp
                    break

        if matched_comp is not None:
            # Reserved for future use — keep as null/empty
            matched_comp["ipv4_addresses"] = []
            matched_comp["smb_port_open"] = None
            matched_comp["smb_signing_required"] = None
            matched_comp["smb_version"] = None

        return {"success": True, "computers": computers, "count": len(computers)}

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as exc:
        return {"success": False, "error": f"Internal server error: {exc}", "code": 500}