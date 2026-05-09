import re
import json
import os
from datetime import datetime, timezone
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPSocketOpenError


def is_ntlm_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}", value))


def domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def get_bind_user(username: str, domain: str) -> str:
    if "@" in username or "\\" in username:
        return username
    netbios = domain.split(".")[0].upper()
    return f"{netbios}\\{username}"


def normalize_value(value):
    if hasattr(value, "value"):
        value = value.value
    if isinstance(value, list):
        return value[0] if value else None
    return value


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


def ldap_timestamp_to_iso(value):
    normalized = normalize_value(value)
    if normalized is None:
        return None
    if isinstance(normalized, datetime):
        return normalized.replace(tzinfo=timezone.utc).isoformat()
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


def decode_group_type(value: int) -> str:
    group_type = safe_int(value, 0)
    scope = "Unknown"
    category = "Security"

    if group_type & 0x00000002:
        scope = "Global"
    elif group_type & 0x00000004:
        scope = "Domain Local"
    elif group_type & 0x00000008:
        scope = "Universal"

    if not (group_type & 0x80000000):
        category = "Distribution"

    return f"{category} / {scope}"


def _parse_isaclprotected(sd_raw) -> bool:
    """
    nTSecurityDescriptor Control word-ünün SE_DACL_PROTECTED (0x1000) bitini yoxlayır.
    Set-dirsə ACL inheritance bloklanıb — BloodHound 'isaclprotected' field-i.
    """
    if isinstance(sd_raw, (bytearray, memoryview)):
        sd_raw = bytes(sd_raw)
    if not isinstance(sd_raw, bytes) or len(sd_raw) < 4:
        return False
    try:
        control = int.from_bytes(sd_raw[2:4], byteorder="little")
        return bool(control & 0x1000)
    except Exception:
        return False


def _extract_domainsid_from_sid(sid_str: str) -> str:
    """
    Qrupun öz SID-indən domain SID-ini çıxarır.
    S-1-5-21-X-X-X-RID  →  S-1-5-21-X-X-X
    """
    if not sid_str:
        return ""
    parts = sid_str.split("-")
    if len(parts) >= 8 and parts[2] == "5" and parts[3] == "21":
        return "-".join(parts[:-1])
    return ""


def _parse_sid_history(entry) -> list:
    """
    sIDHistory atributunu oxuyur — köhnə domainlərdən miras qalan SID-lər.
    Migration zamanı təhlükəli ola bilər (privilege escalation riski).
    """
    sid_history_attr = getattr(entry, "sIDHistory", None)
    if not sid_history_attr:
        return []
    values = getattr(sid_history_attr, "values", []) or []
    return [str(v) for v in values if v]


def _is_protected_users_group(sid: str) -> bool:
    """
    Protected Users Group-u yoxlayır.
    Well-known RID: 525  →  SID S-1-5-21-<domain>-525
    """
    return sid.endswith("-525")


def _extract_rid_from_sid(sid: str) -> int | None:
    sid_text = str(sid or "").strip()
    if not sid_text:
        return None
    parts = sid_text.split("-")
    if not parts:
        return None
    try:
        return int(parts[-1])
    except (TypeError, ValueError):
        return None


def _is_potential_privileged_by_rid(rid: int | None) -> bool:
    potential_privileged_rids = {548, 549, 551, 520, 550, 569, 578, 582, 526, 527, 553, 557}
    return rid in potential_privileged_rids


def get_domain_groups(ip, domain, username, password, config):
    auth_type = "SIMPLE"
    if is_ntlm_hash(password):
        password = f"00000000000000000000000000000000:{password}"
        auth_type = "NTLM"

    base_dn = domain_to_dn(domain)
    bind_user = get_bind_user(username, domain)

    try:
        server = Server(ip, get_info=ALL, connect_timeout=config.LDAP_CONNECT_TIMEOUT)
        conn = Connection(
            server,
            user=bind_user,
            password=password,
            authentication=auth_type,
            auto_bind=True,
            receive_timeout=config.LDAP_RECEIVE_TIMEOUT,
        )

        attrs = [
            "cn", "sAMAccountName", "distinguishedName", "description",
            "objectSid", "groupType", "managedBy",
            "adminCount", "whenCreated", "whenChanged", "memberOf",
            "nTSecurityDescriptor",  # isaclprotected üçün
            "primaryGroupToken",     # PrimaryGroupToken — bu qrupu primary group kimi
                                     # istifadə edən userları tapmaq üçün əsas dəyər
            "sIDHistory",            # SID History — köhnə domainlərdən miras SID-lər
        ]

        conn.search(
            base_dn,
            "(objectClass=group)",
            search_scope=SUBTREE,
            attributes=attrs,
            paged_size=getattr(config, "LDAP_PAGE_SIZE", 500),
        )

        groups = []
        for entry in conn.entries:
            def get_attr(attr_name):
                attr = getattr(entry, attr_name, None)
                if not attr:
                    return None
                return attr.value

            member_of = getattr(entry, "memberOf", None)
            member_of_list = [str(v) for v in (getattr(member_of, "values", []) or [])]
            group_type = safe_int(get_attr("groupType"), 0)
            name = str(get_attr("cn") or "")
            sam_name = str(get_attr("sAMAccountName") or "")
            sid = str(get_attr("objectSid") or "")

            # ── isaclprotected ───────────────────────────────────────────────
            ntsd_raw = get_attr("nTSecurityDescriptor")
            if isinstance(ntsd_raw, (bytearray, memoryview)):
                ntsd_raw = bytes(ntsd_raw)
            elif not isinstance(ntsd_raw, bytes):
                ntsd_raw = b""
            isaclprotected = _parse_isaclprotected(ntsd_raw)

            # ── domainsid ────────────────────────────────────────────────────
            domainsid = _extract_domainsid_from_sid(sid)

            # ── primaryGroupToken ────────────────────────────────────────────
            # Bu token-i primaryGroupID-i eyni olan userlar bu qrupu
            # primary group kimi istifadə edir (default: 513 = Domain Users)
            primary_group_token = safe_int(get_attr("primaryGroupToken"), None)

            # ── SID History ──────────────────────────────────────────────────
            # Köhnə domain SID-lərini saxlayır; migration sonrası silinməyibsə
            # privilege escalation riski yarada bilər
            sid_history = _parse_sid_history(entry)

            # ── Protected Users Group ────────────────────────────────────────
            # RID-525 qrupu — NTLM, RC4, unconstrained delegation-u bloklayır
            is_protected_users = _is_protected_users_group(sid)

            privileged_names = {
                "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
                "ADMINISTRATORS", "ACCOUNT OPERATORS", "SERVER OPERATORS",
                "BACKUP OPERATORS", "PRINT OPERATORS",
            }
            privileged_rids = ("-512", "-518", "-519", "-520", "-544", "-548", "-549", "-550")
            required_privileged_rids = {512, 519, 518, 544, 516, 498, 521}
            sid_rid = _extract_rid_from_sid(sid)
            potential_privileged = _is_potential_privileged_by_rid(sid_rid)
            is_privileged = (
                name.upper() in privileged_names or
                sam_name.upper() in privileged_names or
                sid.endswith(privileged_rids) or
                (sid_rid in required_privileged_rids)
            )

            risk_controls = []
            if is_privileged:
                risk_controls.append("Privileged Group")
            if len(member_of_list) > 0:
                risk_controls.append("Nested Group")
            if sid_history:
                risk_controls.append("SID History Present")
            if is_protected_users:
                risk_controls.append("Protected Users Group")

            groups.append({
                "name": name,
                "group_name": name,
                "sam_name": sam_name,
                "group_sid": sid,
                "dn": str(get_attr("distinguishedName") or ""),
                "description": str(get_attr("description") or ""),
                "sid": sid,
                "group_type": decode_group_type(group_type),
                "group_type_raw": group_type,
                "groupType": group_type,
                "member_count": None,
                "members": [],
                "member_users": [],
                "member_users_count": None,
                "member_of": member_of_list,
                "member_of_count": len(member_of_list),
                "is_empty": False,
                "is_nested": len(member_of_list) > 0,
                "is_privileged": is_privileged,
                "potential_privileged": potential_privileged,
                "managed_by": str(get_attr("managedBy") or ""),
                "managedBy": str(get_attr("managedBy") or ""),
                "is_protected": safe_int(get_attr("adminCount"), 0) == 1,
                "when_created": ldap_timestamp_to_iso(get_attr("whenCreated")),
                "when_changed": ldap_timestamp_to_iso(get_attr("whenChanged")),
                "isaclprotected": isaclprotected,       # ACL inheritance bloklanıb/bloklanmayıb
                "domainsid": domainsid,                 # Domain SID (cross-domain path üçün)
                "primary_group_token": primary_group_token,  # primaryGroupToken dəyəri
                "primaryGroupToken": primary_group_token,
                "sid_history": sid_history,             # Köhnə domain SID-lərinin siyahısı
                "is_protected_users_group": is_protected_users,  # RID-525 Protected Users
                "risk_controls": risk_controls,
            })

        conn.unbind()

        result = {"success": True, "groups": groups, "count": len(groups)}

        # ── domain_groups.json-a yaz ─────────────────────────────────────────
        output_path = os.path.join(
            str(config.DOMAIN_OBJECT_DIR), "domain_groups.json"
        )
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2, default=str)
        except Exception as write_exc:
            result["json_export_error"] = str(write_exc)

        return result

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as exc:
        return {"success": False, "error": f"Internal server error: {exc}", "code": 500}