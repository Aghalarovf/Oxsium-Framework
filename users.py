import re
from datetime import datetime, timezone
from ldap3 import Server, Connection, ALL, SUBTREE, Attribute
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
        "dont_req_preauth": bool(uac & 0x400000),  # Düzəldilən hissə: 0x0040 əvəzinə 0x400000
        "pwd_never_expires": bool(uac & 0x10000),
        "pwd_not_required": bool(uac & 0x0020),
        "locked_out": bool(uac & 0x0010),
        "trusted_for_delegation": bool(uac & 0x80000),
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


def get_domain_users(ip, domain, username, password, config):
    auth_type = "SIMPLE"
    if is_ntlm_hash(password):
        password = f"00000000000000000000000000000000:{password}"
        auth_type = "NTLM"

    base_dn = domain_to_dn(domain)
    bind_user = get_bind_user(username, domain)

    admin_group_keywords = {
        "domain admins", "enterprise admins", "schema admins",
        "administrators", "account operators", "backup operators",
    }

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
            "sAMAccountName", "distinguishedName", "displayName",
            "objectSid", "userPrincipalName", "description",
            "userAccountControl", "memberOf", "servicePrincipalName",
            "pwdLastSet", "whenCreated", "whenChanged",
            "lastLogonTimestamp", "lockoutTime", "logonCount",
        ]

        conn.search(
            base_dn,
            "(&(objectClass=user)(objectCategory=person))",
            search_scope=SUBTREE,
            attributes=attrs,
            paged_size=getattr(config, "LDAP_PAGE_SIZE", 500),
        )

        users = []
        for entry in conn.entries:
            uac_raw = entry.userAccountControl.value if entry.userAccountControl else 0
            user_account_control = parse_user_account_control(uac_raw)
            
            # Atributları təhlükəsiz şəkildə oxumaq üçün köməkçi (Təkmilləşdirilib)
            def get_attr(attr_name, is_list=False):
                attr = getattr(entry, attr_name, None)
                if not attr: return [] if is_list else None
                # ldap3-də multi-valued (siyahı) atributlar üçün attr.values daha dəqiq işləyir
                return attr.values if is_list else attr.value

            sam_name = str(get_attr("sAMAccountName") or "")
            upn_value = str(get_attr("userPrincipalName") or "")
            groups_raw = get_attr("memberOf", is_list=True) or []
            if not isinstance(groups_raw, list): groups_raw = [str(groups_raw)]

            # AS-REP Roasting Məntiqi
            # Şərt: Preauth tələb olunmur (0x400000) VƏ istifadəçi adı mövcuddur.
            # Qeyd: Hesabın 'disabled' olması onun konfiqurasiya olaraq zəif olduğunu dəyişmir, 
            # buna görə disabled yoxlaması məqsədli şəkildə daxil edilməyib.
            is_asrep_vulnerable = user_account_control["dont_req_preauth"] and bool(sam_name)

            is_admin = any(
                any(keyword in group.lower() for keyword in admin_group_keywords)
                for group in [str(g) for g in groups_raw]
            )

            groups_short = []
            for group_dn in groups_raw:
                group_dn_str = str(group_dn)
                first_part = group_dn_str.split(",")[0]
                groups_short.append(first_part[3:] if first_part.lower().startswith("cn=") else first_part)

            users.append({
                "username": sam_name,
                "dn": str(get_attr("distinguishedName") or ""),
                "display_name": str(get_attr("displayName") or ""),
                "sid": str(get_attr("objectSid") or ""),
                "upn": upn_value,
                "description": str(get_attr("description") or ""),
                "disabled": user_account_control["disabled"],
                "is_admin": is_admin,
                "asrep": is_asrep_vulnerable,
                "spn": [str(s) for s in (get_attr("servicePrincipalName", is_list=True) or [])],
                "preauth_required": not user_account_control["dont_req_preauth"],
                "pwd_never_expires": user_account_control["pwd_never_expires"],
                "pwd_not_required": user_account_control["pwd_not_required"],
                "locked_out": user_account_control["locked_out"],
                "must_change_pwd": safe_int(get_attr("pwdLastSet"), 1) == 0,
                "trusted_for_delegation": user_account_control["trusted_for_delegation"],
                "member_of": groups_short,
                "when_created": ldap_timestamp_to_iso(get_attr("whenCreated")),
                "when_changed": ldap_timestamp_to_iso(get_attr("whenChanged")),
                "last_logon": ldap_timestamp_to_iso(get_attr("lastLogonTimestamp")),
                "pwd_last_set": ldap_timestamp_to_iso(get_attr("pwdLastSet")),
                "logon_count": safe_int(get_attr("logonCount"), 0),
            })

        conn.unbind()
        return {"success": True, "users": users, "count": len(users)}

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as exc:
        return {"success": False, "error": f"Internal server error: {exc}", "code": 500}
