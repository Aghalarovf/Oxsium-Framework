import re
from datetime import datetime, timezone, timedelta
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


def get_domain_computers(ip, domain, username, password, config):
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
            "sAMAccountName", "distinguishedName", "displayName",
            "objectSid", "dnsHostName", "description",
            "userAccountControl", "servicePrincipalName",
            "operatingSystem", "operatingSystemVersion",
            "pwdLastSet", "whenCreated", "whenChanged",
            "lastLogonTimestamp", "location", "physicalLocationObject",
            "msDS-AllowedToDelegateTo", "primaryGroupID",
        ]

        conn.search(
            base_dn,
            "(&(objectClass=computer))",
            search_scope=SUBTREE,
            attributes=attrs,
            paged_size=getattr(config, "LDAP_PAGE_SIZE", 500),
        )

        computers = []
        stale_cutoff = datetime.now(timezone.utc) - timedelta(days=45)
        for entry in conn.entries:
            uac_raw = entry.userAccountControl.value if entry.userAccountControl else 0
            user_account_control = parse_user_account_control(uac_raw)
            
            # Atributları təhlükəsiz şəkildə oxumaq üçün köməkçi
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

            # Check for Kerberoasting vulnerability (computer has SPNs)
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

            computers.append({
                "computer_name": sam_name,
                "dns_name": dns_name,
                "dn": dn_value,
                "display_name": str(get_attr("displayName") or ""),
                "sid": str(get_attr("objectSid") or ""),
                "description": str(get_attr("description") or ""),
                "disabled": user_account_control["disabled"],
                "os": os_name,
                "os_version": str(get_attr("operatingSystemVersion") or ""),
                "os_bucket": os_bucket,
                "spn": [str(s) for s in spn_list],
                "has_spn": has_spn,
                "trusted_for_delegation": user_account_control["trusted_for_delegation"],
                "trusted_to_auth_for_delegation": user_account_control["trusted_to_auth_for_delegation"],
                "unconstrained_delegation": user_account_control["trusted_for_delegation"],
                "constrained_delegation": len(allowed_to_delegate) > 0,
                "allowed_to_delegate_to": [str(s) for s in allowed_to_delegate],
                "is_workstation": user_account_control["workstation_trust_account"],
                "is_server": user_account_control["server_trust_account"],
                "is_domain_controller": is_domain_controller,
                "is_stale": is_stale,
                "stale_by_pwd": stale_by_pwd,
                "stale_by_logon": stale_by_logon,
                "location": str(get_attr("location") or ""),
                "when_created": ldap_timestamp_to_iso(get_attr("whenCreated")),
                "when_changed": ldap_timestamp_to_iso(get_attr("whenChanged")),
                "last_logon": last_logon,
                "pwd_last_set": pwd_last_set,
            })

        conn.unbind()
        return {"success": True, "computers": computers, "count": len(computers)}

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as exc:
        return {"success": False, "error": f"Internal server error: {exc}", "code": 500}
