import re
from datetime import datetime, timezone
from ldap3 import Server, Connection, ALL, SUBTREE, BASE
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
            "objectSid", "groupType", "member", "managedBy",
            "adminCount", "whenCreated", "whenChanged", "memberOf",
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

            members = getattr(entry, "member", None)
            members_list = [str(v) for v in (getattr(members, "values", []) or [])]
            member_count = len(members_list)
            member_of = getattr(entry, "memberOf", None)
            member_of_list = [str(v) for v in (getattr(member_of, "values", []) or [])]
            group_type = safe_int(get_attr("groupType"), 0)
            name = str(get_attr("cn") or "")
            sam_name = str(get_attr("sAMAccountName") or "")
            sid = str(get_attr("objectSid") or "")

            privileged_names = {
                "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
                "ADMINISTRATORS", "ACCOUNT OPERATORS", "SERVER OPERATORS",
                "BACKUP OPERATORS", "PRINT OPERATORS",
            }
            privileged_rids = ("-512", "-518", "-519", "-520", "-544", "-548", "-549", "-550")
            is_privileged = (
                name.upper() in privileged_names or
                sam_name.upper() in privileged_names or
                sid.endswith(privileged_rids)
            )

            groups.append({
                "name": name,
                "sam_name": sam_name,
                "dn": str(get_attr("distinguishedName") or ""),
                "description": str(get_attr("description") or ""),
                "sid": sid,
                "group_type": decode_group_type(group_type),
                "group_type_raw": group_type,
                "member_count": member_count,
                "members": members_list,
                "member_of": member_of_list,
                "member_of_count": len(member_of_list),
                "is_empty": member_count == 0,
                "is_nested": len(member_of_list) > 0,
                "is_privileged": is_privileged,
                "managed_by": str(get_attr("managedBy") or ""),
                "is_protected": safe_int(get_attr("adminCount"), 0) == 1,
                "when_created": ldap_timestamp_to_iso(get_attr("whenCreated")),
                "when_changed": ldap_timestamp_to_iso(get_attr("whenChanged")),
            })

        # Resolve group member identities and SIDs for expandable members view.
        member_dns = {
            m.strip()
            for g in groups
            for m in (g.get("members") or [])
            if isinstance(m, str) and m.strip()
        }
        member_map = {}
        for member_dn in member_dns:
            try:
                conn.search(
                    search_base=member_dn,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=["sAMAccountName", "cn", "objectSid", "objectClass"],
                )
                if not conn.entries:
                    continue
                ment = conn.entries[0]
                sam = getattr(ment, "sAMAccountName", None)
                cn = getattr(ment, "cn", None)
                sid = getattr(ment, "objectSid", None)
                cls = getattr(ment, "objectClass", None)
                classes = [str(v).lower() for v in (getattr(cls, "values", []) or [])]
                member_map[member_dn] = {
                    "name": str(getattr(sam, "value", None) or getattr(cn, "value", None) or member_dn),
                    "sid": str(getattr(sid, "value", "") or ""),
                    "dn": member_dn,
                    "is_user": "user" in classes and "computer" not in classes,
                }
            except Exception:
                member_map[member_dn] = {
                    "name": member_dn,
                    "sid": "",
                    "dn": member_dn,
                    "is_user": False,
                }

        for g in groups:
            resolved = [
                member_map[m]
                for m in (g.get("members") or [])
                if isinstance(m, str) and m in member_map
            ]
            users_only = [m for m in resolved if m.get("is_user")]
            g["member_users"] = users_only
            g["member_users_count"] = len(users_only)

        conn.unbind()
        return {"success": True, "groups": groups, "count": len(groups)}

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as exc:
        return {"success": False, "error": f"Internal server error: {exc}", "code": 500}
