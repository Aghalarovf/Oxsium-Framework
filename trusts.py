import re
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


def decode_trust_direction(value: int) -> str:
    direction = safe_int(value, 0)
    if direction == 1:
        return "Inbound"
    if direction == 2:
        return "Outbound"
    if direction == 3:
        return "Bidirectional"
    return "Unknown"


def decode_trust_type(value: int) -> str:
    trust_type = safe_int(value, 0)
    mapping = {
        1: "Downlevel",
        2: "Uplevel (Active Directory)",
        3: "MIT (Kerberos Realm)",
        4: "DCE",
    }
    return mapping.get(trust_type, "Unknown")


def get_domain_trusts(ip, domain, username, password, config):
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
            "cn", "distinguishedName", "flatName", "trustPartner",
            "trustDirection", "trustType", "trustAttributes",
            "securityIdentifier", "whenCreated", "whenChanged",
        ]

        conn.search(
            base_dn,
            "(objectClass=trustedDomain)",
            search_scope=SUBTREE,
            attributes=attrs,
            paged_size=getattr(config, "LDAP_PAGE_SIZE", 500),
        )

        trusts = []
        for entry in conn.entries:
            def get_attr(attr_name):
                attr = getattr(entry, attr_name, None)
                if not attr:
                    return None
                return attr.value

            direction_val = safe_int(get_attr("trustDirection"), 0)
            type_val = safe_int(get_attr("trustType"), 0)
            attr_val = safe_int(get_attr("trustAttributes"), 0)
            is_inbound = direction_val in (1, 3)
            is_outbound = direction_val in (2, 3)
            is_forest = bool(attr_val & 0x00000008) or type_val == 2
            is_transitive = not bool(attr_val & 0x00000001) or is_forest

            trusts.append({
                "name": str(get_attr("cn") or ""),
                "dn": str(get_attr("distinguishedName") or ""),
                "flat_name": str(get_attr("flatName") or ""),
                "partner": str(get_attr("trustPartner") or ""),
                "direction": decode_trust_direction(direction_val),
                "direction_raw": direction_val,
                "trust_type": decode_trust_type(type_val),
                "trust_type_raw": type_val,
                "attributes": attr_val,
                "inbound": is_inbound,
                "outbound": is_outbound,
                "transitive": is_transitive,
                "forest": is_forest,
                "sid": str(get_attr("securityIdentifier") or ""),
                "when_created": ldap_timestamp_to_iso(get_attr("whenCreated")),
                "when_changed": ldap_timestamp_to_iso(get_attr("whenChanged")),
            })

        conn.unbind()
        return {"success": True, "trusts": trusts, "count": len(trusts)}

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as exc:
        return {"success": False, "error": f"Internal server error: {exc}", "code": 500}
