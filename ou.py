import re
from datetime import datetime, timezone
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPSocketOpenError


def is_ntlm_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}", value or ""))


def get_bind_user(username: str, domain: str) -> str:
    if "@" in username or "\\" in username:
        return username
    netbios = domain.split(".")[0].upper()
    return f"{netbios}\\{username}"

def normalize_value(val):
    """Convert LDAP Attribute object to native Python type."""
    if val is None:
        return None
    if hasattr(val, 'value'):
        return val.value
    return val

def normalize_values(vals):
    """Convert list of LDAP Attribute objects to native Python list."""
    if not vals:
        return []
    result = []
    for v in vals:
        if hasattr(v, 'value'):
            result.append(v.value)
        else:
            result.append(v)
    return result

def first_or_none(value):
    """Return first element for LDAP list values safely, otherwise return value itself."""
    if isinstance(value, list):
        return value[0] if value else None
    return value

def safe_int(val, default=0):
    """Safely convert value to int."""
    if val is None:
        return default
    if isinstance(val, bool):
        return default
    if isinstance(val, int):
        return val
    try:
        return int(str(val))
    except (ValueError, TypeError):
        return default

def ldap_timestamp_to_iso(timestamp_val):
    """Convert LDAP timestamp/datetime to ISO 8601 format."""
    if not timestamp_val:
        return None
    normalized = normalize_value(timestamp_val)
    if isinstance(normalized, datetime):
        if normalized.tzinfo is None:
            normalized = normalized.replace(tzinfo=timezone.utc)
        return normalized.isoformat()
    if isinstance(normalized, str):
        return normalized
    ts = safe_int(normalized, 0)
    if ts in (0, 9223372036854775807):
        return None
    try:
        unix_seconds = (ts - 116444736000000000) / 10000000
        return datetime.fromtimestamp(unix_seconds, tz=timezone.utc).isoformat()
    except:
        return None

def get_domain_ous(ip, domain, username, password, config):
    """Enumerate all organizational units in the domain."""
    try:
        bind_user = get_bind_user(username, domain)
        auth_type = "SIMPLE"
        if is_ntlm_hash(password):
            password = f"00000000000000000000000000000000:{password}"
            auth_type = "NTLM"

        server = Server(ip, get_info=ALL, port=389, use_ssl=False, connect_timeout=config.LDAP_CONNECT_TIMEOUT)
        conn = Connection(
            server,
            user=bind_user,
            password=password,
            authentication=auth_type,
            auto_bind=True,
            receive_timeout=getattr(config, "LDAP_RECEIVE_TIMEOUT", 10),
        )
        
        domain_dn = "DC=" + ",DC=".join(domain.split("."))
        search_filter = "(objectClass=organizationalUnit)"
        
        conn.search(
            domain_dn,
            search_filter,
            search_scope=SUBTREE,
            attributes=[
                'name', 'distinguishedName', 'description', 'ou',
                'managedBy', 'whenCreated', 'whenChanged',
                'gPLink', 'gPOptions'
            ]
        )
        
        ous = []
        for entry in conn.entries:
            ou_data = entry.entry_attributes_as_dict
            
            ou_name = normalize_value(first_or_none(ou_data.get('name')))
            ou_path = normalize_value(first_or_none(ou_data.get('distinguishedName')))
            description = normalize_value(first_or_none(ou_data.get('description')))
            ou_type = normalize_value(first_or_none(ou_data.get('ou')))
            
            managed_by = normalize_value(first_or_none(ou_data.get('managedBy')))
            created = ldap_timestamp_to_iso(first_or_none(ou_data.get('whenCreated')))
            modified = ldap_timestamp_to_iso(first_or_none(ou_data.get('whenChanged')))

            gp_link = normalize_value(first_or_none(ou_data.get('gPLink')))
            gp_options = safe_int(normalize_value(first_or_none(ou_data.get('gPOptions'))), 0)
            # Many AD environments do not expose protectedFromAccidentalDeletion as a readable LDAP attribute.
            # Keep this field for UI compatibility with a safe default.
            protected = False

            has_gpo_links = bool(gp_link and str(gp_link).strip())
            inheritance_blocked = bool(gp_options & 1)
            delegated_permissions = bool(managed_by)
            
            ou_obj = {
                "name": ou_name or "Unknown OU",
                "path": ou_path or "",
                "description": description or "",
                "type": ou_type or "OU",
                "managed_by": managed_by or "",
                "created": created or "",
                "modified": modified or "",
                "dn": ou_path or "",
                "gpo_links": str(gp_link or ""),
                "has_gpo_links": has_gpo_links,
                "inheritance_blocked": inheritance_blocked,
                "delegated_permissions": delegated_permissions,
                "is_protected": bool(protected),
            }
            
            ous.append(ou_obj)
        
        conn.unbind()
        
        return {
            "success": True,
            "count": len(ous),
            "ous": ous
        }
    except LDAPInvalidCredentialsResult:
        return {
            "success": False,
            "error": "Authentication failed",
            "code": 401,
        }
    except LDAPSocketOpenError:
        return {
            "success": False,
            "error": "Could not connect to the server",
            "code": 503,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "code": 500,
        }
