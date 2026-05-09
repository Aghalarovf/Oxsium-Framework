"""
Group Policy Objects (GPO) enumeration module for Active Directory.
Enumerates GPOs with their properties, linked containers, and access control information.
"""

import re
from datetime import datetime, timezone
from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPException


def is_ntlm_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}", value or ""))


def get_bind_user(username: str, domain: str) -> str:
    if "@" in username or "\\" in username:
        return username
    netbios = domain.split(".")[0].upper()
    return f"{netbios}\\{username}"


def normalize_value(val):
    """Convert LDAP Attribute to string value."""
    if val is None:
        return ""
    if hasattr(val, 'value'):
        return str(val.value) if val.value is not None else ""
    return str(val)


def normalize_values(val):
    """Convert LDAP Attribute to list of string values."""
    if val is None:
        return []
    if hasattr(val, 'values'):
        return [str(v) for v in val.values if v is not None]
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val]
    return [str(val)]


def safe_int(val, default=0):
    """Safely convert value to integer."""
    try:
        if val is None:
            return default
        if hasattr(val, 'value'):
            val = val.value
        if isinstance(val, bool):
            return default
        return int(val)
    except (ValueError, TypeError):
        try:
            return int(str(val))
        except (ValueError, TypeError):
            return default


def ldap_timestamp_to_iso(timestamp_value):
    """Convert LDAP datetime/timestamp to ISO 8601 format."""
    try:
        if timestamp_value is None:
            return "Never"
        raw = timestamp_value.value if hasattr(timestamp_value, 'value') else timestamp_value
        if isinstance(raw, datetime):
            if raw.tzinfo is None:
                raw = raw.replace(tzinfo=timezone.utc)
            return raw.isoformat()
        if isinstance(raw, str):
            return raw
        ts = safe_int(raw, 0)
        if ts <= 0:
            return "Never"
        unix_seconds = (ts - 116444736000000000) / 10000000
        return datetime.fromtimestamp(unix_seconds, tz=timezone.utc).isoformat()
    except Exception:
        return "Unknown"


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


def _extract_domainsid_from_dn(domain_dn: str, conn) -> str:
    """
    Domain root obyektinin objectSid-indən domain SID-ini çıxarır.
    GPO-ların öz SID-i yoxdur, buna görə domain root-u sorğulanır.
    Nəticə keşlənir ki, hər GPO üçün ayrıca sorğu getməsin.
    """
    try:
        conn.search(domain_dn, "(objectClass=domain)", attributes=["objectSid"])
        if conn.entries:
            sid_val = getattr(conn.entries[0], "objectSid", None)
            sid_str = str(getattr(sid_val, "value", "") or "")
            return sid_str
    except Exception:
        pass
    return ""


def _is_gpo_enforced(gp_link_text: str, gpo_guid: str) -> bool:
    """
    gPLink atributundan GPO-nun enforced olub-olmadığını yoxlayır.
    gPLink formatı: [LDAP://...{GUID};FLAGS]
    FLAGS: 0 = normal, 1 = disabled, 2 = enforced, 3 = disabled+enforced
    Enforced = FLAGS bit 1 set (dəyər 2 və ya 3).
    """
    if not gp_link_text or not gpo_guid:
        return False
    pattern = re.compile(
        r'\[LDAP://[^\]]*' + re.escape(gpo_guid) + r'[^\]]*;(\d+)\]',
        re.IGNORECASE
    )
    for match in pattern.finditer(gp_link_text):
        flags = int(match.group(1))
        if flags & 2:
            return True
    return False


def get_domain_gpos(ip, domain, username, password, config):
    """
    Enumerate Group Policy Objects from Active Directory.
    
    Args:
        ip: Domain controller IP
        domain: Domain name (e.g., 'example.com')
        username: Username for LDAP bind
        password: Password for LDAP bind
        config: Configuration object with timeouts
    
    Returns:
        dict: {
            'success': bool,
            'count': int,
            'gpos': [
                {
                    'name': str,
                    'guid': str,
                    'display_name': str,
                    'dn': str,
                    'path': str,
                    'created': str (ISO 8601),
                    'modified': str (ISO 8601),
                    'version': int,
                    'flags': int,
                    'user_version': int,
                    'computer_version': int,
                    'linked_containers': [str],
                    'gpos_data': {additional fields}
                }
            ]
        }
    """
    
    if not all([ip, domain, username, password]):
        return {
            'success': False,
            'error': 'Missing required parameters (ip, domain, username, password)',
            'count': 0,
            'gpos': []
        }
    
    try:
        server = Server(ip, get_info=ALL, connect_timeout=config.LDAP_CONNECT_TIMEOUT)
        bind_user = get_bind_user(username, domain)
        auth_type = "SIMPLE"
        if is_ntlm_hash(password):
            password = f"00000000000000000000000000000000:{password}"
            auth_type = "NTLM"
        
        domain_dn = 'DC=' + ',DC='.join(domain.split('.'))
        gpo_container = f'CN=Policies,CN=System,{domain_dn}'
        
        with Connection(
            server,
            user=bind_user,
            password=password,
            authentication=auth_type,
            auto_bind=True,
            receive_timeout=config.LDAP_RECEIVE_TIMEOUT
        ) as conn:
            search_filter = '(objectClass=groupPolicyContainer)'
            attributes = [
                'name',
                'displayName',
                'gPCFileSysPath',
                'whenCreated',
                'whenChanged',
                'versionNumber',
                'gPCUserExtensionNames',
                'gPCMachineExtensionNames',
                'flags',
                'objectGUID',
                'ntSecurityDescriptor',
                'managedBy'
            ]
            
            conn.search(gpo_container, search_filter, attributes=attributes)
            
            gpos = []
            for entry in conn.entries:
                gpo_data = {}
                
                def get_attr(attr_name):
                    return getattr(entry, attr_name, None)
                
                gpo_name = normalize_value(get_attr('name'))
                gpo_guid = normalize_value(get_attr('objectGUID'))
                user_ext = normalize_value(get_attr('gPCUserExtensionNames'))
                machine_ext = normalize_value(get_attr('gPCMachineExtensionNames'))
                managed_by = normalize_value(get_attr('managedBy'))
                version_number = safe_int(get_attr('versionNumber'), 0)
                user_version = (version_number >> 16) & 0xFFFF
                computer_version = version_number & 0xFFFF

                # ── isaclprotected ───────────────────────────────────────────
                # ntSecurityDescriptor raw bytes kimi oxunmalıdır
                ntsd_attr = get_attr('ntSecurityDescriptor')
                ntsd_raw = getattr(ntsd_attr, 'value', None) if ntsd_attr else None
                if isinstance(ntsd_raw, (bytearray, memoryview)):
                    ntsd_raw = bytes(ntsd_raw)
                elif not isinstance(ntsd_raw, bytes):
                    ntsd_raw = b""
                isaclprotected = _parse_isaclprotected(ntsd_raw)
                has_security_descriptor = bool(ntsd_raw)

                settings_text = f"{user_ext} {machine_ext}".lower()
                has_settings_markers = any(k in settings_text for k in ('script', 'registry', 'password'))

                # Heuristic: delegated or custom-managed GPOs are worth auditing for edit abuse.
                is_vulnerable = bool(managed_by)

                # ── highvalue ────────────────────────────────────────────────
                # Default Domain Policy və Default Domain Controllers Policy
                # kritik GPO-lardır — dəyişdirilməsi bütün domaini təsir edir
                HIGH_VALUE_GUIDS = {
                    "{31B2F340-016D-11D2-945F-00C04FB984F9}",  # Default Domain Policy
                    "{6AC1786C-016F-11D2-945F-00C04FB984F9}",  # Default Domain Controllers Policy
                }
                highvalue = (
                    gpo_name.upper() in HIGH_VALUE_GUIDS or
                    has_settings_markers or
                    is_vulnerable
                )

                risk_controls = []
                if is_vulnerable:
                    risk_controls.append("Potential Edit Vulnerability")
                if has_settings_markers:
                    risk_controls.append("Settings Markers Found")
                if highvalue:
                    risk_controls.append("High Value Target")
                if isaclprotected:
                    risk_controls.append("ACL Protected")

                gpo_info = {
                    'name': gpo_name,
                    'guid': gpo_guid,
                    'display_name': normalize_value(get_attr('displayName')) or gpo_name,
                    'dn': entry.entry_dn,
                    'path': normalize_value(get_attr('gPCFileSysPath')),
                    'created': ldap_timestamp_to_iso(get_attr('whenCreated')),
                    'modified': ldap_timestamp_to_iso(get_attr('whenChanged')),
                    'version': version_number,
                    'user_version': user_version,
                    'computer_version': computer_version,
                    'flags': safe_int(get_attr('flags'), 0),
                    'linked_containers': [],
                    'linked_count': 0,
                    'managed_by': managed_by,
                    'vulnerable': is_vulnerable,
                    'has_settings_markers': has_settings_markers,
                    'highvalue': highvalue,             # Kritik GPO işarəsi
                    'enforced': False,                  # gPLink-dən sonra doldurulur
                    'domain': domain,                   # GPO-nun aid olduğu domain
                    'isaclprotected': isaclprotected,   # ACL inheritance bloklanıb/bloklanmayıb
                    'domainsid': "",                    # domain root sorğusundan sonra doldurulur
                    'risk_controls': risk_controls,
                    'user_extensions': user_ext,
                    'machine_extensions': machine_ext,
                    'has_security_descriptor': has_security_descriptor,
                    'gpos_data': gpo_data
                }
                
                gpos.append(gpo_info)

            # Resolve GPO links from OU/domain objects via gPLink once and map to each GUID.
            link_map = {}
            # gPLink text-lərini də saxlayırıq ki enforced yoxlanılsın
            link_text_map = {}
            conn.search(domain_dn, '(gPLink=*)', attributes=['distinguishedName', 'gPLink'])
            guid_pattern = re.compile(r'\{([0-9A-Fa-f\-]{36})\}')
            for entry in conn.entries:
                container_dn = entry.entry_dn
                gp_link = normalize_value(getattr(entry, 'gPLink', None))
                if not gp_link:
                    continue
                text = str(gp_link)
                for guid in guid_pattern.findall(text):
                    link_map.setdefault(guid, []).append(container_dn)
                    link_text_map.setdefault(guid, []).append(text)

            # ── domainsid ────────────────────────────────────────────────────
            domainsid = _extract_domainsid_from_dn(domain_dn, conn)

            for gpo in gpos:
                containers = link_map.get(gpo['guid'], [])
                gpo['linked_containers'] = containers
                gpo['linked_count'] = len(containers)

                # enforced: hər hansı linked container-da bu GPO enforced işarələnibsə True
                gp_link_texts = link_text_map.get(gpo['guid'], [])
                gpo['enforced'] = any(
                    _is_gpo_enforced(text, gpo['guid']) for text in gp_link_texts
                )

                # domainsid bütün GPO-lar üçün eynidir
                gpo['domainsid'] = domainsid
            
            return {
                'success': True,
                'count': len(gpos),
                'gpos': gpos
            }
    
    except LDAPException as e:
        return {
            'success': False,
            'error': f'LDAP error: {str(e)}',
            'count': 0,
            'gpos': []
        }
    except Exception as e:
        return {
            'success': False,
            'error': f'Error: {str(e)}',
            'count': 0,
            'gpos': []
        }


def get_gpo_scope(ip, gpo_guid, domain, username, password, config):
    """
    Get containers/OUs where a GPO is linked.
    
    Returns:
        list: List of container DNs where the GPO is linked
    """
    
    if not all([ip, gpo_guid, domain, username, password]):
        return []
    
    try:
        server = Server(ip, get_info=ALL, connect_timeout=config.LDAP_CONNECT_TIMEOUT)
        domain_dn = 'DC=' + ',DC='.join(domain.split('.'))
        bind_user = get_bind_user(username, domain)

        # get_domain_gpos ilə eyni NTLM hash dəstəyi
        auth_type = "SIMPLE"
        if is_ntlm_hash(password):
            password  = f"00000000000000000000000000000000:{password}"
            auth_type = "NTLM"

        with Connection(
            server,
            user=bind_user,
            password=password,
            authentication=auth_type,
            auto_bind=True,
            receive_timeout=config.LDAP_RECEIVE_TIMEOUT
        ) as conn:
            search_filter = f'(gPLink=*{gpo_guid}*)'
            
            conn.search(domain_dn, search_filter, attributes=['dn'])
            
            return [entry.entry_dn for entry in conn.entries]
    
    except Exception:
        return []