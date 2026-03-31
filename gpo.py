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
                sec_desc = normalize_value(get_attr('ntSecurityDescriptor'))
                managed_by = normalize_value(get_attr('managedBy'))
                version_number = safe_int(get_attr('versionNumber'), 0)
                user_version = (version_number >> 16) & 0xFFFF
                computer_version = version_number & 0xFFFF

                settings_text = f"{user_ext} {machine_ext}".lower()
                has_settings_markers = any(k in settings_text for k in ('script', 'registry', 'password'))

                # Heuristic: delegated or custom-managed GPOs are worth auditing for edit abuse.
                is_vulnerable = bool(managed_by)
                
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
                    'user_extensions': user_ext,
                    'machine_extensions': machine_ext,
                    'has_security_descriptor': bool(sec_desc),
                    'gpos_data': gpo_data
                }
                
                gpos.append(gpo_info)

            # Resolve GPO links from OU/domain objects via gPLink once and map to each GUID.
            link_map = {}
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

            for gpo in gpos:
                containers = link_map.get(gpo['guid'], [])
                gpo['linked_containers'] = containers
                gpo['linked_count'] = len(containers)
            
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
        
        with Connection(
            server,
            user=username,
            password=password,
            auto_bind=True,
            receive_timeout=config.LDAP_RECEIVE_TIMEOUT
        ) as conn:
            search_filter = f'(gPLink=*{gpo_guid}*)'
            
            conn.search(domain_dn, search_filter, attributes=['dn'])
            
            return [entry.entry_dn for entry in conn.entries]
    
    except Exception:
        return []
