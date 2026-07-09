import re
import os
import struct
import contextlib
from datetime import datetime, timezone

from ldap3 import ALL, SUBTREE
from ldap3.core.exceptions import LDAPException

from connect.ldap_core import open_standalone_connection

import logging
logger = logging.getLogger("ad_api")

EXTENSION_GUID_MAP = {
    "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}": "Registry Settings",
    "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}": "Security Settings",
    "{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}": "EFS Recovery Policy",
    "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}": "Scripts (Startup/Shutdown)",
    "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}": "Scripts (Logon/Logoff)",
    "{00000000-0000-0000-0000-000000000000}": "Core GPO",
    "{0F6B957E-509E-11D1-A7CC-0000F87571E3}": "Tool Extension Policy",
    "{0F6B957D-509E-11D1-A7CC-0000F87571E3}": "Tool Extension Policy",
    "{1612B55C-243C-48DD-A449-FFC097B19776}": "Deployed Printer Connections",
    "{1A6364EB-776B-4120-ADE1-B63A406A76B5}": "Offline Files",
    "{25537BA6-77A8-11D2-9B6C-0000F8080861}": "Folder Redirection",
    "{2BFCC077-22D2-48DE-BDE1-2F618D9B476D}": "AppV Policy",
    "{3060E8CE-7020-11D2-842D-00C04FA372D4}": "Remote Installation Services",
    "{3610EDA5-77EF-11D2-8DC5-00C04FA31A66}": "Microsoft Disk Quota",
    "{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}": "Internet Explorer Zonemapping",
    "{4D2F9B6F-1E52-4711-A5BE-012D73A3A073}": "Drive Maps",
    "{516FC620-5D34-4B08-8165-6A06B623EDEB}": "Scheduled Tasks",
    "{53D6AB1B-2488-11D1-A28C-00C04FB94F17}": "EFS Recovery",
    "{5794DAFD-BE60-433F-88A2-1A31939AC01F}": "Drive Mappings",
    "{6232C319-91AC-4931-9385-E70C2B099F0E}": "Group Policy Folders",
    "{6A4C88C6-C502-4F74-8F60-2CB23EDC9E0A}": "Group Policy Network Options",
    "{728EE579-943C-4519-9EF7-AB56765798ED}": "Group Policy Data Sources",
    "{74EE6C03-5363-4554-B161-627540339CAB}": "Group Policy ini Files",
    "{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}": "Group Policy Files",
    "{7933F41E-56F8-41D6-A31C-4148A711EE93}": "Group Policy Internet Settings",
    "{A3F3E39B-5D83-4940-B954-28315B82F0A8}": "Group Policy Folder Options",
    "{AADCED64-746C-4633-A97C-D61349046527}": "Group Policy Scheduled Tasks",
    "{B087BE9D-ED37-454F-AF9C-04291E351182}": "Group Policy Registry",
    "{B9CCA4DE-E2B9-4CBD-BF7D-11B6EBFBDDF7}": "Group Policy Printers",
    "{BA649533-0AAC-4E04-B9B8-3D492B3CC60A}": "Group Policy Network Shares",
    "{C6DC5466-785A-11D2-84D0-00C04FB169F7}": "Software Installation",
    "{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}": "Scheduled Tasks (Immediate)",
    "{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}": "Internet Explorer",
    "{E437BC1C-AA7D-11D2-A382-00C04F991E27}": "IP Security",
    "{F9C77450-3A41-477E-9310-9ACD617BD9E3}": "Group Policy Applications",
    "{FB2CA36D-0B40-4307-821B-A13B252DE56C}": "Group Policy Environment",
    "{FBF687E6-F063-4D9F-9F4F-FD9A26ACDD5F}": "Group Policy Shortcuts",
    "{169EBF44-942F-4C43-87CE-13C93996EBBE}": "Group Policy Wireless (Vista+)",
    "{91FBB303-0CD5-4055-BF42-E512A681B325}": "Group Policy Wired Policy",
    "{40B6664F-4972-11D1-A7CA-0000F87571E3}": "Scripts",
    "{CDEAFC3D-948D-49DD-AB12-E578BA4AF7AA}": "TCPIP",
    "{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}": "Group Policy Wireless",
    "{E5094040-C46C-4115-B030-04FB2E545B6F}": "Group Policy Regional Options",
    "{E62688F0-25FD-4C90-BFF5-F508B9D2E31F}": "Group Policy Power Options",
    "{EC4828A8-A768-4A2E-9edd-A73165B7D600}": "Group Policy Start Menu",
    "{F0DB2806-FD46-45B7-81BD-AA0B4B6E7AEB}": "Group Policy Task Bar",
    "{F581DAE7-8064-444A-AEB3-1875662A61CE}": "Group Policy Services",
    "{FD500BEF-9F03-4F58-97B8-2e51C2218566}": "Group Policy Local Users and Groups",
}

ACE_RIGHTS_MAP = {
    0x00000001: "CC",
    0x00000002: "DC",
    0x00000004: "LC",
    0x00000008: "SW",
    0x00000010: "RP",
    0x00000020: "WP",
    0x00000040: "DT",
    0x00000080: "LO",
    0x00000100: "CR",
    0x00010000: "DE",
    0x00020000: "RC",
    0x00040000: "WD",
    0x00080000: "WO",
    0x00100000: "SY",
    0x00F00000: "ST",
    0x001F01FF: "FA",
    0x00120089: "FR",
    0x00120116: "FW",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_bind_user(username: str, domain: str) -> str:
    if "@" in username or "\\" in username:
        return username
    return f"{username}@{domain}"


def normalize_value(val):
    if val is None:
        return ""
    if hasattr(val, 'value'):
        return str(val.value) if val.value is not None else ""
    return str(val)


def normalize_values(val):
    if val is None:
        return []
    if hasattr(val, 'values'):
        return [str(v) for v in val.values if v is not None]
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val]
    return [str(val)]


def safe_int(val, default=0):
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


# ---------------------------------------------------------------------------
# Security Descriptor / DACL helpers (LDAP ntSecurityDescriptor parsing)
# ---------------------------------------------------------------------------

def _parse_isaclprotected(sd_raw) -> bool:
    if isinstance(sd_raw, (bytearray, memoryview)):
        sd_raw = bytes(sd_raw)
    if not isinstance(sd_raw, bytes) or len(sd_raw) < 4:
        return False
    try:
        control = int.from_bytes(sd_raw[2:4], byteorder="little")
        return bool(control & 0x1000)
    except Exception:
        return False


def _parse_sd_owner(sd_raw: bytes) -> str:
    if not isinstance(sd_raw, bytes) or len(sd_raw) < 20:
        return ""
    try:
        offset_owner = struct.unpack_from("<I", sd_raw, 4)[0]
        if offset_owner == 0 or offset_owner >= len(sd_raw):
            return ""
        return _sid_bytes_to_str(sd_raw[offset_owner:])
    except Exception:
        return ""


def _sid_bytes_to_str(data: bytes) -> str:
    if not data or len(data) < 8:
        return ""
    try:
        revision = data[0]
        sub_count = data[1]
        authority = int.from_bytes(data[2:8], byteorder="big")
        subs = []
        for i in range(sub_count):
            offset = 8 + i * 4
            if offset + 4 > len(data):
                break
            subs.append(struct.unpack_from("<I", data, offset)[0])
        return f"S-{revision}-{authority}-" + "-".join(str(s) for s in subs)
    except Exception:
        return ""


def _parse_dacl_aces(sd_raw: bytes) -> list:
    aces = []
    if not isinstance(sd_raw, bytes) or len(sd_raw) < 20:
        return aces
    try:
        control = struct.unpack_from("<H", sd_raw, 2)[0]
        if not (control & 0x0004):
            return aces
        offset_dacl = struct.unpack_from("<I", sd_raw, 16)[0]
        if offset_dacl == 0 or offset_dacl + 8 > len(sd_raw):
            return aces

        ace_count = struct.unpack_from("<H", sd_raw, offset_dacl + 4)[0]
        pos = offset_dacl + 8

        OBJECT_ACE_TYPES = {5, 6, 11, 12}
        ace_type_names = {
            0: "ACCESS_ALLOWED", 1: "ACCESS_DENIED",
            5: "ACCESS_ALLOWED_OBJECT", 6: "ACCESS_DENIED_OBJECT",
        }

        for _ in range(ace_count):
            if pos + 4 > len(sd_raw):
                break
            ace_type  = sd_raw[pos]
            ace_flags = sd_raw[pos + 1]
            ace_size  = struct.unpack_from("<H", sd_raw, pos + 2)[0]
            if ace_size < 8 or pos + ace_size > len(sd_raw):
                break

            access_mask = struct.unpack_from("<I", sd_raw, pos + 4)[0]

            if ace_type in OBJECT_ACE_TYPES and ace_size >= 12:
                obj_flags = struct.unpack_from("<I", sd_raw, pos + 8)[0]
                sid_offset = pos + 12
                if obj_flags & 0x1:
                    sid_offset += 16
                if obj_flags & 0x2:
                    sid_offset += 16
            else:
                sid_offset = pos + 8

            sid_data = sd_raw[sid_offset: pos + ace_size]
            trustee  = _sid_bytes_to_str(sid_data)
            inherited = bool(ace_flags & 0x10)

            rights = []
            for bit, name in ACE_RIGHTS_MAP.items():
                if access_mask & bit == bit:
                    rights.append(name)

            aces.append({
                "type": ace_type_names.get(ace_type, f"TYPE_{ace_type}"),
                "access_mask": hex(access_mask),
                "rights": rights,
                "trustee_sid": trustee,
                "inherited": inherited,
            })
            pos += ace_size
    except Exception:
        pass
    return aces


# ---------------------------------------------------------------------------
# LDAP helpers
# ---------------------------------------------------------------------------

def _extract_domainsid(domain_dn: str, conn) -> str:
    try:
        conn.search(domain_dn, "(objectClass=domain)", attributes=["objectSid"])
        if conn.entries:
            sid_val = getattr(conn.entries[0], "objectSid", None)
            return str(getattr(sid_val, "value", "") or "")
    except Exception:
        pass
    return ""


def _is_gpo_enforced(gp_link_text: str, gpo_guid: str) -> bool:
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


def _is_gpo_link_disabled(gp_link_text: str, gpo_guid: str) -> bool:
    if not gp_link_text or not gpo_guid:
        return False
    pattern = re.compile(
        r'\[LDAP://[^\]]*' + re.escape(gpo_guid) + r'[^\]]*;(\d+)\]',
        re.IGNORECASE
    )
    for match in pattern.finditer(gp_link_text):
        flags = int(match.group(1))
        if flags & 1:
            return True
    return False


def _parse_extension_guids(ext_str: str) -> list:
    if not ext_str:
        return []
    guids = re.findall(r'\{[0-9A-Fa-f\-]{36}\}', ext_str)
    result = []
    seen = set()
    for g in guids:
        gu = g.upper()
        if gu not in seen:
            seen.add(gu)
            result.append({
                "guid": gu,
                "name": EXTENSION_GUID_MAP.get(gu, "Unknown Extension"),
            })
    return result


def _resolve_sid_to_name(sid: str, conn, domain_dn: str) -> str:
    WELL_KNOWN = {
        "S-1-1-0": "Everyone",
        "S-1-5-7": "Anonymous Logon",
        "S-1-5-11": "Authenticated Users",
        "S-1-5-18": "SYSTEM",
        "S-1-5-19": "LOCAL SERVICE",
        "S-1-5-20": "NETWORK SERVICE",
        "S-1-5-32-544": "BUILTIN\\Administrators",
        "S-1-5-32-545": "BUILTIN\\Users",
        "S-1-5-32-546": "BUILTIN\\Guests",
        "S-1-5-32-548": "BUILTIN\\Account Operators",
        "S-1-5-32-549": "BUILTIN\\Server Operators",
        "S-1-5-32-550": "BUILTIN\\Print Operators",
        "S-1-5-32-551": "BUILTIN\\Backup Operators",
        "S-1-5-32-552": "BUILTIN\\Replicators",
    }
    if sid in WELL_KNOWN:
        return WELL_KNOWN[sid]
    try:
        conn.search(
            domain_dn,
            f"(objectSid={sid})",
            attributes=["sAMAccountName", "name"],
            search_scope=SUBTREE
        )
        if conn.entries:
            e = conn.entries[0]
            sam = normalize_value(getattr(e, "sAMAccountName", None))
            name = normalize_value(getattr(e, "name", None))
            return sam or name or sid
    except Exception:
        pass
    return sid


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_domain_gpos(ip, domain, username, password, config, conn=None, base_dn=None):
    if not all([ip, domain, username, password]):
        return {
            "success": False,
            "error": "Missing required parameters (ip, domain, username, password)",
            "count": 0,
            "gpos": [],
        }

    owns_connection = conn is None

    try:
        if owns_connection:
            conn, base_dn = open_standalone_connection(ip, username, password, domain, config)
            conn_cm = conn
        else:
            conn_cm = contextlib.nullcontext(conn)

        domain_dn = base_dn or ("DC=" + ",DC=".join(domain.split(".")))
        gpo_container = f"CN=Policies,CN=System,{domain_dn}"

        with conn_cm as conn:
            conn.search(
                gpo_container,
                "(objectClass=groupPolicyContainer)",
                attributes=[
                    "name",
                    "displayName",
                    "description",
                    "gPCFileSysPath",
                    "whenCreated",
                    "whenChanged",
                    "versionNumber",
                    "gPCUserExtensionNames",
                    "gPCMachineExtensionNames",
                    "flags",
                    "objectGUID",
                    "ntSecurityDescriptor",
                    "managedBy",
                ],
            )

            gpo_entries = list(conn.entries)
            domainsid = _extract_domainsid(domain_dn, conn)
            gpos = []

            for entry in gpo_entries:
                def get_attr(a):
                    return getattr(entry, a, None)

                gpo_name     = normalize_value(get_attr("name"))
                gpo_guid_raw = normalize_value(get_attr("objectGUID"))
                gpo_guid = gpo_guid_raw.upper()
                if not gpo_guid.startswith("{"):
                    gpo_guid = "{" + gpo_guid + "}"

                user_ext    = normalize_value(get_attr("gPCUserExtensionNames"))
                machine_ext = normalize_value(get_attr("gPCMachineExtensionNames"))
                managed_by  = normalize_value(get_attr("managedBy"))
                description = normalize_value(get_attr("description"))
                gpc_fs_path = normalize_value(get_attr("gPCFileSysPath"))
                version_num = safe_int(get_attr("versionNumber"), 0)
                user_version     = (version_num >> 16) & 0xFFFF
                computer_version = version_num & 0xFFFF

                ntsd_attr = get_attr("ntSecurityDescriptor")
                ntsd_raw  = getattr(ntsd_attr, "value", None) if ntsd_attr else None
                if isinstance(ntsd_raw, (bytearray, memoryview)):
                    ntsd_raw = bytes(ntsd_raw)
                elif not isinstance(ntsd_raw, bytes):
                    ntsd_raw = b""

                isaclprotected = _parse_isaclprotected(ntsd_raw)
                owner_sid      = _parse_sd_owner(ntsd_raw)
                dacl_aces      = _parse_dacl_aces(ntsd_raw)
                owner_name     = _resolve_sid_to_name(owner_sid, conn, domain_dn) if owner_sid else ""

                user_extensions    = _parse_extension_guids(user_ext)
                machine_extensions = _parse_extension_guids(machine_ext)

                gpo_flags = safe_int(get_attr("flags"), 0)
                user_settings_disabled     = bool(gpo_flags & 1)
                computer_settings_disabled = bool(gpo_flags & 2)

                HIGH_VALUE_GUIDS = {
                    "{31B2F340-016D-11D2-945F-00C04FB984F9}",
                    "{6AC1786C-016F-11D2-945F-00C04FB984F9}",
                }
                cn_upper = gpo_name.upper()
                if not cn_upper.startswith("{"):
                    cn_upper = "{" + cn_upper + "}"
                settings_text = f"{user_ext} {machine_ext}".lower()
                has_settings_markers = any(
                    k in settings_text for k in ("script", "registry", "password")
                )
                highvalue = cn_upper in HIGH_VALUE_GUIDS or has_settings_markers

                gpo_info = {
                    "name":         gpo_name,
                    "guid":         gpo_guid,
                    "display_name": normalize_value(get_attr("displayName")) or gpo_name,
                    "description":  description,
                    "dn":           entry.entry_dn,
                    "path":         gpc_fs_path,
                    "domain":       domain,
                    "domainsid":    domainsid,

                    "created":  ldap_timestamp_to_iso(get_attr("whenCreated")),
                    "modified": ldap_timestamp_to_iso(get_attr("whenChanged")),

                    "version":          version_num,
                    "user_version":     user_version,
                    "computer_version": computer_version,

                    "flags":                      gpo_flags,
                    "user_settings_disabled":     user_settings_disabled,
                    "computer_settings_disabled": computer_settings_disabled,

                    "linked_containers": [],
                    "linked_count":      0,
                    "enforced":          False,
                    "link_disabled":     False,
                    "isaclprotected":    isaclprotected,

                    "owner_sid":  owner_sid,
                    "owner_name": owner_name,

                    "ldap_dacl_aces": dacl_aces,

                    "user_extensions":    user_extensions,
                    "machine_extensions": machine_extensions,

                    "highvalue": highvalue,

                    "sysvol_available": False,

                    "risk_controls": [],
                }

                gpos.append(gpo_info)

            # gPLink / inheritance sorğuları
            conn.search(
                domain_dn,
                "(gPLink=*)",
                attributes=["distinguishedName", "gPLink", "gPOptions"],
                search_scope=SUBTREE,
            )

            guid_pattern  = re.compile(r'\{([0-9A-Fa-f\-]{36})\}')
            link_map      = {}
            link_text_map = {}
            inheritance_blocked = []

            for entry in conn.entries:
                container_dn = entry.entry_dn
                gp_link = normalize_value(getattr(entry, "gPLink",   None))
                gp_opts = safe_int(getattr(entry, "gPOptions", None), 0)

                if gp_opts & 1:
                    inheritance_blocked.append(container_dn)

                if not gp_link:
                    continue

                text = str(gp_link)
                for guid in guid_pattern.findall(text):
                    gu = "{" + guid.upper() + "}"
                    link_map.setdefault(gu, []).append(container_dn)
                    link_text_map.setdefault(gu, []).append(text)

            conn.search(
                domain_dn,
                "(&(gpOptions=1)(!(gPLink=*)))",
                attributes=["distinguishedName"],
                search_scope=SUBTREE,
            )
            for entry in conn.entries:
                dn = entry.entry_dn
                if dn not in inheritance_blocked:
                    inheritance_blocked.append(dn)

            conn.search(
                domain_dn,
                "(objectClass=organizationalUnit)",
                attributes=["distinguishedName", "gPOptions"],
                search_scope=SUBTREE,
            )
            ou_inheritance = []
            for entry in conn.entries:
                gp_opts = safe_int(getattr(entry, "gPOptions", None), 0)
                ou_inheritance.append({
                    "dn":                entry.entry_dn,
                    "block_inheritance": bool(gp_opts & 1),
                })

            for gpo in gpos:
                cn_guid = gpo["name"].upper()
                if not cn_guid.startswith("{"):
                    cn_guid = "{" + cn_guid + "}"

                containers = link_map.get(cn_guid, [])
                gpo["linked_containers"] = containers
                gpo["linked_count"]      = len(containers)

                texts = link_text_map.get(cn_guid, [])
                gpo["enforced"]      = any(_is_gpo_enforced(t, cn_guid) for t in texts)
                gpo["link_disabled"] = any(_is_gpo_link_disabled(t, cn_guid) for t in texts)

                rc = gpo["risk_controls"]
                if gpo["highvalue"]:
                    rc.append("High Value Target")
                if gpo["enforced"]:
                    rc.append("Enforced")
                if gpo["isaclprotected"]:
                    rc.append("ACL Inheritance Blocked")
                if gpo["user_settings_disabled"]:
                    rc.append("User Settings Disabled")
                if gpo["computer_settings_disabled"]:
                    rc.append("Computer Settings Disabled")

        import json as _json
        result = {
            "success":             True,
            "count":               len(gpos),
            "sysvol_available":    False,
            "gpos":                gpos,
            "all_cpasswords":      [],
            "inheritance_blocked": inheritance_blocked,
            "ou_inheritance":      ou_inheritance,
        }

        try:
            output_path = os.path.join(
                str(config.DOMAIN_OBJECT_DIR), "domain_gpos.jsonl"
            )
            with open(output_path, "w", encoding="utf-8") as f:
                meta = {
                    "success":          result["success"],
                    "count":            result["count"],
                    "sysvol_available": result["sysvol_available"],
                }
                f.write(_json.dumps(meta, ensure_ascii=False, default=str) + "\n")
                for gpo in result["gpos"]:
                    f.write(_json.dumps(gpo, ensure_ascii=False, default=str) + "\n")
                inh_line = {
                    "inheritance_blocked": result["inheritance_blocked"],
                    "ou_inheritance":      result["ou_inheritance"],
                }
                f.write(_json.dumps(inh_line, ensure_ascii=False, default=str) + "\n")
        except Exception as write_exc:
            result["json_export_error"] = str(write_exc)

        return result

    except LDAPException as e:
        return {"success": False, "error": f"LDAP error: {e}", "count": 0, "gpos": []}
    except Exception as e:
        return {"success": False, "error": f"Error: {e}", "count": 0, "gpos": []}


def get_gpo_scope(ip, gpo_guid, domain, username, password, config, conn=None, base_dn=None):
    if not all([ip, gpo_guid, domain, username, password]):
        return []
    owns_connection = conn is None
    try:
        if owns_connection:
            conn, base_dn = open_standalone_connection(ip, username, password, domain, config)
            conn_cm = conn
        else:
            conn_cm = contextlib.nullcontext(conn)

        domain_dn = base_dn or ("DC=" + ",DC=".join(domain.split(".")))

        with conn_cm as conn:
            conn.search(
                domain_dn,
                f"(gPLink=*{gpo_guid}*)",
                attributes=["dn"],
                search_scope=SUBTREE,
            )
            return [e.entry_dn for e in conn.entries]
    except Exception:
        return []