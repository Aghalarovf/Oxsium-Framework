import re
import json
import os
from datetime import datetime, timezone
from ldap3 import Server, Connection, ALL, SUBTREE, LEVEL
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPSocketOpenError


def is_ntlm_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}", value or ""))


def get_bind_user(username: str, domain: str) -> str:
    if "@" in username or "\\" in username:
        return username
    return f"{username}@{domain}"


def normalize_value(val):
    if val is None:
        return None
    if hasattr(val, "value"):
        return val.value
    return val


def normalize_values(vals):
    if not vals:
        return []
    return [v.value if hasattr(v, "value") else v for v in vals]


def first_or_none(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def safe_int(val, default=0):
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
    except Exception:
        return None


def _get_domain_sid(conn, domain_dn: str) -> str:
    try:
        conn.search(domain_dn, "(objectClass=domain)", search_scope=SUBTREE,
                    attributes=["objectSid"])
        if conn.entries:
            raw = normalize_value(
                first_or_none(conn.entries[0].entry_attributes_as_dict.get("objectSid"))
            )
            if raw:
                return str(raw)
    except Exception:
        pass
    return ""


def _guid_to_bloodhound_id(guid_val) -> str:
    if not guid_val:
        return ""
    import uuid as _uuid
    try:
        if isinstance(guid_val, bytes):
            return str(_uuid.UUID(bytes_le=guid_val)).upper()
        return str(guid_val).upper()
    except Exception:
        return str(guid_val)


def _get_child_ous(conn, parent_dn: str, page_size: int = 500) -> list:
    try:
        conn.search(parent_dn, "(objectClass=organizationalUnit)",
                    search_scope=LEVEL, attributes=["distinguishedName"],
                    paged_size=page_size)
        return [
            normalize_value(first_or_none(e.entry_attributes_as_dict.get("distinguishedName")))
            for e in conn.entries
            if first_or_none(e.entry_attributes_as_dict.get("distinguishedName"))
        ]
    except Exception:
        return []


def _extract_parent_dn(dn: str) -> str:
    if not dn:
        return ""
    parts = dn.split(",", 1)
    return parts[1] if len(parts) > 1 else ""


def _calc_depth(dn: str) -> int:
    if not dn:
        return 0
    return sum(1 for part in dn.split(",") if part.strip().upper().startswith("OU="))


def _parse_gplink(gp_link_str: str) -> list:
    if not gp_link_str or not gp_link_str.strip():
        return []
    pattern = re.compile(r"\[([^\]]+)\]")
    raw_links = pattern.findall(gp_link_str)
    parsed = []
    total = len(raw_links)
    for idx, link in enumerate(raw_links):
        parts = link.split(";")
        gpo_dn = parts[0].replace("LDAP://", "").strip() if parts else ""
        flag = safe_int(parts[1]) if len(parts) > 1 else 0
        guid_match = re.search(r"\{([A-Fa-f0-9\-]+)\}", gpo_dn)
        gpo_guid = guid_match.group(1).upper() if guid_match else ""
        parsed.append({
            "gpo_dn":    gpo_dn,
            "gpo_guid":  gpo_guid,
            "order":     total - idx,   
            "enforced":  bool(flag & 2),
            "disabled":  bool(flag & 1),
            "link_flag": flag,
        })
    return parsed


def _get_inherited_gpos(conn, ou_dn: str, domain_dn: str,
                        page_size: int = 500) -> list:
    inherited = []
    current = _extract_parent_dn(ou_dn)
    visited = set()

    while current and current.upper() != domain_dn.upper() and current not in visited:
        visited.add(current)
        try:
            conn.search(current, "(objectClass=organizationalUnit)",
                        search_scope=LEVEL, attributes=["gPLink", "gPOptions"],
                        paged_size=page_size)
            conn.search(current, "(distinguishedName=" + current + ")",
                        search_scope=SUBTREE, attributes=["gPLink", "gPOptions"],
                        paged_size=1)
            if conn.entries:
                p_data = conn.entries[0].entry_attributes_as_dict
                p_gplink = normalize_value(first_or_none(p_data.get("gPLink"))) or ""
                p_gpopts = safe_int(normalize_value(first_or_none(p_data.get("gPOptions"))), 0)
                links = _parse_gplink(str(p_gplink))
                for lnk in links:
                    lnk["inherited_from"] = current
                    inherited.extend([lnk])
                if p_gpopts & 1:  
                    break
        except Exception:
            pass
        current = _extract_parent_dn(current)

    return inherited


def _get_privileged_objects_in_ou(conn, ou_dn: str, page_size: int = 500) -> dict:
    priv_users = []
    priv_computers = []

    try:
        conn.search(
            ou_dn,
            "(&(objectClass=user)(objectCategory=person)(adminCount=1))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "distinguishedName", "objectSid"],
            paged_size=page_size,
        )
        for e in conn.entries:
            d = e.entry_attributes_as_dict
            priv_users.append({
                "sam_name": str(normalize_value(first_or_none(d.get("sAMAccountName"))) or ""),
                "dn":       str(normalize_value(first_or_none(d.get("distinguishedName"))) or ""),
                "sid":      str(normalize_value(first_or_none(d.get("objectSid"))) or ""),
            })
    except Exception:
        pass

    try:
        conn.search(
            ou_dn,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            search_scope=SUBTREE,
            attributes=["cn", "distinguishedName", "objectSid", "dNSHostName"],
            paged_size=page_size,
        )
        for e in conn.entries:
            d = e.entry_attributes_as_dict
            priv_computers.append({
                "cn":       str(normalize_value(first_or_none(d.get("cn"))) or ""),
                "dn":       str(normalize_value(first_or_none(d.get("distinguishedName"))) or ""),
                "sid":      str(normalize_value(first_or_none(d.get("objectSid"))) or ""),
                "dns_name": str(normalize_value(first_or_none(d.get("dNSHostName"))) or ""),
            })
    except Exception:
        pass

    return {
        "privileged_users":          priv_users,
        "privileged_users_count":    len(priv_users),
        "privileged_computers":      priv_computers,
        "privileged_computers_count": len(priv_computers),
    }


_HIGH_VALUE_OU_PATTERNS = {
    "domain controllers", "domain admins", "enterprise admins",
    "schema admins", "administrators", "admin", "privileged",
    "tier 0", "tier0", "protected users",
}


def _is_high_value(ou_name: str, ou_path: str) -> bool:
    name_lower = (ou_name or "").lower()
    path_lower = (ou_path or "").lower()
    return any(p in name_lower or p in path_lower for p in _HIGH_VALUE_OU_PATTERNS)


def get_domain_ous(ip, domain, username, password, config):
    try:
        bind_user = get_bind_user(username, domain)
        auth_type = "SIMPLE"
        if is_ntlm_hash(password):
            password = f"00000000000000000000000000000000:{password}"
            auth_type = "NTLM"

        server = Server(ip, get_info=ALL, port=389, use_ssl=False,
                        connect_timeout=config.LDAP_CONNECT_TIMEOUT)
        conn = Connection(
            server, user=bind_user, password=password,
            authentication=auth_type, auto_bind=True,
            receive_timeout=getattr(config, "LDAP_RECEIVE_TIMEOUT", 10),
        )

        domain_dn  = "DC=" + ",DC=".join(domain.split("."))
        page_size  = getattr(config, "LDAP_PAGE_SIZE", 500)
        domain_sid = _get_domain_sid(conn, domain_dn)

        conn.search(
            domain_dn,
            "(objectClass=organizationalUnit)",
            search_scope=SUBTREE,
            attributes=[
                "name", "distinguishedName", "description", "ou",
                "managedBy", "whenCreated", "whenChanged",
                "gPLink", "gPOptions", "msDS-Approx-Immed-Subordinates",
                "objectGUID",
            ],
        )

        ous = []
        for entry in conn.entries:
            ou_data = entry.entry_attributes_as_dict

            ou_name   = normalize_value(first_or_none(ou_data.get("name")))
            ou_path   = normalize_value(first_or_none(ou_data.get("distinguishedName")))
            description = normalize_value(first_or_none(ou_data.get("description")))
            ou_type   = normalize_value(first_or_none(ou_data.get("ou")))
            managed_by = normalize_value(first_or_none(ou_data.get("managedBy")))
            created   = ldap_timestamp_to_iso(first_or_none(ou_data.get("whenCreated")))
            modified  = ldap_timestamp_to_iso(first_or_none(ou_data.get("whenChanged")))

            gp_link_raw = normalize_value(first_or_none(ou_data.get("gPLink")))
            gp_options  = safe_int(normalize_value(first_or_none(ou_data.get("gPOptions"))), 0)

            object_count = safe_int(
                normalize_value(first_or_none(ou_data.get("msDS-Approx-Immed-Subordinates"))), -1
            )

            raw_guid   = first_or_none(ou_data.get("objectGUID"))
            if hasattr(raw_guid, "value"):
                raw_guid = raw_guid.value
            object_guid = _guid_to_bloodhound_id(raw_guid)
            object_id   = object_guid

            parent_dn  = _extract_parent_dn(ou_path or "")
            child_ous  = _get_child_ous(conn, ou_path, page_size) if ou_path else []

            depth = _calc_depth(ou_path or "")

            linked_gpos = _parse_gplink(str(gp_link_raw or ""))

            inherited_gpos = _get_inherited_gpos(conn, ou_path or "", domain_dn, page_size)

            gpo_precedence = [
                {"gpo_guid": g["gpo_guid"], "order": g["order"], "enforced": g["enforced"]}
                for g in linked_gpos
            ]

            priv = _get_privileged_objects_in_ou(conn, ou_path or "", page_size)

            has_gpo_links       = bool(linked_gpos)
            inheritance_blocked = bool(gp_options & 1)
            isaclprotected      = inheritance_blocked
            delegated_permissions = bool(managed_by)

            if object_count < 0 and ou_path:
                try:
                    conn.search(ou_path, "(objectClass=*)", search_scope=LEVEL,
                                attributes=["distinguishedName"], paged_size=page_size)
                    object_count = len(conn.entries)
                except Exception:
                    object_count = 0
            elif object_count < 0:
                object_count = 0

            highvalue = _is_high_value(ou_name or "", ou_path or "")

            risk_controls = []
            if has_gpo_links:
                risk_controls.append("GPO Links")
            if inheritance_blocked:
                risk_controls.append("Inheritance Blocked")
            if delegated_permissions:
                risk_controls.append("Delegated Permissions")
            if priv["privileged_users_count"] > 0:
                risk_controls.append("Privileged Users Present")
            if priv["privileged_computers_count"] > 0:
                risk_controls.append("Privileged Computers Present")

            ous.append({
                "name":         ou_name or "Unknown OU",
                "path":         ou_path or "",
                "dn":           ou_path or "",
                "description":  description or "",
                "type":         ou_type or "OU",
                "managed_by":   managed_by or "",
                "created":      created or "",
                "modified":     modified or "",
                "parent_dn":    parent_dn,
                "childous":     child_ous,
                "depth":        depth,
                "gpo_links_raw":    str(gp_link_raw or ""),
                "linked_gpos":      linked_gpos,      
                "gpo_precedence":   gpo_precedence,   
                "inherited_gpos":   inherited_gpos,   
                "has_gpo_links":    has_gpo_links,
                "inheritance_blocked": inheritance_blocked,
                "privileged_users":           priv["privileged_users"],
                "privileged_users_count":     priv["privileged_users_count"],
                "privileged_computers":       priv["privileged_computers"],
                "privileged_computers_count": priv["privileged_computers_count"],
                "object_count":        object_count,
                "is_protected":        False,
                "delegated_permissions": delegated_permissions,
                "highvalue":           highvalue,
                "isaclprotected":      isaclprotected,
                "blocksinheritance":   inheritance_blocked,
                "domainsid":           domain_sid,
                "objectid":            object_id,
                "objectguid":          object_guid,
                "risk_controls":       risk_controls,
            })

        conn.unbind()

        result = {"success": True, "count": len(ous), "ous": ous}

        output_path = os.path.join(
            str(config.DOMAIN_OBJECT_DIR), "domain_ous.jsonl"
        )
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                meta = {"success": result["success"], "count": result["count"]}
                f.write(json.dumps(meta, ensure_ascii=False, default=str) + "\n")
                for ou in result["ous"]:
                    f.write(json.dumps(ou, ensure_ascii=False, default=str) + "\n")
        except Exception as write_exc:
            result["json_export_error"] = str(write_exc)

        return result

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as e:
        return {"success": False, "error": str(e), "code": 500}