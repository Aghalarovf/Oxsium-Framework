import uuid

from .constants import (
    WELL_KNOWN_SIDS,
    OBJECT_TYPE_RIGHTS,
    INDIVIDUAL_RIGHTS,
    INTERESTING_RIGHTS,
    ACE_TYPE_DENIED,
    ACE_TYPE_DENIED_OBJECT,
    _PAGED_CTRL_OID,
    _SD_FLAGS,
    _PRIVILEGED_RIDS,
    _BROAD_RIDS,
    _BROAD_SIDS,
    AD_OBJECT_TYPE_MAP,
    GENERIC_ALL_RAW,
    GENERIC_ALL_COMPOSED,
    RAW_GENERIC_WRITE,
    GENERIC_WRITE_COMPOSED,
    WRITE_PROPERTY_BIT,
    SELF_BIT,
    READ_PROPERTY_BIT,
    CONTROL_ACCESS_RIGHT,
    ACE_FLAG_INHERITED,
    ACE_FLAG_INHERIT_ONLY,
    _DEFAULT_TRUSTEE_SIDS,
    _DEFAULT_TRUSTEE_RIDS,
)
from .models import LdapBackend, SecurityDescriptorParser, AclFilterConfig
from .backends import normalize_value, ldap_ts_to_iso


def classify_target(dn: str, classes: list) -> str:
    _EXTRA_TYPE_MAP: dict[str, str] = {
        "msds-groupmanagedserviceaccount": "gMSA",
        "msds-managedserviceaccount":      "MSA",
        "pkicertificatetemplate":          "CertTemplate",
        "pkienrollmentservice":            "CA",
        "certificationauthority":          "CA",
        "trusteddomain":                   "Trust",
        "dnszone":                         "DNSZone",
        "dnsnode":                         "DNSNode",
        "serviceconnectionpoint":          "SCP",
        "msds-passwordsettings":           "PSO",
        "ntdsdsa":                         "DCService",
        "server":                          "Server",
        "site":                            "Site",
        "sitelink":                        "SiteLink",
        "subnet":                          "Subnet",
        "crossref":                        "CrossRef",
        "crossrefcontainer":               "CrossRefContainer",
        "foreignsecurityprincipal":        "ForeignPrincipal",
        "msexchmailboxdatabase":           "ExchangeDB",
        "msexchserver":                    "ExchangeServer",
        "publicfolder":                    "PublicFolder",
    }

    cs = {c.lower() for c in classes}

    for cls_name, label in AD_OBJECT_TYPE_MAP.items():
        if cls_name in cs:
            return label

    for cls_name, label in _EXTRA_TYPE_MAP.items():
        if cls_name in cs:
            return label
    specific = None
    for cls in reversed(classes):
        low = cls.lower()
        if low not in ("top", "classschema", "attributeschema"):
            specific = cls
            break

    if specific:
        return f"Other:{specific}"

    if dn.upper().startswith("CN="):
        return "Container"
    return "Object"


def classify_principal(sid: str, name: str) -> str:
    parts = sid.split("-")
    last  = f"-{parts[-1]}" if len(parts) > 1 else ""

    if last in _PRIVILEGED_RIDS and not sid.startswith("S-1-5-32-"):
        return "Privileged"
    if sid == "S-1-5-32-544":
        return "Privileged"
    if sid in _BROAD_SIDS or last in _BROAD_RIDS:
        return "Broad"

    n = (name or "").upper()
    if any(k in n for k in ("DOMAIN ADMINS", "ENTERPRISE ADMINS",
                             "SCHEMA ADMINS", "ADMINISTRATORS")):
        return "Privileged"
    if n in {"EVERYONE", "AUTHENTICATED USERS", "DOMAIN USERS", "DOMAIN COMPUTERS"}:
        return "Broad"
    return "Custom"


def _normalize_controls(controls: list | None) -> list[tuple[str, bool, bytes | None]]:
    normalized: list[tuple[str, bool, bytes | None]] = []
    for control in controls or []:
        if isinstance(control, tuple) and len(control) == 3:
            normalized.append(control)
            continue
        if isinstance(control, list) and len(control) == 3:
            normalized.append((control[0], bool(control[1]), control[2]))
            continue

        try:
            control_type = str(control["controlType"])
            criticality = bool(control["criticality"])
            try:
                control_value = bytes(control["controlValue"])
            except Exception:
                control_value = None
            normalized.append((control_type, criticality, control_value))
            continue
        except Exception:
            pass

        try:
            control_type = str(getattr(control, "controlType", getattr(control, "control_type", None) or ""))
            if not control_type:
                control_type = str(getattr(control, "controlType", ""))
            criticality = bool(getattr(control, "criticality", False) or getattr(control, "critical", False))
            try:
                control_value = bytes(getattr(control, "controlValue", None) or getattr(control, "control_value", None) or b"")
            except Exception:
                control_value = None
            if control_type:
                normalized.append((control_type, criticality, control_value))
                continue
        except Exception:
            continue
    return normalized

def _paged_search(
    conn: LdapBackend,
    base_dn: str,
    ldap_filter: str,
    attributes: list,
    page_size: int = 500,
    extra_controls: list | None = None,
    search_scope: str = "SUBTREE",
) -> list:

    from ldap3.protocol.rfc2696 import paged_search_control

    all_entries: list = []
    cookie: bytes = b""
    extra = extra_controls or []

    while True:
        paged_ctrl = paged_search_control(size=page_size, cookie=cookie)
        conn.search(
            base_dn, ldap_filter,
            search_scope=search_scope,
            attributes=attributes,
            controls=_normalize_controls(extra + [paged_ctrl]),
        )
        all_entries.extend(conn.entries)

        result      = conn.result or {}
        result_code = result.get("result", 0)
        ctrl_resp   = result.get("controls", {}).get(_PAGED_CTRL_OID, {})
        cookie      = ctrl_resp.get("value", {}).get("cookie", b"") or b""

        if not cookie:
            break
        if result_code not in (0, 4, 11):
            break

    return all_entries


def _build_sid_map(
    conn: LdapBackend,
    base_dn: str,
    page_size: int = 1000,
) -> tuple[dict[str, str], frozenset[str]]:

    sid_map: dict[str, str] = dict(WELL_KNOWN_SIDS)
    disabled_sids: set[str] = set()
    _UF_ACCOUNTDISABLE = 0x2

    entries = _paged_search(
        conn, base_dn,
        "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
        attributes=["sAMAccountName", "objectSid", "userAccountControl"],
        page_size=page_size,
    )
    for e in entries:
        sid  = str(normalize_value(getattr(e, "objectSid",      None)) or "")
        name = str(normalize_value(getattr(e, "sAMAccountName", None)) or sid)
        if not sid:
            continue
        sid_map[sid] = name
        try:
            uac = int(normalize_value(getattr(e, "userAccountControl", None)) or 0)
            if uac & _UF_ACCOUNTDISABLE:
                disabled_sids.add(sid)
        except (ValueError, TypeError):
            pass

    return sid_map, frozenset(disabled_sids)


def _resolve_sid_realtime(
    conn: LdapBackend,
    sid: str,
    base_dn: str,
    sid_cache: dict[str, str],
    disabled_cache: set[str],
) -> str:
    if sid in sid_cache:
        return sid_cache[sid]

    _UF_ACCOUNTDISABLE = 0x2

    for search_base in [base_dn, f"CN=Configuration,{base_dn}"]:
        try:
            conn.search(
                search_base,
                f"(objectSid={sid})",
                search_scope="SUBTREE",
                attributes=["sAMAccountName", "cn", "objectSid", "userAccountControl"],
            )
            for e in conn.entries:
                found_sid = str(normalize_value(getattr(e, "objectSid", None)) or "")
                if not found_sid:
                    continue
                name = str(
                    normalize_value(getattr(e, "sAMAccountName", None))
                    or normalize_value(getattr(e, "cn", None))
                    or found_sid
                )
                sid_cache[found_sid] = name
                try:
                    uac = int(normalize_value(getattr(e, "userAccountControl", None)) or 0)
                    if uac & _UF_ACCOUNTDISABLE:
                        disabled_cache.add(found_sid)
                except (ValueError, TypeError):
                    pass
                if found_sid == sid:
                    return name
        except Exception:
            continue
    sid_cache[sid] = sid
    return sid


def _resolve_self_dn(conn: LdapBackend, base_dn: str, username: str) -> str | None:
    from ldap3.utils.conv import escape_filter_chars
    from ldap3.protocol.microsoft import security_descriptor_control

    sam = username
    if "\\" in username:
        sam = username.split("\\", 1)[1]
    elif "@" in username:
        sam = username.split("@", 1)[0]

    sd_ctrl = security_descriptor_control(sdflags=_SD_FLAGS)
    conn.search(
        base_dn,
        f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(sam)}))",
        search_scope="SUBTREE",
        attributes=["distinguishedName", "objectClass", "name", "whenChanged"],
        controls=_normalize_controls([sd_ctrl]),
    )
    if not conn.entries:
        return None
    return str(normalize_value(getattr(conn.entries[0], "distinguishedName", None)) or "")


def _fetch_object_sd(
    conn: LdapBackend, dn: str, sdflags: int = _SD_FLAGS
) -> tuple[bytes | None, object | None]:

    from ldap3.protocol.microsoft import security_descriptor_control

    sd_ctrl = security_descriptor_control(sdflags=sdflags)
    conn.search(
        dn, "(objectClass=*)",
        search_scope="BASE",
        attributes=["name", "distinguishedName", "objectClass",
                    "whenChanged", "nTSecurityDescriptor"],
        controls=_normalize_controls([sd_ctrl]),
    )
    if not conn.entries:
        return None, None
    entry      = conn.entries[0]
    raw_values = getattr(
        getattr(entry, "nTSecurityDescriptor", None), "raw_values", None
    ) or []
    return (raw_values[0] if raw_values else None), entry


def _build_guid_map(conn: LdapBackend, base_dn: str, page_size: int = 1000) -> dict[str, str]:
    guid_map: dict[str, str] = {
        "00000000-0000-0000-0000-000000000000": "All"
    }
    try:
        schema_dn = f"CN=Schema,CN=Configuration,{base_dn}"
        entries = _paged_search(
            conn, schema_dn, "(schemaIDGUID=*)",
            attributes=["name", "schemaIDGUID"],
            page_size=page_size,
            search_scope="SUBTREE",
        )
        for e in entries:
            try:
                raw = getattr(getattr(e, "schemaIDGUID", None), "raw_values", None) or []
                name = str(normalize_value(getattr(e, "name", None)) or "")
                if raw and name:
                    try:
                        import uuid as _uuid

                        guid = str(_uuid.UUID(bytes_le=raw[0])).lower()
                        guid_map[guid] = name
                    except Exception:
                        continue
            except Exception:
                continue

        ext_dn = schema_dn.replace("Schema", "Extended-Rights")
        entries = _paged_search(
            conn, ext_dn, "(objectClass=controlAccessRight)",
            attributes=["name", "rightsGuid", "rightsGUID"],
            page_size=page_size,
            search_scope="SUBTREE",
        )
        for e in entries:
            try:
                name = str(normalize_value(getattr(e, "name", None)) or "")
                raw = None
                for attr in ("rightsGuid", "rightsGUID", "rightsGuid"):
                    raw = getattr(getattr(e, attr, None), "raw_values", None) or []
                    if raw:
                        break
                if raw and name:
                    try:
                        import uuid as _uuid

                        guid = str(_uuid.UUID(bytes_le=raw[0])).lower()
                        guid_map[guid] = name
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass

    return guid_map


def _apply_filters(
    record: dict,
    ace_flags: int,
    flt: AclFilterConfig,
    skip_inherit_only: bool = True,
) -> bool:
    if skip_inherit_only and (ace_flags & ACE_FLAG_INHERIT_ONLY):
        return False

    if flt.exclude_inherited and (ace_flags & ACE_FLAG_INHERITED):
        return False

    principal_sid = str(record.get("principal_sid", "") or "")
    principal_name = str(record.get("principal", "") or "")
    target_name = str(record.get("target_name", "") or "")
    target_dn = str(record.get("target_dn", "") or "")
    target_type = str(record.get("target_type", "") or "")
    principal_scope = str(record.get("principal_scope", "") or "")

    is_default_trustee = (
        principal_sid in _DEFAULT_TRUSTEE_SIDS
        or any(principal_sid.endswith(rid) for rid in _DEFAULT_TRUSTEE_RIDS)
    )

    if flt.exclude_default and is_default_trustee:
        return False

    if flt.exclude_inherited_defaults and (ace_flags & ACE_FLAG_INHERITED) and is_default_trustee:
        return False

    if flt.interesting_only and not record.get("is_edge", False):
        return False

    if flt.rights_filter:
        rights = set(record.get("rights", []))
        if not rights.intersection(flt.rights_filter):
            return False

    if flt.principal_filter:
        principal_filter = flt.principal_filter.casefold()
        if principal_filter not in principal_name.casefold() and principal_filter not in principal_sid.casefold():
            return False

    if flt.target_filter:
        target_filter = flt.target_filter.casefold()
        if target_filter not in target_name.casefold() and target_filter not in target_dn.casefold():
            return False

    if flt.target_type_filter and target_type not in set(flt.target_type_filter):
        return False

    if flt.scope_filter and principal_scope not in set(flt.scope_filter):
        return False

    return True

def _get_mask(ace_data) -> int:
    try:
        return int(ace_data["Mask"]["Mask"])
    except (KeyError, TypeError):
        pass
    try:
        return int(ace_data["Mask"])
    except (KeyError, TypeError):
        pass
    return 0


def _get_sid(ace_data) -> str:
    try:
        sid_obj = ace_data["Sid"]
        return (
            str(sid_obj.formatCanonical())
            if hasattr(sid_obj, "formatCanonical")
            else str(sid_obj)
        )
    except (KeyError, TypeError):
        return ""


def _get_ace_flags(ace) -> int:
    try:
        return int(ace["AceFlags"])
    except (KeyError, TypeError):
        return 0


def _get_object_type_guid(ace_data, parser: SecurityDescriptorParser) -> str | None:
    try:
        if not parser.is_object_ace(ace_data):
            return None
        flags = int(ace_data["Flags"]) if "Flags" in getattr(ace_data, "fields", {}) else 0
        if not (flags & 0x1):
            return None
        raw_value = ace_data["ObjectType"]
        if hasattr(raw_value, "formatCanonical"):
            return str(raw_value.formatCanonical()).lower()
        if isinstance(raw_value, (bytes, bytearray)):
            try:
                return str(uuid.UUID(bytes_le=bytes(raw_value))).lower()
            except Exception:
                return raw_value.hex().lower()
        return str(raw_value).strip().lower()
    except (KeyError, TypeError, AttributeError):
        return None


def _parse_rights(ace_data, parser: SecurityDescriptorParser) -> list[str]:
    mask = _get_mask(ace_data)

    is_generic_all = (
        bool(mask & GENERIC_ALL_RAW)
        or (mask & GENERIC_ALL_COMPOSED) == GENERIC_ALL_COMPOSED
    )
    if is_generic_all:
        return ["GenericAll"]

    obj_guid = _get_object_type_guid(ace_data, parser)

    is_generic_write = (
        bool(mask & RAW_GENERIC_WRITE)
        or (not obj_guid and (mask & GENERIC_WRITE_COMPOSED) == GENERIC_WRITE_COMPOSED)
    )

    rights: list[str] = []

    if is_generic_write:
        rights.append("GenericWrite")
        _skip = {"WriteProperty", "Self"}
        for right, val in INDIVIDUAL_RIGHTS.items():
            if right not in _skip and (mask & val):
                rights.append(right)
    else:
        for right, val in INDIVIDUAL_RIGHTS.items():
            if mask & val:
                rights.append(right)

    if obj_guid and obj_guid in OBJECT_TYPE_RIGHTS:
        specific  = OBJECT_TYPE_RIGHTS[obj_guid]
        to_remove = {
            n for bit, n in (
                (WRITE_PROPERTY_BIT, "WriteProperty"),
                (SELF_BIT,           "Self"),
                (READ_PROPERTY_BIT,  "ReadProperty"),
            )
            if mask & bit
        }
        rights = [r for r in rights if r not in to_remove]
        if specific not in rights:
            rights.append(specific)

    elif obj_guid:
        to_remove = {
            n for bit, n in (
                (WRITE_PROPERTY_BIT, "WriteProperty"),
                (SELF_BIT,           "Self"),
                (READ_PROPERTY_BIT,  "ReadProperty"),
            )
            if mask & bit
        }
        rights = [r for r in rights if r not in to_remove]
        if "ExtendedRights" not in rights:
            rights.append("ExtendedRights")

    if (mask & CONTROL_ACCESS_RIGHT) and not obj_guid:
        if "All-Extended-Rights" not in rights:
            rights.append("All-Extended-Rights")

    order = (
        "GenericAll", "GenericWrite",
        "WriteDACL", "WriteOwner",
        "WriteProperty","Self","Delete",
        "AddMember", "ForceChangePassword", "ChangePassword",
        "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All",
        "DS-Replication-Get-Changes-In-Filtered-Set",
        "DS-Replication-Manage-Topology", "DS-Replication-Synchronize",
        "Write-msDS-KeyCredentialLink",
        "Write-msDS-AllowedToActOnBehalfOfOtherIdentity",
        "Write-msDS-AllowedToDelegateTo",
        "Write-gPLink", "Write-gPOptions",
        "Validated-Write-SPN", "Validated-DNS-Host-Name",
        "Send-As", "Receive-As",
        "Apply-Group-Policy", "Self-Membership",
        "Validated-Write-Computer", "Read-gMSA-Password",
        "All-Extended-Rights", "ExtendedRights",
    )
    ordered = [r for r in order if r in rights]
    for r in rights:
        if r not in ordered:
            ordered.append(r)

    if not ordered and mask:
        ordered.append("Other Rights")

    return ordered


def _parse_dacl_to_records(
    raw_sd: bytes,
    dn: str,
    conn_entry,
    sid_map: dict,
    parser: SecurityDescriptorParser,
    disabled_sids: frozenset[str] | None = None,
    skip_inherit_only: bool = False,
    conn: LdapBackend | None = None,
    base_dn: str = "",
    disabled_cache: set[str] | None = None,
    guid_map: dict[str, str] | None = None,
) -> list[dict]:

    _mutable_disabled: set[str] = disabled_cache if disabled_cache is not None else set()
    records: list[dict] = []
    try:
        dacl = parser.parse(raw_sd)
    except Exception:
        return records
    if not dacl:
        return records

    name     = str(normalize_value(getattr(conn_entry, "name", None)) or dn)
    classes  = [
        str(v)
        for v in (getattr(getattr(conn_entry, "objectClass", None), "values", []) or [])
    ]
    modified   = ldap_ts_to_iso(getattr(conn_entry, "whenChanged", None))
    target_sid = str(normalize_value(getattr(conn_entry, "objectSid", None)) or "")

    for ace in dacl.aces:
        try:
            ace_data = ace["Ace"]
        except (KeyError, TypeError):
            continue
        try:
            ace_type = int(ace["AceType"])
        except (KeyError, TypeError):
            continue

        ace_fields = getattr(ace_data, "fields", {})
        if "Mask" not in ace_fields or "Sid" not in ace_fields:
            continue

        obj_guid = _get_object_type_guid(ace_data, parser) or ""
        rights   = _parse_rights(ace_data, parser)
        if not rights:
            continue

        sid = _get_sid(ace_data)
        if not sid:
            continue

        if conn and base_dn and sid not in sid_map:
            _resolve_sid_realtime(conn, sid, base_dn, sid_map, _mutable_disabled)

        principal    = sid_map.get(sid, sid)
        ace_flags    = _get_ace_flags(ace)
        is_inherited = bool(ace_flags & ACE_FLAG_INHERITED)

        ace_qualifier = "Deny" if ace_type in (ACE_TYPE_DENIED, ACE_TYPE_DENIED_OBJECT) else "Allow"

        if skip_inherit_only and (ace_flags & ACE_FLAG_INHERIT_ONLY):
            continue

        is_disabled = sid in sid_map and sid in _mutable_disabled
        if disabled_sids:
            is_disabled = is_disabled or sid in disabled_sids

        expanded_obj = guid_map.get(obj_guid) if (guid_map and obj_guid) else obj_guid

        records.append({
            "target_name":           name,
            "target_dn":             dn,
            "target_sid":            target_sid,
            "target_type":           classify_target(dn, classes),
            "principal":             principal,
            "principal_sid":         sid,
            "principal_scope":       classify_principal(sid, principal),
            "principal_is_disabled": is_disabled,
            "object_acetype":        expanded_obj,
            "object_ace_type":       expanded_obj,
            "ace_qualifier":         ace_qualifier,
            "ace_type_raw":          ace_type,
            "rights":                rights,
            "rights_display":        ", ".join(rights),
            "edge_rights":           [r for r in rights if r in INTERESTING_RIGHTS],
            "is_edge":               bool(set(rights).intersection(INTERESTING_RIGHTS)),
            "edge_kind":             "Edge" if set(rights).intersection(INTERESTING_RIGHTS) else "ACL",
            "is_inherited":          is_inherited,
            "ace_flags":             ace_flags,
            "modified":              modified,
        })

    return records