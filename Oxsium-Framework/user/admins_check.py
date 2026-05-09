import logging

logger = logging.getLogger(__name__)

try:
    import proto_bridge as _proto_bridge
    _PROTO_BRIDGE_OK = True
except ImportError:
    _PROTO_BRIDGE_OK = False


_RID_DOMAIN_ADMINS         = 512
_RID_ENTERPRISE_ADMINS     = 519
_RID_SCHEMA_ADMINS         = 518
_RID_BUILTIN_ADMINS        = 544
_RID_ACCOUNT_OPERATORS     = 548
_RID_SERVER_OPERATORS      = 549
_RID_PRINT_OPERATORS       = 550
_RID_BACKUP_OPERATORS      = 551
_RID_GROUP_POLICY_CREATORS = 520
_RID_CRYPTOGRAPHIC_OPERATORS = 569
_RID_HYPERV_ADMINISTRATORS = 578
_RID_STORAGE_REPLICA_ADMINISTRATORS = 582
_RID_KEY_ADMINS = 526
_RID_ENTERPRISE_KEY_ADMINS = 527
_RID_DOMAIN_CONTROLLERS  = 516
_RID_ENTERPRISE_READONLY_CONTROLLERS = 498
_RID_ONLY_DOMAIN_CONTROLLERS = 521
_RID_RAS_IAS_Servers = 553
_RID_CERT_PUBLISHERS = 557
_RID_REMOTE_MANAGEMENT_USERS   = 580


_RID_DNS_ADMINS_NAME = "dnsadmins"

_RIGHT_GENERIC_ALL   = 0x000F01FF
_RIGHT_WRITE_DACL    = 0x00040000
_RIGHT_WRITE_OWNER   = 0x00080000
_RIGHT_GENERIC_WRITE = 0x0002019F
_RIGHT_ALL_EXTENDED  = 0x00000100

_GENERIC_ALL_MASK = 0x000F01FF

_GUID_FORCE_CHANGE_PASSWORD                        = "00299570-246d-11d0-a768-00aa006e0529"
_GUID_DS_REPLICATION_GET_CHANGES_ALL               = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
_GUID_DS_REPLICATION_GET_CHANGES                   = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
_GUID_DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET   = "89e95b76-444d-4c62-991a-0facbeda640c"

_RIGHT_ADS_RIGHT_DS_WRITE_PROP = 0x20

# Rule 1 — Confirmed high-privilege domain groups.
# Membership here = definitive admin.  Used by _rule_01_domain_admins.
_RULE1_RIDS = frozenset({
    _RID_DOMAIN_ADMINS,       # 512 — full domain control
    _RID_ENTERPRISE_ADMINS,   # 519 — forest-wide control
    _RID_SCHEMA_ADMINS,       # 518 — schema modification rights
    _RID_BUILTIN_ADMINS,      # 544 — local admin on every DC
    _RID_DOMAIN_CONTROLLERS,  # 516 — full control over DC computer objects, plus local admin on DCs
    _RID_ENTERPRISE_READONLY_CONTROLLERS, # 498 — read-only access to DC computer objects, plus local admin on DCs 
    _RID_ONLY_DOMAIN_CONTROLLERS, # 521 — same as Domain Controllers but without the local admin rights on DCs (exists in some Windows versions)
})

# Rule 2 — Operator groups that carry significant privilege but are not
# full domain admins.  Used by _rule_02_operator_groups.
_RULE2_RIDS = frozenset({
    _RID_ACCOUNT_OPERATORS,      # 548 — manage user/group accounts
    _RID_SERVER_OPERATORS,       # 549 — manage DC services & shares
    _RID_BACKUP_OPERATORS,       # 551 — bypass NTFS ACLs for backup
    _RID_GROUP_POLICY_CREATORS,  # 520 — create & edit GPOs
    _RID_PRINT_OPERATORS,        # 550 — load drivers on DCs
    _RID_CRYPTOGRAPHIC_OPERATORS,# 569 — cryptographic operators
    _RID_HYPERV_ADMINISTRATORS,  # 578 — Hyper-V Administrators
    _RID_STORAGE_REPLICA_ADMINISTRATORS, # 582 — Storage Replica Administrators
    _RID_KEY_ADMINS, #526 - Key Admins - manage BitLocker keys and other KMS-related functions
    _RID_ENTERPRISE_KEY_ADMINS, #527 - Enterprise Key Admins - manage BitLocker keys and other KMS-related functions at the enterprise level
    _RID_RAS_IAS_Servers, # 553 - RAS and IAS Servers - manage Remote Access and Internet Authentication Service servers
    _RID_CERT_PUBLISHERS, # 557 - Cert Publishers - manage certificate templates and publish certificates to the domain
    _RID_REMOTE_MANAGEMENT_USERS, # 580 - Remote Management Users - manage remote management of domain controllers
})

# Combined set kept for helpers that need to check either category.
_PRIVILEGED_RIDS = _RULE1_RIDS | _RULE2_RIDS

# ---------------------------------------------------------------------------
# Rule 14 — Privileged Primary Group RIDs
# ---------------------------------------------------------------------------
# Bir istifadəçinin primaryGroupID atributu bu RID-lərdən birinə bərabər
# olarsa, o, memberOf siyahısında görünmədən imtiyazlı qrupa mənsub sayılır.
# Bu, gizli admin membership-in ən çox istifadə olunan üsullarından biridir.
PRIVILEGED_PRIMARY_GROUP_RIDS: dict[int, str] = {
    512: "Domain Admins — Ən kritik. Domain üzərində tam nəzarət; memberOf-da görünməyə bilər.",
    519: "Enterprise Admins — Forest (meşə) səviyyəsində tam idarəetmə.",
    520: "Schema Admins — AD strukturunu (schema) dəyişmək hüququ.",
    517: "Cert Publishers — AD CS ilə bağlı hücumlar üçün kritik (sertifikat buraxmaq hüququ).",
    544: "Administrators (Built-in) — Lokal admin + domain səviyyəli idarəetmə.",
    548: "Account Operators — Digər istifadəçilərin parollarını dəyişmə və hesab idarəetmə.",
    549: "Server Operators — DC-lərə daxil olmaq və xidmətləri dayandırmaq hüququ.",
    551: "Backup Operators — Fayl icazələrindən asılı olmayaraq NTDS.dit oxumaq hüququ.",
    516: "Domain Controllers — Kompüter deyilsə ciddi konfiqurasiya səhvidir.",
}

# Human-readable labels for each RID — used in match details.
_RID_LABEL: dict[int, str] = {
    _RID_DOMAIN_ADMINS:         "Domain Admins",
    _RID_ENTERPRISE_ADMINS:     "Enterprise Admins",
    _RID_SCHEMA_ADMINS:         "Schema Admins",
    _RID_BUILTIN_ADMINS:        "Builtin Administrators",
    _RID_ACCOUNT_OPERATORS:     "Account Operators",
    _RID_SERVER_OPERATORS:      "Server Operators",
    _RID_BACKUP_OPERATORS:      "Backup Operators",
    _RID_GROUP_POLICY_CREATORS: "Group Policy Creator Owners",
    _RID_PRINT_OPERATORS:       "Print Operators",
    _RID_CRYPTOGRAPHIC_OPERATORS: "Cryptographic Operators",
    _RID_HYPERV_ADMINISTRATORS: "Hyper-V Administrators",
    _RID_STORAGE_REPLICA_ADMINISTRATORS: "Storage Replica Administrators",
    _RID_KEY_ADMINS: "Key Admins",
    _RID_ENTERPRISE_KEY_ADMINS: "Enterprise Key Admins",
    _RID_DOMAIN_CONTROLLERS: "Domain Controllers",
    _RID_ENTERPRISE_READONLY_CONTROLLERS: "Enterprise Read-Only Domain Controllers",
    _RID_ONLY_DOMAIN_CONTROLLERS: "Only Domain Controllers",
    _RID_RAS_IAS_Servers: "RAS and IAS Servers",
    _RID_CERT_PUBLISHERS: "Cert Publishers",
    _RID_REMOTE_MANAGEMENT_USERS: "Remote Management Users",
    # Rule 14 — əlavə RID labels
    517: "Cert Publishers (primaryGroup)",
    520: "Schema Admins (primaryGroup)",
}


def _safe_int(val, default=0):
    try:
        return int(val)
    except Exception:
        return default


def _safe_str(val):
    try:
        return str(val or "").strip()
    except Exception:
        return ""


def _rid(sid):
    try:
        s = _safe_str(sid).upper()
        if not s or "-" not in s:
            return None
        return int(s.rsplit("-", 1)[1])
    except Exception:
        return None


def _get_identities(ctx):
    try:
        group_sids = set(ctx.get("all_group_sids") or set())
        user_sid   = _safe_str(ctx.get("user_sid"))
        if user_sid:
            group_sids.add(user_sid)
        return group_sids
    except Exception:
        return set()


def _get_aces(ctx, key):
    try:
        val = ctx.get(key)
        return list(val) if val else []
    except Exception:
        return []


def _group_names_contain(member_of_lower, name):
    try:
        return any(name in g for g in member_of_lower)
    except Exception:
        return False


def _build_group_sid_index(ctx: dict) -> dict[str, set[str]]:
    index: dict[str, set[str]] = {}
    for group in ctx.get("groups", []):
        try:
            gsid = _safe_str(group.get("sid")).upper()
            if not gsid:
                continue
            members = {
                _safe_str(m).upper()
                for m in (group.get("member_sids") or [])
                if m
            }
            if gsid in index:
                index[gsid].update(members)
            else:
                index[gsid] = members
        except Exception:
            continue
    return index


def _collect_privileged_group_sids(ctx: dict) -> set[str]:
    privileged: set[str] = set()
    for group in ctx.get("groups", []):
        try:
            rid  = _safe_int(group.get("rid"))
            name = _safe_str(group.get("name")).strip().lower()
            gsid = _safe_str(group.get("sid")).upper()
            if rid in _PRIVILEGED_RIDS or name == _RID_DNS_ADMINS_NAME:
                if gsid:
                    privileged.add(gsid)
        except Exception:
            continue
    return privileged


def _collect_rule1_group_sids(ctx: dict) -> set[str]:
    """Return SIDs of groups whose RID falls in _RULE1_RIDS (Domain/Enterprise/Schema/Builtin Admins)."""
    privileged: set[str] = set()
    for group in ctx.get("groups", []):
        try:
            rid = _safe_int(group.get("rid"))
            if rid in _RULE1_RIDS:
                gsid = _safe_str(group.get("sid")).upper()
                if gsid:
                    privileged.add(gsid)
        except Exception:
            continue
    return privileged


def _collect_rule2_group_sids(ctx: dict) -> set[str]:
    """Return SIDs of groups whose RID falls in _RULE2_RIDS (Operator groups)."""
    privileged: set[str] = set()
    for group in ctx.get("groups", []):
        try:
            rid = _safe_int(group.get("rid"))
            gsid = _safe_str(group.get("sid")).upper()
            if rid in _RULE2_RIDS:
                if gsid:
                    privileged.add(gsid)
        except Exception:
            continue
    return privileged


def _is_nested_member(
    target_sid: str,
    privileged_sids: set[str],
    group_index: dict[str, set[str]],
    visited: set[str] | None = None,
) -> bool:
    if visited is None:
        visited = set()

    target = target_sid.upper()

    for psid in privileged_sids:
        members = group_index.get(psid, set())
        if target in members:
            return True

    for psid in privileged_sids:
        for member in group_index.get(psid, set()):
            if member in visited:
                continue
            if member not in group_index:          # not a group, skip
                continue
            visited.add(member)
            if _is_nested_member(target, {member}, group_index, visited):
                return True

    return False

def _rule_01_domain_admins(ctx: dict) -> bool:
    try:
        matched_rids:   list[int] = []
        matched_sids:   list[str] = []
        matched_groups: list[str] = []
        match_sources:  list[str] = []

        # ── 1. Primary group ─────────────────────────────────────────────────
        primary_rid = _safe_int(ctx.get("primary_group_id"))
        if primary_rid and primary_rid in _RULE1_RIDS:
            matched_rids.append(primary_rid)
            matched_groups.append(_RID_LABEL.get(primary_rid, str(primary_rid)))
            match_sources.append("primary_group")
            # primary group has no separate SID in ctx, mark as synthesised
            user_sid = _safe_str(ctx.get("user_sid"))
            if user_sid and "-" in user_sid:
                domain_sid = user_sid.rsplit("-", 1)[0]
                matched_sids.append(f"{domain_sid}-{primary_rid}")
            else:
                matched_sids.append(f"<domain>-{primary_rid}")

        # ── 2. Token / transitive group SIDs ─────────────────────────────────
        group_sids = set(ctx.get("all_group_sids") or set())
        for sid in group_sids:
            r = _rid(sid)
            if r is not None and r in _RULE1_RIDS:
                sid_upper = _safe_str(sid).upper()
                if sid_upper not in matched_sids:          # deduplicate
                    matched_rids.append(r)
                    matched_sids.append(sid_upper)
                    matched_groups.append(_RID_LABEL.get(r, str(r)))
                    match_sources.append("token_group")

        # ── 3. User's own SID (rare but valid) ───────────────────────────────
        user_sid = _safe_str(ctx.get("user_sid")).upper()
        if user_sid:
            r = _rid(user_sid)
            if r is not None and r in _RULE1_RIDS and user_sid not in matched_sids:
                matched_rids.append(r)
                matched_sids.append(user_sid)
                matched_groups.append(_RID_LABEL.get(r, str(r)))
                match_sources.append("user_sid")

        if matched_rids:
            ctx["rule1_detail"] = {
                "matched_rids":   matched_rids,
                "matched_sids":   matched_sids,
                "matched_groups": matched_groups,
                "match_sources":  match_sources,
            }
            return True

        return False

    except Exception:
        return False


def _rule_02_operator_groups(ctx: dict) -> bool:
    try:
        matched_rids:   list[int] = []
        matched_sids:   list[str] = []
        matched_groups: list[str] = []
        match_sources:  list[str] = []

        # ── 1. Primary group ─────────────────────────────────────────────────
        primary_rid = _safe_int(ctx.get("primary_group_id"))
        if primary_rid and primary_rid in _RULE2_RIDS:
            matched_rids.append(primary_rid)
            matched_groups.append(_RID_LABEL.get(primary_rid, str(primary_rid)))
            match_sources.append("primary_group")
            user_sid = _safe_str(ctx.get("user_sid"))
            if user_sid and "-" in user_sid:
                domain_sid = user_sid.rsplit("-", 1)[0]
                matched_sids.append(f"{domain_sid}-{primary_rid}")
            else:
                matched_sids.append(f"<domain>-{primary_rid}")

        # ── 2. Token / transitive group SIDs ─────────────────────────────────
        group_sids = set(ctx.get("all_group_sids") or set())
        for sid in group_sids:
            r = _rid(sid)
            sid_upper = _safe_str(sid).upper()
            if r is not None and r in _RULE2_RIDS:
                if sid_upper not in matched_sids:
                    matched_rids.append(r)
                    matched_sids.append(sid_upper)
                    matched_groups.append(_RID_LABEL.get(r, str(r)))
                    match_sources.append("token_group")

        # ── 3. User's own SID ────────────────────────────────────────────────
        user_sid = _safe_str(ctx.get("user_sid")).upper()
        if user_sid:
            r = _rid(user_sid)
            if r is not None and r in _RULE2_RIDS and user_sid not in matched_sids:
                matched_rids.append(r)
                matched_sids.append(user_sid)
                matched_groups.append(_RID_LABEL.get(r, str(r)))
                match_sources.append("user_sid")

        if matched_rids:
            ctx["rule2_detail"] = {
                "matched_rids":   matched_rids,
                "matched_sids":   matched_sids,
                "matched_groups": matched_groups,
                "match_sources":  match_sources,
            }
            return True

        return False

    except Exception:
        return False


def _rule_03_generic_all_domain_root(ctx):
    try:
        aces       = _get_aces(ctx, "domain_root_aces")
        identities = _get_identities(ctx)

        _DANGEROUS_RIGHTS = (
            ("GenericAll",    _GENERIC_ALL_MASK),
            ("WriteDACL",     _RIGHT_WRITE_DACL),
            ("WriteOwner",    _RIGHT_WRITE_OWNER),
            ("GenericWrite",  0x40000000),                  # ActiveDirectoryRights.GenericWrite
            ("WriteProperty", _RIGHT_ADS_RIGHT_DS_WRITE_PROP),
        )

        for ace in aces:
            try:
                sid = ace.get("trustee_sid") or ace.get("sid")
                if sid not in identities:
                    continue

                ace_type = ace.get("ace_type")
                if ace_type is not None and "ALLOW" not in _safe_str(ace_type).upper():
                    continue

                mask = _safe_int(ace.get("access_mask") or ace.get("mask"))

                if (mask & _GENERIC_ALL_MASK) == _GENERIC_ALL_MASK or (mask & 0x10000000):
                    return True

                for _right_name, right_mask in _DANGEROUS_RIGHTS[1:]:
                    if mask & right_mask:
                        return True

            except Exception:
                continue

        return False
    except Exception:
        return False


def _rule_04_dcsync_get_changes_all(ctx):
    try:
        if bool(ctx.get("has_dcsync_right")):
            return True

        identities = _get_identities(ctx)
        if not identities:
            return False

        for ace in _get_aces(ctx, "domain_root_aces"):
            try:
                if ace.get("trustee_sid") not in identities:
                    continue
                if "ALLOW" not in _safe_str(ace.get("ace_type")).upper():
                    continue

                mask     = _safe_int(ace.get("access_mask") or ace.get("mask"))
                obj_type = _safe_str(
                    ace.get("object_type") or ace.get("object_guid")
                ).lower().strip()

                if (mask & _RIGHT_ALL_EXTENDED) and not obj_type:
                    return True

                if obj_type == _GUID_DS_REPLICATION_GET_CHANGES_ALL and (mask & _RIGHT_ALL_EXTENDED):
                    return True

            except Exception:
                continue

        return False
    except Exception:
        return False

def _rule_5_krbtgt_generic_all(ctx: dict) -> bool:
    _RIGHT_WRITE_PROPERTY = 0x00000020   # ADS_RIGHT_DS_WRITE_PROP

    try:
        aces       = _get_aces(ctx, "krbtgt_aces")
        identities = _get_identities(ctx)

        for ace in aces:
            try:
                sid = ace.get("sid") or ace.get("trustee_sid")
                if sid not in identities:
                    continue

                ace_type = _safe_str(ace.get("ace_type") or ace.get("type") or "ALLOW").upper()
                if "DENY" in ace_type:
                    continue

                mask = _safe_int(ace.get("mask") or ace.get("access_mask"))

                # GenericAll  (0x000F01FF or 0x10000000 bit)
                if (mask & _GENERIC_ALL_MASK) == _GENERIC_ALL_MASK:
                    return True
                if mask & 0x10000000:
                    return True

                # GenericWrite (0x0002019F)
                if (mask & _RIGHT_GENERIC_WRITE) == _RIGHT_GENERIC_WRITE:
                    return True

                # WriteDACL   (0x00040000)
                if mask & _RIGHT_WRITE_DACL:
                    return True

                # WriteOwner  (0x00080000)
                if mask & _RIGHT_WRITE_OWNER:
                    return True

                # WriteProperty (ADS_RIGHT_DS_WRITE_PROP = 0x20)
                if mask & _RIGHT_WRITE_PROPERTY:
                    return True

            except Exception:
                continue

        return False
    except Exception:
        return False

def _rule_06_adminsdholder_generic_all(ctx):
    try:
        aces       = _get_aces(ctx, "adminsdholder_aces")
        identities = _get_identities(ctx)

        # Rights masks to check: (name, mask)
        _DANGEROUS_RIGHTS = (
            ("GenericAll",    _GENERIC_ALL_MASK),
            ("WriteOwner",    _RIGHT_WRITE_OWNER),
            ("WriteDACL",     _RIGHT_WRITE_DACL),
            ("GenericWrite",  _RIGHT_GENERIC_WRITE),
            ("WriteProperty", _RIGHT_ADS_RIGHT_DS_WRITE_PROP),
        )

        for ace in aces:
            try:
                if ace.get("sid") not in identities:
                    continue
                ace_type = ace.get("ace_type")
                if ace_type is not None and "ALLOW" not in _safe_str(ace_type).upper():
                    continue

                mask = _safe_int(ace.get("mask") or ace.get("access_mask"))

                # GenericAll — full mask match + 0x10000000 (GA bit)
                if (mask & _GENERIC_ALL_MASK) == _GENERIC_ALL_MASK or (mask & 0x10000000):
                    return True

                # Other dangerous rights
                for _right_name, right_mask in _DANGEROUS_RIGHTS[1:]:
                    if mask & right_mask:
                        return True

            except Exception:
                continue

        return False
    except Exception:
        return False

def _rule_07_all_extended_rights_domain(ctx):
    try:
        if bool(ctx.get("has_all_extended_rights_on_domain")):
            return True
    except Exception:
        pass

    # GUIDs that are dangerous as a scoped AllExtendedRights on the domain root
    _DR_EXTENDED_GUIDS = frozenset({
        _GUID_DS_REPLICATION_GET_CHANGES,
        _GUID_DS_REPLICATION_GET_CHANGES_ALL,
        _GUID_DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET,
        _GUID_FORCE_CHANGE_PASSWORD,
    })

    try:
        aces       = _get_aces(ctx, "domain_root_aces")
        identities = _get_identities(ctx)

        for ace in aces:
            try:
                # ── Trustee match ─────────────────────────────────────────────
                trustee_sid = _safe_str(ace.get("trustee_sid") or ace.get("sid")).upper()
                if not trustee_sid:
                    continue

                identities_upper = {_safe_str(i).upper() for i in identities}
                if trustee_sid not in identities_upper:
                    continue

                # ── ACE type — skip explicit Deny ACEs ────────────────────────
                ace_type = ace.get("ace_type")
                if ace_type is not None and "ALLOW" not in _safe_str(ace_type).upper():
                    continue

                mask     = _safe_int(ace.get("access_mask") or ace.get("mask"))
                obj_type = _safe_str(
                    ace.get("object_type") or ace.get("object_guid") or ""
                ).lower().strip()

                # ── Check 1: GenericAll (0x000F01FF) implies everything ────────
                if (mask & _GENERIC_ALL_MASK) == _GENERIC_ALL_MASK:
                    return True

                # ── Check 2: AllExtendedRights bit must be set for checks 3-7 ─
                if not (mask & _RIGHT_ALL_EXTENDED):
                    continue

                # ── Check 3: Blanket AllExtendedRights (no GUID restriction) ──
                if not obj_type:
                    return True

                # ── Check 4-7: Scoped to one of the dangerous GUIDs ───────────
                if obj_type in _DR_EXTENDED_GUIDS:
                    return True

            except Exception:
                continue

        return False
    except Exception:
        return False

def _rule_08_nested_to_domain_admins(ctx):
    try:
        # Fast-path yalnız Rule 1 SID-lərinə real uyğunluq varsa keçərlidir.
        if ctx.get("is_nested_admin"):
            identities = _get_identities(ctx)
            group_index = _build_group_sid_index(ctx)
            privileged_sids = _collect_rule1_group_sids(ctx)
            for sid in identities:
                sid_upper = _safe_str(sid).upper()
                if sid_upper and sid_upper not in privileged_sids:
                    if _is_nested_member(sid_upper, privileged_sids, group_index):
                        return True

        group_index     = _build_group_sid_index(ctx)
        privileged_sids = _collect_rule1_group_sids(ctx)

        if not privileged_sids or not group_index:
            return False

        identities = _get_identities(ctx)

        for sid in identities:
            sid_upper = _safe_str(sid).upper()
            if not sid_upper:
                continue
            if sid_upper in privileged_sids:
                continue
            if _is_nested_member(sid_upper, privileged_sids, group_index):
                return True

        return False
    except Exception:
        return False


def _rule_09_shadow_cred_on_dc(ctx):
    try:
        return bool(ctx.get("can_write_key_credential_link_on_dc"))
    except Exception:
        return False

def _rule_10_dns_admins(ctx):
    try:
        names = [_safe_str(g).lower() for g in (ctx.get("member_of_names") or [])]
        if _group_names_contain(names, "dnsadmins"):
            return True
        
        dns_admins_sids: set[str] = set()
        for group in ctx.get("groups", []):
            try:
                name = _safe_str(group.get("name")).strip().lower()
                if "dnsadmins" in name:
                    gsid = _safe_str(group.get("sid")).upper()
                    if gsid:
                        dns_admins_sids.add(gsid)
            except Exception:
                continue

        if dns_admins_sids:
            group_sids = {_safe_str(s).upper() for s in (ctx.get("all_group_sids") or [])}
            if group_sids & dns_admins_sids:
                return True

        return False
    except Exception:
        return False
    
def _rule_12_nested_to_operator_groups(ctx):
    try:
        if ctx.get("is_nested_operator_admin"):
            identities = _get_identities(ctx)
            group_index = _build_group_sid_index(ctx)
            privileged_sids = _collect_rule2_group_sids(ctx)
            for sid in identities:
                sid_upper = _safe_str(sid).upper()
                if sid_upper and sid_upper not in privileged_sids:
                    if _is_nested_member(sid_upper, privileged_sids, group_index):
                        return True

        group_index     = _build_group_sid_index(ctx)
        privileged_sids = _collect_rule2_group_sids(ctx)

        if not privileged_sids or not group_index:
            return False

        identities = _get_identities(ctx)

        for sid in identities:
            sid_upper = _safe_str(sid).upper()
            if not sid_upper:
                continue
            if sid_upper in privileged_sids:
                continue
            if _is_nested_member(sid_upper, privileged_sids, group_index):
                return True

        return False
    except Exception:
        return False

def _rule_13_krbtgt_rid_502(ctx):
    try:
        return _rid(_safe_str(ctx.get("user_sid"))) == 502
    except Exception:
        return False


def _rule_14_privileged_primary_group(ctx: dict) -> bool:
    try:
        primary_rid = _safe_int(ctx.get("primary_group_id"))
        if not primary_rid:
            return False

        if primary_rid not in PRIVILEGED_PRIMARY_GROUP_RIDS:
            return False
        if primary_rid == 516:
            sam = _safe_str(ctx.get("user_sid", ""))
            sam_name = _safe_str(ctx.get("sam_account_name") or ctx.get("username") or "")
            if sam_name.endswith("$"):
                return False

        user_sid    = _safe_str(ctx.get("user_sid"))
        domain_sid  = user_sid.rsplit("-", 1)[0] if user_sid and "-" in user_sid else ""
        primary_sid = f"{domain_sid}-{primary_rid}" if domain_sid else f"<domain>-{primary_rid}"

        ctx["rule14_detail"] = {
            "primary_group_rid": primary_rid,
            "primary_group_sid": primary_sid,
            "primary_group_label": _RID_LABEL.get(primary_rid, str(primary_rid)),
            "description": PRIVILEGED_PRIMARY_GROUP_RIDS[primary_rid],
            "note": (
                "Bu üzv memberOf atributunda görünmür — "
                "standart qrup üzvlüyü yoxlamalarından gizli qala bilər."
            ),
        }
        return True

    except Exception:
        return False


_RULES = [
    (1,  "absolute", "Domain Admins / Enterprise Admins / Schema Admins / Builtin Admins", _rule_01_domain_admins),
    (2,  "tier1", "Operator Groups (Account/Server/Backup/GPO/Print/Cryptographic/Hyper-V/Storage Replica Administrators)",        _rule_02_operator_groups),
    (3,  "tier1",    "GenericAll+WriteOwner @ Domain root",                                _rule_03_generic_all_domain_root),
    (4,  "tier1",    "DS-Replication-Get-Changes-All — DCSync",                            _rule_04_dcsync_get_changes_all),
    (5,  "tier1",    "krbtgt Admin",                                                       _rule_5_krbtgt_generic_all),
    (6,  "tier1",    "AdminSDHolder — GA/WriteOwner/WriteDACL/GenericWrite/WriteProperty", _rule_06_adminsdholder_generic_all),
    (7,  "tier1",    "AllExtendedRights @ Domain — includes DCSync",                       _rule_07_all_extended_rights_domain),
    (8,  "absolute",    "Nested group -> Domain Admins (Rule 1 groups)",                      _rule_08_nested_to_domain_admins),
    (9,  "tier1",    "Shadow Credentials write on DC object",                              _rule_09_shadow_cred_on_dc),
    (10, "tier1",    "DnsAdmins member — DLL injection on DC",                             _rule_10_dns_admins),
    (12, "tier1",    "Nested group -> Operator Groups (Rule 2 groups)",                    _rule_12_nested_to_operator_groups),
    (13, "absolute", "krbtgt account (RID 502) — always absolute admin",                    _rule_13_krbtgt_rid_502),
    (14, "absolute",   "Privileged primaryGroupID — gizli qrup üzvlüyü (memberOf-da görünmür)", _rule_14_privileged_primary_group),
]

potential_admin_lvl1: list[int] = [
    level for level, severity, *_ in _RULES if severity == "tier1"
]

potential_admin_lvl2: list[int] = [
    level for level, severity, *_ in _RULES if severity == "tier2"
]

potential_admin_lvl3: list[int] = [
    level for level, severity, *_ in _RULES if severity == "tier3"
]

SEVERITY_COLOR: dict[str, dict] = {
    "absolute": {"ansi": "\033[91m",       "hex": "#FF4444", "label": "Absolute Admin"},
    "tier1":    {"ansi": "\033[38;5;208m", "hex": "#FF8C00", "label": "Potential Admin Lvl 1"},
    "tier2":    {"ansi": "\033[93m",       "hex": "#FFD700", "label": "Potential Admin Lvl 2"},
    "tier3":    {"ansi": "\033[96m",       "hex": "#00BFFF", "label": "Potential Admin Lvl 3"},
    "reset":    {"ansi": "\033[0m",        "hex": "",         "label": ""},
}

_SEVERITY_LEVEL_MAP: dict[int, str] = {
    level: severity
    for level, severity, *_ in _RULES
}


def get_severity(level: int) -> str:
    try:
        return _SEVERITY_LEVEL_MAP.get(int(level), "unknown")
    except Exception:
        return "unknown"


def colorize(level: int, text: str) -> str:
    try:
        sev   = get_severity(level)
        color = SEVERITY_COLOR.get(sev, {}).get("ansi", "")
        reset = SEVERITY_COLOR["reset"]["ansi"]
        return f"{color}{text}{reset}"
    except Exception:
        return text


def check_admin(ctx: dict) -> dict:
    if not ctx or not isinstance(ctx, dict):
        return {
            "is_admin":      False,
            "matched_rules": [],
            "by_severity": {
                "absolute": [],
                "tier1":    [],
                "tier2":    [],
                "tier3":    [],
            },
        }

    matched: list[dict] = []

    # Detail keys written into ctx by rules after a successful match.
    _DETAIL_KEYS: dict[int, str] = {
        1:  "rule1_detail",
        2:  "rule2_detail",
        14: "rule14_detail",
    }

    for level, severity, label, fn in _RULES:
        try:
            if fn(ctx):
                entry: dict = {
                    "level":    level,
                    "severity": severity,
                    "label":    label,
                }
                detail_key = _DETAIL_KEYS.get(level)
                if detail_key and detail_key in ctx:
                    entry["detail"] = ctx[detail_key]
                matched.append(entry)
        except Exception as exc:
            logger.debug("Rule %d (%s) error: %s", level, label, exc)

    by_severity: dict[str, list[dict]] = {
        "absolute": [],
        "tier1":    [],
        "tier2":    [],
        "tier3":    [],
    }

    for rule in matched:
        sev = rule.get("severity", "")
        if sev in by_severity:
            by_severity[sev].append(rule)

    return {
        "is_admin":      bool(matched),
        "matched_rules": matched,
        "by_severity":   by_severity,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Protobuf Integration
# ─────────────────────────────────────────────────────────────────────────────

def check_admin_from_proto(admin_ctx_proto) -> dict:

    if not _PROTO_BRIDGE_OK:
        raise ImportError("Protobuf bridge unavailable.")
    ctx = _proto_bridge.admin_ctx_from_proto(admin_ctx_proto)
    return check_admin(ctx)


def check_admin_from_file(proto_path: str) -> list[dict]:

    if not _PROTO_BRIDGE_OK:
        raise ImportError("Protobuf bridge unavailable.")

    payload_dict = _proto_bridge.load_payload(proto_path)

    import domain_users_pb2 as _pb2
    from pathlib import Path as _Path

    raw_payload = _pb2.DomainUsersPayload()
    raw_payload.ParseFromString(_Path(proto_path).read_bytes())

    proto_user_index = {u.username: u for u in raw_payload.users}

    results: list[dict] = []

    for user in payload_dict.get("users", []):
        try:
            proto_user = proto_user_index.get(user["username"])

            if proto_user is not None and proto_user.HasField("admin_ctx"):
                ctx = _proto_bridge.admin_ctx_from_proto(proto_user.admin_ctx)
            else:
                ctx = {}

            check_result = check_admin(ctx)

        except Exception as exc:
            logger.warning(
                "check_admin_from_file: context read error for '%s': %s",
                user.get("username"), exc,
            )
            check_result = {
                "is_admin":      False,
                "matched_rules": [],
                "by_severity":   {"absolute": [], "tier1": [], "tier2": [], "tier3": []},
            }

        results.append({
            "username":     user.get("username", ""),
            "sid":          user.get("sid", ""),
            "check_result": check_result,
        })

    return results