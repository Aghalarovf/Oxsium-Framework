"""
users_dump.py — LDAP user enumeration.

Fetches all AD user objects and enriches each with an admin-check
context that is evaluated by admins_check.check_admin().

Context keys forwarded to admins_check
---------------------------------------
Required by rules that inspect group membership:
  user_sid              str          — normalised SID of this user
  all_group_sids        set[str]     — all transitive group SIDs incl. primary group
  member_of_names       list[str]    — short CN names of direct groups
  is_nested_admin       bool         — user reaches a privileged group via nesting

Required by rules that inspect UAC flags:
  user_account_control  int          — raw UAC bitmask

Required by rules that inspect delegation:
  msds_allowedtodelegateto  list[str] — SPNs from msDS-AllowedToDelegateTo

Required by rules that inspect ACLs (pre-fetched once per session):
  domain_root_aces          list[dict]  — ACEs on the domain root NC object
  adminsdholder_aces        list[dict]  — ACEs on CN=AdminSDHolder,CN=System,...
  krbtgt_aces               list[dict]  — ACEs on CN=krbtgt,CN=Users,...
  domain_admins_group_aces  list[dict]  — ACEs on the Domain Admins group object
  dc_ou_aces                list[dict]  — ACEs on OU=Domain Controllers,...
  gpo_container_aces        list[dict]  — ACEs on CN=Policies,CN=System,...
  computer_target_aces      list[dict]  — ACEs on computer objects (best-effort)

Required by rules resolved at session level (bool flags):
  has_dcsync_right                        bool
  has_rbcd_on_dc                          bool
  has_force_change_password_on_da         bool
  can_write_key_credential_link           bool
  can_write_key_credential_link_on_dc     bool
  has_gpo_write_dacl_on_dc_linked_gpo    bool
  has_adcs_esc1_enrollment                bool
  has_adcs_esc4_template_write_dacl       bool
  has_all_extended_rights_on_domain       bool
  has_generic_write_on_da_user            bool
  has_write_spn_on_other                  bool
  can_read_laps_password                  bool
  can_write_gmsa_membership               bool

  sid_history               list[str]   — sIDHistory attribute values

Each bool flag that cannot be determined defaults to False.
ACE lists that cannot be fetched default to [].
"""

import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ldap3 import ALL, BASE, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPSocketOpenError

try:
    from impacket.ldap import ldaptypes as _ldaptypes
    _IMPACKET_OK = True
except ImportError:
    _IMPACKET_OK = False

from user import admins_check

# Optional protobuf bridge; enumeration still works without it.
try:
    from proto_bridge import save_payload as _proto_save_payload  # noqa: F401
    _PROTO_OK = True
except ImportError:
    _PROTO_OK = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level overrides (same interface as original users.py)
# ---------------------------------------------------------------------------
ADMIN_GROUP_DNS: list[str] = []
USER_EXTRA_FILTERS: list[str] = []

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_EMPTY_LM_HASH               = "aad3b435b51404eeaad3b435b51404ee"
_FILETIME_EPOCH_DELTA        = 116_444_736_000_000_000
_FILETIME_NEVER              = 9_223_372_036_854_775_807
_PAGED_CTRL_OID              = "1.2.840.113556.1.4.319"
_LDAP_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"
_PRIVILEGED_USER_RIDS        = {500, 502}
_ENABLE_TOKEN_GROUPS         = os.getenv("LDAP_ENABLE_TOKEN_GROUPS", "0") == "1"

_DCSYNC_RIGHT_GUIDS = {
    str(uuid.UUID("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")),
    str(uuid.UUID("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")),
    str(uuid.UUID("8970210d-4501-11d3-ad06-00c04f79758a")),
}

_ACE_OBJECT_TYPE_PRESENT        = 0x01
_ACCESS_ALLOWED_ACE_TYPE        = 0x00
_ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
_GENERIC_ALL_MASK               = 0x000F01FF
_RIGHT_WRITE_DACL               = 0x00040000
_RIGHT_WRITE_OWNER              = 0x00080000
_RIGHT_GENERIC_ALL              = 0x10000000
_SD_FLAGS_CONTROL               = ("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x04")

_USER_ATTRS: list[str] = [
    "sAMAccountName",
    "distinguishedName",
    "dNSHostName",
    "displayName",
    "objectSid",
    "userPrincipalName",
    "description",
    "userAccountControl",
    "memberOf",
    "servicePrincipalName",
    "pwdLastSet",
    "whenCreated",
    "whenChanged",
    "lastLogonTimestamp",
    "lockoutTime",
    "logonCount",
    "mail",
    "telephoneNumber",
    "department",
    "title",
    "adminCount",
    "primaryGroupID",
    "msDS-AllowedToDelegateTo",
    "msDS-SupportedEncryptionTypes",
    "sIDHistory",
    "nTSecurityDescriptor",
    # --- Yeni atributlar ---
    "badPwdCount",
    "badPasswordTime",
    "accountExpires",
    "msDS-ResultantPSO",
    "msDS-UserPasswordExpiryTimeComputed",
    "msDS-KeyCredentialLink",
    "scriptPath",
    "homeDirectory",
    "homeDrive",
]

if _ENABLE_TOKEN_GROUPS:
    _USER_ATTRS.append("tokenGroups")


# ---------------------------------------------------------------------------
# msDS-SupportedEncryptionTypes — MS-KILE §2.2.7 rəsmi bitmask xəritəsi
#
# Qaydalar:
#   • Yalnız tək bit dəyərləri — kombinasiyalar (0x1F, 0x27 və s.)
#     parse zamanı _parse_enc_types() ilə bitlərə ayrılır.
#   • Risk skoru:  > 500 → kritik/yüksək risk
#                 ≤ 500 → qəbul edilə bilər / təhlükəsiz
#   • Capability bitləri (FAST, Claims...) şifrələmə alqoritmi deyil;
#     onlar üçün risk = 0 (informativ).
# ---------------------------------------------------------------------------
_MSDS_ENC_TYPE_MAP: dict[int, tuple[str, int]] = {
    # ── Bit A — şifrələmə alqoritmləri ──────────────────────────────────────
    0x0001: ("DES-CBC-CRC",                      950),  # 56-bit, aktif istismar
    0x0002: ("DES-CBC-MD5",                      900),  # 56-bit, MD5 bütövlük
    0x0004: ("RC4-HMAC",                         700),  # Kerberoast / AS-REP roast
    0x0008: ("AES128-CTS-HMAC-SHA1-96",          200),  # Qəbul edilə bilər
    0x0010: ("AES256-CTS-HMAC-SHA1-96",          100),  # Tövsiyə edilən
    # ── Bit J — session key enforcement ─────────────────────────────────────
    0x0040: ("AES256-CTS-HMAC-SHA1-96-SK",        80),  # RC4 aktifkən AES session key
    # ── Bit K/L — müasir SHA-2 alqoritmləri (RFC 8009) ──────────────────────
    0x0080: ("AES128-CTS-HMAC-SHA256-128",         60),  # RFC 8009
    0x0100: ("AES256-CTS-HMAC-SHA384-192",         40),  # RFC 8009, ən güclü
    # ── Capability bitləri (şifrələmə deyil, KDC xüsusiyyətləri) ────────────
    0x0020: ("FAST-supported",                      0),  # Bit F
    0x0400: ("Compound-identity-supported",         0),  # Bit G
    0x0800: ("Claims-supported",                    0),  # Bit H
    0x1000: ("Resource-SID-compression-disabled",   0),  # Bit I
}

# Yalnız şifrələmə alqoritm bitləri (risk > 0 olanlar)
_ENC_ALGO_BITS: frozenset[int] = frozenset(
    b for b, (_, risk) in _MSDS_ENC_TYPE_MAP.items() if risk > 0
)


def _parse_enc_types(value: int) -> list[tuple[str, int]]:
    return sorted(
        (info for bit, info in _MSDS_ENC_TYPE_MAP.items() if value & bit),
        key=lambda x: x[1],
        reverse=True,
    )


def _max_enc_risk_score(value: int | None) -> int:
    if value is None or value == 0:
        return 700  # null/0 → DC implicit RC4 default
    scores = [
        risk
        for bit, (_, risk) in _MSDS_ENC_TYPE_MAP.items()
        if (value & bit) and risk > 0
    ]
    return max(scores, default=0)


def _msds_supported_encryption_types_names(value: int | None) -> list[dict]:
    if value is None:
        return []
    try:
        ival = int(value)
    except Exception:
        return []
    if ival == 0:
        return []
    return [
        {"name": name, "risk": risk, "is_weak": risk > 500}
        for name, risk in _parse_enc_types(ival)
    ]


# ---------------------------------------------------------------------------
# Low-level LDAP helpers (unchanged from original users.py)
# ---------------------------------------------------------------------------

def _is_ntlm_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}", value or ""))


def _domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def _get_bind_user(username: str, domain: str) -> str:
    if "@" in username or "\\" in username:
        return username
    return f"{domain.split('.')[0].upper()}\\{username}"


def _ldap_escape_dn(dn: str) -> str:
    return (
        dn
        .replace("\\", "\\5c")
        .replace("*",  "\\2a")
        .replace("(",  "\\28")
        .replace(")",  "\\29")
        .replace("\x00", "\\00")
    )


def _read_attr(entry, name: str):
    try:
        attr = getattr(entry, name, None)
        if attr is None:
            return None
        val = attr.value
        if isinstance(val, list) and len(val) == 0:
            return None
        return val
    except Exception:
        return None


def _read_attr_list(entry, name: str) -> list[str]:
    try:
        attr = getattr(entry, name, None)
        if attr is None:
            return []
        values = attr.values
        return [str(v) for v in values if v is not None] if values else []
    except Exception:
        return []


def _read_str(entry, name: str, default: str = "") -> str:
    val = _read_attr(entry, name)
    if val is None:
        return default
    if isinstance(val, list):
        return str(val[0]) if val else default
    return str(val)


def _read_int(entry, name: str, default: int = 0) -> int:
    val = _read_attr(entry, name)
    if val is None:
        return default
    try:
        if isinstance(val, list):
            val = val[0] if val else default
        return int(val)
    except Exception:
        return default


def _filetime_to_iso(value: int) -> str | None:
    if value <= 0 or value in (_FILETIME_NEVER,):
        return None
    try:
        unix_seconds = (value - _FILETIME_EPOCH_DELTA) / 10_000_000
        dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _read_timestamp(entry, name: str) -> str | None:
    val = _read_attr(entry, name)
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val.isoformat().replace("+00:00", "Z")
    try:
        ival = int(val)
        parsed = _filetime_to_iso(ival)
        return parsed if parsed is not None else str(val)
    except Exception:
        return str(val)


def _parse_uac(entry) -> dict:
    uac = _read_int(entry, "userAccountControl", 0)
    return {
        "disabled":                       bool(uac & 0x00000002),
        "lockout":                        bool(uac & 0x00000010),
        "pwd_not_required":               bool(uac & 0x00000020),
        "encrypted_text_pwd_allowed":     bool(uac & 0x00000080),
        "normal_account":                 bool(uac & 0x00000200),
        "workstation_trust_account":      bool(uac & 0x00001000),
        "server_trust_account":           bool(uac & 0x00002000),
        # pwd_cant_change UAC bitindən oxunmur — AD bunu DACL-də saxlayır.
        # nTSecurityDescriptor üzərindən _check_pwd_cant_change() ilə hesablanır.
        "pwd_cant_change":                False,  # _parse_uac-dan sonra ayrıca set edilir
        "pwd_never_expires":              bool(uac & 0x00010000),
        "smartcard_required":             bool(uac & 0x00040000),
        "trusted_for_delegation":         bool(uac & 0x00080000),
        "not_delegated":                  bool(uac & 0x00100000),
        "dont_req_preauth":               bool(uac & 0x00400000),
        "pwd_expired":                    bool(uac & 0x00800000),
        "trusted_to_auth_for_delegation": bool(uac & 0x01000000),
    }


# GUID: CR "User-Change-Password" extended right
_CHANGE_PASSWORD_GUID = "ab721a53-1e2f-11d0-9819-00aa0040529b"
# DENY ACE type
_ACCESS_DENIED_ACE_TYPE        = 0x01
_ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
# Self SID (S-1-5-10) — "change own password" trustee
_SELF_SID = "S-1-5-10"
# Everyone SID (S-1-1-0)
_EVERYONE_SID = "S-1-1-0"


def _check_pwd_cant_change(entry) -> bool:
    """
    'User Cannot Change Password' AD-də UAC biti deyil, DACL-də saxlanır.
    Qaydası: Self (S-1-5-10) və ya Everyone (S-1-1-0) üçün
    'User-Change-Password' extended right-ına DENY ACE varsa → True.
    impacket olmadan yalnız raw bytes parse edilə bilmədiyi üçün False qaytarır.
    """
    if not _IMPACKET_OK:
        return False
    raw = _read_attr(entry, "nTSecurityDescriptor")
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if not isinstance(raw, bytes):
        return False
    try:
        sd = _ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(raw)
        if not sd["Dacl"]:
            return False
        for ace in sd["Dacl"].aces:
            try:
                ace_type = ace["AceType"]
                if ace_type not in (_ACCESS_DENIED_ACE_TYPE, _ACCESS_DENIED_OBJECT_ACE_TYPE):
                    continue
                ace_body = ace["Ace"]
                trustee  = _normalize_sid(ace_body["Sid"].formatCanonical())
                if trustee not in (_SELF_SID, _EVERYONE_SID):
                    continue
                if ace_type == _ACCESS_DENIED_ACE_TYPE:
                    # Generic DENY — "Change Password" hüququnu da əhatə edir
                    return True
                # Object ACE: GUID yoxla
                flags = int(ace_body.get("Flags", 0))
                if flags & _ACE_OBJECT_TYPE_PRESENT:
                    obj_guid = str(uuid.UUID(bytes_le=bytes(ace_body["ObjectType"])))
                    if obj_guid.lower() == _CHANGE_PASSWORD_GUID:
                        return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def _normalize_delegation_targets(values: list[str]) -> list[str]:
    """Normalize and deduplicate msDS-AllowedToDelegateTo SPN targets."""
    result: list[str] = []
    seen: set[str] = set()
    for raw in values or []:
        v = str(raw or "").strip()
        if not v:
            continue
        key = v.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(v)
    return result


def _strip_domain_tld(value: str) -> str:
    parts = [part for part in str(value or "").strip().split(".") if part]
    if len(parts) <= 1:
        return str(value or "").strip()
    return ".".join(parts[:-1])


def _structure_delegation_target(value: str) -> dict:
    raw = str(value or "").strip()
    if not raw:
        return {"raw": "", "service": "", "hostname": "", "host_fqdn": "", "domain": "", "domain_short": ""}

    parts = [part.strip() for part in raw.split("/") if part.strip()]
    service = parts[0] if parts else ""
    host_part = parts[1] if len(parts) >= 2 else ""
    explicit_domain = parts[2] if len(parts) >= 3 else ""

    hostname = host_part
    host_domain = ""
    if host_part and "." in host_part:
        hostname, host_domain = host_part.split(".", 1)

    domain = explicit_domain or host_domain
    return {
        "raw": raw,
        "service": service,
        "hostname": hostname,
        "host_fqdn": host_part,
        "domain": domain,
        "domain_short": _strip_domain_tld(domain),
    }


def _structure_delegation_targets(values: list[str]) -> list[dict]:
    return [_structure_delegation_target(value) for value in (values or []) if str(value or "").strip()]


def _derive_delegation_state(uac: dict, delegation_targets: list[str]) -> dict:
    """
    Build a safer delegation state model.

    Notes:
    - UAC flags may be configured while delegation is effectively blocked
      (e.g. ACCOUNT_NOT_DELEGATED).
    - We expose both configured flags and effective booleans.
    """
    disabled = bool(uac.get("disabled"))
    not_delegated = bool(uac.get("not_delegated"))
    trusted_for_delegation = bool(uac.get("trusted_for_delegation"))
    trusted_to_auth = bool(uac.get("trusted_to_auth_for_delegation"))
    has_targets = bool(delegation_targets)

    unconstrained_effective = trusted_for_delegation and not not_delegated
    constrained_effective = has_targets and not not_delegated
    protocol_transition_effective = trusted_to_auth and constrained_effective

    return {
        "trusted_for_delegation_configured": trusted_for_delegation,
        "trusted_to_auth_for_delegation_configured": trusted_to_auth,
        "constrained_delegation_configured": has_targets,
        "unconstrained_delegation": unconstrained_effective,
        "constrained_delegation": constrained_effective,
        "protocol_transition_delegation": protocol_transition_effective,
        "delegation_effective": unconstrained_effective or constrained_effective,
        "delegation_blocked_by_not_delegated": not_delegated and (trusted_for_delegation or trusted_to_auth or has_targets),
    }


def _normalize_sid(sid: str | None) -> str:
    if not sid:
        return ""
    return str(sid).strip().upper()


def _extract_rid_from_sid(sid: str | None) -> int | None:
    sid_norm = _normalize_sid(sid)
    if not sid_norm or "-" not in sid_norm:
        return None
    try:
        return int(sid_norm.rsplit("-", 1)[1])
    except Exception:
        return None


def _sid_bytes_to_str(data: bytes | bytearray) -> str:
    raw = bytes(data or b"")
    if len(raw) < 8:
        return ""
    revision       = raw[0]
    sub_auth_count = raw[1]
    identifier_authority = int.from_bytes(raw[2:8], byteorder="big", signed=False)
    offset = 8
    subs: list[str] = []
    for _ in range(sub_auth_count):
        if offset + 4 > len(raw):
            break
        subs.append(str(int.from_bytes(raw[offset:offset + 4], byteorder="little", signed=False)))
        offset += 4
    return f"S-{revision}-{identifier_authority}" + ("-" + "-".join(subs) if subs else "")


def _paged_search(conn, base_dn: str, ldap_filter: str,
                  attributes: list[str], page_size: int) -> list:
    all_entries: list = []
    conn.search(base_dn, ldap_filter, search_scope=SUBTREE,
                attributes=attributes, paged_size=page_size)
    all_entries.extend(conn.entries)
    while True:
        cookie = (
            conn.result
            .get("controls", {})
            .get(_PAGED_CTRL_OID, {})
            .get("value", {})
            .get("cookie")
        )
        if not cookie:
            break
        conn.search(base_dn, ldap_filter, search_scope=SUBTREE,
                    attributes=attributes, paged_size=page_size,
                    paged_cookie=cookie)
        all_entries.extend(conn.entries)
    return all_entries


def _resolve_admin_membership(conn, base_dn: str, page_size: int) -> tuple[set[str], set[str]]:
    # Rule 8 must track only Rule 1 groups (512/518/519/544), not every adminCount group.
    admin_groups = _paged_search(
        conn,
        base_dn,
        "(|(objectSid=*-512)(objectSid=*-518)(objectSid=*-519)(objectSid=*-544))",
        ["distinguishedName"],
        page_size,
    )
    direct_group_dns: set[str] = set()
    transitive_dns: set[str] = set()
    for entry in admin_groups:
        try:
            group_dn = str(entry.distinguishedName.value)
        except Exception:
            continue
        if group_dn:
            direct_group_dns.add(group_dn)
        escaped = _ldap_escape_dn(group_dn)
        try:
            members = _paged_search(
                conn, base_dn,
                f"(&(objectClass=user)(memberOf:{_LDAP_MATCHING_RULE_IN_CHAIN}:={escaped}))",
                ["distinguishedName"],
                page_size,
            )
            for m in members:
                try:
                    transitive_dns.add(str(m.distinguishedName.value))
                except Exception:
                    continue
        except Exception as exc:
            logger.warning("Transitive member lookup failed [%s]: %s", group_dn, exc)
    return direct_group_dns, transitive_dns


def _resolve_operator_membership(conn, base_dn: str, page_size: int) -> tuple[set[str], set[str]]:
    operator_groups = _paged_search(
        conn,
        base_dn,
        "(|(objectSid=*-520)(objectSid=*-548)(objectSid=*-549)(objectSid=*-550)(objectSid=*-551)(objectSid=*-569)(objectSid=*-578)(objectSid=*-582))",
        ["distinguishedName"],
        page_size,
    )
    operator_group_dns: set[str] = set()
    transitive_dns: set[str] = set()
    for entry in operator_groups:
        try:
            group_dn = str(entry.distinguishedName.value)
        except Exception:
            continue
        if group_dn:
            operator_group_dns.add(group_dn)
        escaped = _ldap_escape_dn(group_dn)
        try:
            members = _paged_search(
                conn, base_dn,
                f"(&(objectClass=user)(memberOf:{_LDAP_MATCHING_RULE_IN_CHAIN}:={escaped}))",
                ["distinguishedName"],
                page_size,
            )
            for m in members:
                try:
                    transitive_dns.add(str(m.distinguishedName.value))
                except Exception:
                    continue
        except Exception as exc:
            logger.warning("Transitive operator member lookup failed [%s]: %s", group_dn, exc)
    return operator_group_dns, transitive_dns


def _shorten_group_dns(group_dns: list[str]) -> list[str]:
    result: list[str] = []
    for dn in group_dns:
        if not dn:
            continue
        first = dn.split(",")[0]
        result.append(first[3:] if first.upper().startswith("CN=") else first)
    return result


def _get_dcsync_sids(conn, base_dn: str, page_size: int) -> tuple[set[str], str | None]:
    dcsync_sids: set[str] = set()
    if not _IMPACKET_OK:
        return dcsync_sids, "impacket is not installed"
    last_error: str | None = None
    try:
        conn.search(base_dn, "(objectClass=*)", search_scope=BASE,
                    attributes=["nTSecurityDescriptor"], controls=[_SD_FLAGS_CONTROL])
        if not conn.entries:
            return dcsync_sids, None
        ntsd_raw = _read_attr(conn.entries[0], "nTSecurityDescriptor")
        if isinstance(ntsd_raw, list):
            ntsd_raw = ntsd_raw[0] if ntsd_raw else None
        if not isinstance(ntsd_raw, bytes):
            return dcsync_sids, None
        sd = _ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(ntsd_raw)
        if not sd["Dacl"]:
            return dcsync_sids, None
        for ace in sd["Dacl"].aces:
            try:
                ace_type = ace["AceType"]
                ace_body = ace["Ace"]
                if ace_type == _ACCESS_ALLOWED_ACE_TYPE:
                    if (int(ace_body["Mask"]["Mask"]) & _GENERIC_ALL_MASK) == _GENERIC_ALL_MASK:
                        dcsync_sids.add(_normalize_sid(ace_body["Sid"].formatCanonical()))
                    continue
                if ace_type != _ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                    continue
                if (int(ace_body["Mask"]["Mask"]) & _GENERIC_ALL_MASK) == _GENERIC_ALL_MASK:
                    dcsync_sids.add(_normalize_sid(ace_body["Sid"].formatCanonical()))
                    continue
                if not (ace_body["Flags"] & _ACE_OBJECT_TYPE_PRESENT):
                    continue
                obj_guid = str(uuid.UUID(bytes_le=bytes(ace_body["ObjectType"])))
                if obj_guid in _DCSYNC_RIGHT_GUIDS:
                    dcsync_sids.add(_normalize_sid(ace_body["Sid"].formatCanonical()))
            except Exception:
                continue
    except Exception as exc:
        last_error = str(exc)
        logger.warning("DCSync ACL parse failed for %s: %s", base_dn, exc)
    return dcsync_sids, last_error


def _get_principal_sid_map(conn, base_dn: str, page_size: int) -> dict[str, str]:
    entries = _paged_search(
        conn, base_dn,
        "(|(objectClass=group)(objectClass=foreignSecurityPrincipal))",
        ["distinguishedName", "objectSid"],
        page_size,
    )
    result: dict[str, str] = {}
    for entry in entries:
        try:
            dn  = str(entry.distinguishedName.value).lower()
            sid = _normalize_sid(str(entry.objectSid.value))
            if dn and sid:
                result[dn] = sid
        except Exception:
            continue
    return result


# ---------------------------------------------------------------------------
# ACL helpers — parse nTSecurityDescriptor into a list of plain ACE dicts
# ---------------------------------------------------------------------------

def _parse_sd_to_aces(raw: bytes) -> list[dict]:
    """Convert a raw nTSecurityDescriptor into a list of plain dicts for admins_check."""
    aces: list[dict] = []
    if not _IMPACKET_OK or not isinstance(raw, bytes):
        return aces
    try:
        sd = _ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(raw)
        if not sd["Dacl"]:
            return aces
        for ace in sd["Dacl"].aces:
            try:
                ace_body  = ace["Ace"]
                ace_type  = ace["AceType"]
                mask      = int(ace_body["Mask"]["Mask"])
                sid       = _normalize_sid(ace_body["Sid"].formatCanonical())
                obj_guid  = ""
                if ace_type == _ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                    flags = int(ace_body.get("Flags", 0))
                    if flags & _ACE_OBJECT_TYPE_PRESENT:
                        obj_guid = str(uuid.UUID(bytes_le=bytes(ace_body["ObjectType"])))
                aces.append({"sid": sid, "mask": mask, "object_type": obj_guid})
            except Exception:
                continue
    except Exception as exc:
        logger.debug("SD parse error: %s", exc)
    return aces


def _fetch_object_aces(conn, dn: str) -> list[dict]:
    """Fetch and parse the DACL for a single object DN."""
    try:
        conn.search(
            dn, "(objectClass=*)", search_scope=BASE,
            attributes=["nTSecurityDescriptor"],
            controls=[_SD_FLAGS_CONTROL],
        )
        if not conn.entries:
            return []
        raw = _read_attr(conn.entries[0], "nTSecurityDescriptor")
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        if not isinstance(raw, bytes):
            return []
        return _parse_sd_to_aces(raw)
    except Exception as exc:
        logger.debug("_fetch_object_aces(%s) failed: %s", dn, exc)
        return []


# ---------------------------------------------------------------------------
# Session-level ACL pre-fetch
# ---------------------------------------------------------------------------

def _collect_session_acl_context(conn, base_dn: str) -> dict:
    """
    Fetch ACLs for well-known objects once per LDAP session.
    Returns a partial admin context dict with ACE lists and bool flags.
    """
    ctx: dict = {
        "domain_root_aces":          [],
        "adminsdholder_aces":        [],
        "krbtgt_aces":               [],
        "domain_admins_group_aces":  [],
        "dc_ou_aces":                [],
        "gpo_container_aces":        [],
        "computer_target_aces":      [],
        # bool flags resolved via ACL / attribute reads
        "has_dcsync_right":                     False,
        "has_rbcd_on_dc":                       False,
        "has_force_change_password_on_da":      False,
        "can_write_key_credential_link":        False,
        "can_write_key_credential_link_on_dc":  False,
        "has_gpo_write_dacl_on_dc_linked_gpo":  False,
        "has_adcs_esc1_enrollment":             False,
        "has_adcs_esc4_template_write_dacl":    False,
        "has_all_extended_rights_on_domain":    False,
        "has_generic_write_on_da_user":         False,
        "has_write_spn_on_other":               False,
        "can_read_laps_password":               False,
        "can_write_gmsa_membership":            False,
    }

    # Domain root
    ctx["domain_root_aces"] = _fetch_object_aces(conn, base_dn)

    # AdminSDHolder
    adminsdholder_dn = f"CN=AdminSDHolder,CN=System,{base_dn}"
    ctx["adminsdholder_aces"] = _fetch_object_aces(conn, adminsdholder_dn)

    # krbtgt
    krbtgt_dn = f"CN=krbtgt,CN=Users,{base_dn}"
    ctx["krbtgt_aces"] = _fetch_object_aces(conn, krbtgt_dn)

    # Domain Admins group DN
    try:
        conn.search(
            base_dn,
            "(&(objectClass=group)(objectSid=*-512))",
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
            size_limit=1,
        )
        if conn.entries:
            da_dn = str(conn.entries[0].distinguishedName.value)
            ctx["domain_admins_group_aces"] = _fetch_object_aces(conn, da_dn)
    except Exception as exc:
        logger.debug("Domain Admins group ACL fetch failed: %s", exc)

    # Domain Controllers OU
    dc_ou_dn = f"OU=Domain Controllers,{base_dn}"
    ctx["dc_ou_aces"] = _fetch_object_aces(conn, dc_ou_dn)

    # GPO container
    gpo_container_dn = f"CN=Policies,CN=System,{base_dn}"
    ctx["gpo_container_aces"] = _fetch_object_aces(conn, gpo_container_dn)

    # Check if any DC has msDS-AllowedToActOnBehalfOfOtherIdentity set (RBCD signal)
    try:
        conn.search(
            base_dn,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)"
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
            size_limit=1,
        )
        ctx["has_rbcd_on_dc"] = bool(conn.entries)
    except Exception:
        pass

    # user_aces — Rule 29/30 üçün lazımdır, lakin bu mərhələdə admin SID-ləri
    # hələ məlum deyil (Rule 1-18 hələ işləməyib). İkinci keçiddə doldurulur.
    ctx["user_aces"] = []

    return ctx


# ---------------------------------------------------------------------------
# Per-user admin context builder
# ---------------------------------------------------------------------------

def _build_user_admin_ctx(
    entry,
    user_sid: str,
    uac_raw: int,
    groups_raw: list[str],
    is_nested_admin: bool,
    is_nested_operator_admin: bool,
    principal_sid_map: dict[str, str],
    dcsync_sids: set[str],
    session_acl_ctx: dict,
) -> dict:
    """
    Compose the full context dict for admins_check.check_admin().
    Per-user fields are derived here; session-level ACL fields are merged in.
    """
    # Collect all group SIDs (direct + primary group)
    user_group_sids: set[str] = {
        principal_sid_map[g.lower()]
        for g in groups_raw
        if g.lower() in principal_sid_map
    }

    if _ENABLE_TOKEN_GROUPS:
        token_groups_raw = _read_attr(entry, "tokenGroups")
        if isinstance(token_groups_raw, list):
            for sid_blob in token_groups_raw:
                sid_text = _sid_bytes_to_str(sid_blob)
                if sid_text:
                    user_group_sids.add(_normalize_sid(sid_text))

    primary_group_id = _read_int(entry, "primaryGroupID", default=0)
    if user_sid and primary_group_id > 0 and "-" in user_sid:
        domain_sid = user_sid.rsplit("-", 1)[0]
        user_group_sids.add(_normalize_sid(f"{domain_sid}-{primary_group_id}"))

    all_sids = user_group_sids | ({user_sid} if user_sid else set())

    # DCSync via extended rights
    has_dcsync = bool(dcsync_sids and (user_sid in dcsync_sids or bool(user_group_sids & dcsync_sids)))

    # sIDHistory
    sid_history_raw = _read_attr_list(entry, "sIDHistory")
    sid_history = [_normalize_sid(s) for s in sid_history_raw if s]

    # Delegation SPNs
    msds_delegate = _normalize_delegation_targets(_read_attr_list(entry, "msDS-AllowedToDelegateTo"))

    ctx: dict = {
        "user_sid":              user_sid,
        "all_group_sids":        all_sids,
        "member_of_names":       _shorten_group_dns(groups_raw),
        "is_nested_admin":       is_nested_admin,
        "user_account_control":  uac_raw,
        "msds_allowedtodelegateto": msds_delegate,
        "has_dcsync_right":      has_dcsync,
        "sid_history":           sid_history,
        "is_nested_operator_admin": is_nested_operator_admin,
    }

    # Merge session-level ACL context (ACE lists + bool flags), but don't
    # override per-user has_dcsync_right we just computed.
    for k, v in session_acl_ctx.items():
        if k != "has_dcsync_right":
            ctx[k] = v

    return ctx


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def get_domain_users(ip: str, domain: str, username: str,
                     password: str, config,
                     proto_output_path: str | None = None) -> dict:

    auth_type = "SIMPLE"
    if _is_ntlm_hash(password):
        password  = f"00000000000000000000000000000000:{password}"
        auth_type = "NTLM"

    base_dn   = _domain_to_dn(domain)
    bind_user = _get_bind_user(username, domain)
    page_size = getattr(config, "LDAP_PAGE_SIZE", 500)

    admin_group_dns_lower: set[str] = {dn.lower() for dn in ADMIN_GROUP_DNS}

    conn = None
    try:
        server = Server(ip, get_info=ALL,
                        connect_timeout=config.LDAP_CONNECT_TIMEOUT)
        conn   = Connection(server, user=bind_user, password=password,
                            authentication=auth_type, auto_bind=True,
                            receive_timeout=config.LDAP_RECEIVE_TIMEOUT)

        # ── Session-level pre-fetches ────────────────────────────────────────
        admin_group_dns, transitive_dns = _resolve_admin_membership(conn, base_dn, page_size)
        admin_group_dns_lower = {dn.lower() for dn in admin_group_dns}
        transitive_dns_lower = {dn.lower() for dn in transitive_dns}

        operator_group_dns, operator_transitive_dns = _resolve_operator_membership(conn, base_dn, page_size)
        operator_group_dns_lower       = {dn.lower() for dn in operator_group_dns}
        operator_transitive_dns_lower   = {dn.lower() for dn in operator_transitive_dns}

        dcsync_sids, dcsync_error = _get_dcsync_sids(conn, base_dn, page_size)

        try:
            principal_sid_map = _get_principal_sid_map(conn, base_dn, page_size)
        except Exception as exc:
            logger.warning("Failed to get principal SID map: %s", exc)
            principal_sid_map = {}

        session_acl_ctx = _collect_session_acl_context(conn, base_dn)

        # ── User enumeration ─────────────────────────────────────────────────
        if USER_EXTRA_FILTERS:
            extra       = "".join(USER_EXTRA_FILTERS)
            user_filter = f"(&(objectClass=user)(objectCategory=person){extra})"
        else:
            user_filter = "(&(objectClass=user)(objectCategory=person))"

        all_entries = _paged_search(conn, base_dn, user_filter, _USER_ATTRS, page_size)

        users: list[dict] = []
        admin_ctx_map: dict[str, dict] = {}   # username → admin_ctx (proto serializasiyası üçün)

        for entry in all_entries:
            sam_name = _read_str(entry, "sAMAccountName")
            user_dn  = _read_str(entry, "distinguishedName")
            upn      = _read_str(entry, "userPrincipalName")

            if not sam_name:
                continue

            uac_parsed = _parse_uac(entry)
            uac_parsed["pwd_cant_change"] = _check_pwd_cant_change(entry)
            uac_raw    = _read_int(entry, "userAccountControl", 0)

            groups_raw:   list[str] = _read_attr_list(entry, "memberOf")
            groups_lower: set[str]  = {g.lower() for g in groups_raw}
            groups_short: list[str] = _shorten_group_dns(groups_raw)

            is_direct_admin = bool(admin_group_dns_lower.intersection(groups_lower))
            is_group_admin  = user_dn.lower() in transitive_dns_lower
            is_direct_operator = bool(operator_group_dns_lower and operator_group_dns_lower.intersection(groups_lower))
            is_operator_group  = user_dn.lower() in operator_transitive_dns_lower
            user_sid        = _normalize_sid(_read_str(entry, "objectSid"))

            # Nested admin means the user reaches an adminCount group through
            # group nesting, but is not a direct member of the admin group.
            is_nested_admin = is_group_admin and not is_direct_admin
            is_nested_operator_admin = is_operator_group and not is_direct_operator

            # ── Build admin context and run all 40 rules ─────────────────────
            admin_ctx    = _build_user_admin_ctx(
                entry          = entry,
                user_sid       = user_sid,
                uac_raw        = uac_raw,
                groups_raw     = groups_raw,
                is_nested_admin= is_nested_admin,
                is_nested_operator_admin = is_nested_operator_admin,
                principal_sid_map = principal_sid_map,
                dcsync_sids    = dcsync_sids,
                session_acl_ctx= session_acl_ctx,
            )
            admin_ctx_map[sam_name] = admin_ctx   # proto serializasiyası üçün saxla
            admin_result = admins_check.check_admin(admin_ctx)
            is_admin     = admin_result["is_admin"]
            matched_levels = {
                int(rule.get("level"))
                for rule in admin_result.get("matched_rules", [])
                if isinstance(rule, dict) and str(rule.get("level", "")).isdigit()
            }
            is_potential_admin = is_admin and matched_levels and matched_levels.issubset({2, 10})

            # ── Supplementary flags (unchanged from original) ─────────────────
            pwd_last_set_int  = _read_int(entry, "pwdLastSet", default=-1)
            must_change_pwd   = (pwd_last_set_int == 0)
            is_locked_out     = _read_int(entry, "lockoutTime", default=0) > 0
            is_asrep          = uac_parsed["dont_req_preauth"] and bool(sam_name)
            spn_list          = _read_attr_list(entry, "servicePrincipalName")
            is_kerberoastable = bool(spn_list)
            delegation_targets = _normalize_delegation_targets(_read_attr_list(entry, "msDS-AllowedToDelegateTo"))
            delegation_state = _derive_delegation_state(uac_parsed, delegation_targets)

            user_group_sids_for_dcsync: set[str] = {
                principal_sid_map[g.lower()]
                for g in groups_raw
                if g.lower() in principal_sid_map
            }
            primary_group_id = _read_int(entry, "primaryGroupID", default=0)
            if user_sid and primary_group_id > 0 and "-" in user_sid:
                domain_sid = user_sid.rsplit("-", 1)[0]
                user_group_sids_for_dcsync.add(_normalize_sid(f"{domain_sid}-{primary_group_id}"))

            is_dcsync = bool(
                dcsync_sids and (
                    user_sid in dcsync_sids or bool(user_group_sids_for_dcsync & dcsync_sids)
                )
            )

            # ── Yeni atributlar ───────────────────────────────────────────────
            # domain_sid: user SID-dən çıxarılır (S-1-5-21-X-Y-Z)
            domain_sid_val = user_sid.rsplit("-", 1)[0] if user_sid and "-" in user_sid else ""

            # badPwdCount / badPasswordTime
            bad_pwd_count = _read_int(entry, "badPwdCount", default=0)
            bad_pwd_time  = _read_timestamp(entry, "badPasswordTime")

            # accountExpires: 0 və ya FILETIME_NEVER → heç vaxt bitmir
            account_expires_raw = _read_int(entry, "accountExpires", default=0)
            account_expires = (
                None
                if account_expires_raw in (0, _FILETIME_NEVER)
                else _filetime_to_iso(account_expires_raw)
            )
            account_never_expires = account_expires_raw in (0, _FILETIME_NEVER)

            # msDS-ResultantPSO: Fine-Grained Password Policy DN (varsa)
            msds_resultant_pso = _read_str(entry, "msDS-ResultantPSO")

            # msDS-UserPasswordExpiryTimeComputed: şifrənin bitmə vaxtı
            pwd_expiry_raw = _read_int(entry, "msDS-UserPasswordExpiryTimeComputed", default=0)
            pwd_expiry_time = (
                None
                if pwd_expiry_raw in (0, _FILETIME_NEVER)
                else _filetime_to_iso(pwd_expiry_raw)
            )

            # msDS-KeyCredentialLink: Shadow Credentials hücumu üçün
            key_credential_link = _read_attr_list(entry, "msDS-KeyCredentialLink")
            has_key_credential_link = bool(key_credential_link)

            # Logon script, home directory/drive (NTLM relay vektorları)
            script_path    = _read_str(entry, "scriptPath")
            home_directory = _read_str(entry, "homeDirectory")
            home_drive     = _read_str(entry, "homeDrive")

            users.append({
                "username":     sam_name,
                "dn":           user_dn,
                "display_name": _read_str(entry, "displayName"),
                "sid":          user_sid,
                "upn":          upn,
                "description":  _read_str(entry, "description"),
                "mail":         _read_str(entry, "mail"),
                "phone":        _read_str(entry, "telephoneNumber"),
                "department":   _read_str(entry, "department"),
                "title":        _read_str(entry, "title"),

                "disabled":           uac_parsed["disabled"],
                "locked_out":         is_locked_out,
                "must_change_pwd":    must_change_pwd,
                "smartcard_required": uac_parsed["smartcard_required"],
                "normal_account":     uac_parsed["normal_account"],

                "pwd_never_expires": uac_parsed["pwd_never_expires"],
                "pwd_not_required":  uac_parsed["pwd_not_required"],
                "pwd_cant_change":   uac_parsed["pwd_cant_change"],
                "preauth_required":  not uac_parsed["dont_req_preauth"],

                # ── Admin determination via admins_check ──────────────────────
                "is_admin":        is_admin,
                "potential_admin": "PAD" if is_potential_admin else "",
                "is_direct_admin": is_direct_admin,
                "is_nested_admin": is_nested_admin,
                "admin_rules":     admin_result["matched_rules"],

                "dcsync": is_dcsync,

                "asrep":                          is_asrep,
                "kerberoastable":                 is_kerberoastable,
                "spn":                            spn_list,
                "trusted_for_delegation":         uac_parsed["trusted_for_delegation"],
                "unconstrained_delegation":       delegation_state["unconstrained_delegation"],
                "constrained_delegation":         delegation_state["constrained_delegation"],
                "delegation_effective":           delegation_state["delegation_effective"],
                "delegation_blocked":             delegation_state["delegation_blocked_by_not_delegated"],
                "trusted_to_auth_for_delegation": uac_parsed["trusted_to_auth_for_delegation"],
                "protocol_transition_delegation": delegation_state["protocol_transition_delegation"],
                "not_delegated":                  uac_parsed["not_delegated"],

                "msds_allowedtodelegateto": delegation_targets,
                "msds_allowedtodelegateto_structurized": _structure_delegation_targets(delegation_targets),
                # msDS-SupportedEncryptionTypes — raw bitmask, human-friendly
                # ad siyahısı və hesablanmış risk skoru.
                # enc_implicit_rc4: atribut null/0 olduqda DC RC4 istifadə edir.
                "msds_supportedencryptiontypes": (
                    _read_int(entry, "msDS-SupportedEncryptionTypes", default=-1)
                    if _read_attr(entry, "msDS-SupportedEncryptionTypes") is not None
                    else None
                ),
                "msds_supportedencryptiontypesname": _msds_supported_encryption_types_names(
                    _read_int(entry, "msDS-SupportedEncryptionTypes", default=-1)
                    if _read_attr(entry, "msDS-SupportedEncryptionTypes") is not None
                    else None
                ),
                "msds_supportedencryptiontypes_name": _msds_supported_encryption_types_names(
                    _read_int(entry, "msDS-SupportedEncryptionTypes", default=-1)
                    if _read_attr(entry, "msDS-SupportedEncryptionTypes") is not None
                    else None
                ),
                "enc_risk_score": _max_enc_risk_score(
                    _read_int(entry, "msDS-SupportedEncryptionTypes", default=0)
                    if _read_attr(entry, "msDS-SupportedEncryptionTypes") is not None
                    else None
                ),
                "enc_implicit_rc4": (
                    _read_attr(entry, "msDS-SupportedEncryptionTypes") is None
                    or _read_int(entry, "msDS-SupportedEncryptionTypes", default=0) == 0
                ),

                "member_of": groups_short,

                "when_created": _read_timestamp(entry, "whenCreated"),
                "when_changed": _read_timestamp(entry, "whenChanged"),
                "last_logon":   _read_timestamp(entry, "lastLogonTimestamp"),
                "pwd_last_set": _read_timestamp(entry, "pwdLastSet"),

                "logon_count": _read_int(entry, "logonCount", 0),

                # ── Yeni atributlar ───────────────────────────────────────────
                "domain_sid":               domain_sid_val,
                "primary_group_id":         primary_group_id,
                "primary_group_sid":        (
                    f"{domain_sid_val}-{primary_group_id}"
                    if domain_sid_val and primary_group_id > 0
                    else ""
                ),
                "bad_pwd_count":            bad_pwd_count,
                "bad_pwd_time":             bad_pwd_time,
                "account_expires":          account_expires,
                "account_never_expires":    account_never_expires,
                "msds_resultant_pso":       msds_resultant_pso,
                "pwd_expiry_time":          pwd_expiry_time,
                "key_credential_link":      key_credential_link,
                "has_key_credential_link":  has_key_credential_link,
                "script_path":              script_path,
                "home_directory":           home_directory,
                "home_drive":               home_drive,
            })

        dcsync_users_count = sum(1 for u in users if u.get("dcsync"))

        result = {
            "success": True,
            "users":   users,
            "count":   len(users),
            "meta": {
                "dcsync": {
                    "enabled":            _IMPACKET_OK,
                    "resolved_sid_count": len(dcsync_sids),
                    "principal_count":    len(principal_sid_map),
                    "dcsync_users_count": dcsync_users_count,
                    "error":              dcsync_error,
                }
            },
        }

        # ── Protobuf serialization ────────────────────────────────────────────
        if proto_output_path and _PROTO_OK:
            try:
                from proto_bridge import save_payload
                save_payload(result, proto_output_path, admin_ctx_map)
                logger.info("Protobuf payload yazıldı: %s", proto_output_path)
            except Exception as exc:
                logger.warning("Protobuf serialization uğursuz oldu: %s", exc)

        return result

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except ValueError as exc:
        msg = str(exc or "")
        if "invalid server address" in msg.lower():
            return {"success": False, "error": "Invalid LDAP server address", "code": 400}
        logger.exception("get_domain_users invalid input: %s", exc)
        return {"success": False, "error": msg or "Invalid LDAP input", "code": 400}
    except Exception as exc:
        logger.exception("get_domain_users failed: %s", exc)
        return {"success": False, "error": "Internal server error", "code": 500}
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:
                pass