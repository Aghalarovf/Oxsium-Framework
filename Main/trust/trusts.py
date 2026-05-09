import re
import json
import os
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


def decode_trust_attributes(attr_val: int) -> dict:
    """
    trustAttributes bitfield-ini tam decode edir.
    MS-ADTS 2.2.16 cədvəlinə uyğun bütün flag-lər.
    """
    return {
        "NON_TRANSITIVE":              bool(attr_val & 0x00000001),
        "UPLEVEL_ONLY":                bool(attr_val & 0x00000002),
        "QUARANTINED_DOMAIN":          bool(attr_val & 0x00000004),  # SID Filtering
        "FOREST_TRANSITIVE":           bool(attr_val & 0x00000008),  # Forest trust
        "CROSS_ORGANIZATION":          bool(attr_val & 0x00000010),  # Selective Auth
        "WITHIN_FOREST":               bool(attr_val & 0x00000020),
        "TREAT_AS_EXTERNAL":           bool(attr_val & 0x00000040),
        "USES_RC4_ENCRYPTION":         bool(attr_val & 0x00000080),
        "CROSS_ORG_NO_TGT_DELEGATION": bool(attr_val & 0x00000200),
        "PIM_TRUST":                   bool(attr_val & 0x00000400),
    }


def _parse_forest_trust_info(raw) -> list:
    """
    msDS-TrustForestTrustInfo atributunu oxuyur.
    Binary blob-dur; parse edilə bilmirsə raw hex string kimi saxlanılır.
    Forest trust-larda trusted namespace/SID məlumatlarını ehtiva edir.
    """
    if raw is None:
        return []
    if isinstance(raw, (bytearray, memoryview)):
        raw = bytes(raw)
    if isinstance(raw, bytes) and raw:
        # Binary blob — hex string kimi saxla (tam parser ayrıca modul tələb edir)
        return [raw.hex()]
    if isinstance(raw, list):
        return [str(v) for v in raw if v]
    if isinstance(raw, str) and raw:
        return [raw]
    return []


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
            "description",                  # Trust açıqlaması
            "msDS-TrustForestTrustInfo",    # Forest trust namespace/SID məlumatları
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
            type_val      = safe_int(get_attr("trustType"), 0)
            attr_val      = safe_int(get_attr("trustAttributes"), 0)

            # ── Decoded flags ────────────────────────────────────────────────
            flags = decode_trust_attributes(attr_val)

            is_inbound    = direction_val in (1, 3)
            is_outbound   = direction_val in (2, 3)
            is_forest     = flags["FOREST_TRANSITIVE"] or type_val == 2
            is_transitive = not flags["NON_TRANSITIVE"] or is_forest

            # ── SID Filtering (Quarantine) ───────────────────────────────────
            # QUARANTINED_DOMAIN flag-i set-dirsə SID filtering aktiv deməkdir;
            # bu zaman cross-domain SID-lər trust üzərindən keçə bilməz
            sid_filtering_enabled = flags["QUARANTINED_DOMAIN"]

            # ── TREAT_AS_EXTERNAL ────────────────────────────────────────────
            # Forest trust olsa belə external trust kimi davranılır;
            # SID filtering daha sərt tətbiq edilir
            treat_as_external = flags["TREAT_AS_EXTERNAL"]

            # ── Selective Authentication ─────────────────────────────────────
            # CROSS_ORGANIZATION flag-i set-dirsə yalnız icazə verilmiş
            # hesablar authenticate ola bilər (forest-wide deyil)
            selective_auth = flags["CROSS_ORGANIZATION"]

            # ── Forest-wide Authentication ───────────────────────────────────
            # Selective auth yoxdursa və forest trust-dursa bütün hesablar
            # authenticate ola bilər
            forest_wide_auth = is_forest and not selective_auth

            # ── msDS-TrustForestTrustInfo ────────────────────────────────────
            fti_raw = get_attr("msDS-TrustForestTrustInfo")
            forest_trust_info = _parse_forest_trust_info(fti_raw)

            # ── risk_controls ────────────────────────────────────────────────
            risk_controls = []
            if is_inbound:
                risk_controls.append("Inbound Trust")
            if is_outbound:
                risk_controls.append("Outbound Trust")
            if is_forest:
                risk_controls.append("Forest Trust")
            if is_transitive:
                risk_controls.append("Transitive")
            if not sid_filtering_enabled:
                risk_controls.append("SID Filtering Disabled")
            if treat_as_external:
                risk_controls.append("Treat As External")
            if selective_auth:
                risk_controls.append("Selective Authentication")
            if forest_wide_auth:
                risk_controls.append("Forest-wide Authentication")
            if flags["USES_RC4_ENCRYPTION"]:
                risk_controls.append("Weak RC4 Encryption")

            trusts.append({
                "name":                 str(get_attr("cn") or ""),
                "dn":                   str(get_attr("distinguishedName") or ""),
                "flat_name":            str(get_attr("flatName") or ""),
                "partner":              str(get_attr("trustPartner") or ""),
                "description":          str(get_attr("description") or ""),
                "direction":            decode_trust_direction(direction_val),
                "direction_raw":        direction_val,
                "trust_type":           decode_trust_type(type_val),
                "trust_type_raw":       type_val,
                "attributes_raw":       attr_val,
                "attributes_decoded":   flags,              # Bütün flag-lər açıq şəkildə
                "inbound":              is_inbound,
                "outbound":             is_outbound,
                "transitive":           is_transitive,
                "forest":               is_forest,
                "sid_filtering_enabled":   sid_filtering_enabled,
                "treat_as_external":       treat_as_external,
                "selective_auth":          selective_auth,
                "forest_wide_auth":        forest_wide_auth,
                "forest_trust_info":       forest_trust_info,
                "sid":                  str(get_attr("securityIdentifier") or ""),
                "when_created":         ldap_timestamp_to_iso(get_attr("whenCreated")),
                "when_changed":         ldap_timestamp_to_iso(get_attr("whenChanged")),
                "risk_controls":        risk_controls,
            })

        conn.unbind()

        result = {"success": True, "trusts": trusts, "count": len(trusts)}

        # ── domain_trusts.json-a yaz ─────────────────────────────────────────
        output_path = os.path.join(
            str(config.DOMAIN_OBJECT_DIR), "domain_trusts.json"
        )
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2, default=str)
        except Exception as write_exc:
            result["json_export_error"] = str(write_exc)

        return result

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as exc:
        return {"success": False, "error": f"Internal server error: {exc}", "code": 500}