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
    return f"{username}@{domain}"


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
    return {
        "NON_TRANSITIVE":                          bool(attr_val & 0x00000001),
        "UPLEVEL_ONLY":                             bool(attr_val & 0x00000002),
        "QUARANTINED_DOMAIN":                       bool(attr_val & 0x00000004), 
        "FOREST_TRANSITIVE":                        bool(attr_val & 0x00000008), 
        "CROSS_ORGANIZATION":                       bool(attr_val & 0x00000010), 
        "WITHIN_FOREST":                            bool(attr_val & 0x00000020),
        "TREAT_AS_EXTERNAL":                        bool(attr_val & 0x00000040),
        "USES_RC4_ENCRYPTION":                      bool(attr_val & 0x00000080),
        "CROSS_ORG_NO_TGT_DELEGATION":              bool(attr_val & 0x00000200),
        "PIM_TRUST":                                bool(attr_val & 0x00000400),
        "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION": bool(attr_val & 0x00000800),
    }


def decode_supported_encryption_types(value) -> dict:
    raw = safe_int(value, None) if value is not None else None
    if normalize_value(value) is None:
        return {
            "raw": None,
            "configured": False,
            "DES_CBC_CRC": False,
            "DES_CBC_MD5": False,
            "RC4_HMAC": False,
            "AES128_CTS_HMAC_SHA1_96": False,
            "AES256_CTS_HMAC_SHA1_96": False,
            "only_weak_des": False,
            "rc4_allowed": False,
            "aes_allowed": False,
        }
    des_crc = bool(raw & 0x00000001)
    des_md5 = bool(raw & 0x00000002)
    rc4     = bool(raw & 0x00000004)
    aes128  = bool(raw & 0x00000008)
    aes256  = bool(raw & 0x00000010)
    return {
        "raw":                       raw,
        "configured":                True,
        "DES_CBC_CRC":               des_crc,
        "DES_CBC_MD5":               des_md5,
        "RC4_HMAC":                  rc4,
        "AES128_CTS_HMAC_SHA1_96":   aes128,
        "AES256_CTS_HMAC_SHA1_96":   aes256,
        "only_weak_des":             (des_crc or des_md5) and not (rc4 or aes128 or aes256),
        "rc4_allowed":               rc4,
        "aes_allowed":               aes128 or aes256,
    }


def assess_security_posture(
    *,
    sid_filtering_enabled: bool,
    within_forest: bool,
    tgt_delegation_enabled: bool,
    selective_auth: bool,
    is_forest: bool,
) -> dict:
    risks: list[dict] = []

    if not sid_filtering_enabled:
        risks.append({
            "level": "HIGH",
            "text": (
                "SID Filtering DISABLED → vulnerable to ExtraSids / SID-History "
                "Golden Ticket forgery; compromise of krbtgt or the trust key "
                "enables cross-domain privilege escalation"
            ),
        })

    if within_forest:
        risks.append({
            "level": "HIGH",
            "text": (
                "Parent-Child trust (WITHIN_FOREST) — TGT delegation is unrestricted "
                "by design → vulnerable to Coercion (PrinterBug/PetitPotam) combined "
                "with Unconstrained Delegation TGT capture"
            ),
        })

    elif tgt_delegation_enabled:
        risks.append({
            "level": "HIGH",
            "text": (
                "TGT Delegation ENABLED on an external/forest trust → vulnerable to "
                "Coercion + Unconstrained Delegation TGT capture across the trust boundary"
            ),
        })
    else:
        risks.append({
            "level": "INFO",
            "text": (
                "TGT Delegation is restricted → Coercion + Unconstrained Delegation "
                "path is mitigated; however, if ADCS exists on the other side, "
                "NTLM Relay → ESC8 may still apply"
            ),
        })

    if not selective_auth and not within_forest:
        risks.append({
            "level": "MEDIUM",
            "text": (
                "Selective Authentication DISABLED → principals from the trusted domain "
                "can authenticate to any resource without an explicit allow-list, "
                "widening the attack surface"
            ),
        })

    if not risks or all(r["level"] in ("INFO", "OK") for r in risks):
        risks.append({
            "level": "OK",
            "text": "No high-risk indicators detected from trust attributes alone",
        })

    dangerous = any(r["level"] == "HIGH" for r in risks)
    return {"risks": risks, "dangerous": dangerous}


def format_object_guid(value) -> str:
    normalized = normalize_value(value)
    if normalized is None:
        return ""
    if isinstance(normalized, (bytearray, memoryview)):
        normalized = bytes(normalized)
    if isinstance(normalized, bytes):
        if len(normalized) != 16:
            return normalized.hex()
        import uuid
        return str(uuid.UUID(bytes_le=normalized))
    return str(normalized)


def _parse_forest_trust_info(raw) -> list:
    if raw is None:
        return []
    if isinstance(raw, (bytearray, memoryview)):
        raw = bytes(raw)
    if isinstance(raw, bytes) and raw:
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
            "description",                 
            "msDS-TrustForestTrustInfo",  
            "msDS-SupportedEncryptionTypes", 
            "objectGUID",                 
            "uSNCreated", "uSNChanged",   
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

            flags = decode_trust_attributes(attr_val)

            is_inbound    = direction_val in (1, 3)
            is_outbound   = direction_val in (2, 3)
            is_forest     = flags["FOREST_TRANSITIVE"] or type_val == 2
            is_transitive = not flags["NON_TRANSITIVE"] or is_forest
            sid_filtering_enabled = flags["QUARANTINED_DOMAIN"]
            treat_as_external = flags["TREAT_AS_EXTERNAL"]
            selective_auth = flags["CROSS_ORGANIZATION"]
            forest_wide_auth = is_forest and not selective_auth
            fti_raw = get_attr("msDS-TrustForestTrustInfo")
            forest_trust_info = _parse_forest_trust_info(fti_raw)
            enc_types = decode_supported_encryption_types(get_attr("msDS-SupportedEncryptionTypes"))
            object_guid = format_object_guid(get_attr("objectGUID"))
            usn_created = safe_int(get_attr("uSNCreated"), None)
            usn_changed = safe_int(get_attr("uSNChanged"), None)

            tgt_delegation_enabled = (
                flags["CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"]
                or not flags["CROSS_ORG_NO_TGT_DELEGATION"]
            )

            posture = assess_security_posture(
                sid_filtering_enabled=sid_filtering_enabled,
                within_forest=flags["WITHIN_FOREST"],
                tgt_delegation_enabled=tgt_delegation_enabled,
                selective_auth=selective_auth,
                is_forest=is_forest,
            )

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
            if flags["CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"]:
                risk_controls.append("Cross-Org TGT Delegation Enabled")
            if enc_types["only_weak_des"]:
                risk_controls.append("Only Weak DES Encryption Supported")
            elif enc_types["configured"] and enc_types["rc4_allowed"] and not enc_types["aes_allowed"]:
                risk_controls.append("RC4-Only Encryption Supported")
            elif not enc_types["configured"]:
                risk_controls.append("Encryption Types Not Explicitly Configured")

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
                "attributes_decoded":   flags,              
                "inbound":              is_inbound,
                "outbound":             is_outbound,
                "transitive":           is_transitive,
                "forest":               is_forest,
                "sid_filtering_enabled":   sid_filtering_enabled,
                "treat_as_external":       treat_as_external,
                "selective_auth":          selective_auth,
                "forest_wide_auth":        forest_wide_auth,
                "forest_trust_info":       forest_trust_info,
                "supported_encryption_types": enc_types,
                "object_guid":           object_guid,
                "usn_created":           usn_created,
                "usn_changed":           usn_changed,
                "sid":                  str(get_attr("securityIdentifier") or ""),
                "when_created":         ldap_timestamp_to_iso(get_attr("whenCreated")),
                "when_changed":         ldap_timestamp_to_iso(get_attr("whenChanged")),
                "risk_controls":        risk_controls,
                "security_posture":     posture["risks"],
                "dangerous":            posture["dangerous"],
            })

        conn.unbind()

        result = {"success": True, "trusts": trusts, "count": len(trusts)}

        output_path = os.path.join(
            str(config.DOMAIN_OBJECT_DIR), "domain_trusts.jsonl"
        )
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                dangerous_count = sum(1 for t in result["trusts"] if t.get("dangerous"))
                meta = {
                    "success":         result["success"],
                    "count":           result["count"],
                    "dangerous_count": dangerous_count,
                }
                f.write(json.dumps(meta, ensure_ascii=False, default=str) + "\n")
                for trust in result["trusts"]:
                    f.write(json.dumps(trust, ensure_ascii=False, default=str) + "\n")
        except Exception as write_exc:
            result["json_export_error"] = str(write_exc)

        return result

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as exc:
        return {"success": False, "error": f"Internal server error: {exc}", "code": 500}