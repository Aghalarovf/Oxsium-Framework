import json
import os
from typing import Optional

from .constants import (
    DANGEROUS_RIGHTS,
    EXTENDED_RIGHT_NAMES,
    _AD_SENSITIVE_TEMPLATES,
    _TEMPLATE_CRITICAL_RIGHTS,
    _SD_FLAGS_FULL,
)
from .models import LdapConfig, AclFilterConfig, ObjectScope
from .backends import (
    ImpacketParser,
    Ldap3Backend,
    is_ntlm_hash,
    domain_to_dn,
    get_bind_user,
)
from .parsers import _build_sid_map, _fetch_object_sd, _parse_dacl_to_records, _build_guid_map
from .collector import AclCollector


def _write_acls_to_parquet(acl_result: dict, output_path: str) -> str:
    try:
        import pandas as pd
    except ImportError as e:
        raise ImportError(

        ) from e

    records = acl_result.get("acls")
    if records is None:
        raise ValueError("acl_result['acls'] is missing or None")

    df = pd.DataFrame(records)

    for col in df.columns:
        if df[col].dtype == object:
            sample = df[col].dropna()
            if not sample.empty and isinstance(sample.iloc[0], list):
                df[col] = df[col].apply(
                    lambda v: json.dumps(v, ensure_ascii=False) if isinstance(v, list) else v
                )

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    df.to_parquet(output_path, index=False, engine="pyarrow")
    return output_path


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

def get_domain_acls(
    ip: str,
    domain: str,
    username: str,
    password: str,
    config,
    acl_filter: Optional[AclFilterConfig] = None,
    scope: ObjectScope = ObjectScope.SECURITY_PRINCIPALS,
    custom_filter: str = "",
    resolve_guids: bool = False,
) -> dict:

    flt      = acl_filter or AclFilterConfig()
    ldap_cfg = LdapConfig.from_app_config(config)

    try:
        parser = ImpacketParser()
    except ImportError as e:
        return {"success": False, "error": str(e), "code": 500}

    auth_type = "NTLM" if is_ntlm_hash(password) else "SIMPLE"
    if auth_type == "NTLM":
        password = f"00000000000000000000000000000000:{password}"

    try:
        base_dn   = domain_to_dn(domain)
        bind_user = get_bind_user(username, domain)
    except ValueError as e:
        return {"success": False, "error": str(e), "code": 400}

    conn = None
    try:
        from ldap3.core.exceptions import (
            LDAPInvalidCredentialsResult,
            LDAPSocketOpenError,
        )
        conn = Ldap3Backend(ip, bind_user, password, auth_type, ldap_cfg)
    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Cannot connect to LDAP server", "code": 503}
    except Exception as e:
        return {"success": False, "error": str(e), "code": 500}

    try:
        _guid_map = None
        if resolve_guids:
            try:
                _guid_map = _build_guid_map(conn, base_dn, page_size=ldap_cfg.page_size)
            except Exception:
                _guid_map = None

        collector = AclCollector(
            conn, base_dn, parser,
            page_size=ldap_cfg.page_size,
            guid_map=_guid_map,
        )
        return collector.collect(flt, scope=scope, custom_filter=custom_filter)
    except Exception as e:
        return {"success": False, "error": f"Internal error: {e}", "code": 500}
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:
                pass


def collect_all_aces_to_parquet(
    ip: str,
    domain: str,
    username: str,
    password: str,
    config,
    acl_filter: Optional[AclFilterConfig] = None,
    output_dir: str = ".",
    filename: str = "domain_aces.parquet",
) -> dict:

    _no_filter = AclFilterConfig(
        exclude_inherited          = False,
        exclude_default            = False,
        interesting_only           = False,
        exclude_inherited_defaults = False,
        rights_filter              = [],
        principal_filter           = acl_filter.principal_filter    if acl_filter else "",
        target_filter              = acl_filter.target_filter        if acl_filter else "",
        target_type_filter         = acl_filter.target_type_filter   if acl_filter else [],
        scope_filter               = [],
        self_acl_only              = False,
    )

    result = get_domain_acls(
        ip=ip,
        domain=domain,
        username=username,
        password=password,
        config=config,
        acl_filter=_no_filter,
        scope=ObjectScope.ALL_WITH_ACL, 
    )

    if not result.get("success"):
        return result  

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    try:
        _write_acls_to_parquet(result, output_path)
    except ImportError as e:
        return {
            "success": False,
            "error":   str(e),
            "code":    500,
        }
    except Exception as e:
        return {
            "success": False,
            "error":   f"Error {e}",
            "code":    500,
        }

    return {
        "success":     True,
        "count":       result["count"],
        "output_file": output_path,
        "meta":        result.get("meta", {}),
    }


def check_sensitive_template_acls(
    ip: str,
    domain: str,
    username: str,
    password: str,
    config,
    templates: list[str] | None = None,
    output_dir: str = ".",
    filename: str = "domain_template_acls.json",
    resolve_guids: bool = False,
) -> dict:
    
    try:
        parser = ImpacketParser()
    except ImportError as e:
        return {"success": False, "error": str(e), "code": 500}

    auth_type = "NTLM" if is_ntlm_hash(password) else "SIMPLE"
    if auth_type == "NTLM":
        password = f"00000000000000000000000000000000:{password}"

    try:
        base_dn   = domain_to_dn(domain)
        bind_user = get_bind_user(username, domain)
    except ValueError as e:
        return {"success": False, "error": str(e), "code": 400}

    ldap_cfg = LdapConfig.from_app_config(config)
    conn = None
    try:
        from ldap3.core.exceptions import (
            LDAPInvalidCredentialsResult,
            LDAPSocketOpenError,
        )
        conn = Ldap3Backend(ip, bind_user, password, auth_type, ldap_cfg)
    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Cannot connect to LDAP server", "code": 503}
    except Exception as e:
        return {"success": False, "error": str(e), "code": 500}

    try:
        sid_map, disabled_sids = _build_sid_map(conn, base_dn,
                                                page_size=ldap_cfg.page_size)
        _guid_map = None
        if resolve_guids:
            try:
                _guid_map = _build_guid_map(conn, base_dn, page_size=ldap_cfg.page_size)
            except Exception:
                _guid_map = None

        selected: dict[str, tuple[str, str]] = {}
        if templates:
            for key in templates:
                if key in _AD_SENSITIVE_TEMPLATES:
                    selected[key] = _AD_SENSITIVE_TEMPLATES[key]

        else:
            selected = dict(_AD_SENSITIVE_TEMPLATES)

        results: list[dict] = []
        critical_count = 0

        for template_key, (dn_template, description) in selected.items():
            dn = dn_template.format(base_dn=base_dn)

            raw_sd, entry = _fetch_object_sd(conn, dn, sdflags=_SD_FLAGS_FULL)

            if raw_sd is None:
                results.append({
                    "template":          template_key,
                    "dn":                dn,
                    "description":       description,
                    "exists":            False,
                    "ace_count":         0,
                    "critical_ace_count": 0,
                    "has_critical":      False,
                    "aces":              [],
                })
                continue

            records = _parse_dacl_to_records(
                raw_sd, dn, entry, sid_map, parser,
                disabled_sids=disabled_sids,
                guid_map=_guid_map,
                skip_inherit_only=False,
            )

            critical_aces = []
            normal_aces   = []
            for rec in records:
                rights_set = set(rec.get("rights", []))
                if rights_set & _TEMPLATE_CRITICAL_RIGHTS:
                    critical_aces.append({**rec, "is_template_critical": True})
                else:
                    normal_aces.append({**rec, "is_template_critical": False})

            has_critical = bool(critical_aces)
            if has_critical:
                critical_count += 1

            results.append({
                "template":           template_key,
                "dn":                 dn,
                "description":        description,
                "exists":             True,
                "ace_count":          len(records),
                "critical_ace_count": len(critical_aces),
                "has_critical":       has_critical,
                "aces":               critical_aces + normal_aces,
            })

        output = {
            "success":        True,
            "checked":        len(selected),
            "found":          sum(1 for r in results if r["exists"]),
            "critical_count": critical_count,
            "results":        results,
        }

        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        try:
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(output, fh, ensure_ascii=False, indent=2, default=str)
            output["output_file"] = output_path
        except Exception as write_exc:
            output["output_file"]        = ""
            output["json_export_error"]  = str(write_exc)

        return output

    except Exception as e:
        return {"success": False, "error": f"Internal error: {e}", "code": 500}
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:
                pass


def deep_scan_domain_acls(
    ip: str,
    domain: str,
    username: str,
    password: str,
    config,
    acl_filter: Optional[AclFilterConfig] = None,
    output_dir: str = ".",
    filename: str = "domain_deep_scan.parquet",
) -> dict:
    _no_filter = AclFilterConfig(
        exclude_inherited          = False,
        exclude_default            = False,
        interesting_only           = False,
        exclude_inherited_defaults = False,
        rights_filter              = [],
        principal_filter           = acl_filter.principal_filter   if acl_filter else "",
        target_filter              = acl_filter.target_filter       if acl_filter else "",
        target_type_filter         = acl_filter.target_type_filter  if acl_filter else [],
        scope_filter               = [],
        self_acl_only              = False,
    )

    result = get_domain_acls(
        ip=ip,
        domain=domain,
        username=username,
        password=password,
        config=config,
        acl_filter=_no_filter,
        scope=ObjectScope.DEEP_SCAN,
    )

    if not result.get("success"):
        return result

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    try:
        _write_acls_to_parquet(result, output_path)
    except ImportError as e:
        return {"success": False, "error": str(e), "code": 500}
    except Exception as e:
        return {"success": False, "error": f"Parquet yazma xətası: {e}", "code": 500}

    return {
        "success":     True,
        "count":       result["count"],
        "output_file": output_path,
        "meta":        result.get("meta", {}),
    }


def dangerous_ace(
    acl_result: dict,
    output_dir: str = ".",
    dangerous_filename: str  = "domain_dangerous_ace.json",
    extended_filename:  str  = "domain_extended_rights.json",
) -> dict:
    
    if not acl_result.get("success"):
        return {
            "dangerous_count": 0,
            "extended_count":  0,
            "dangerous_file":  "",
            "extended_file":   "",
            "error":           acl_result.get("error", "ACL result is not successful"),
        }

    dangerous_records: list[dict] = []
    extended_records:  list[dict] = []

    for record in acl_result.get("acls", []):
        rights = set(record.get("rights", []))
        dangerous_matched = rights & DANGEROUS_RIGHTS
        if not dangerous_matched:
            continue

        is_extended = bool(dangerous_matched & EXTENDED_RIGHT_NAMES)

        entry = {
            "target_name":           record.get("target_name"),
            "target_dn":             record.get("target_dn"),
            "target_sid":            record.get("target_sid"),
            "target_type":           record.get("target_type"),
            "principal":             record.get("principal"),
            "principal_sid":         record.get("principal_sid"),
            "principal_scope":       record.get("principal_scope"),
            "principal_is_disabled": record.get("principal_is_disabled", False),
            "rights":                sorted(dangerous_matched),
            "all_rights":            record.get("rights", []),
            "is_inherited":          record.get("is_inherited"),
            "modified":              record.get("modified"),
        }

        if is_extended:
            extended_records.append(entry)
        else:
            dangerous_records.append(entry)

    os.makedirs(output_dir, exist_ok=True)

    dangerous_path = os.path.join(output_dir, dangerous_filename)
    extended_path  = os.path.join(output_dir, extended_filename)

    with open(dangerous_path, "w", encoding="utf-8") as fh:
        json.dump(dangerous_records, fh, ensure_ascii=False, indent=2)

    with open(extended_path, "w", encoding="utf-8") as fh:
        json.dump(extended_records, fh, ensure_ascii=False, indent=2)

    return {
        "dangerous_count": len(dangerous_records),
        "extended_count":  len(extended_records),
        "dangerous_file":  dangerous_path,
        "extended_file":   extended_path,
    }