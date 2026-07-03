import json
import os
import sys
import threading
import traceback
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Config import etmə
_PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from connect.config import Config
except ImportError:
    # Əgər connect config-inə çata bilmə, dəfault istifadə etməli
    class Config:
        DOMAIN_OBJECT_DIR           = Path(__file__).parent.parent.parent / "Main" / "Domain Object"
        DOMAIN_ACES_JSON            = DOMAIN_OBJECT_DIR / "domain_aces.jsonl"
        DOMAIN_DEEP_SCAN_JSON       = DOMAIN_OBJECT_DIR / "domain_deep_scan.jsonl"
        DOMAIN_TEMPLATE_ACLS_JSON   = DOMAIN_OBJECT_DIR / "domain_template_acls.jsonl"
        DOMAIN_EXTENDED_RIGHTS_JSON = DOMAIN_OBJECT_DIR / "domain_extended_rights.jsonl"
        DOMAIN_DANGEROUS_ACE_JSON   = DOMAIN_OBJECT_DIR / "domain_dangerous_ace.jsonl"

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
    make_conn_factory,
)
from .parsers import _build_sid_map, _fetch_object_sd, _parse_dacl_to_records, _build_guid_map
from .collector import AclCollector



def _write_jsonl(records: list[dict], output_path: str) -> str:
    """Hər record-u öz sətrində JSON obyekti kimi yazır (JSON Lines / .jsonl)."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False, default=str))
            fh.write("\n")
    return output_path


def _write_acls_to_jsonl(acl_result: dict, output_path: str) -> str:
    records = acl_result.get("acls")
    if records is None:
        raise ValueError("acl_result['acls'] is missing or None")
    return _write_jsonl(records, output_path)


def _jsonl_name(config_attr: str, default_name: str) -> str:
    """Config-də müvafiq atribut varsa onun fayl adını qaytarır;
    yoxdursa default_name qaytarır. Bütün yollar artıq .jsonl-dir."""
    _path = getattr(Config, config_attr, None)
    if _path is None:
        return default_name
    return _path.name


def _capture_error(stage: str, context: str, exc: BaseException) -> dict:
    """SRP: istənilən yerdə (api.py səviyyəsində) tutulan xətanı collector.py-
    dəki `_record_error` ilə EYNİ formata salır ki, bütün xəta mənbələri
    (LDAP bağlantısı, guid_map qurulması, fayl I/O, gözlənilməz istisnalar)
    domain_aces.jsonl-in son metadata sətrində vahid formatda görünsün."""
    return {
        "stage":         stage,
        "context":       context,
        "error_type":    type(exc).__name__,
        "error_message": str(exc),
        "traceback":     traceback.format_exc(limit=20),
    }


def _build_metadata_record(result: dict, extra_errors: list[dict] | None = None) -> dict:
    """domain_aces.jsonl-in son sətri kimi yazılacaq metadata obyektini qurur.
    `result["meta"]["errors"]` (collector daxilində toplanmış bütün xətalar)
    + `extra_errors` (api.py səviyyəsində, collector çağırışından kənarda
    tutulan xətalar — məs. fayl açıla bilməməsi, guid_map qurula bilməməsi,
    tamamilə gözlənilməz istisnalar) burada birləşdirilir ki, HANSI mərhələdə
    baş versə belə, hər xəta bu yekun sətirdə tam (stage/context/error_type/
    error_message/traceback) əks olunsun."""
    meta   = dict(result.get("meta") or {})
    errors = list(meta.get("errors") or [])
    if extra_errors:
        errors.extend(extra_errors)

    return {
        "_metadata":        True,
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "success":          bool(result.get("success")) and not extra_errors,
        "top_level_error":  None if result.get("success") else result.get("error"),
        "objects_with_sd":  meta.get("objects_with_sd", 0),
        "aces_seen":        meta.get("aces_seen", 0),
        "aces_exported":    meta.get("aces_exported", 0),
        "aces_filtered":    meta.get("aces_filtered", 0),
        "error_count":      len(errors),
        "errors":           errors,
    }


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
    scope: ObjectScope = ObjectScope.DEEP_SCAN,
    custom_filter: str = "",
    resolve_guids: bool = False,
    on_records: Optional[Callable[[list[dict]], None]] = None,
    sequential: bool = False,
    deep_scan_minimal: bool = False,
    io_workers: Optional[int] = None,
) -> dict:

    flt      = acl_filter or AclFilterConfig()
    ldap_cfg = LdapConfig.from_app_config(config)

    # DÜZƏLİŞ: bu funksiyanın hər erkən çıxış nöqtəsi (parser, domain/bind
    # parse, LDAP bind) indi `meta.errors` daxilində eyni formatda (stage/
    # context/error_type/error_message/traceback) tam xəta təfərrüatı
    # qaytarır. Əvvəllər yalnız qısa `error` sətri var idi — indi çağıran
    # (məs. collect_all_aces_to_json) bunu birbaşa domain_aces.jsonl-in
    # metadata sətrinə əlavə edə bilir.
    try:
        parser = ImpacketParser()
    except ImportError as e:
        err = _capture_error("init_parser", "ImpacketParser", e)
        return {"success": False, "error": str(e), "code": 500,
                "meta": {"error_count": 1, "errors": [err]}}

    auth_type = "NTLM" if is_ntlm_hash(password) else "SIMPLE"
    if auth_type == "NTLM":
        password = f"00000000000000000000000000000000:{password}"

    try:
        base_dn   = domain_to_dn(domain)
        bind_user = get_bind_user(username, domain)
    except ValueError as e:
        err = _capture_error("parse_domain", domain, e)
        return {"success": False, "error": str(e), "code": 400,
                "meta": {"error_count": 1, "errors": [err]}}

    conn = None
    try:
        from ldap3.core.exceptions import (
            LDAPInvalidCredentialsResult,
            LDAPSocketOpenError,
        )
        conn = Ldap3Backend(ip, bind_user, password, auth_type, ldap_cfg)
    except LDAPInvalidCredentialsResult as e:
        err = _capture_error("ldap_bind", f"{ip} user={bind_user}", e)
        return {"success": False, "error": "Authentication failed", "code": 401,
                "meta": {"error_count": 1, "errors": [err]}}
    except LDAPSocketOpenError as e:
        err = _capture_error("ldap_connect", ip, e)
        return {"success": False, "error": "Cannot connect to LDAP server", "code": 503,
                "meta": {"error_count": 1, "errors": [err]}}
    except Exception as e:
        err = _capture_error("ldap_bind", f"{ip} user={bind_user}", e)
        return {"success": False, "error": str(e), "code": 500,
                "meta": {"error_count": 1, "errors": [err]}}

    # Collector yaradılmazdan ƏVVƏL (məs. guid_map qurularkən) baş verə
    # biləcək xətalar da bu siyahıya yığılır və collector-a ötürülür ki,
    # nəticədəki `meta.errors`-da itməsin — əvvəllər bu xəta sadəcə udulub
    # `_guid_map = None` edilirdi, heç yerdə görünmürdü.
    pre_errors: list[dict] = []
    try:
        _guid_map = None
        if resolve_guids:
            try:
                _guid_map = _build_guid_map(conn, base_dn, page_size=ldap_cfg.page_size)
            except Exception as e:
                _guid_map = None
                pre_errors.append(_capture_error("build_guid_map", base_dn, e))

        # 4 NC-nin paralel skan olunması üçün hər thread özünə ayrıca
        # bağlantı aça bilsin deyə (ldap3 Connection thread-safe deyil).
        # `sequential=True` olduqda conn_factory ötürülmür — bütün bazalar
        # TƏK bağlantı üzərində ardıcıl skan olunur (VPN-də daha stabil,
        # amma daha yavaş; users/computers modulunun yanaşmasına ən yaxın).
        conn_factory = None if sequential else make_conn_factory(
            ip, bind_user, password, auth_type, ldap_cfg,
        )

        collector = AclCollector(
            conn, base_dn, parser,
            page_size=ldap_cfg.page_size,
            guid_map=_guid_map,
            conn_factory=conn_factory,
            initial_errors=pre_errors,
            io_workers=io_workers if io_workers is not None else 2,
            deep_scan_minimal=deep_scan_minimal,
        )
        # `collector.collect(...)` artıq öz daxilində HƏR bir xətanı tutur
        # və heç vaxt istisna atmır (bax: collector.py `collect()`), ona görə
        # aşağıdakı `except Exception` yalnız tamamilə gözlənilməz (collector
        # instansiyası qurularkən və s.) hallar üçün son mühafizə xəttidir.
        return collector.collect(
            flt, scope=scope, custom_filter=custom_filter, on_records=on_records,
        )
    except Exception as e:
        err = _capture_error("get_domain_acls_internal", base_dn, e)
        errors = pre_errors + [err]
        return {"success": False, "error": f"Internal error: {e}", "code": 500,
                "meta": {"error_count": len(errors), "errors": errors}}
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:
                pass


def collect_all_aces_to_json(
    ip: str,
    domain: str,
    username: str,
    password: str,
    config,
    acl_filter: Optional[AclFilterConfig] = None,
    output_dir: Optional[str] = None,
    filename: Optional[str] = None,
    sequential: bool = False,
    deep_scan_minimal: bool = False,
    io_workers: Optional[int] = None,
) -> dict:
    # Config-dən default-ləri oxu
    if output_dir is None:
        output_dir = str(Config.DOMAIN_OBJECT_DIR)
    if filename is None:
        filename = _jsonl_name("DOMAIN_ACES_JSON", "domain_aces.jsonl")


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

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    # DƏYİŞİKLİK: əvvəllər `get_domain_acls` bütün nəticəni yaddaşda
    # topladıqdan SONRA `_write_acls_to_jsonl` bir dəfəyə bütöv faylı
    # yazırdı. İndi hər batch (bax: collector._PARSE_BATCH_SIZE) hazır
    # olan kimi, `on_records` callback-i ilə birbaşa fayla axın-axın
    # yazılır — nəticə axırda gözlənilmir, mərhələ-mərhələ diskə düşür.
    # (`_no_filter` istifadə olunduğu üçün bu funksiyada streaming zamanı
    # heç bir record post-filter-də itmir — bütün filtrlər deaktivdir.)
    write_lock = threading.Lock()
    try:
        out_fh = open(output_path, "w", encoding="utf-8")
    except Exception as e:
        # Fayl heç açıla bilməyibsə, içinə metadata da yaza bilmərik —
        # bu, YEGANƏ hal ki, xəta yalnız qaytarılan dict-də qalır.
        err = _capture_error("open_output_file", output_path, e)
        return {"success": False, "error": f"Fayl açıla bilmədi: {e}", "code": 500,
                "meta": {"error_count": 1, "errors": [err]}}

    # DƏYİŞİKLİK: streaming yazısı zamanı baş verə biləcək xətalar (məs.
    # JSON-a çevrilə bilməyən bir sahə, disk dolması, I/O xətası) əvvəllər
    # `on_records` çağırışından collector-a sızıb bütün müvafiq NC-nin
    # taranmasını dayandırırdı, amma HEÇ yerdə görünmürdü. İndi burada da
    # tutulur, `stream_errors`-a yazılır və son metadata sətrinə əlavə edilir.
    stream_errors: list[dict] = []

    def _stream_write(records: list[dict]) -> None:
        try:
            with write_lock:
                for record in records:
                    out_fh.write(json.dumps(record, ensure_ascii=False, default=str))
                    out_fh.write("\n")
                out_fh.flush()
        except Exception as e:
            stream_errors.append(_capture_error(
                "stream_write", f"batch_size={len(records)}", e,
            ))

    # DÜZƏLİŞ: `get_domain_acls(...)` özü artıq (collector.collect() daxilində)
    # istisna atmır, amma burada YENƏ DƏ try/except qoyulur — bu, "istənilən
    # hansı xəta olur olsun" tələbinə cavab verən son mühafizə xəttidir: hətta
    # tamamilə gözlənilməyən (məs. kod dəyişikliyindən sonra yeni bir bug) bir
    # istisna belə bura sızsa, proses çökmür, sadəcə metadata sətrinə yazılır.
    result: dict = {}
    top_level_error: dict | None = None
    try:
        result = get_domain_acls(
            ip=ip,
            domain=domain,
            username=username,
            password=password,
            config=config,
            acl_filter=_no_filter,
            scope=ObjectScope.DEEP_SCAN,
            on_records=_stream_write,
            sequential=sequential,
            deep_scan_minimal=deep_scan_minimal,
            io_workers=io_workers,
        )
    except Exception as e:
        top_level_error = _capture_error("collect_all_aces_to_json", domain, e)
        result = {"success": False, "error": str(e), "code": 500}
    finally:
        # Metadata sətri fayl bağlanmazdan ƏVVƏL, .jsonl-in DAXİLİNDƏ son
        # sətir kimi yazılır — istənilən hansı xəta olursa olsun (collector
        # daxili, api.py səviyyəsi, streaming yazısı, tamamilə gözlənilməz),
        # hamısı burada bir yerə toplanıb faylın özündə görünür. Bu, "success"
        # olsa belə həmişə yazılır ki, qismən uğur/qismən xəta halları da
        # (məs. 4 NC-dən biri uğursuz olsa) izlənilə bilsin.
        extra_errors = stream_errors + ([top_level_error] if top_level_error else [])
        try:
            meta_record = _build_metadata_record(result, extra_errors=extra_errors)
            with write_lock:
                out_fh.write(json.dumps(meta_record, ensure_ascii=False, default=str))
                out_fh.write("\n")
                out_fh.flush()
        except Exception:
            # Metadata yazısının özü belə uğursuz olsa (məs. disk dolub),
            # faylın bağlanmasına mane olmamalıdır — məlumat itkisi minimal
            # saxlanılır, yenə də çağırana xəta strukturu qaytarılır.
            pass
        out_fh.close()

    if top_level_error:
        return {
            "success":     False,
            "error":       top_level_error["error_message"],
            "error_type":  top_level_error["error_type"],
            "code":        500,
            "output_file": output_path,
            "meta": {
                "error_count": len(extra_errors),
                "errors":      extra_errors,
            },
        }

    if not result.get("success"):
        result["output_file"] = output_path
        meta = dict(result.get("meta") or {})
        if stream_errors:
            meta["errors"] = list(meta.get("errors") or []) + stream_errors
            meta["error_count"] = len(meta["errors"])
        result["meta"] = meta
        return result

    meta = dict(result.get("meta", {}))
    if stream_errors:
        meta["errors"] = list(meta.get("errors") or []) + stream_errors
        meta["error_count"] = len(meta["errors"])

    return {
        "success":     True,
        "count":       result["count"],
        "output_file": output_path,
        "meta":        meta,
    }


def check_sensitive_template_acls(
    ip: str,
    domain: str,
    username: str,
    password: str,
    config,
    templates: list[str] | None = None,
    output_dir: Optional[str] = None,
    filename: Optional[str] = None,
    resolve_guids: bool = False,
) -> dict:
    # Config-dən default-ləri oxu
    if output_dir is None:
        output_dir = str(Config.DOMAIN_OBJECT_DIR)
    if filename is None:
        filename = _jsonl_name("DOMAIN_TEMPLATE_ACLS_JSON", "domain_template_acls.jsonl")

    
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

        # Hər ACE-ni template metadata ilə birlikdə ayrı sətir kimi yaz (JSONL)
        flat_records: list[dict] = []
        for r in results:
            for ace in r.get("aces", []):
                flat_records.append({
                    "template":           r["template"],
                    "template_dn":        r["dn"],
                    "template_exists":    r["exists"],
                    "is_template_critical": ace.get("is_template_critical", False),
                    **{k: v for k, v in ace.items() if k != "is_template_critical"},
                })

        output = {
            "success":        True,
            "checked":        len(selected),
            "found":          sum(1 for r in results if r["exists"]),
            "critical_count": critical_count,
            "ace_count":      len(flat_records),
        }

        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        try:
            _write_jsonl(flat_records, output_path)
            output["output_file"] = output_path
        except Exception as write_exc:
            output["output_file"]       = ""
            output["json_export_error"] = str(write_exc)

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
    output_dir: Optional[str] = None,
    filename: Optional[str] = None,
) -> dict:
    # Config-dən default-ləri oxu
    if output_dir is None:
        output_dir = str(Config.DOMAIN_OBJECT_DIR)
    if filename is None:
        filename = _jsonl_name("DOMAIN_DEEP_SCAN_JSON", "domain_deep_scan.jsonl")

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
        _write_acls_to_jsonl(result, output_path)
    except Exception as e:
        return {"success": False, "error": f"JSONL yazma xətası: {e}", "code": 500}

    return {
        "success":     True,
        "count":       result["count"],
        "output_file": output_path,
        "meta":        result.get("meta", {}),
    }


def dangerous_ace(
    acl_result: dict,
    output_dir: Optional[str] = None,
    dangerous_filename: Optional[str] = None,
    extended_filename: Optional[str] = None,
) -> dict:
    # Config-dən default-ləri oxu
    if output_dir is None:
        output_dir = str(Config.DOMAIN_OBJECT_DIR)
    if dangerous_filename is None:
        dangerous_filename = _jsonl_name("DOMAIN_DANGEROUS_ACE_JSON", "domain_dangerous_ace.jsonl")
    if extended_filename is None:
        extended_filename = _jsonl_name("DOMAIN_EXTENDED_RIGHTS_JSON", "domain_extended_rights.jsonl")

    
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

    _write_jsonl(dangerous_records, dangerous_path)
    _write_jsonl(extended_records, extended_path)

    return {
        "dangerous_count": len(dangerous_records),
        "extended_count":  len(extended_records),
        "dangerous_file":  dangerous_path,
        "extended_file":   extended_path,
    }