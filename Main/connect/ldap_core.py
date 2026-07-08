import logging
import re

from ldap3 import Server, Connection, ALL, BASE, SUBTREE
from ldap3.core.exceptions import LDAPBindError, LDAPInvalidCredentialsResult

from connect.config import Config
from connect.utils import (
    domain_to_dn, get_upn_bind_user, is_ntlm_hash,
    build_ldap_bind_users,
    ldap_escape_filter, _is_ipv4_text, _pick_dc_fqdn_from_entries,
)
from connect.network import check_port

logger = logging.getLogger("ad_api")


def _normalize_ldap_target(value: str) -> str:
    target = str(value or "").strip()
    if not target:
        return ""
    target = re.sub(r"^(?:ldaps?|https?)://", "", target, flags=re.IGNORECASE)
    target = target.split("/", 1)[0].strip()
    target = target.split("\\", 1)[0].strip()

    if target.count(":") == 1 and ("." in target):
        host, port = target.rsplit(":", 1)
        if port.isdigit():
            target = host.strip()

    return target

SEARCH_QUERIES: dict[str, str] = {
    "groups":    "(objectClass=group)",
    "gpos":      "(objectClass=groupPolicyContainer)",
    "ous":       "(objectClass=organizationalUnit)",
    "trusts":    "(objectClass=trustedDomain)",
    "computers": "(objectClass=computer)",
    "users":     "(&(objectClass=user)(objectCategory=person))",
}


def _build_ldap_targets(req: dict) -> list[str]:
    protocol  = str(req.get("protocol", "")).lower()
    ip        = str(req.get("ip", "")).strip()
    domain    = str(req.get("domain", "")).strip()
    ldap_host = str(req.get("ldap_host", "")).strip()
    dc        = str(req.get("dc", "")).strip()

    targets: list[str] = []

    for candidate in (ldap_host, dc):
        normalized = _normalize_ldap_target(candidate)
        if normalized:
            targets.append(normalized)

    if protocol in ("ldap", "ldaps") and ip:
        targets.append(_normalize_ldap_target(ip))

    if domain:
        targets.append(_normalize_ldap_target(domain))

    if ip:
        targets.append(_normalize_ldap_target(ip))

    deduped: list[str] = []
    for t in targets:
        if not t:
            continue
        if t not in deduped:
            deduped.append(t)
    return deduped


def _is_retryable_ldap_error(message: str) -> bool:
    msg = (message or "").lower()
    retry_markers = (
        "socket",
        "connection",
        "timeout",
        "timed out",
        "can't contact",
        "server unavailable",
        "could not connect to the server",
        "cannot connect to ldap server",
        "unable to connect",
        "refused",
        "unreachable",
        "invalid server address",
    )
    return any(m in msg for m in retry_markers)


def _is_ldap_bind_failure(message: str) -> bool:
    msg = (message or "").lower()
    return any(marker in msg for marker in (
        "invalidcredentials",
        "automatic bind not successful",
        "invalid credentials",
        "ldapbinderror",
    ))


def _collect_ldap_environment_for_target(
    ldap_target: str,
    username: str,
    password: str,
    domain: str,
    use_ssl: bool = False,
) -> dict:
    last_error = None
    for bind_user in build_ldap_bind_users(username, domain):
        try:
            env = _collect_ldap_environment(
                ldap_target,
                username,
                password,
                domain,
                use_ssl=use_ssl,
                bind_user=bind_user,
            )
            env["ldap_target"] = ldap_target
            env["bind_user"] = bind_user
            return {"success": True, "data": env}
        except (LDAPInvalidCredentialsResult, LDAPBindError) as exc:
            last_error = exc
            if _is_ldap_bind_failure(str(exc)):
                continue
            break
        except Exception as exc:
            last_error = exc
            if _is_retryable_ldap_error(str(exc)):
                return {"success": False, "error": str(exc), "code": 503}
            break

    if last_error and _is_ldap_bind_failure(str(last_error)):
        return {
            "success": False,
            "error": (
                f"LDAP bind failed for {username}; tried UPN, NETBIOS, and raw username formats. "
                f"Verify the AD logon name (for example user@domain or DOMAIN\\user)."
            ),
            "code": 401,
        }

    return {"success": False, "error": str(last_error) if last_error else "LDAP env probe failed"}


def _run_enumeration_with_target_fallback(req: dict, enum_fn):
    last_result = None
    targets = _build_ldap_targets(req)

    for target in targets:
        result = enum_fn(target, req["domain"], req["username"], req["password"], Config)
        if result.get("success"):
            if target != req.get("ip"):
                result.setdefault("meta", {})
                result["meta"]["ldap_target"] = target
            return result

        last_result = result
        if int(result.get("code") or 0) == 503:
            continue
        if not _is_retryable_ldap_error(result.get("error", "")):
            break

    return last_result or {"success": False, "error": "Enumeration failed", "code": 500}


def _paged_count(conn: Connection, base_dn: str, ldap_filter: str) -> int:
    count = 0
    cookie = None
    while True:
        conn.search(
            base_dn,
            ldap_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
            paged_size=Config.LDAP_PAGE_SIZE,
            paged_cookie=cookie,
        )
        count += len(conn.entries)
        cookie = (
            conn.result
            .get("controls", {})
            .get("1.2.840.113556.1.4.319", {})
            .get("value", {})
            .get("cookie")
        )
        if not cookie:
            break
    return count


def _collect_ldap_environment(
    ldap_target: str,
    username: str,
    password: str,
    domain: str,
    use_ssl: bool = False,
    bind_user: str | None = None,
) -> dict:
    base_dn   = domain_to_dn(domain)
    bind_user = bind_user or get_upn_bind_user(username, domain)

    auth_type    = "SIMPLE"
    bind_secret  = password
    if is_ntlm_hash(password):
        bind_secret = f"00000000000000000000000000000000:{password}"
        auth_type   = "NTLM"

    server = Server(
        ldap_target,
        port=636 if use_ssl else 389,
        use_ssl=use_ssl,
        get_info=ALL,
        connect_timeout=Config.LDAP_CONNECT_TIMEOUT,
    )
    conn = Connection(
        server,
        user=bind_user,
        password=bind_secret,
        authentication=auth_type,
        auto_bind=True,
        receive_timeout=Config.LDAP_RECEIVE_TIMEOUT,
    )

    counts: dict[str, int] = {}
    for key, query in SEARCH_QUERIES.items():
        counts[key] = _paged_count(conn, base_dn, query)

    dc_name          = ldap_target
    matched_dc_obj   = None
    domain_level_raw = "0"
    kerberos_enabled = True
    smb_enabled      = None

    conn.search(
        search_base="",
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=["dnsHostName", "msDS-Behavior-Version", "supportedSASLMechanisms"],
    )
    if conn.entries:
        root = conn.entries[0]
        try:
            dns_host = getattr(root, "dnsHostName", None)
            if dns_host and dns_host.value:
                dc_name = str(dns_host.value)
        except Exception:
            pass
        try:
            dfl = getattr(root, "msDS_Behavior_Version", None)
            if dfl and dfl.value is not None:
                domain_level_raw = str(dfl.value)
        except Exception:
            pass
        try:
            sasl   = getattr(root, "supportedSASLMechanisms", None)
            values = [str(v).upper() for v in (sasl.values if sasl else [])]
            kerberos_enabled = any(v in ("GSSAPI", "GSS-SPNEGO") for v in values)
        except Exception:
            kerberos_enabled = True

    dc_filters = [
        "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        "(&(objectCategory=computer)(objectCapability=13))",
    ]
    for dc_filter in dc_filters:
        try:
            conn.search(
                base_dn,
                dc_filter,
                search_scope=SUBTREE,
                attributes=["dNSHostName", "operatingSystem", "operatingSystemVersion"],
                size_limit=50,
            )
            if not conn.entries:
                continue

            picked_dc = _pick_dc_fqdn_from_entries(conn.entries, ldap_target, domain)
            if picked_dc:
                dc_name = picked_dc
            for entry in conn.entries:
                dns_attr = getattr(entry, "dNSHostName", None)
                dns_val  = str(dns_attr.value).strip() if dns_attr and dns_attr.value else ""
                if dns_val and dc_name.lower().rstrip(".") == dns_val.lower().rstrip("."):
                    matched_dc_obj = entry
                    break
            if matched_dc_obj is not None or picked_dc:
                break
        except Exception:
            continue

    os_version = f"Windows Server ({Config.DOMAIN_LEVEL_MAP.get(domain_level_raw, 'Unknown')})"
    if matched_dc_obj is not None:
        os_name     = getattr(matched_dc_obj, "operatingSystem", None)
        os_ver      = getattr(matched_dc_obj, "operatingSystemVersion", None)
        os_name_val = str(os_name.value) if os_name and os_name.value else ""
        os_ver_val  = str(os_ver.value)  if os_ver  and os_ver.value  else ""
        if os_name_val and os_ver_val:
            os_version = f"{os_name_val} ({os_ver_val})"
        elif os_name_val:
            os_version = os_name_val
    elif dc_name:
        escaped_dc = ldap_escape_filter(dc_name)
        conn.search(
            base_dn,
            f"(&(objectClass=computer)(dNSHostName={escaped_dc}))",
            search_scope=SUBTREE,
            attributes=["operatingSystem", "operatingSystemVersion"],
            size_limit=1,
        )
        if conn.entries:
            dc_obj      = conn.entries[0]
            os_name     = getattr(dc_obj, "operatingSystem", None)
            os_ver      = getattr(dc_obj, "operatingSystemVersion", None)
            os_name_val = str(os_name.value) if os_name and os_name.value else ""
            os_ver_val  = str(os_ver.value)  if os_ver  and os_ver.value  else ""
            if os_name_val and os_ver_val:
                os_version = f"{os_name_val} ({os_ver_val})"
            elif os_name_val:
                os_version = os_name_val

    for smb_target in (dc_name, ldap_target, domain):
        candidate = str(smb_target or "").strip()
        if not candidate:
            continue
        try:
            smb_enabled = check_port(candidate, 445)
            break
        except Exception:
            continue

    conn.unbind()
    return {
        "dc":               dc_name,
        "dnsHostName":      dc_name,
        "os_version":       os_version,
        "domain_level":     f"Level {domain_level_raw} ({Config.DOMAIN_LEVEL_MAP.get(domain_level_raw, 'Unknown')})",
        "kerberos_enabled": kerberos_enabled,
        "smb_enabled":      smb_enabled,
        "counts":           counts,
    }


def _collect_ldap_environment_with_fallback(req: dict) -> dict:
    last_error = None
    for target in _build_ldap_targets(req):
        result = _collect_ldap_environment_for_target(
            target,
            req["username"],
            req["password"],
            req["domain"],
        )
        if result.get("success"):
            return result

        last_error = result.get("error")
        logger.warning("LDAP env probe failed on %s: %s", target, last_error)
        if int(result.get("code") or 0) == 401 or _is_ldap_bind_failure(str(last_error)):
            break
        if "refused" in str(last_error).lower():
            break

    return {"success": False, "error": str(last_error) if last_error else "LDAP env probe failed"}


def _collect_counts_via_enumeration_fallback(req: dict) -> dict[str, int]:
    from user import users_dump as users_mod
    from computer import computers as computers_mod
    from group import groups as groups_mod
    from ou import ous as ou_mod
    from gpo import gpos as gpo_mod
    from trust import trusts as trust_mod

    counts = {k: 0 for k in ("users", "computers", "groups", "ous", "gpos", "trusts")}
    mapping = [
        ("groups",    groups_mod.get_domain_groups),
        ("ous",       ou_mod.get_domain_ous),
        ("gpos",      gpo_mod.get_domain_gpos),
        ("trusts",    trust_mod.get_domain_trusts),
        ("computers", computers_mod.get_domain_computers),
        ("users",     users_mod.get_domain_users),
    ]

    for key, enum_fn in mapping:
        try:
            res = _run_enumeration_with_target_fallback(req, enum_fn)
            if res.get("success"):
                counts[key] = int(
                    res.get("count", len(res.get(key, [])) if isinstance(res.get(key), list) else 0)
                )
        except Exception as exc:
            logger.warning("Count fallback failed for %s: %s", key, exc)

    return counts