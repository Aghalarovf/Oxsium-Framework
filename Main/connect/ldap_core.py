import inspect
import logging
import re

from ldap3 import Server, Connection, ALL, BASE, SUBTREE, AUTO_BIND_NO_TLS
from ldap3.core.exceptions import LDAPBindError, LDAPInvalidCredentialsResult

from connect.config import Config
from connect.utils import (
    domain_to_dn, get_upn_bind_user, is_ntlm_hash,
    build_ldap_bind_users,
    ldap_escape_filter, _is_ipv4_text, _pick_dc_fqdn_from_entries,
    extract_ad_bind_subcode,
)
from connect.network import check_port

logger = logging.getLogger("ad_api")


def open_standalone_connection(
    ip: str,
    username: str,
    password: str,
    domain: str,
    config,
    use_ssl: bool = False,
) -> tuple[Connection, str]:
    """Single source of truth for collector modules that need to open their
    OWN LDAP connection (i.e. no shared session was available/reused).

    Every collector (users, groups, trusts, ous, gpos, acl ...) used to
    hand-roll this with a plain `Connection(..., auto_bind=True)` call and a
    single bind_user format. That skipped the StartTLS-before-bind step, so
    on any DC that enforces LDAP signing it failed with
    'automatic bind not successful - strongerAuthRequired' -- even though
    the exact same credentials worked fine through /api/connect, which DOES
    go through `_open_ldap_connection` (StartTLS first, LDAPS fallback).

    Collector modules should call this instead of building ldap3.Connection
    directly, so every code path -- shared session AND standalone fallback
    -- authenticates the same way.

    Returns (conn, base_dn). Caller is responsible for conn.unbind().
    """
    secret = password
    auth_type = "SIMPLE"
    if is_ntlm_hash(password):
        secret = f"00000000000000000000000000000000:{password}"
        auth_type = "NTLM"

    base_dn = domain_to_dn(domain)

    last_error: Exception | None = None
    for bind_user in build_ldap_bind_users(username, domain):
        try:
            conn = _open_ldap_connection(
                ldap_target=ip,
                bind_user=bind_user,
                bind_secret=secret,
                auth_type=auth_type,
                use_ssl=use_ssl,
            )
            return conn, base_dn
        except (LDAPInvalidCredentialsResult, LDAPBindError) as exc:
            last_error = exc
            exc_msg = str(exc)
            # Hard-stop: real AD policy error — raise immediately with the
            # original message so callers see the actual reason.
            if _is_hard_stop_bind_error(exc_msg):
                raise
            if _is_ldap_bind_failure(exc_msg):
                continue
            raise
    raise last_error or LDAPBindError("LDAP bind failed")


def enum_fn_supports_shared_session(enum_fn) -> bool:
    """Inspect enum_fn's signature to see if it accepts conn/base_dn kwargs,
    instead of blindly calling it and catching TypeError. Catching TypeError
    is unreliable: a TypeError raised *inside* the function body (a real
    bug) would be silently swallowed and misreported as 'unsupported'."""
    try:
        params = inspect.signature(enum_fn).parameters
    except (TypeError, ValueError):
        return False
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return True
    return "conn" in params and "base_dn" in params


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
    """Return True for errors where retrying with a different username format
    makes sense (wrong UPN/NETBIOS format, not an actual auth failure).

    Errors like strongerAuthRequired or accountExpired are *real* AD errors
    that won't be fixed by a format retry — they must surface to the caller.
    """
    msg = (message or "").lower()
    return any(marker in msg for marker in (
        "invalidcredentials",
        "automatic bind not successful",
        "invalid credentials",
        "ldapbinderror",
    ))


# AD data codes that should NOT be retried with a different username format.
# These are real policy/account errors where the bind_user format is correct
# but AD itself is rejecting the attempt for a specific reason.
_AD_HARD_STOP_MARKERS = (
    "strongerauthre",        # strongerAuthRequired  (DC needs signing/TLS)
    "insufficientaccessrigh", # insufficientAccessRights
    "accountexpired",
    "accountlocked",
    "passwordexpired",
    "passwordmustchange",
    "unwillingtoperform",
    "constraintviolation",
    "530",  # AD sub-code: not permitted to logon at this time
    "531",  # AD sub-code: not permitted to logon from this workstation
    "532",  # AD sub-code: password expired
    "533",  # AD sub-code: account disabled
    "701",  # AD sub-code: account expired
    "773",  # AD sub-code: user must reset password
    "775",  # AD sub-code: account locked out
)


def _is_hard_stop_bind_error(message: str) -> bool:
    """Return True when the error is a definitive AD rejection that should
    surface immediately rather than being retried or replaced with a generic
    message."""
    msg = (message or "").lower()
    return any(marker in msg for marker in _AD_HARD_STOP_MARKERS)


def _is_ldaps_protocol(protocol: str) -> bool:
    return str(protocol or "").strip().lower() == "ldaps"


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
            logger.info("LDAP bind SUCCEEDED with bind_user=%s target=%s", bind_user, ldap_target)
            return {"success": True, "data": env}
        except (LDAPInvalidCredentialsResult, LDAPBindError) as exc:
            last_error = exc
            exc_msg = str(exc)
            logger.error(
                "LDAP bind RAW error | target=%s bind_user=%s exc_type=%s message=%s",
                ldap_target, bind_user, type(exc).__name__, exc_msg,
                exc_info=True,
            )
            # Hard-stop errors (strongerAuthRequired, accountLocked, etc.)
            # are definitive AD rejections — surface them immediately with
            # the real reason instead of retrying other username formats.
            if _is_hard_stop_bind_error(exc_msg):
                subcode = extract_ad_bind_subcode(exc_msg)
                detail = f" {subcode[0]} — {subcode[1]}" if subcode else f" {exc_msg}"
                return {
                    "success": False,
                    "error": f"LDAP bind rejected by AD: {detail.strip()}",
                    "code": 401,
                }
            if _is_ldap_bind_failure(exc_msg):
                continue
            break
        except Exception as exc:
            last_error = exc
            logger.error(
                "LDAP connection RAW error | target=%s bind_user=%s exc_type=%s message=%s",
                ldap_target, bind_user, type(exc).__name__, str(exc),
                exc_info=True,
            )
            if _is_retryable_ldap_error(str(exc)):
                return {"success": False, "error": str(exc), "code": 503}
            break

    if last_error:
        exc_msg = str(last_error)
        subcode = extract_ad_bind_subcode(exc_msg)
        if subcode:
            # We have a machine-readable AD sub-code — always prefer it.
            detail = f"{subcode[0]} — {subcode[1]}"
            return {"success": False, "error": f"LDAP bind failed: {detail}", "code": 401}
        if _is_ldap_bind_failure(exc_msg):
            # Generic wrong-format failure after exhausting all username formats.
            return {
                "success": False,
                "error": (
                    f"LDAP bind failed for {username}; tried UPN, NETBIOS, and raw username "
                    f"formats. Verify the AD logon name (for example user@domain or DOMAIN\\user)."
                ),
                "code": 401,
            }
        # Any other error (network, TLS, etc.) — keep the original message.
        return {"success": False, "error": exc_msg, "code": 503}

    return {"success": False, "error": "LDAP env probe failed"}


def _run_enumeration_with_target_fallback(req: dict, enum_fn):
    # Prefer the single shared LDAP connection opened by /api/connect, so
    # each collector doesn't have to open (and re-authenticate) its own
    # connection. Falls back to the old per-target connect behaviour if
    # no matching shared session is currently open.
    from connect import session_manager

    shared_session = session_manager.get_active_session(
        req.get("ip"), req.get("domain"), req.get("username"),
    )
    if shared_session is not None:
        if not enum_fn_supports_shared_session(enum_fn):
            logger.warning(
                "enum_fn %s does not accept conn/base_dn -- update it to support "
                "shared-session reuse; falling back to per-target connect",
                getattr(enum_fn, "__name__", enum_fn),
            )
        else:
            try:
                # IMPORTANT: use the IP the shared session actually bound with,
                # not req.get("dc"). Even when conn= is passed and the main
                # collector doesn't open a new connection, some enum_fn's
                # (e.g. get_domain_acls) still use this positional "ip" to
                # open *additional* connections themselves -- e.g. parallel
                # ACL workers via make_conn_factory(). If we hand them the
                # DC's self-reported hostname (often unresolvable from the
                # client, e.g. dc.sequel.htb) instead of the IP the shared
                # session proved reachable, every one of those extra
                # connections fails with "invalid server address", even
                # though the shared session itself is healthy.
                result = enum_fn(
                    shared_session.ip or req.get("ip"),
                    req["domain"], req["username"], req["password"], Config,
                    conn=shared_session.conn, base_dn=shared_session.base_dn,
                )
                if result.get("success"):
                    result.setdefault("meta", {})
                    result["meta"]["shared_session"] = True
                    return result
                logger.warning(
                    "Enumeration via shared session failed (%s), falling back to per-target connect",
                    result.get("error"),
                )
            except Exception as exc:
                # A real bug inside enum_fn now surfaces here instead of being
                # mistaken for "doesn't support shared sessions".
                logger.warning("Enumeration via shared session raised %s, falling back to per-target connect", exc, exc_info=True)

    last_result = None
    targets = _build_ldap_targets(req)

    # Derive use_ssl once: honour the explicit boolean first, then fall back
    # to checking whether the protocol string is "ldaps".
    req_use_ssl = (
        bool(req.get("use_ssl"))
        or str(req.get("protocol", "")).strip().lower() == "ldaps"
    )

    for target in targets:
        if enum_fn_supports_shared_session(enum_fn):
            # Open a standalone SSL-aware connection for this fallback attempt.
            try:
                conn, base_dn = open_standalone_connection(
                    target,
                    req["username"],
                    req["password"],
                    req["domain"],
                    Config,
                    use_ssl=req_use_ssl,
                )
                result = enum_fn(
                    target, req["domain"], req["username"], req["password"], Config,
                    conn=conn, base_dn=base_dn,
                )
                try:
                    conn.unbind()
                except Exception:
                    pass
            except Exception as exc:
                last_result = {"success": False, "error": str(exc), "code": 503}
                logger.warning(
                    "_run_enumeration_with_target_fallback: standalone open failed on %s: %s",
                    target, exc,
                )
                continue
        else:
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


def _open_ldap_connection_gssapi(
    *,
    ldap_target: str,
    ccache_path: str,
    use_ssl: bool,
) -> Connection:
    """Bind using an existing Kerberos ticket cache (SASL GSSAPI) instead of
    a username/password. KRB5CCNAME must point at the supplied ccache file
    before ldap3/gssapi opens the security context."""
    from ldap3 import SASL, GSSAPI

    prev_ccache = os.environ.get("KRB5CCNAME")
    os.environ["KRB5CCNAME"] = ccache_path
    try:
        port = 636 if use_ssl else 389
        label = "LDAPS:636 (GSSAPI)" if use_ssl else "LDAP:389 (GSSAPI)"
        server = Server(
            ldap_target,
            port=port,
            use_ssl=use_ssl,
            get_info=ALL,
            connect_timeout=Config.LDAP_CONNECT_TIMEOUT,
        )
        conn = Connection(
            server,
            authentication=SASL,
            sasl_mechanism=GSSAPI,
            auto_bind=AUTO_BIND_NO_TLS,
            receive_timeout=Config.LDAP_RECEIVE_TIMEOUT,
        )
        logger.info("LDAP connection established [%s] target=%s", label, ldap_target)
        return conn
    except (LDAPInvalidCredentialsResult, LDAPBindError):
        raise
    except Exception as exc:
        logger.warning("LDAP GSSAPI connect error target=%s: %s", ldap_target, exc)
        raise
    finally:
        if prev_ccache is None:
            os.environ.pop("KRB5CCNAME", None)
        else:
            os.environ["KRB5CCNAME"] = prev_ccache


def _open_ldap_connection_certificate(
    *,
    ldap_target: str,
    cert_file: str,
    key_file: str,
) -> Connection:
    """Bind over LDAPS using a client certificate (from a supplied PFX) for
    mutual-TLS. Requires the DC to accept certificate-mapped authentication
    (Schannel / SASL EXTERNAL)."""
    from ldap3 import Tls, SASL, EXTERNAL
    import ssl as _ssl

    tls = Tls(
        local_certificate_file=cert_file,
        local_private_key_file=key_file,
        validate=_ssl.CERT_NONE,
    )
    try:
        server = Server(
            ldap_target,
            port=636,
            use_ssl=True,
            tls=tls,
            get_info=ALL,
            connect_timeout=Config.LDAP_CONNECT_TIMEOUT,
        )
        conn = Connection(
            server,
            authentication=SASL,
            sasl_mechanism=EXTERNAL,
            auto_bind=AUTO_BIND_NO_TLS,
            receive_timeout=Config.LDAP_RECEIVE_TIMEOUT,
        )
        logger.info("LDAP connection established [LDAPS:636 (cert/EXTERNAL)] target=%s", ldap_target)
        return conn
    except (LDAPInvalidCredentialsResult, LDAPBindError):
        raise
    except Exception as exc:
        logger.warning("LDAP certificate connect error target=%s: %s", ldap_target, exc)
        raise


def _open_ldap_connection(
    *,
    ldap_target: str,
    bind_user: str,
    bind_secret: str,
    auth_type: str,
    use_ssl: bool,
) -> Connection:
    """Open an LDAP connection exactly as the caller requested — no automatic
    fallback between LDAP and LDAPS.

    use_ssl=False  →  plain LDAP:389, no TLS negotiation whatsoever
    use_ssl=True   →  LDAPS:636, full TLS tunnel from the start

    The GUI lets the user pick the protocol explicitly (SSL toggle), so the
    code must honour that choice strictly.  Auto-fallback hides real errors
    and causes WinError 10054 when the DC rejects an unsolicited StartTLS.
    """
    if use_ssl:
        port      = 636
        bind_mode = AUTO_BIND_NO_TLS
        label     = "LDAPS:636"
    else:
        port      = 389
        bind_mode = AUTO_BIND_NO_TLS
        label     = "LDAP:389"

    try:
        server = Server(
            ldap_target,
            port=port,
            use_ssl=use_ssl,
            get_info=ALL,
            connect_timeout=Config.LDAP_CONNECT_TIMEOUT,
        )
        conn = Connection(
            server,
            user=bind_user,
            password=bind_secret,
            authentication=auth_type,
            auto_bind=bind_mode,
            receive_timeout=Config.LDAP_RECEIVE_TIMEOUT,
        )
        logger.info("LDAP connection established [%s] target=%s", label, ldap_target)
        return conn
    except (LDAPInvalidCredentialsResult, LDAPBindError):
        raise
    except Exception as exc:
        logger.warning(
            "LDAP connect error [%s] target=%s: %s", label, ldap_target, exc,
        )
        raise


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

    conn = _open_ldap_connection(
        ldap_target=ldap_target,
        bind_user=bind_user,
        bind_secret=bind_secret,
        auth_type=auth_type,
        use_ssl=use_ssl,
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
    use_ssl = _is_ldaps_protocol(req.get("protocol"))
    for target in _build_ldap_targets(req):
        result = _collect_ldap_environment_for_target(
            target,
            req["username"],
            req["password"],
            req["domain"],
            use_ssl=use_ssl,
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