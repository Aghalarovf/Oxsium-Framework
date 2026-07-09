import re
import ipaddress


# Common Active Directory sub-error codes embedded in LDAP bind error messages
# (e.g. "80090308: LdapErr: ... data 775, v4563"). These explain the *real*
# reason a bind was rejected, which is often not a credential/format issue.
_AD_BIND_SUBCODES: dict[str, str] = {
    "525": "İstifadəçi adı tapılmadı (user not found)",
    "52e": "Şifrə/istifadəçi adı yanlışdır (invalid credentials)",
    "530": "Bu hesab hazırkı saatlarda giriş etməyə icazəli deyil (logon hours restriction)",
    "531": "Bu hesab bu iş stansiyasından giriş etməyə icazəli deyil (workstation restriction)",
    "532": "Hesabın şifrəsinin vaxtı bitib (password expired)",
    "533": "Hesab deaktiv edilib (account disabled)",
    "701": "Hesabın vaxtı bitib (account expired)",
    "773": "İstifadəçi ilk növbədə şifrəni dəyişməlidir (must reset password)",
    "775": "Hesab kilidlənib (account locked out)",
}


def extract_ad_bind_subcode(message: str) -> tuple[str, str] | None:
    """Extract the AD sub-error code (e.g. '775') from an LDAP bind error
    message and return (code, human_readable_reason), or None if not found."""
    if not message:
        return None
    match = re.search(r"data\s+([0-9a-fA-F]{2,4})\b", message)
    if not match:
        return None
    code = match.group(1).lower()
    reason = _AD_BIND_SUBCODES.get(code)
    if reason:
        return code, reason
    return code, "Naməlum AD alt-xəta kodu"


def is_ntlm_hash(password: str) -> bool:
    return bool(re.match(r"^[a-fA-F0-9]{32}$", password))


def get_upn_bind_user(username: str, domain: str) -> str:
    """Build a UPN-style bind user (user@domain.local); no NETBIOS\\user needed."""
    raw_user = str(username or "").strip()
    domain = str(domain or "").strip()

    if "@" in raw_user:
        return raw_user

    if "\\" in raw_user:
        local_user = raw_user.split("\\", 1)[-1].strip()
    else:
        local_user = raw_user

    if domain:
        return f"{local_user}@{domain}"

    return local_user


# Kept for backwards compatibility with any external callers; no longer used
# internally for bind-user construction (UPN is used instead).
def get_netbios_bind_user(username: str, domain: str) -> str:
    if "\\" in username or "@" in username:
        return username
    netbios = domain.split('.')[0].upper()
    return f"{netbios}\\{username}"


def build_ldap_bind_users(username: str, domain: str) -> list[str]:
    """Return bind-user candidates, UPN-first (user@domain.local).

    Order tried:
      1. UPN format: user@domain.local
      2. Raw username, as passed in by the caller
      3. Local username (no domain/netbios prefix)
      4. NETBIOS format: DOMAIN\\user (last-resort fallback)
    """
    raw_user = str(username or "").strip()
    domain = str(domain or "").strip()
    candidates: list[str] = []

    def add(candidate: str) -> None:
        candidate = str(candidate or "").strip()
        if candidate and candidate not in candidates:
            candidates.append(candidate)

    if not raw_user:
        return candidates

    if "@" in raw_user:
        local_user = raw_user.split("@", 1)[0].strip()
    elif "\\" in raw_user:
        local_user = raw_user.split("\\", 1)[-1].strip()
    else:
        local_user = raw_user

    # UPN format first: user@domain.local
    add(get_upn_bind_user(raw_user, domain))

    # Fallbacks, in case UPN bind is rejected for some reason
    add(raw_user)
    add(local_user)

    # Last resort: NETBIOS\user format
    if domain:
        add(get_netbios_bind_user(local_user, domain))

    return candidates


def domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))


def ldap_escape_filter(value: str) -> str:
    return (
        (value or "")
        .replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
        .replace("\x00", "\\00")
    )


def _is_ipv4_text(value: str) -> bool:
    try:
        ipaddress.IPv4Address((value or "").strip())
        return True
    except Exception:
        return False


def _pick_dc_fqdn_from_entries(entries: list, ldap_target: str, domain: str) -> str:
    candidates: list[str] = []
    for entry in entries or []:
        dns_host = getattr(entry, "dNSHostName", None) or getattr(entry, "dnsHostName", None)
        val = str(dns_host.value).strip() if dns_host and dns_host.value else ""
        if not val:
            continue
        if "." not in val and domain:
            val = f"{val}.{domain}"
        candidates.append(val)

    if not candidates:
        return ""

    target = (ldap_target or "").strip().lower().rstrip(".")
    if target and not _is_ipv4_text(target):
        target_short = target.split(".")[0]
        for cand in candidates:
            cand_l = cand.lower().rstrip(".")
            if cand_l == target or cand_l.split(".")[0] == target_short:
                return cand

    return candidates[0]


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    return bool(re.match(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
        domain,
    ))


def validate_username(username: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9@.\\\-_]{1,128}$", username))