import re
import ipaddress


def is_ntlm_hash(password: str) -> bool:
    return bool(re.match(r"^[a-fA-F0-9]{32}$", password))


def get_netbios_bind_user(username: str, domain: str) -> str:
    if "\\" in username or "@" in username:
        return username
    netbios = domain.split('.')[0].upper()
    return f"{netbios}\\{username}"


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