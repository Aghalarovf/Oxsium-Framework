_DEF_COUNTS = {
    "groups": 0,
    "gpos": 0,
    "ous": 0,
    "trusts": 0,
    "computers": 0,
    "users": 0,
}


def apply_deep_defaults(result: dict, ip: str, check_port) -> None:
    """Apply deep-connect defaults to keep response shape stable."""
    result.setdefault("os_version", "Unknown")
    result.setdefault("domain_level", "Unknown")
    result.setdefault("kerberos_enabled", True)
    result.setdefault("smb_enabled", check_port(ip, 445))
    result.setdefault("counts", dict(_DEF_COUNTS))


def enrich_with_env_probe(
    *,
    result: dict,
    req: dict,
    ip: str,
    collect_ldap_environment_with_fallback,
    collect_counts_via_enumeration_fallback,
) -> None:
    """Attach LDAP environment details for deep connect, preserving existing fallbacks."""
    env_probe = collect_ldap_environment_with_fallback(req)
    if env_probe.get("success"):
        env = env_probe["data"]
        env_dc = env.get("dnsHostName") or env.get("dc") or result.get("dnsHostName") or result.get("dc") or ip
        result["dc"] = env_dc
        result["dnsHostName"] = env_dc
        result["os_version"] = env.get("os_version") or result.get("os_version")
        result["domain_level"] = env.get("domain_level") or result.get("domain_level")
        result["kerberos_enabled"] = env.get("kerberos_enabled", result.get("kerberos_enabled", True))
        if env.get("smb_enabled") is not None:
            result["smb_enabled"] = env.get("smb_enabled")
        result["counts"] = env.get("counts", result.get("counts", {}))
        result["ldap_target"] = env.get("ldap_target")
        return

    if "refused" in str(env_probe.get("error", "")).lower():
        result["env_probe_error"] = env_probe.get("error", "LDAP env probe failed")
        return

    result["counts"] = collect_counts_via_enumeration_fallback(req)
    result["env_probe_error"] = env_probe.get("error", "LDAP env probe failed")