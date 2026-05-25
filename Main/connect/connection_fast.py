def run_connect_strategy(
    *,
    connect_mode: str,
    proto: str,
    ip: str,
    username: str,
    password: str,
    domain: str,
    connect_ldap_fast,
    protocol_handlers: dict,
):
    """Select and execute fast/deep connection strategy without changing behavior."""
    if connect_mode == "fast" and proto in ("ldap", "ldaps", "rpc", "agent", "beacon"):
        return connect_ldap_fast(ip, username, password, domain, use_ssl=(proto == "ldaps"))
    return protocol_handlers[proto](ip, username, password, domain)
