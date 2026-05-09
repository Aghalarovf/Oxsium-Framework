# connect package — Active Directory connection & enumeration helpers
#
# Public surface area re-exported for convenience:
from connect.config        import Config, logger
from connect.utils         import (
    is_ntlm_hash, get_netbios_bind_user, domain_to_dn,
    ldap_escape_filter, validate_ip, validate_domain, validate_username,
)
from connect.network       import check_port, host_up, _tcp_probe
from connect.ldap_core     import (
    SEARCH_QUERIES,
    _build_ldap_targets,
    _run_enumeration_with_target_fallback,
    _collect_ldap_environment,
    _collect_ldap_environment_with_fallback,
    _collect_counts_via_enumeration_fallback,
)
from connect.protocols     import (
    connect_ldap, connect_ldap_fast,
    connect_winrm, connect_smb, connect_ssh, connect_local,
    PROTOCOL_HANDLERS,
)
from connect.shell         import (
    run_local_command, run_winrm_command, run_ssh_command,
    _collect_powershell_profile, _apply_powershell_profile,
)
from connect.tools         import (
    run_local_inventory_c_tool,
    run_smb_checker_tool,
    run_ntlm_checker_tool,
    run_kerberos_checker_tool,
)
from connect.saved_users   import _read_old_users, _write_old_users
from connect.flask_helpers import require_json_fields, is_local_request, get_enumeration_request_data
from connect.dcsync        import _read_dcsync_history, run_dcsync_tool, save_kerberos_key

__all__ = [
    "Config", "logger",
    "is_ntlm_hash", "get_netbios_bind_user", "domain_to_dn",
    "ldap_escape_filter", "validate_ip", "validate_domain", "validate_username",
    "check_port", "host_up", "_tcp_probe",
    "SEARCH_QUERIES",
    "_build_ldap_targets", "_run_enumeration_with_target_fallback",
    "_collect_ldap_environment", "_collect_ldap_environment_with_fallback",
    "_collect_counts_via_enumeration_fallback",
    "connect_ldap", "connect_ldap_fast",
    "connect_winrm", "connect_smb", "connect_ssh", "connect_local",
    "PROTOCOL_HANDLERS",
    "run_local_command", "run_winrm_command", "run_ssh_command",
    "_collect_powershell_profile", "_apply_powershell_profile",
        "run_local_inventory_c_tool", "run_smb_checker_tool",
        "run_ntlm_checker_tool", "run_kerberos_checker_tool",
    "_read_old_users", "_write_old_users",
        "_read_dcsync_history", "run_dcsync_tool",
    "require_json_fields", "is_local_request", "get_enumeration_request_data",
]