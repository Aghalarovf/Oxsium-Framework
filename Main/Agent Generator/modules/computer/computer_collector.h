#pragma once
#include "../../include/core.h"
#include "../../include/ldap_engine.h"
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  ComputerCollectorOptions
// ─────────────────────────────────────────────────────────────────────────────
struct ComputerCollectorOptions {
    std::string output_dir  = "raw_cache";
    int         max_results = 0;
    // Stale threshold in days — accounts with no logon/pwd change beyond
    // this limit are flagged as stale. Default: 45 days (matches computers.py).
    int         stale_days  = 45;
};

// ─────────────────────────────────────────────────────────────────────────────
//  ComputerCollector  — Phase 1 / Extract
//
//  Single LDAP query: (&(objectClass=computer))
//  Output: raw_computers.ndjson  — one computer object per line.
//
//  Output schema (raw_computers.ndjson):
//
//  {
//    "computer_name"              : "DC01$",
//    "dns_name"                   : "dc01.corp.local",
//    "dn"                         : "CN=DC01,OU=Domain Controllers,DC=...",
//    "display_name"               : "",
//    "sid"                        : "S-1-5-21-...-1000",
//    "description"                : "",
//    "disabled"                   : false,
//    "os"                         : "Windows Server 2022 Standard",
//    "os_version"                 : "10.0 (20348)",
//    "os_service_pack"            : "",
//    "os_bucket"                  : "server",
//    "spn"                        : ["HOST/dc01", ...],
//    "has_spn"                    : true,
//    "trusted_for_delegation"     : true,
//    "trusted_to_auth_for_delegation": false,
//    "unconstrained_delegation"   : true,
//    "constrained_delegation"     : false,
//    "allowed_to_delegate_to"     : [],
//    "rbcd_enabled"               : false,
//    "rbcd_principals"            : [],
//    "has_laps"                   : false,
//    "haslaps"                    : false,
//    "laps_expiration"            : "",
//    "is_workstation"             : false,
//    "is_server"                  : false,
//    "is_domain_controller"       : true,
//    "potential_privileged"       : false,
//    "is_stale"                   : false,
//    "stale_by_pwd"               : false,
//    "stale_by_logon"             : false,
//    "isaclprotected"             : false,
//    "sid_history"                : [],
//    "domainsid"                  : "S-1-5-21-...",
//    "primary_group_id"           : 516,
//    "location"                   : "",
//    "when_created"               : "2026-04-26T10:45:44+00:00",
//    "when_changed"               : "2026-05-29T07:44:27+00:00",
//    "last_logon"                 : "...",
//    "pwd_last_set"               : "...",
//    "risk_controls"              : ["Domain Controller", ...],
//    // ── Network stubs (populated by future network probe stage) ──────────
//    "is_ip_only"                 : null,
//    "ipv4_addresses"             : [],
//    "ipv6_addresses"             : [],
//    "smb_port_open"              : null,
//    "smb_signing_required"       : null,
//    "smb_version"                : null,
//    "generated_at"               : "2026-05-29T07:50:43Z"
//  }
//
//  Admin analysis (is_admin, admin_rules) is computed by OfflineProcessor
//  from group membership — not stored here.
//  RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity is parsed as raw bytes
//  via decode_rbcd_sids(); no impacket dependency — portable C++ only.
// ─────────────────────────────────────────────────────────────────────────────
class ComputerCollector {
public:
    explicit ComputerCollector(LDAPEngine& engine);

    int      collect(const ComputerCollectorOptions& opts = {});
    fs::path output_path() const { return output_path_; }

private:
    LDAPEngine& engine_;
    fs::path    output_path_;

    std::vector<std::string> required_attrs() const;

    // Converts one LDAP entry to an NDJSON line
    std::string computer_to_ndjson(const LDAPEngine::AttrMap& entry,
                                   const std::string& generated_at,
                                   int stale_days) const;

    // ── UAC helpers ───────────────────────────────────────────────────────────
    static bool         uac_flag      (unsigned int uac, unsigned int bit);

    // ── Timestamp helpers ─────────────────────────────────────────────────────
    static std::string  filetime_to_iso(const std::string& ft_str);
    // Returns Unix seconds from a FILETIME string; 0 on error / sentinel values
    static long long    filetime_to_unix(const std::string& ft_str);
    // Checks whether a FILETIME is older than stale_days from now
    static bool         is_stale_filetime(const std::string& ft_str, int stale_days);
    // Converts LDAP Generalized Time "YYYYMMDDHHmmss.0Z" to "YYYY-MM-DDTHH:MM:SSZ"
    static std::string  generalized_time_to_iso(const std::string& gt);

    // ── SID helpers ───────────────────────────────────────────────────────────
    static std::string  decode_sid    (const std::string& raw_bytes);
    static std::string  domain_sid_from_sid(const std::string& sid);

    // ── ACL helpers ───────────────────────────────────────────────────────────
    // Parses SE_DACL_PROTECTED from the raw nTSecurityDescriptor bytes
    static bool         parse_isaclprotected(const std::string& raw_sd);
    // Extracts trustee SIDs from msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
    // Parses the SECURITY_DESCRIPTOR DACL without external dependencies
    static std::vector<std::string> decode_rbcd_sids(const std::string& raw_sd);
    // Decodes a binary SID from a raw buffer starting at offset
    static std::string  decode_sid_from_buf(const unsigned char* buf,
                                             size_t buf_len, size_t offset);

    // ── SID history ───────────────────────────────────────────────────────────
    // Each sIDHistory value is a raw binary SID — decoded same as objectSid
    static std::vector<std::string> decode_sid_history(
        const std::vector<std::string>& raw_values);

    // ── Risk helpers ──────────────────────────────────────────────────────────
    static bool is_potential_privileged_by_rid(int primary_group_id);

    // ── LAPS helpers ──────────────────────────────────────────────────────────
    // Returns true if any LAPS attribute is non-empty
    static bool detect_laps(const LDAPEngine::AttrMap& entry,
                             const std::vector<std::string>& laps_attr_names);
    // Returns the expiration timestamp string (ms-Mcs-AdmPwdExpirationTime
    // or msLAPS-PasswordExpirationTime), whichever is present
    static std::string laps_expiration(const LDAPEngine::AttrMap& entry);
    // Builds the full laps_attributes JSON object (key → array of values)
    static std::string build_laps_attributes_json(const LDAPEngine::AttrMap& entry);

    // ── RBCD SDDL helper ──────────────────────────────────────────────────────
    // Reconstructs a human-readable SDDL string from the decoded RBCD SID list
    static std::string build_rbcd_sddl(const std::vector<std::string>& sids);

    // ── OS bucket ─────────────────────────────────────────────────────────────
    static std::string os_bucket(const std::string& os_name);

    // ── JSON helpers ──────────────────────────────────────────────────────────
    static std::string je (const std::string& s);
    static std::string jb (bool v);
    static std::string ji (int v);
    static std::string jnull();
    static std::string ja (const std::vector<std::string>& v);
    static std::string now_iso8601();
};