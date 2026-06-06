#pragma once
#include "../../include/core.h"
#include "../../include/ldap_engine.h"
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  UserCollectorOptions
// ─────────────────────────────────────────────────────────────────────────────
struct UserCollectorOptions {
    std::string output_dir  = "raw_cache";
    int         max_results = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  UserCollector  — Phase 1 / Extract
//
//  Output schema (raw_users.ndjson) — hər sətir bir user:
//
//  {
//    "username"              : "Administrator",
//    "dn"                    : "CN=Administrator,CN=Users,DC=...",
//    "display_name"          : "",
//    "sid"                   : "S-1-5-21-...-500",
//    "upn"                   : "",
//    "description"           : "Built-in account...",
//    "mail"                  : "",
//    "department"            : "",
//    "title"                 : "",
//    "disabled"              : false,
//    "locked_out"            : false,
//    "must_change_pwd"       : false,
//    "smartcard_required"    : false,
//    "normal_account"        : true,
//    "pwd_never_expires"     : true,
//    "pwd_not_required"      : false,
//    "pwd_cant_change"       : false,
//    "preauth_required"      : true,
//    "dcsync"                : false,
//    "asrep"                 : false,
//    "kerberoastable"        : false,
//    "spn"                   : [],
//    "unconstrained_delegation": false,
//    "constrained_delegation"  : false,
//    "trusted_for_delegation"  : false,
//    "not_delegated"           : false,
//    "msds_allowedtodelegateto": [],
//    "enc_implicit_rc4"        : false,
//    "member_of"               : ["Domain Admins", ...],
//    "primary_group_id"        : 513,
//    "when_created"            : "2026-04-26T10:45:44+00:00",
//    "when_changed"            : "2026-05-29T07:44:27+00:00",
//    "last_logon"              : "...",
//    "pwd_last_set"            : "...",
//    "logon_count"             : 42,
//    "bad_pwd_count"           : 0,
//    "domain_sid"              : "S-1-5-21-...",
//    "generated_at"            : "2026-05-29T07:50:43Z"
//  }
//
//  Bu schema domain_users.ndjson ilə uyğundur.
//  Admin analizi (is_admin, admin_rules) OfflineProcessor tərəfindən
//  group membership-dən hesablanır.
// ─────────────────────────────────────────────────────────────────────────────
class UserCollector {
public:
    explicit UserCollector(LDAPEngine& engine);

    int      collect(const UserCollectorOptions& opts = {});
    fs::path output_path() const { return output_path_; }

private:
    LDAPEngine& engine_;
    fs::path    output_path_;

    std::vector<std::string> required_attrs() const;

    // Bir LDAP entry-ni NDJSON sətrinə çevirir
    std::string user_to_ndjson(const LDAPEngine::AttrMap& entry,
                               const std::string& generated_at) const;

    // userAccountControl bitmask decoderlar
    static bool uac_flag(unsigned int uac, unsigned int bit);
    static std::string filetime_to_iso(const std::string& ft_str);
    static std::string decode_sid(const std::string& raw_bytes);
    static std::string domain_sid_from_user_sid(const std::string& sid);

    // Encryption risk
    static bool is_rc4_implicit(unsigned int enc_types);

    static std::string je (const std::string& s);
    static std::string jb (bool v);
    static std::string ji (int v);
    static std::string ji64(long long v);
    static std::string ja (const std::vector<std::string>& v);
    static std::string now_iso8601();
};