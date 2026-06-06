#pragma once
#include "../../include/core.h"
#include "../../include/ldap_engine.h"
#include <filesystem>
#include <string>
#include <vector>
#include <unordered_map>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  GroupCollectorOptions
// ─────────────────────────────────────────────────────────────────────────────
struct GroupCollectorOptions {
    std::string output_dir  = "raw_cache";
    int         max_results = 0;  // 0 = limitsiz
};

// ─────────────────────────────────────────────────────────────────────────────
//  GroupCollector  — Phase 1 / Extract
//
//  Output schema (raw_groups.ndjson) — hər sətir bir qrup:
//
//  {
//    "name"                   : "Administrators",
//    "sam_name"               : "Administrators",
//    "sid"                    : "S-1-5-32-544",
//    "dn"                     : "CN=Administrators,CN=Builtin,DC=...",
//    "description"            : "...",
//    "group_type"             : "Security / Domain Local",
//    "group_type_raw"         : -2147483643,
//    "member_count"           : 3,
//    "members"                : ["CN=...", "CN=..."],
//    "member_of"              : ["CN=..."],
//    "member_of_count"        : 0,
//    "is_privileged"          : true,
//    "is_protected"           : true,
//    "is_nested"              : false,
//    "managed_by"             : "",
//    "primary_group_token"    : 544,
//    "sid_history"            : [],
//    "is_protected_users_group": false,
//    "risk_controls"          : ["Privileged Group"],
//    "when_created"           : "2026-04-26T10:45:44+00:00",
//    "when_changed"           : "2026-05-29T07:44:27+00:00",
//    "generated_at"           : "2026-05-29T07:50:45Z"
//  }
//
//  Bu schema domain_groups.ndjson ilə uyğundur.
//  Tranzitiv üzvlük OfflineProcessor tərəfindən lokalda DFS ilə hesablanır.
// ─────────────────────────────────────────────────────────────────────────────
class GroupCollector {
public:
    explicit GroupCollector(LDAPEngine& engine);

    int      collect(const GroupCollectorOptions& opts = {});
    fs::path output_path() const { return output_path_; }

private:
    LDAPEngine& engine_;
    fs::path    output_path_;

    std::vector<std::string> required_attrs() const;

    struct GroupRecord {
        LDAPEngine::AttrMap      attrs;
        std::string              sid;
        int                      group_type_raw = 0;
        std::string              dn;
        std::vector<std::string> direct_member_dns;
    };

    // Bir GroupRecord-u NDJSON sətrinə çevirir
    std::string group_to_ndjson(const GroupRecord& g,
                                const std::string& generated_at) const;

    // groupType int → "Security / Domain Local" kimi string
    static std::string decode_group_type(int raw);

    // risk_controls: privileged qrupları təyin et
    static std::vector<std::string> compute_risk_controls(
        const std::string& sid, int group_type_raw, bool is_protected);

    // Builtin privileged SID-lər
    static bool is_privileged_sid(const std::string& sid);

    static std::string decode_sid  (const std::string& raw_bytes);
    static std::string je          (const std::string& s);
    static std::string jb          (bool v);
    static std::string ji          (int v);
    static std::string ja          (const std::vector<std::string>& v);
    static std::string now_iso8601 ();
};