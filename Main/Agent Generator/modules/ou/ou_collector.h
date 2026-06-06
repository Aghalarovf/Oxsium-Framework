#pragma once
#include "../../include/core.h"
#include "../../include/ldap_engine.h"
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  OUCollectorOptions
// ─────────────────────────────────────────────────────────────────────────────
struct OUCollectorOptions {
    std::string output_dir  = "raw_cache";
    int         max_results = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  OUCollector  — Phase 1 / Extract
//
//  Two LDAP queries:
//    1. SUBTREE  (&(objectClass=organizationalUnit))  — all OU objects
//    2. Per-OU LEVEL queries for direct child OU DNs  (child_ous)
//
//  Output: raw_ous.ndjson  — one OU object per line.
//
//  Output schema (raw_ous.ndjson):
//
//  {
//    "name"                   : "Sales",
//    "dn"                     : "OU=Sales,OU=Corp,DC=corp,DC=local",
//    "description"            : "Sales department",
//    "managed_by"             : "CN=Alice,...",
//    "object_guid"            : "550E8400-E29B-41D4-A716-446655440000",
//    "object_id"              : "550E8400-E29B-41D4-A716-446655440000",
//    "parent_dn"              : "OU=Corp,DC=corp,DC=local",
//    "child_ous"              : ["OU=North,OU=Sales,...", ...],
//    "depth"                  : 2,
//    "gpo_links_raw"          : "[LDAP://CN={GUID},...;0]",
//    "linked_gpos"            : [
//        { "gpo_dn":"CN={...},...", "gpo_guid":"...", "order":1,
//          "enforced":false, "disabled":false, "link_flag":0 }
//    ],
//    "gpo_precedence"         : [
//        { "gpo_guid":"...", "order":1, "enforced":false }
//    ],
//    "inherited_gpos"         : [
//        { "gpo_dn":"...", "gpo_guid":"...", "order":1,
//          "enforced":false, "disabled":false, "link_flag":0,
//          "inherited_from":"OU=Corp,..." }
//    ],
//    "has_gpo_links"          : false,
//    "inheritance_blocked"    : false,
//    "gp_options"             : 0,
//    "object_count"           : 12,
//    "privileged_users"       : [{ "sam_name":"...", "dn":"...", "sid":"..." }],
//    "privileged_users_count" : 0,
//    "privileged_computers"   : [{ "cn":"...", "dn":"...", "sid":"...", "dns_name":"..." }],
//    "privileged_computers_count": 0,
//    "delegated_permissions"  : false,
//    "highvalue"              : false,
//    "isaclprotected"         : false,
//    "blocksinheritance"      : false,
//    "domainsid"              : "S-1-5-21-...",
//    "when_created"           : "2026-01-01T10:00:00Z",
//    "when_changed"           : "2026-05-01T08:30:00Z",
//    "risk_controls"          : ["GPO Links", ...],
//    "generated_at"           : "2026-05-30T10:00:00Z"
//  }
// ─────────────────────────────────────────────────────────────────────────────
class OUCollector {
public:
    explicit OUCollector(LDAPEngine& engine);

    int      collect(const OUCollectorOptions& opts = {});
    fs::path output_path() const { return output_path_; }

private:
    LDAPEngine& engine_;
    fs::path    output_path_;

    std::vector<std::string> required_attrs() const;

    // Converts one LDAP entry to an NDJSON line
    std::string ou_to_ndjson(const LDAPEngine::AttrMap& entry,
                              const std::string& domain_sid,
                              const std::string& generated_at) const;

    // ── Child OU query ────────────────────────────────────────────────────────
    // Fetches direct child OU DNs via a LEVEL-scope LDAP search on parent_dn
    std::vector<std::string> get_child_ous(const std::string& parent_dn) const;

    // ── Privileged object queries ─────────────────────────────────────────────
    // Returns adminCount=1 users and DC computers directly under ou_dn (SUBTREE)
    struct PrivSummary {
        std::vector<std::string> priv_user_json;      // JSON objects as strings
        std::vector<std::string> priv_computer_json;  // JSON objects as strings
    };
    PrivSummary get_privileged_objects(const std::string& ou_dn) const;

    // ── GPO helpers ───────────────────────────────────────────────────────────
    // Parses gPLink attribute "[LDAP://...;flag][...]" into JSON object array
    static std::string parse_gplink_json(const std::string& gplink_raw);
    // Builds gpo_precedence array from linked_gpos
    static std::string build_gpo_precedence_json(const std::string& gplink_raw);
    // Walks parent chain collecting inherited GPO links (stops at domain root
    // or when gPOptions & 1 is set on a parent OU)
    std::string get_inherited_gpos_json(const std::string& ou_dn,
                                         const std::string& domain_dn) const;

    // ── SID helpers ───────────────────────────────────────────────────────────
    // Converts raw binary Windows SID bytes to "S-1-5-21-..." string form.
    // If the value is already a text SID, returns it unchanged.
    static std::string sid_to_string(const std::string& raw_bytes);

    // ── DN / GUID helpers ─────────────────────────────────────────────────────
    static std::string extract_parent_dn(const std::string& dn);
    static int         calc_depth(const std::string& dn);
    static std::string guid_to_string(const std::string& raw_bytes);
    static std::string generalized_time_to_iso(const std::string& gt);

    // ── High-value detection ──────────────────────────────────────────────────
    static bool is_high_value(const std::string& name, const std::string& dn);

    // ── JSON helpers ──────────────────────────────────────────────────────────
    static std::string je  (const std::string& s);
    static std::string jb  (bool v);
    static std::string ji  (int v);
    static std::string jnull();
    static std::string ja  (const std::vector<std::string>& v);
    static std::string ja_obj(const std::vector<std::string>& json_objects);
    static std::string now_iso8601();
};