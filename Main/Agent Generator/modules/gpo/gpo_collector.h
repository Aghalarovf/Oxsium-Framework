#pragma once
#include "../../include/core.h"
#include "../../include/ldap_engine.h"
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  GPOCollectorOptions
// ─────────────────────────────────────────────────────────────────────────────
struct GPOCollectorOptions {
    std::string output_dir  = "raw_cache";
    int         max_results = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  GPOCollector  — Phase 1 / Extract
//
//  LDAP queries:
//    1. SUBTREE on CN=Policies,CN=System,<base_dn>
//       filter: (objectClass=groupPolicyContainer)
//       attrs : name, displayName, description, gPCFileSysPath,
//               whenCreated, whenChanged, versionNumber,
//               gPCUserExtensionNames, gPCMachineExtensionNames,
//               flags, objectGUID, ntSecurityDescriptor, managedBy
//
//    2. SUBTREE on <base_dn>  filter: (gPLink=*)
//       attrs : distinguishedName, gPLink, gPOptions
//       → populates linked_containers / enforced / link_disabled per GPO
//
//    3. SUBTREE on <base_dn>  filter: (&(gpOptions=1)(!(gPLink=*)))
//       attrs : distinguishedName
//       → additional inheritance-blocked containers with no gPLink
//
//  Output: raw_gpos.jsonl — one GPO object per line.
//
//  Output schema (raw_gpos.jsonl):
//
//  {
//    "name"                      : "{31B2F340-016D-11D2-945F-00C04FB984F9}",
//    "guid"                      : "{31B2F340-016D-11D2-945F-00C04FB984F9}",
//    "display_name"              : "Default Domain Policy",
//    "description"               : "",
//    "dn"                        : "CN={...},CN=Policies,CN=System,DC=corp,DC=local",
//    "path"                      : "\\\\server\\SysVol\\corp.local\\Policies\\{...}",
//    "domain"                    : "corp.local",
//    "domainsid"                 : "S-1-5-21-...",
//    "created"                   : "2026-01-01T10:00:00Z",
//    "modified"                  : "2026-05-01T08:30:00Z",
//    "version"                   : 65536,
//    "user_version"              : 1,
//    "computer_version"          : 0,
//    "flags"                     : 0,
//    "user_settings_disabled"    : false,
//    "computer_settings_disabled": false,
//    "linked_containers"         : ["OU=Corp,DC=corp,DC=local", ...],
//    "linked_count"              : 1,
//    "enforced"                  : false,
//    "link_disabled"             : false,
//    "isaclprotected"            : false,
//    "owner_sid"                 : "S-1-5-21-...-500",
//    "owner_name"                : "Administrator",
//    "user_extensions"           : [
//        { "guid": "{35378EAC-...}", "name": "Registry Settings" }
//    ],
//    "machine_extensions"        : [...],
//    "highvalue"                 : false,
//    "risk_controls"             : ["Enforced", ...],
//    "generated_at"              : "2026-05-30T10:00:00Z"
//  }
// ─────────────────────────────────────────────────────────────────────────────
class GPOCollector {
public:
    explicit GPOCollector(LDAPEngine& engine);

    int      collect(const GPOCollectorOptions& opts = {});
    fs::path output_path() const { return output_path_; }

private:
    LDAPEngine& engine_;
    fs::path    output_path_;

    std::vector<std::string> required_attrs() const;

    // ── Per-GPO serialization ─────────────────────────────────────────────────
    // Converts one LDAP entry (plus enriched link data) to a raw JSONL line.
    std::string gpo_to_jsonl(
        const LDAPEngine::AttrMap& entry,
        const std::string&         domain_sid,
        const std::string&         domain_name,
        const std::vector<std::string>& linked_containers,
        bool                        enforced,
        bool                        link_disabled,
        const std::string&          generated_at) const;

    // ── Link enrichment ───────────────────────────────────────────────────────
    // Builds a map from GPO CN-GUID (upper) → list of container DNs that link it,
    // and a parallel map CN-GUID → list of raw gPLink strings (for flag parsing).
    struct LinkInfo {
        std::vector<std::string> containers;   // linked container DNs
        std::vector<std::string> link_texts;   // raw gPLink strings from each container
    };
    using LinkMap = std::map<std::string, LinkInfo>;

    LinkMap build_link_map() const;

    // ── gPLink flag helpers ───────────────────────────────────────────────────
    // Returns true if the given CN-GUID is enforced (flag & 2) in any link text.
    static bool is_enforced   (const std::vector<std::string>& link_texts,
                                const std::string& cn_guid);
    // Returns true if the given CN-GUID is link-disabled (flag & 1) in any link text.
    static bool is_link_disabled(const std::vector<std::string>& link_texts,
                                  const std::string& cn_guid);

    // ── Security Descriptor helpers ───────────────────────────────────────────
    // Parses SE_DACL_PROTECTED (0x1000) from raw nTSecurityDescriptor bytes.
    static bool        parse_isaclprotected(const std::string& sd_raw);
    // Extracts Owner SID from raw nTSecurityDescriptor bytes.
    static std::string parse_sd_owner      (const std::string& sd_raw);
    // Converts binary SID bytes to "S-R-I-S1-S2-..." string.
    // Handles both raw binary and double-escaped \\uXXXX forms.
    static std::string sid_to_string       (const std::string& raw);

    // ── Extension GUID helpers ────────────────────────────────────────────────
    // Parses gPCUserExtensionNames / gPCMachineExtensionNames into a JSON array
    // of { "guid":"...", "name":"..." } objects.
    static std::string parse_extension_guids_json(const std::string& ext_str);

    // ── Version helpers ───────────────────────────────────────────────────────
    // versionNumber: low 16 bits = computerVersion, high 16 bits = userVersion
    static int user_version    (int version_num) { return (version_num >> 16) & 0xFFFF; }
    static int computer_version(int version_num) { return  version_num        & 0xFFFF; }

    // ── High-value detection ──────────────────────────────────────────────────
    // A GPO is high-value if its CN matches a well-known default policy GUID,
    // or if its extension attributes indicate scripts/registry/password policies.
    static bool is_high_value(const std::string& cn_guid,
                               const std::string& user_ext,
                               const std::string& machine_ext);

    // ── DN / GUID / time helpers ──────────────────────────────────────────────
    static std::string guid_to_string           (const std::string& raw_bytes);
    static std::string generalized_time_to_iso  (const std::string& gt);
    static std::string extract_domain_name      (const std::string& base_dn);

    // ── JSON helpers ──────────────────────────────────────────────────────────
    static std::string je    (const std::string& s);
    static std::string jb    (bool v);
    static std::string ji    (int v);
    static std::string jnull ();
    static std::string ja    (const std::vector<std::string>& v);
    static std::string ja_obj(const std::vector<std::string>& json_objects);
    static std::string now_iso8601();

    // ── Well-known high-value GPO CN GUIDs (Default Domain / DC Policies) ─────
    static const char* HIGH_VALUE_GUIDS[];

    // ── Extension GUID → human name map ──────────────────────────────────────
    static const std::pair<const char*, const char*> EXTENSION_GUID_MAP[];
};