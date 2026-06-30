// ─── offline_processor_p2.cpp ───────────────────────────────────────────────
// This file is part of offline_processor.cpp.
// Admin rules + ACE checks + user analysis logic.
// ─────────────────────────────────────────────────────────────────────────────
#include "offline_processor.h"
#include <algorithm>
#include <cctype>

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 5 — ACE helper
// ═════════════════════════════════════════════════════════════════════════════

bool OfflineProcessor::ace_has_dangerous_right(const RawAceEntry& ace,
                                                const std::set<std::string>& ids)
{
    if (!ace.is_allow) return false;
    if (ids.find(ace.trustee_sid) == ids.end()) return false;
    unsigned int m = ace.mask;
    if ((m & OfflineAceRight::ACE_GENERIC_ALL) == OfflineAceRight::ACE_GENERIC_ALL) return true;
    if (m & OfflineAceRight::ACE_GA_BIT)       return true;
    if (m & OfflineAceRight::ACE_WRITE_DACL)   return true;
    if (m & OfflineAceRight::ACE_WRITE_OWNER)  return true;
    if (m & OfflineAceRight::ACE_DS_WRITE_PROP) return true;
    return false;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 6 — Admin rules  (same logic as user_enum.cpp, offline)
// ═════════════════════════════════════════════════════════════════════════════

// Rule 1 — Domain Admins / Enterprise / Schema / Builtin + DC groups
bool OfflineProcessor::rule_01_domain_admins(const std::set<std::string>& all_sids,
                                              int primary_gid,
                                              const std::string& user_sid,
                                              std::vector<PAdminRule>& out)
{
    static const struct { int rid; const char* name; } rids[] = {
        { OfflineAdminRID::DOMAIN_ADMINS,                   "Domain Admins"                   },
        { OfflineAdminRID::ENTERPRISE_ADMINS,               "Enterprise Admins"               },
        { OfflineAdminRID::SCHEMA_ADMINS,                   "Schema Admins"                   },
        { OfflineAdminRID::BUILTIN_ADMINS,                  "Builtin Administrators"          },
        { OfflineAdminRID::DOMAIN_CONTROLLERS,              "Domain Controllers"              },
        { OfflineAdminRID::ENTERPRISE_READONLY_CONTROLLERS, "Enterprise Read-Only Controllers"},
        { OfflineAdminRID::ONLY_DOMAIN_CONTROLLERS,         "Read-Only Domain Controllers"    },
        { 0, nullptr }
    };

    PAdminRuleDetail detail;
    bool matched = false;

    // Primary group
    for (int i = 0; rids[i].name; ++i) {
        if (primary_gid == rids[i].rid) {
            detail.matched_rids.push_back(rids[i].rid);
            detail.matched_groups.push_back(std::string(rids[i].name) + " (primaryGroup)");
            detail.match_sources.push_back("primary_group");
            matched = true;
        }
    }

    // Token group SIDs
    for (const auto& sid : all_sids) {
        int r = rid_from_sid(sid);
        for (int i = 0; rids[i].name; ++i) {
            if (r == rids[i].rid) {
                detail.matched_rids.push_back(r);
                detail.matched_sids.push_back(sid);
                detail.matched_groups.push_back(rids[i].name);
                detail.match_sources.push_back("token_group");
                matched = true; break;
            }
        }
    }

    // User's own SID
    if (!matched) {
        int r = rid_from_sid(user_sid);
        for (int i = 0; rids[i].name; ++i) {
            if (r == rids[i].rid) {
                detail.matched_rids.push_back(r);
                detail.matched_sids.push_back(user_sid);
                detail.matched_groups.push_back(rids[i].name);
                detail.match_sources.push_back("user_sid");
                matched = true; break;
            }
        }
    }

    if (matched) {
        PAdminRule rule;
        rule.level      = 1;
        rule.severity   = "absolute";
        rule.label      = "Domain Admins / Enterprise Admins / Schema Admins / Builtin Admins";
        rule.detail     = detail;
        rule.has_detail = true;
        out.push_back(rule);
    }
    return matched;
}

// Rule 2 — Operator groups
bool OfflineProcessor::rule_02_operator_groups(const std::set<std::string>& all_sids,
                                                int primary_gid,
                                                const std::string& user_sid,
                                                std::vector<PAdminRule>& out)
{
    static const struct { int rid; const char* name; } op_rids[] = {
        { OfflineAdminRID::ACCOUNT_OPERATORS,              "Account Operators"                   },
        { OfflineAdminRID::SERVER_OPERATORS,               "Server Operators"                    },
        { OfflineAdminRID::BACKUP_OPERATORS,               "Backup Operators"                    },
        { OfflineAdminRID::GROUP_POLICY_CREATORS,          "Group Policy Creator Owners"         },
        { OfflineAdminRID::PRINT_OPERATORS,                "Print Operators"                     },
        { OfflineAdminRID::CRYPTOGRAPHIC_OPERATORS,        "Cryptographic Operators"             },
        { OfflineAdminRID::HYPERV_ADMINISTRATORS,          "Hyper-V Administrators"              },
        { OfflineAdminRID::STORAGE_REPLICA_ADMINISTRATORS, "Storage Replica Administrators"      },
        { OfflineAdminRID::KEY_ADMINS,                     "Key Admins"                          },
        { OfflineAdminRID::ENTERPRISE_KEY_ADMINS,          "Enterprise Key Admins"               },
        { OfflineAdminRID::RAS_IAS_SERVERS,                "RAS and IAS Servers"                 },
        { OfflineAdminRID::CERT_PUBLISHERS,                "Cert Publishers"                     },
        { OfflineAdminRID::REMOTE_MANAGEMENT_USERS,        "Remote Management Users"             },
        { 0, nullptr }
    };

    PAdminRuleDetail detail;
    bool matched = false;

    // Primary group
    if (primary_gid) {
        for (int i = 0; op_rids[i].name; ++i) {
            if (primary_gid == op_rids[i].rid) {
                detail.matched_rids.push_back(op_rids[i].rid);
                detail.matched_groups.push_back(std::string(op_rids[i].name) + " (primaryGroup)");
                detail.match_sources.push_back("primary_group");
                matched = true; break;
            }
        }
    }

    // Token group SIDs
    for (const auto& sid : all_sids) {
        int r = rid_from_sid(sid);
        for (int i = 0; op_rids[i].name; ++i) {
            if (r == op_rids[i].rid) {
                detail.matched_rids.push_back(r);
                detail.matched_sids.push_back(sid);
                detail.matched_groups.push_back(op_rids[i].name);
                detail.match_sources.push_back("token_group");
                matched = true; break;
            }
        }
    }

    // User's own SID
    if (!matched) {
        int r = rid_from_sid(user_sid);
        for (int i = 0; op_rids[i].name; ++i) {
            if (r == op_rids[i].rid) {
                detail.matched_rids.push_back(r);
                detail.matched_sids.push_back(user_sid);
                detail.matched_groups.push_back(op_rids[i].name);
                detail.match_sources.push_back("user_sid");
                matched = true; break;
            }
        }
    }

    if (matched) {
        PAdminRule rule;
        rule.level      = 2;
        rule.severity   = "tier1";
        rule.label      = "Operator Groups (Account/Server/Backup/GPO/Print/"
                          "Cryptographic/Hyper-V/Storage Replica Administrators)";
        rule.detail     = detail;
        rule.has_detail = true;
        out.push_back(rule);
    }
    return matched;
}

// Rule 3 — GenericAll / dangerous rights on domain root
bool OfflineProcessor::rule_03_generic_all_domain(const std::set<std::string>& ids) const {
    for (const auto& ace : domain_root_aces_) {
        if (ace_has_dangerous_right(ace, ids)) return true;
        if (!ace.is_allow) continue;
        if (ids.find(ace.trustee_sid) == ids.end()) continue;
        if (ace.mask & OfflineAceRight::ACE_GENERIC_WRITE) return true;
    }
    return false;
}

// Rule 4 — DCSync
// Matches ONLY the three specific DCSync extended-right GUIDs on the domain root
// AND on the Configuration NC (config_nc_aces_).
// GenericAll and AllExtendedRights-without-guid are intentionally excluded here:
//   • GenericAll is covered by Rule 3 (generic_all_domain).
//   • AllExtendedRights-without-guid is covered by Rule 7 (all_extended_rights).
// Including them here would create duplicate admin_rules entries and inflate severity.
bool OfflineProcessor::rule_04_dcsync(const std::set<std::string>& ids) const {
    static const char* GUIDS[] = {
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  // DS-Replication-Get-Changes
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  // DS-Replication-Get-Changes-All
        "89e95b76-444d-4c62-991a-0facbeda640c",  // DS-Replication-Get-Changes-In-Filtered-Set
        nullptr
    };

    // Helper: scan one ACE list for DCSync GUIDs only
    auto scan = [&](const std::vector<RawAceEntry>& aces) -> bool {
        for (const auto& ace : aces) {
            if (!ace.is_allow) continue;
            if (ids.find(ace.trustee_sid) == ids.end()) continue;
            if (ace.object_type_guid.empty()) continue;  // must be a specific GUID
            if (!(ace.mask & OfflineAceRight::ACE_ALL_EXTENDED)) continue;
            for (int i = 0; GUIDS[i]; ++i)
                if (ace.object_type_guid == GUIDS[i]) return true;
        }
        return false;
    };

    // Check domain root ACEs and Configuration NC ACEs
    return scan(domain_root_aces_) || scan(config_nc_aces_);
}

// Rule 6 — AdminSDHolder dangerous rights
bool OfflineProcessor::rule_06_adminsdholder(const std::set<std::string>& ids) const {
    for (const auto& ace : adminsdholder_aces_) {
        if (ace_has_dangerous_right(ace, ids)) return true;
        if (!ace.is_allow) continue;
        if (ids.find(ace.trustee_sid) == ids.end()) continue;
        if (ace.mask & OfflineAceRight::ACE_GENERIC_WRITE) return true;
    }
    return false;
}

// Rule 7 — AllExtendedRights on domain (includes DCSync GUIDs + User-Force-Change-Password)
// Also checks Configuration NC ACEs where AllExtendedRights can grant DCSync.
bool OfflineProcessor::rule_07_all_extended_rights(const std::set<std::string>& ids) const {
    static const char* GUIDS[] = {
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        "89e95b76-444d-4c62-991a-0facbeda640c",
        "00299570-246d-11d0-a768-00aa006e0529",
        nullptr
    };

    auto scan = [&](const std::vector<RawAceEntry>& aces) -> bool {
        for (const auto& ace : aces) {
            if (!ace.is_allow) continue;
            if (ids.find(ace.trustee_sid) == ids.end()) continue;
            if ((ace.mask & OfflineAceRight::ACE_GENERIC_ALL) == OfflineAceRight::ACE_GENERIC_ALL)
                return true;
            if (!(ace.mask & OfflineAceRight::ACE_ALL_EXTENDED)) continue;
            if (ace.object_type_guid.empty()) return true;
            for (int i = 0; GUIDS[i]; ++i)
                if (ace.object_type_guid == GUIDS[i]) return true;
        }
        return false;
    };

    return scan(domain_root_aces_) || scan(config_nc_aces_);
}

// Rule 8 — Nested → Domain Admins
// If any rule-1 RID is found in the token group SIDs
bool OfflineProcessor::rule_08_nested_domain_admins(const std::set<std::string>& all_sids) {
    static const int rids[] = {
        OfflineAdminRID::DOMAIN_ADMINS, OfflineAdminRID::ENTERPRISE_ADMINS,
        OfflineAdminRID::SCHEMA_ADMINS, OfflineAdminRID::BUILTIN_ADMINS,
        OfflineAdminRID::DOMAIN_CONTROLLERS, OfflineAdminRID::ENTERPRISE_READONLY_CONTROLLERS,
        OfflineAdminRID::ONLY_DOMAIN_CONTROLLERS, 0
    };
    for (const auto& sid : all_sids) {
        int r = rid_from_sid(sid);
        for (int i = 0; rids[i]; ++i) if (r == rids[i]) return true;
    }
    return false;
}

bool OfflineProcessor::rule_09_shadow_cred_on_dc(const std::string& user_dn) const {
    // Searches for ACEs with msDS-KeyCredentialLink write rights.
    // Trustee: the user themselves, one of their token group SIDs, or their direct SID.
    // We check only trustee_sid against the SID matching user_dn —
    // when called from analyze_admin, user SID + token SIDs come from the ids set,
    // but this function only receives user_dn. So we use dn_to_sid_ lookup.

    static const char* KCL_GUID  = "5b47d60f-6090-40b2-9f37-2a4de88f3063";

    if (dc_object_aces_.empty()) return false;

    // user_dn → SID
    std::string user_sid;
    {
        auto it = dn_to_sid_.find(upper(user_dn));
        if (it != dn_to_sid_.end()) user_sid = upper(it->second);
    }
    if (user_sid.empty()) return false;

    // User's transitive group SIDs (from lookup table)
    std::set<std::string> identities;
    identities.insert(user_sid);
    for (const auto& [gsid, members] : group_transitive_sids_) {
        if (members.count(user_sid))
            identities.insert(gsid);
    }

    // Check ACEs for each DC object
    for (const auto& [dc_dn, aces] : dc_object_aces_) {
        for (const auto& ace : aces) {
            if (!ace.is_allow) continue;
            if (!identities.count(ace.trustee_sid)) continue;

            // GenericAll / Full-Control — allows everything including shadow creds
            if ((ace.mask & OfflineAceRight::ACE_GENERIC_ALL) ==
                 OfflineAceRight::ACE_GENERIC_ALL) return true;
            if (ace.mask & OfflineAceRight::ACE_GA_BIT)      return true;

            // WriteDACL/WriteOwner — can modify DACL to grant self KCL write
            if (ace.mask & OfflineAceRight::ACE_WRITE_DACL)  return true;
            if (ace.mask & OfflineAceRight::ACE_WRITE_OWNER) return true;

            // Direct msDS-KeyCredentialLink write
            // object_type_guid == KCL_GUID && ACE_DS_WRITE_PROP
            if ((ace.mask & OfflineAceRight::ACE_DS_WRITE_PROP) &&
                ace.object_type_guid == KCL_GUID) return true;

            // AllExtendedRights — if no guid, all extended rights are included
            if ((ace.mask & OfflineAceRight::ACE_ALL_EXTENDED) &&
                ace.object_type_guid.empty()) return true;
        }
    }
    return false;
}

// Rule 10 — DnsAdmins
bool OfflineProcessor::rule_10_dns_admins(const std::vector<std::string>& member_of_names,
                                            const std::set<std::string>& all_sids,
                                            const std::set<std::string>& dns_admins_sids)
{
    for (const auto& name : member_of_names)
        if (lower(std::string(name)).find("dnsadmins") != std::string::npos) return true;
    for (const auto& gsid : dns_admins_sids)
        if (all_sids.count(gsid)) return true;
    return false;
}

// Rule 12 — Nested → Operator groups
bool OfflineProcessor::rule_12_nested_operator_groups(const std::set<std::string>& all_sids) {
    static const int rids[] = {
        OfflineAdminRID::ACCOUNT_OPERATORS,
        OfflineAdminRID::SERVER_OPERATORS,
        OfflineAdminRID::BACKUP_OPERATORS,
        OfflineAdminRID::PRINT_OPERATORS,
        OfflineAdminRID::CRYPTOGRAPHIC_OPERATORS,
        OfflineAdminRID::HYPERV_ADMINISTRATORS,
        OfflineAdminRID::STORAGE_REPLICA_ADMINISTRATORS,
        OfflineAdminRID::KEY_ADMINS,
        OfflineAdminRID::ENTERPRISE_KEY_ADMINS,
        OfflineAdminRID::RAS_IAS_SERVERS,
        OfflineAdminRID::CERT_PUBLISHERS,
        OfflineAdminRID::REMOTE_MANAGEMENT_USERS,
        0
    };
    for (const auto& sid : all_sids) {
        int r = rid_from_sid(sid);
        for (int i = 0; rids[i]; ++i) if (r == rids[i]) return true;
    }
    return false;
}

// Rule 13 — krbtgt
bool OfflineProcessor::rule_13_krbtgt(const std::string& user_sid) {
    return rid_from_sid(user_sid) == OfflineAdminRID::KRBTGT_RID;
}

// Rule 14 — Privileged primaryGroupID
bool OfflineProcessor::rule_14_privileged_primary(int primary_gid,
                                                    std::vector<PAdminRule>& out)
{
    static const struct { int rid; const char* label; } priv[] = {
        { 512, "Domain Admins — primary group (hidden membership)"              },
        { 519, "Enterprise Admins — primary group (hidden membership)"          },
        { 518, "Schema Admins — primary group (hidden membership)"              },
        { 517, "Cert Publishers — primary group (hidden membership)"            },
        { 544, "Administrators (Built-in) — primary group (hidden membership)"  },
        { 548, "Account Operators — primary group (hidden membership)"          },
        { 549, "Server Operators — primary group (hidden membership)"           },
        { 551, "Backup Operators — primary group (hidden membership)"           },
        { 516, "Domain Controllers — primary group (non-computer, suspicious)"  },
        {   0, nullptr }
    };
    if (primary_gid == 0) return false;
    for (int i = 0; priv[i].label; ++i) {
        if (primary_gid == priv[i].rid) {
            PAdminRule rule;
            rule.level    = 14;
            rule.severity = "absolute";
            rule.label    = "Privileged primaryGroupID (" +
                             std::string(priv[i].label) + ") — hidden from memberOf";
            out.push_back(rule);
            return true;
        }
    }
    return false;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 7 — analyze_admin  (aggregates all rules)
// ═════════════════════════════════════════════════════════════════════════════
void OfflineProcessor::analyze_admin(ProcessedUser& u) const {
    u.admin_rules.clear();
    u.is_admin        = false;
    u.is_direct_admin = false;
    u.is_nested_admin = false;

    // Identities set: token group SIDs + primary group SID + user's own SID
    std::set<std::string> all_sids;
    for (const auto& s : u.token_group_sids) all_sids.insert(upper(s));
    if (!u.domain_sid.empty() && u.primary_group_id > 0)
        all_sids.insert(upper(u.domain_sid + "-" + std::to_string(u.primary_group_id)));
    std::string user_sid_upper = upper(u.sid);

    // Rule 13 — krbtgt
    if (rule_13_krbtgt(user_sid_upper)) {
        PAdminRule r; r.level = 13; r.severity = "absolute";
        r.label = "krbtgt account (RID 502) — always absolute admin";
        u.admin_rules.push_back(r); u.is_admin = true;
    }

    // Rule 1
    bool r1 = rule_01_domain_admins(all_sids, u.primary_group_id,
                                    user_sid_upper, u.admin_rules);
    if (r1) u.is_admin = true;

    // Rule 2
    if (rule_02_operator_groups(all_sids, u.primary_group_id,
                                user_sid_upper, u.admin_rules))
        u.is_admin = true;

    // Rule 3
    std::set<std::string> ids = all_sids;
    if (!user_sid_upper.empty()) ids.insert(user_sid_upper);

    if (rule_03_generic_all_domain(ids)) {
        PAdminRule r; r.level = 3; r.severity = "tier1";
        r.label = "GenericAll+WriteOwner @ Domain root";
        u.admin_rules.push_back(r); u.is_admin = true;
    }

    // Rule 4 — DCSync
    if (rule_04_dcsync(ids)) {
        PAdminRule r; r.level = 4; r.severity = "tier1";
        r.label = "DS-Replication-Get-Changes-All — DCSync";
        u.admin_rules.push_back(r);
        u.is_admin = true; u.dcsync = true;
    }

    // Rule 6
    if (rule_06_adminsdholder(ids)) {
        PAdminRule r; r.level = 6; r.severity = "tier1";
        r.label = "AdminSDHolder — GA/WriteOwner/WriteDACL/GenericWrite/WriteProperty";
        u.admin_rules.push_back(r); u.is_admin = true;
    }

    // Rule 7
    if (rule_07_all_extended_rights(ids)) {
        PAdminRule r; r.level = 7; r.severity = "tier1";
        r.label = "AllExtendedRights @ Domain — includes DCSync";
        u.admin_rules.push_back(r); u.is_admin = true;
    }

    // Rule 8 — only if rule 1 did not match
    if (!r1 && rule_08_nested_domain_admins(all_sids)) {
        PAdminRule r; r.level = 8; r.severity = "absolute";
        r.label = "Nested group -> Domain Admins (Rule 1 groups)";
        u.admin_rules.push_back(r);
        u.is_admin = true; u.is_nested_admin = true;
    }

    // Rule 9
    if (rule_09_shadow_cred_on_dc(u.dn)) {
        PAdminRule r; r.level = 9; r.severity = "tier1";
        r.label = "Shadow Credentials write on DC object";
        u.admin_rules.push_back(r); u.is_admin = true;
    }

    // Rule 10
    if (rule_10_dns_admins(u.member_of, all_sids, dns_admins_sids_)) {
        PAdminRule r; r.level = 10; r.severity = "tier1";
        r.label = "DnsAdmins member — DLL injection on DC";
        u.admin_rules.push_back(r); u.is_admin = true;
    }

    // Rule 12
    if (rule_12_nested_operator_groups(all_sids)) {
        PAdminRule r; r.level = 12; r.severity = "tier1";
        r.label = "Nested group -> Operator Groups (Rule 2 groups)";
        u.admin_rules.push_back(r); u.is_admin = true;
    }

    // Rule 14
    if (rule_14_privileged_primary(u.primary_group_id, u.admin_rules))
        u.is_admin = true;

    // is_direct_admin: check CN names in member_of AND token-group RIDs
    // (DN set-intersection is unreliable when ldap3 returns mismatched formats)
    static const char* DIRECT_ADMIN_CNS[] = {
        "domain admins", "enterprise admins", "schema admins",
        "administrators", "builtin administrators",
        "domain controllers",
        "enterprise read-only domain controllers",
        "read-only domain controllers",
        nullptr
    };
    for (const auto& g : u.member_of) {
        std::string gl = lower(g);
        for (int i = 0; DIRECT_ADMIN_CNS[i]; ++i) {
            if (gl == DIRECT_ADMIN_CNS[i]) { u.is_direct_admin = true; break; }
        }
        if (u.is_direct_admin) break;
    }
    // Fallback: if not found by name, trust rule_01 match with non-nested source
    if (!u.is_direct_admin && r1) {
        for (const auto& rule : u.admin_rules) {
            if (rule.level != 1) continue;
            for (const auto& src : rule.detail.match_sources) {
                if (src == "token_group" || src == "user_sid") {
                    u.is_direct_admin = true; break;
                }
            }
            break;
        }
    }

    // potential_admin: has tier1 but no absolute
    bool has_absolute = false;
    for (const auto& r : u.admin_rules)
        if (r.severity == "absolute") { has_absolute = true; break; }
    if (u.is_admin && !has_absolute) {
        u.is_admin        = false;
        u.potential_admin = "PAD";
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 8 — UAC / encryption / delegation  (same as user_enum.cpp)
// ═════════════════════════════════════════════════════════════════════════════

void OfflineProcessor::decode_uac(ProcessedUser& u, int uac) const {
    u.uac_flags          = uac;
    u.disabled           = (uac & UAC::ACCOUNTDISABLE)       != 0;
    u.locked_out         = (uac & UAC::LOCKOUT)              != 0;
    u.smartcard_required = (uac & UAC::SMARTCARD_REQUIRED)   != 0;
    u.normal_account     = (uac & UAC::NORMAL_ACCOUNT)       != 0;
    u.pwd_never_expires  = (uac & UAC::DONT_EXPIRE_PASSWORD) != 0;
    u.pwd_not_required   = (uac & UAC::PASSWD_NOTREQD)       != 0;
    u.pwd_cant_change    = (uac & UAC::PASSWD_CANT_CHANGE)   != 0;
    u.preauth_required   = (uac & UAC::DONT_REQ_PREAUTH)     == 0;
}

void OfflineProcessor::analyze_encryption(ProcessedUser& u) const {
    int enc = u.msds_supportedencryptiontypes;
    bool absent = (enc == -1);
    u.enc_implicit_rc4 = absent || (enc == 0);

    // Each entry stored as a compact JSON object — serialized raw in user_to_json
    // to match Python format: [{"name": "RC4-HMAC", "risk": 700, "is_weak": true}]
    static const struct { int bit; const char* name; int risk; } ENC_MAP[] = {
        { 0x001, "DES-CBC-CRC",                      950 },
        { 0x002, "DES-CBC-MD5",                      900 },
        { 0x004, "RC4-HMAC",                         700 },
        { 0x008, "AES128-CTS-HMAC-SHA1-96",          200 },
        { 0x010, "AES256-CTS-HMAC-SHA1-96",          100 },
        { 0x040, "AES256-CTS-HMAC-SHA1-96-SK",        80 },
        { 0x080, "AES128-CTS-HMAC-SHA256-128",        60 },
        { 0x100, "AES256-CTS-HMAC-SHA384-192",        40 },
        { 0, nullptr, 0 }
    };

    u.msds_supportedencryptiontypesname.clear();
    if (!absent && enc != 0) {
        for (int i = 0; ENC_MAP[i].name; ++i) {
            if (enc & ENC_MAP[i].bit) {
                bool is_weak = ENC_MAP[i].risk > 500;
                std::string entry = "{\"name\":\"";
                entry += ENC_MAP[i].name;
                entry += "\",\"risk\":";
                entry += std::to_string(ENC_MAP[i].risk);
                entry += ",\"is_weak\":";
                entry += (is_weak ? "true" : "false");
                entry += "}";
                u.msds_supportedencryptiontypesname.push_back(entry);
            }
        }
    }

    // Risk score — highest risk among active algorithm bits
    int max_risk = 0;
    if (!absent && enc != 0) {
        if (enc & 0x001) max_risk = std::max(max_risk, 950);
        if (enc & 0x002) max_risk = std::max(max_risk, 900);
        if (enc & 0x004) max_risk = std::max(max_risk, 700);
        if (enc & 0x008) max_risk = std::max(max_risk, 200);
        if (enc & 0x010) max_risk = std::max(max_risk, 100);
    } else if (u.enc_implicit_rc4) {
        max_risk = 700;
    }
    u.enc_risk_score = max_risk;

    if (u.unconstrained_delegation && u.enc_risk_score > 0)
        u.enc_risk_score = std::min(1000, u.enc_risk_score + 200);
    else if (u.constrained_delegation && u.enc_risk_score > 0)
        u.enc_risk_score = std::min(1000, u.enc_risk_score + 100);
}

void OfflineProcessor::analyze_delegation(ProcessedUser& u) const {
    // uac_flags is populated only when decode_uac() has been called (online path).
    // In the offline path parse_raw_user() reads pre-decoded booleans directly from
    // raw_users.jsonl (the collector already writes unconstrained_delegation, etc.).
    // In that case uac_flags == 0 and re-deriving from the bitmask would silently
    // zero-out every delegation flag that the collector correctly set.
    //
    // Rule: prefer the UAC bitmask when it is non-zero (online / decode_uac path);
    //       fall back to the already-set booleans when uac_flags == 0 (offline path).
    if (u.uac_flags != 0) {
        u.unconstrained_delegation       = (u.uac_flags & UAC::TRUSTED_FOR_DELEGATION)  != 0;
        u.protocol_transition_delegation = (u.uac_flags & UAC::TRUSTED_TO_AUTH_FOR_DEL) != 0;
        u.delegation_blocked             = (u.uac_flags & UAC::NOT_DELEGATED)            != 0;
        u.trusted_for_delegation         = u.unconstrained_delegation;
        u.trusted_to_auth_for_delegation = u.protocol_transition_delegation;
        u.not_delegated                  = u.delegation_blocked;
    } else {
        // Offline path: boolean fields already set from JSONL by parse_raw_user().
        // Sync the aliased fields that the collector does not write explicitly.
        u.delegation_blocked             = u.not_delegated;
        u.protocol_transition_delegation = u.trusted_to_auth_for_delegation;
    }

    // constrained_delegation: authoritative source is the SPN list, not the stored bool.
    u.constrained_delegation = !u.msds_allowedtodelegateto.empty();

    u.delegation_effective = (u.unconstrained_delegation || u.constrained_delegation)
                              && !u.delegation_blocked;

    for (const auto& s : u.msds_allowedtodelegateto) {
        PDelegationTarget dt; dt.raw = s;
        size_t slash1 = s.find('/');
        if (slash1 == std::string::npos) {
            dt.service = s; dt.host_fqdn = s; dt.hostname = s;
        } else {
            dt.service = s.substr(0, slash1);
            std::string rest = s.substr(slash1 + 1);
            size_t slash2 = rest.find('/');
            if (slash2 != std::string::npos) {
                dt.host_fqdn = rest.substr(0, slash2);
                dt.domain    = rest.substr(slash2 + 1);
            } else { dt.host_fqdn = rest; }
            size_t dot = dt.host_fqdn.find('.');
            dt.hostname = (dot != std::string::npos)
                          ? dt.host_fqdn.substr(0, dot) : dt.host_fqdn;
            if (!dt.domain.empty()) {
                size_t last_dot = dt.domain.rfind('.');
                dt.domain_short = (last_dot != std::string::npos)
                                  ? dt.domain.substr(0, last_dot) : dt.domain;
            }
        }
        u.msds_allowedtodelegateto_structurized.push_back(dt);
    }
}