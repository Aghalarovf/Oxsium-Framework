#pragma once
#include "../../include/core.h"
#include <filesystem>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>


namespace fs = std::filesystem;

namespace OfflineAdminRID {
    constexpr int DOMAIN_ADMINS                   = 512;
    constexpr int DOMAIN_USERS                    = 513;
    constexpr int DOMAIN_GUESTS                   = 514;
    constexpr int ENTERPRISE_ADMINS               = 519;
    constexpr int SCHEMA_ADMINS                   = 518;
    constexpr int GROUP_POLICY_CREATORS           = 520;
    constexpr int BUILTIN_ADMINS                  = 544;
    constexpr int KRBTGT_RID                      = 502;
    constexpr int DOMAIN_CONTROLLERS              = 516;
    constexpr int ENTERPRISE_READONLY_CONTROLLERS = 498;
    constexpr int ONLY_DOMAIN_CONTROLLERS         = 521;
    constexpr int ACCOUNT_OPERATORS               = 548;
    constexpr int SERVER_OPERATORS                = 549;
    constexpr int BACKUP_OPERATORS                = 551;
    constexpr int PRINT_OPERATORS                 = 550;
    constexpr int CRYPTOGRAPHIC_OPERATORS         = 569;
    constexpr int HYPERV_ADMINISTRATORS           = 578;
    constexpr int STORAGE_REPLICA_ADMINISTRATORS  = 582;
    constexpr int KEY_ADMINS                      = 526;
    constexpr int ENTERPRISE_KEY_ADMINS           = 527;
    constexpr int RAS_IAS_SERVERS                 = 553;
    constexpr int CERT_PUBLISHERS                 = 557;
    constexpr int REMOTE_MANAGEMENT_USERS         = 580;
}

namespace OfflineAceRight {
    constexpr unsigned int ACE_GENERIC_ALL   = 0x000F01FF;  // AD-də expand edilmiş GenericAll (composed)
    // FIX: Python constants.py-dakı GENERIC_ALL_RAW = 0x10000000 ilə ekvivalent.
    // Windows-un xam Generic-All access mask biti; AD object ACE-lərində
    // composed formdan (0x000F01FF) ASILI OLMAYARAQ tək başına gələ bilir.
    constexpr unsigned int ACE_GENERIC_ALL_RAW = 0x10000000;
    constexpr unsigned int ACE_GA_BIT        = 0x00100000;
    constexpr unsigned int ACE_GENERIC_WRITE = 0x40000000;
    constexpr unsigned int ACE_WRITE_DACL    = 0x00040000;
    constexpr unsigned int ACE_WRITE_OWNER   = 0x00080000;
    constexpr unsigned int ACE_DS_WRITE_PROP = 0x00000020;
    constexpr unsigned int ACE_ALL_EXTENDED  = 0x00000100;
    constexpr unsigned int ACE_READ_CONTROL  = 0x00020000;
    constexpr unsigned int ACE_DELETE        = 0x00010000;
    constexpr unsigned int ACE_CREATE_CHILD  = 0x00000001;
    constexpr unsigned int ACE_DELETE_CHILD  = 0x00000002;
    constexpr unsigned int ACE_LIST_OBJECT   = 0x00000080;
}

struct RawAceEntry {
    std::string  trustee_sid;
    unsigned int mask                        = 0;
    bool         is_allow                    = true;
    bool         is_inherited                = false;
    std::string  object_type_guid;           // empty = not present
    std::string  inherited_object_type_guid;
};

struct RawObjectAces {
    std::string              dn;
    std::string              object_class;
    std::vector<RawAceEntry> aces;
};


struct PAdminRuleDetail {
    std::vector<int>         matched_rids;
    std::vector<std::string> matched_sids;
    std::vector<std::string> matched_groups;
    std::vector<std::string> match_sources;
};

struct PAdminRule {
    int             level     = 0;
    std::string     severity;
    std::string     label;
    PAdminRuleDetail detail;
    bool            has_detail = false;
};

struct PDelegationTarget {
    std::string raw;
    std::string service;
    std::string hostname;
    std::string host_fqdn;
    std::string domain;
    std::string domain_short;
};

struct ProcessedUser {
    // identity
    std::string username;
    std::string dn;
    std::string display_name;
    std::string sid;
    std::string domain_sid;
    std::string upn;
    std::string description;
    std::string mail;
    std::string phone;
    std::string department;
    std::string title;
    std::string domain_name;

    // UAC flags
    bool disabled            = false;
    bool locked_out          = false;
    bool must_change_pwd     = false;
    bool smartcard_required  = false;
    bool normal_account      = true;
    bool pwd_never_expires   = false;
    bool pwd_not_required    = false;
    bool pwd_cant_change     = false;
    bool preauth_required    = true;
    int  uac_flags           = 0;

    // admin analysis
    bool is_admin            = false;
    std::string potential_admin;
    bool is_direct_admin     = false;
    bool is_nested_admin     = false;
    std::vector<PAdminRule> admin_rules;

    // attack paths
    bool dcsync              = false;
    bool asrep               = false;
    bool kerberoastable      = false;

    // kerberos / delegation
    std::vector<std::string>       spn;
    bool trusted_for_delegation          = false;
    bool unconstrained_delegation        = false;
    bool constrained_delegation          = false;
    bool delegation_effective            = false;
    bool delegation_blocked              = false;
    bool trusted_to_auth_for_delegation  = false;
    bool protocol_transition_delegation  = false;
    bool not_delegated                   = false;
    std::vector<std::string>       msds_allowedtodelegateto;
    std::vector<PDelegationTarget> msds_allowedtodelegateto_structurized;

    // encryption
    int  msds_supportedencryptiontypes = -1;
    std::vector<std::string> msds_supportedencryptiontypesname;
    int  enc_risk_score      = 0;
    bool enc_implicit_rc4    = false;

    // group membership
    std::vector<std::string> member_of;       // CN display names
    std::vector<std::string> token_group_sids;

    // timestamps
    std::string when_created;
    std::string when_changed;
    std::string last_logon;
    std::string pwd_last_set;
    int         logon_count          = 0;
    int         primary_group_id     = 0;
    std::string primary_group_sid;
    int         bad_pwd_count        = 0;
    std::string bad_pwd_time;
    std::string account_expires;
    bool        account_never_expires = false;
    std::string msds_resultant_pso;
    std::string pwd_expiry_time;

    // shadow credentials
    bool has_key_credential_link = false;

    // logon script / home
    std::string script_path;
    std::string home_directory;
    std::string home_drive;
};

struct ProcessedGroup {
    std::string sam_account_name;
    std::string dn;
    std::string display_name;
    std::string description;
    std::string sid;
    int         rid                  = 0;
    std::string group_type;
    std::string group_scope;
    std::string managed_by;
    std::string admin_count;
    bool        is_protected         = false;
    std::string when_created;
    std::string when_changed;

    // membership
    std::vector<std::string> direct_member_dns;
    std::vector<std::string> member_of;
    std::vector<std::string> transitive_member_dns;
    std::vector<std::string> transitive_member_sids;
    int transitive_member_count = 0;

    // computed
    bool is_admin_group      = false;
    bool is_operator_group   = false;
    int  member_user_count   = 0;
    int  member_group_count  = 0;
    int  member_computer_count = 0;
};

struct ProcessedAce {
    std::string  trustee_sid;
    std::string  mask_hex;
    unsigned int mask            = 0;
    bool         is_allow        = true;
    bool         is_inherited    = false;
    std::string  object_type_guid;
    std::string  inherited_object_type_guid;

    std::string  trustee_name;          // SAM or well-known name
    std::string  trustee_display_name;  // displayName (if available)
    std::string  trustee_type;          // user | group | computer | well_known | unknown
    bool         trustee_is_admin       = false;  // is trustee in an admin group?
    std::vector<std::string> rights_labels;
    bool         is_dangerous           = false;
    std::string  danger_reason;
    std::string  guid_name;             // ObjectType GUID → known name
    std::string  inherited_guid_name;   // InheritedObjectType GUID → known name
};

struct ProcessedAceObject {
    std::string              dn;
    std::string              object_class;
    std::string              sam_name;      // from dn_to_sam_ lookup
    std::vector<ProcessedAce> aces;

    // Aggregate flags
    int  total_ace_count       = 0;
    int  dangerous_ace_count   = 0;
    int  allow_ace_count       = 0;
    int  deny_ace_count        = 0;
    bool has_dangerous_aces    = false;
};

struct ProcessedComputer {

    std::string computer_name;
    std::string dns_name;
    std::string dn;
    std::string display_name;
    std::string sid;
    std::string domain_sid;
    std::string description;

    bool disabled = false;

    std::string os;
    std::string os_version;
    std::string os_service_pack;
    std::string os_bucket;          // "server" | "workstation" | "dc" | "other"

    bool is_workstation        = false;
    bool is_server             = false;
    bool is_domain_controller  = false;
    bool potential_privileged  = false;

    bool is_stale       = false;
    bool stale_by_pwd   = false;
    bool stale_by_logon = false;

    std::vector<std::string> spn;
    bool has_spn = false;

    bool trusted_for_delegation              = false;
    bool trusted_to_auth_for_delegation      = false;
    bool unconstrained_delegation            = false;
    bool constrained_delegation              = false;
    bool protocol_transition_delegation      = false;
    bool delegation_effective                = false;
    std::vector<std::string>       allowed_to_delegate_to;
    std::vector<PDelegationTarget> allowed_to_delegate_to_structured;

    bool rbcd_enabled = false;
    std::string rbcd_sddl;                      // reconstructed SDDL string
    std::vector<std::string> rbcd_principals;       // raw SIDs from collector
    std::vector<std::string> rbcd_principal_names;  // enriched: SID → SAM name

    bool        has_laps        = false;
    bool        haslaps         = false;
    std::string laps_expiration;
    // Full per-attribute values forwarded from collector (key → raw values)
    std::map<std::string, std::vector<std::string>> laps_attributes;

    bool isaclprotected = false;

    std::vector<std::string> sid_history;

    std::vector<std::string> token_group_sids;
    int         primary_group_id  = 0;
    std::string primary_group_sid;

    bool kerberoastable        = false;  // has_spn && !disabled
    bool asrep                 = false;  // !preauth_required (rare for computers, still tracked)
    bool preauth_required      = true;
    bool has_shadow_credential = false;  // msDS-KeyCredentialLink present

    int                      risk_score   = 0;
    std::vector<std::string> risk_factors;
    std::vector<std::string> risk_controls; // from collector (e.g. "Domain Controller", "LAPS")

    bool        is_ip_only           = false;
    bool        smb_port_open        = false;
    bool        smb_signing_required = false;
    std::string smb_version;
    std::vector<std::string> ipv4_addresses;
    std::vector<std::string> ipv6_addresses;
    bool        net_probed = false; // true when SMB probe fields are present in collector output

    std::string when_created;
    std::string when_changed;
    std::string last_logon;
    std::string pwd_last_set;

    // ── Domain ────────────────────────────────────────────────────────────────
    std::string location;
    std::string domain_name;
};

struct ProcessedOU {
    std::string name;
    std::string dn;
    std::string description;
    std::string managed_by;
    std::string managed_by_name;
    std::string object_guid;
    std::string object_id;

    std::string parent_dn;
    std::vector<std::string> child_ous;
    int depth = 0;

    std::string gpo_links_raw;
    std::string linked_gpos_raw;
    std::string gpo_precedence_raw;
    std::string inherited_gpos_raw;
    bool has_gpo_links = false;
    bool inheritance_blocked = false;
    bool blocksinheritance = false;
    int gp_options = 0;
    int gpo_count = 0;
    int inherited_gpo_count = 0;

    int object_count = 0;

    std::string privileged_users_raw;
    int privileged_users_count = 0;
    std::string privileged_computers_raw;
    int privileged_computers_count = 0;

    bool delegated_permissions = false;
    bool highvalue = false;
    bool high_risk = false;
    bool isaclprotected = false;

    int risk_score = 0;
    std::vector<std::string> risk_controls;

    std::string domain_sid;
    std::string domain_name;
    std::string when_created;
    std::string when_changed;
};

struct ProcessedGPO {
    // ── Identity ──────────────────────────────────────────────────────────────
    std::string name;              // CN-level GUID, e.g. {31B2F340-...}
    std::string guid;              // objectGUID (may differ from CN name)
    std::string display_name;
    std::string description;
    std::string dn;
    std::string path;              // gPCFileSysPath (UNC SYSVOL path)
    std::string managed_by;        // DN of delegated manager

    // ── Domain ────────────────────────────────────────────────────────────────
    std::string domain_name;
    std::string domain_sid;

    // ── Timestamps ────────────────────────────────────────────────────────────
    std::string when_created;      // ISO-8601 (already converted by collector)
    std::string when_changed;

    // ── Version ───────────────────────────────────────────────────────────────
    int version          = 0;      // raw versionNumber
    int user_version     = 0;      // high 16 bits
    int computer_version = 0;      // low 16 bits

    // ── GPO flags ─────────────────────────────────────────────────────────────
    int  flags                      = 0;
    bool user_settings_disabled     = false;  // flags & 1
    bool computer_settings_disabled = false;  // flags & 2

    // ── Link data ─────────────────────────────────────────────────────────────
    std::vector<std::string> linked_containers;
    int  linked_count  = 0;
    bool enforced      = false;   // any link has flag bit 2
    bool link_disabled = false;   // any link has flag bit 1

    // ── ACL / Owner ───────────────────────────────────────────────────────────
    bool        isaclprotected = false;
    std::string owner_sid;
    std::string owner_name;        // resolved via sid_to_dn_ + dn_to_sam_

    // ── Extension GUIDs (raw JSON arrays from collector) ──────────────────────
    std::string user_extensions_raw;     // "[{"guid":"...","name":"..."}]"
    std::string machine_extensions_raw;

    // ── Risk ──────────────────────────────────────────────────────────────────
    bool                     highvalue    = false;
    std::vector<std::string> risk_controls;  // forwarded from collector
    int                      risk_score   = 0;
    bool                     high_risk    = false;
    bool                     orphaned     = false; // linked_count == 0
};

struct OfflineProcessorOptions {
    std::string raw_dir    = "raw_cache";   // raw_users.jsonl, raw_groups.jsonl, raw_aces.jsonl
    std::string output_dir = "Domain Objects";
    std::string domain_name;               // optional — read from raw_users if empty
    std::string output_ext = "jsonl";     // "jsonl" (default) or "json"
    std::string target_cidr;               // optional — scanned CIDR (e.g. "192.168.1.0/24")
                                           // used by NetworkProcessor for gateway detection
};

class OfflineProcessor {
public:
    explicit OfflineProcessor() = default;

    // Main entry point — process all supported outputs together
    bool process(const OfflineProcessorOptions& opts = {});

    // Can be run independently
    bool process_users        (const OfflineProcessorOptions& opts = {});
    bool process_groups       (const OfflineProcessorOptions& opts = {});
    bool process_aces         (const OfflineProcessorOptions& opts = {});
    bool process_computers    (const OfflineProcessorOptions& opts = {});
    bool process_ous          (const OfflineProcessorOptions& opts = {});
    bool process_gpos         (const OfflineProcessorOptions& opts = {});
    bool process_network      (const OfflineProcessorOptions& opts = {});
    bool process_certificates (const OfflineProcessorOptions& opts = {});
    bool process_domaininfo   (const OfflineProcessorOptions& opts = {});
    bool process_trusts       (const OfflineProcessorOptions& opts = {});

    bool enrich_network_mac_vendors(const std::string& in_path,
                                    const std::string& out_path) const;
    bool enrich_network_mac_vendors(const OfflineProcessorOptions& opts = {}) const;

    // ── Minimal JSON parser helpers (public — used by cert processing helpers) ─
    static std::string  jp_str (const std::string& json, const std::string& key);
    static int          jp_int (const std::string& json, const std::string& key, int def = 0);
    static bool         jp_bool(const std::string& json, const std::string& key, bool def = false);
    static std::vector<std::string> jp_arr(const std::string& json, const std::string& key);
    static std::string  jp_extract_array(const std::string& json, const std::string& key);
    static std::string  jp_extract_obj  (const std::string& json, const std::string& key);
    static int          count_json_array_items(const std::string& json_array);

    // ── Generic JSON emit helpers (public — used by cert processing helpers) ──
    static std::string  je (const std::string& s);
    static std::string  jb (bool v);
    static std::string  ji (int v);
    static std::string  jnl(const std::string& s);
    static std::string  ja (const std::vector<std::string>& v);

private:
    // ── Lookup tables (populated from raw JSON) ──────────────────────────
    std::unordered_map<std::string, std::string> sid_to_dn_;
    std::unordered_map<std::string, std::string> dn_to_sid_;
    std::unordered_map<std::string, std::string> dn_to_class_;
    std::unordered_map<std::string, std::string> dn_to_sam_;
    // SID → displayName (user/group)
    std::unordered_map<std::string, std::string> sid_to_display_;
    // Group SID → transitive member SID set
    std::unordered_map<std::string, std::set<std::string>> group_transitive_sids_;
    // Domain root ACEs
    std::vector<RawAceEntry> domain_root_aces_;
    // AdminSDHolder ACEs
    std::vector<RawAceEntry> adminsdholder_aces_;
    // Configuration NC ACEs — DCSync GUIDs can live here too (Rules 4 & 7)
    std::vector<RawAceEntry> config_nc_aces_;
    // DC object ACEs  — DN (upper) → ACE list
    // Rule 9: for checking msDS-KeyCredentialLink write on DC objects
    std::unordered_map<std::string, std::vector<RawAceEntry>> dc_object_aces_;
    // DnsAdmins group SIDs
    std::set<std::string> dns_admins_sids_;
    // Admin group SIDs (rule-1 groups) — for ACE trustee analysis
    std::set<std::string> admin_group_sids_;
    // Base DN (read from raw files)
    std::string base_dn_;
    std::string domain_name_;
    std::string ldap_target_;

    // ── Phase 0 — populate lookup tables ─────────────────────────────────
    bool build_lookup_tables(const std::string& raw_dir);
    bool load_raw_users_lookup (const std::string& path);
    bool load_raw_groups_lookup(const std::string& path);
    bool load_raw_aces_lookup  (const std::string& path);

    // ── Computer processing ───────────────────────────────────────────────────
    bool load_and_process_computers(const std::string& raw_path,
                                    const std::string& out_path);
    ProcessedComputer parse_raw_computer   (const std::string& json_obj) const;
    void              analyze_computer_delegation(ProcessedComputer& c) const;
    void              analyze_computer_risk      (ProcessedComputer& c) const;
    std::string       computer_to_json           (const ProcessedComputer& c) const;

    // ── OU processing ────────────────────────────────────────────────────────
    bool load_and_process_ous(const std::string& raw_path,
                              const std::string& out_path);
    ProcessedOU parse_raw_ou(const std::string& json_obj) const;
    void        analyze_ou_risk(ProcessedOU& ou) const;
    std::string ou_to_json(const ProcessedOU& ou) const;

    // ── GPO processing ───────────────────────────────────────────────────────
    bool         load_and_process_gpos(const std::string& raw_path,
                                       const std::string& out_path);
    ProcessedGPO parse_raw_gpo        (const std::string& json_obj) const;
    void         analyze_gpo_risk     (ProcessedGPO& g) const;
    std::string  gpo_to_json          (const ProcessedGPO& g) const;

    bool load_and_process_cert_templates(const std::string& raw_path,
                                         const std::string& out_path) const;
    bool load_and_process_pki_objects   (const std::string& raw_path,
                                         const std::string& out_path) const;

    // ── User processing ───────────────────────────────────────────────────
    bool load_and_process_users(const std::string& raw_path,
                                const std::string& out_path);
    ProcessedUser parse_raw_user(const std::string& json_obj) const;
    void          decode_uac    (ProcessedUser& u, int uac) const;
    void          analyze_encryption(ProcessedUser& u) const;
    void          analyze_delegation(ProcessedUser& u) const;
    void          analyze_admin (ProcessedUser& u) const;

    // Admin rules
    static bool rule_01_domain_admins    (const std::set<std::string>& all_sids,
                                          int primary_gid,
                                          const std::string& user_sid,
                                          std::vector<PAdminRule>& out);
    static bool rule_02_operator_groups  (const std::set<std::string>& all_sids,
                                          int primary_gid,
                                          const std::string& user_sid,
                                          std::vector<PAdminRule>& out);
    bool        rule_03_generic_all_domain(const std::set<std::string>& identities) const;
    bool        rule_04_dcsync           (const std::set<std::string>& identities) const;
    bool        rule_06_adminsdholder    (const std::set<std::string>& identities) const;
    bool        rule_07_all_extended_rights(const std::set<std::string>& identities) const;
    static bool rule_08_nested_domain_admins(const std::set<std::string>& all_sids);
    bool        rule_09_shadow_cred_on_dc(const std::string& user_dn) const;
    static bool rule_10_dns_admins       (const std::vector<std::string>& member_of_names,
                                          const std::set<std::string>& all_sids,
                                          const std::set<std::string>& dns_admins_sids);
    static bool rule_12_nested_operator_groups(const std::set<std::string>& all_sids);
    static bool rule_13_krbtgt           (const std::string& user_sid);
    static bool rule_14_privileged_primary(int primary_gid,
                                           std::vector<PAdminRule>& out);

    // ACE helper
    static bool ace_has_dangerous_right(const RawAceEntry& ace,
                                        const std::set<std::string>& ids);
    static bool is_dangerous_right   (const std::string& right);
    static bool is_extended_right    (const std::string& right);
    static bool ace_has_any_dangerous(const ProcessedAce& a);
    static bool ace_has_any_extended (const ProcessedAce& a);

    // ── Group processing ──────────────────────────────────────────────────
    bool load_and_process_groups(const std::string& raw_path,
                                 const std::string& out_path);
    ProcessedGroup parse_raw_group(const std::string& json_obj) const;
    void           compute_group_stats(ProcessedGroup& g) const;

    bool load_and_process_aces(const std::string& raw_path,
                               const std::string& out_path);

    // Parses one raw ACE object JSON string and returns a ProcessedAce
    ProcessedAce enrich_ace(const RawAceEntry& raw) const;

    // Parses one raw object block (dn + aces array) and returns a ProcessedAceObject
    ProcessedAceObject enrich_ace_object(
        const std::string& dn,
        const std::string& object_class,
        const std::vector<RawAceEntry>& raw_aces) const;

    // mask → rights labels list
    static std::vector<std::string> mask_to_rights(unsigned int mask,
                                                    const std::string& object_type_guid);

    // mask + guid → description of first dangerous right found, empty = none
    static std::string find_danger_reason(unsigned int mask,
                                          const std::string& object_type_guid,
                                          bool is_allow);

    // SID → trustee type ("user" | "group" | "computer" | "well_known" | "unknown")
    std::string trustee_type_from_sid(const std::string& sid) const;

    // trustee SID → {name, display_name}  (lookup + well-known SID table)
    std::pair<std::string,std::string> resolve_trustee(const std::string& sid) const;

    // trustee admin flag (intersection with admin_group_sids_)
    bool trustee_is_admin(const std::string& trustee_sid) const;

    // Well-known SID table — static
    static const std::string& well_known_sid_name(const std::string& sid);

    // Well-known AD GUID table — static
    static const std::string& guid_to_name(const std::string& guid);

    // Parses one "objects" array element from raw_aces.jsonl and returns a raw ACE list
    // (different from load_raw_aces_lookup — works for ALL objects)
    static std::vector<RawAceEntry> parse_aces_block(const std::string& block);

    // ── JSON serialization ────────────────────────────────────────────────
    std::string user_to_json (const ProcessedUser&  u) const;
    std::string group_to_json(const ProcessedGroup& g) const;
    std::string ace_object_to_json(const ProcessedAceObject& obj) const;
    std::string ace_entry_to_json (const ProcessedAce& ace) const;

    // ── Output format helpers ─────────────────────────────────────────────
    //  Returns true if out_path ends with ".json" (exact JSON array output).
    static bool is_json_ext(const std::string& out_path);

    static bool write_objects(std::ofstream& out,
                              const std::vector<std::string>& rows,
                              const std::string& out_path,
                              const std::string& log_tag);


    static std::string json_admin_rules (const std::vector<PAdminRule>& rules);
    static std::string json_rule_detail (const PAdminRuleDetail& d);
    static std::string json_delegation_arr(const std::vector<PDelegationTarget>& v);
    static std::string json_rights_arr(const std::vector<std::string>& v);

    // ── Generic helpers (remainder) ───────────────────────────────────────
    static int          rid_from_sid(const std::string& sid);
    static std::string  upper(std::string s);
    static std::string  lower(std::string s);
    static std::string  trim (std::string s);
    static std::string  cn_from_dn(const std::string& dn);
    static std::string  base_dn_to_domain(const std::string& base_dn);
    static std::string  filetime_to_iso(const std::string& ft_raw);
    static std::string  generalized_time_to_iso(const std::string& gt);

    // NDJSON reader — each line is a JSON object (for collector outputs)
    static std::vector<std::string> read_ndjson_lines(const std::string& path);

    // Legacy wrapped-JSON array reader (backward compatibility)
    static std::vector<std::string> read_json_array(const std::string& path,
                                                     const std::string& array_key);
};