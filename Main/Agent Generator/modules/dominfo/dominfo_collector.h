#pragma once
#include "../../include/core.h"
#include "../../include/ldap_engine.h"
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  DomainInfoCollectorOptions
// ─────────────────────────────────────────────────────────────────────────────
struct DomainInfoCollectorOptions {
    std::string output_dir = "raw_cache";
};

// ─────────────────────────────────────────────────────────────────────────────
//  DomainInfoCollector  — Phase 1 / Extract
//
//  Targeted LDAP queries to collect domain-level security information:
//
//  Queries performed:
//    (1) Domain Root Object
//          base   : <domainNC>
//          scope  : BASE
//          attrs  : distinguishedName, name, dc, msDS-Behavior-Version,
//                   objectSid, nTSecurityDescriptor, pwdProperties,
//                   minPwdLength, maxPwdAge, minPwdAge, lockoutDuration,
//                   lockoutThreshold, lockoutObservationWindow, pwdHistoryLength,
//                   ms-DS-MachineAccountQuota
//          output : raw_domaininfo.jsonl
//
//    (2) Domain Controllers (computer objects with userAccountControl bit 0x2000)
//          base   : <domainNC>
//          filter : (userAccountControl:1.2.840.113556.1.4.803:=8192)
//          attrs  : distinguishedName, cn, dNSHostName, operatingSystem,
//                   operatingSystemVersion, whenCreated, userAccountControl,
//                   objectSid, servicePrincipalName, msDS-SupportedEncryptionTypes
//          output : raw_domaininfo.jsonl (embedded in domain object)
//
//    (3) FSMO Role Holders (5 single-object BASE lookups via well-known attribute paths)
//          - Schema Master     : CN=Schema,CN=Configuration,<forestNC>
//          - Domain Naming     : CN=Partitions,CN=Configuration,<forestNC>
//          - RID Master        : CN=RID Manager$,CN=System,<domainNC>
//          - PDC Emulator      : domain root fSMORoleOwner
//          - Infrastructure    : CN=Infrastructure,<domainNC>
//          output : embedded in domain object
//
//    (4) Password Settings Objects (Fine-Grained Password Policies)
//          base   : CN=Password Settings Container,CN=System,<domainNC>
//          filter : (objectClass=msDS-PasswordSettings)
//          attrs  : cn, msDS-MinimumPasswordLength, msDS-PasswordComplexityEnabled,
//                   msDS-MaximumPasswordAge, msDS-MinimumPasswordAge,
//                   msDS-LockoutDuration, msDS-LockoutThreshold,
//                   msDS-LockoutObservationWindow, msDS-PasswordHistoryLength,
//                   msDS-PasswordSettingsPrecedence, msDS-PSOAppliesTo
//          output : embedded in domain object
//
//    (5) Kerberos Policy (from Default Domain Policy GPO)
//          base   : CN=Default Domain Policy,CN=System,<domainNC>
//          scope  : BASE
//          attrs  : gPCMachineExtensionNames, distinguishedName
//          Reads krbtgt's msDS-MaxTicketAge / msDS-MaxRenewAge from:
//            CN=krbtgt,CN=Users,<domainNC>
//          output : embedded in domain object
//
//    (6) Enterprise CA detection (Enrollment Services)
//          base   : CN=Enrollment Services,CN=Public Key Services,
//                   CN=Services,CN=Configuration,<domainNC>
//          filter : (objectClass=pKIEnrollmentService)
//          attrs  : cn, dNSHostName, cACertificate
//          output : embedded in domain object (has_enterprise_ca flag + ca_list)
//
//    (7) LAPS detection
//          Checks for ms-Mcs-AdmPwd attribute schema presence:
//            base   : CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,<domainNC>
//            scope  : BASE
//          Also checks for Windows LAPS (msLAPS-Password):
//            base   : CN=msLAPS-Password,CN=Schema,CN=Configuration,<domainNC>
//            scope  : BASE
//          output : embedded in domain object (laps_legacy, laps_windows flags)
//
//    (8) DNS Zone Security
//          base   : CN=MicrosoftDNS,DC=DomainDnsZones,<domainNC>
//          filter : (objectClass=dnsZone)
//          attrs  : name, dnsProperty (zone flags byte checked for secure-only)
//          output : embedded in domain object (dns_zones array)
//
//    (9) Smart Card policy
//          Read from domain root: msDS-RequireSignOrSeal,
//          and from Default Domain Controllers Policy GPO: SmartCardRequired
//          output : embedded in domain object
//
//    (10) SMB Signing (from Default Domain Controllers Policy GPO)
//          base   : CN=Policies,CN=System,<domainNC>
//          filter : (cn={6AC1786C-016F-11D2-945F-00C04fB984F9})
//          attrs  : gPCFileSysPath (path to SYSVOL GptTmpl.inf — not read here;
//                   presence of DC Policy is noted; actual value requires SYSVOL access)
//          output : embedded as smb_signing_policy_present flag
//
//  Output schema — raw_domaininfo.jsonl (single-line JSON object):
//  {
//    "fqdn"                      : "corp.local",
//    "netbios_name"              : "CORP",
//    "domain_sid"                : "S-1-5-21-...",
//    "functional_level"          : 7,
//    "functional_level_name"     : "Windows Server 2016",
//    "generated_at"              : "2026-05-29T07:50:43Z",
//
//    "domain_controllers"        : [
//      {
//        "dn"          : "CN=DC01,...",
//        "cn"          : "DC01",
//        "dns_name"    : "dc01.corp.local",
//        "os"          : "Windows Server 2019 Standard",
//        "os_version"  : "10.0 (17763)",
//        "sid"         : "S-1-5-21-...-1000",
//        "is_schema_master"      : false,
//        "is_naming_master"      : false,
//        "is_rid_master"         : false,
//        "is_pdc_emulator"       : true,
//        "is_infrastructure_master" : false,
//        "enc_types"             : 28
//      }, ...
//    ],
//
//    "fsmo": {
//      "schema_master"      : "CN=DC01,...",
//      "naming_master"      : "CN=DC01,...",
//      "rid_master"         : "CN=DC01,...",
//      "pdc_emulator"       : "CN=DC01,...",
//      "infrastructure"     : "CN=DC01,..."
//    },
//
//    "password_policy": {
//      "min_length"              : 7,
//      "complexity_enabled"      : true,
//      "max_age_days"            : 42,
//      "min_age_days"            : 1,
//      "history_count"           : 24,
//      "lockout_threshold"       : 0,
//      "lockout_duration_mins"   : 30,
//      "lockout_observation_mins": 30,
//      "reversible_encryption"   : false
//    },
//
//    "fine_grained_policies"     : [ { ... }, ... ],
//
//    "kerberos_policy": {
//      "max_ticket_age_hours"    : 10,
//      "max_renew_age_days"      : 7,
//      "max_service_age_mins"    : 600,
//      "max_clock_skew_mins"     : 5
//    },
//
//    "has_enterprise_ca"         : true,
//    "ca_list"                   : [ { "cn": "CORP-CA", "dns": "ca01.corp.local" }, ... ],
//
//    "laps_legacy"               : false,
//    "laps_windows"              : false,
//    "laps_enabled"              : false,
//
//    "smb_signing_policy_present": true,
//
//    "smart_card_required"       : false,
//
//    "dns_zones"                 : [
//      { "name": "corp.local", "secure_only": true },
//      ...
//    ],
//
//    "machine_account_quota"     : 10
//  }
//
//  Offline analysis (DomainInfoOfflineProcessor) reads raw_domaininfo.jsonl and emits:
//    domain_info.json  — enriched domain info with risk analysis
// ─────────────────────────────────────────────────────────────────────────────
class DomainInfoCollector {
public:
    explicit DomainInfoCollector(LDAPEngine& engine);

    // Main entry point. Returns 1 on success (one domain object written), -1 on error.
    int collect(const DomainInfoCollectorOptions& opts = {});

    fs::path output_path() const { return output_path_; }

private:
    LDAPEngine& engine_;
    fs::path    output_path_;

    // ── Sub-collectors ────────────────────────────────────────────────────────
    struct DomainInfo;

    bool collect_domain_root      (const std::string& domain_nc,
                                   const std::string& config_nc,
                                   DomainInfo& info);
    bool collect_domain_controllers(const std::string& domain_nc,
                                    const std::string& config_nc,
                                    DomainInfo& info);
    bool collect_fsmo_roles       (const std::string& domain_nc,
                                   const std::string& config_nc,
                                   DomainInfo& info);
    bool collect_password_policy  (const std::string& domain_nc,
                                   DomainInfo& info);
    bool collect_fine_grained_policies(const std::string& domain_nc,
                                       DomainInfo& info);
    bool collect_kerberos_policy  (const std::string& domain_nc,
                                   DomainInfo& info);
    bool collect_enterprise_cas   (const std::string& config_nc,
                                   DomainInfo& info);
    bool collect_laps             (const std::string& config_nc,
                                   DomainInfo& info);
    bool collect_dns_zones        (const std::string& domain_nc,
                                   DomainInfo& info);
    bool collect_smb_signing      (const std::string& domain_nc,
                                   DomainInfo& info);

    // ── Serializer ────────────────────────────────────────────────────────────
    std::string domaininfo_to_jsonl(const DomainInfo& info,
                                     const std::string& generated_at) const;

    // ── Helpers ───────────────────────────────────────────────────────────────
    // Reads fSMORoleOwner attribute from a single BASE-scope search.
    // Returns the ntdsDsa DN or empty string on failure.
    std::string read_fsmo_role_owner(const std::string& object_dn) const;

    // Converts ntdsDsa DN (CN=NTDS Settings,CN=DC01,...) to server DN (CN=DC01,...)
    static std::string ntds_dn_to_server_dn(const std::string& ntds_dn);

    // Converts raw msDS-Behavior-Version integer to human-readable name.
    static std::string functional_level_name(int level);

    // Converts raw FILETIME negative-offset interval to days (password/lockout ages).
    static int64_t filetime_interval_to_seconds(const std::string& raw_val);
    static int     interval_to_days            (const std::string& raw_val);
    static int     interval_to_minutes         (const std::string& raw_val);

    // Converts raw objectSid bytes to "S-1-5-21-..." string.
    static std::string format_sid(const std::string& raw_bytes);

    // Timestamp helper.
    static std::string generalized_time_to_iso(const std::string& gt);

    // JSON helpers (same convention as CertificateCollector).
    static std::string je (const std::string& s);
    static std::string jb (bool v);
    static std::string ji (int v);
    static std::string jl (int64_t v);
    static std::string jnull();
    static std::string ja (const std::vector<std::string>& v);
    static std::string now_iso8601();

    // ── Internal domain info aggregate struct ─────────────────────────────────
    struct DcEntry {
        std::string dn;
        std::string cn;
        std::string dns_name;
        std::string os;
        std::string os_version;
        std::string sid;
        int         enc_types             = 0;
        bool        is_schema_master      = false;
        bool        is_naming_master      = false;
        bool        is_rid_master         = false;
        bool        is_pdc_emulator       = false;
        bool        is_infrastructure_master = false;
    };

    struct FineGrainedPolicy {
        std::string cn;
        int         precedence            = 0;
        int         min_length            = 0;
        bool        complexity_enabled    = false;
        int64_t     max_age_secs          = 0;
        int64_t     min_age_secs          = 0;
        int64_t     lockout_duration_secs = 0;
        int         lockout_threshold     = 0;
        int64_t     lockout_obs_secs      = 0;
        int         history_count         = 0;
        std::vector<std::string> applies_to;  // DNs of users/groups
    };

    struct CaEntry {
        std::string cn;
        std::string dns_name;
    };

    struct DnsZone {
        std::string name;
        bool        secure_only           = false;
    };

    struct DomainInfo {
        // Identity
        std::string fqdn;
        std::string netbios_name;
        std::string domain_sid;
        int         functional_level      = -1;

        // DCs
        std::vector<DcEntry> domain_controllers;

        // FSMO (server DNs)
        std::string fsmo_schema_master;
        std::string fsmo_naming_master;
        std::string fsmo_rid_master;
        std::string fsmo_pdc_emulator;
        std::string fsmo_infrastructure;

        // Default password policy
        int     pwd_min_length            = 0;
        bool    pwd_complexity            = false;
        int64_t pwd_max_age_secs          = 0;
        int64_t pwd_min_age_secs          = 0;
        int     pwd_history_count         = 0;
        int     lockout_threshold         = 0;
        int64_t lockout_duration_secs     = 0;
        int64_t lockout_obs_secs          = 0;
        bool    reversible_encryption     = false;
        int     pwd_properties_raw        = 0;

        // Fine-grained policies
        std::vector<FineGrainedPolicy> fine_grained_policies;

        // Kerberos (from krbtgt msDS-* or default AD values)
        int     krb_max_ticket_age_hours  = 10;
        int     krb_max_renew_age_days    = 7;
        int     krb_max_service_age_mins  = 600;
        int     krb_max_clock_skew_mins   = 5;

        // CA
        bool    has_enterprise_ca         = false;
        std::vector<CaEntry> ca_list;

        // LAPS
        bool    laps_legacy               = false;  // ms-Mcs-AdmPwd schema present
        bool    laps_windows              = false;  // msLAPS-Password schema present

        // SMB Signing
        bool    smb_signing_policy_present = false;

        // Smart card
        bool    smart_card_required       = false;

        // DNS Zones
        std::vector<DnsZone> dns_zones;

        // Machine account quota
        int     machine_account_quota     = 10;
    };
};