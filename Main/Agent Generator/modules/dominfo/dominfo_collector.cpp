// ─── dominfo_collector.cpp ───────────────────────────────────────────────────
//  Phase 1 — Domain Information Collector
//
//  Collects domain-level security posture data via targeted LDAP queries:
//    - Domain FQDN, NetBIOS name, SID, Functional Level
//    - Domain Controllers and their FSMO role assignments
//    - Default Password Policy (and Fine-Grained PSOs)
//    - Kerberos ticket lifetime policy
//    - Enterprise CA presence
//    - LAPS deployment (legacy ms-Mcs-AdmPwd and modern msLAPS-Password)
//    - DNS Zone security mode (Secure-only vs Non-secure)
//    - SMB Signing policy presence (DC Policy GPO)
//    - Smart Card requirement
//
//  Offline analysis: DomainInfoOfflineProcessor (offline_processorp11.cpp)
// ─────────────────────────────────────────────────────────────────────────────
#include "dominfo_collector.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <cstring>

// ─────────────────────────────────────────────────────────────────────────────
//  Constructor
// ─────────────────────────────────────────────────────────────────────────────
DomainInfoCollector::DomainInfoCollector(LDAPEngine& engine) : engine_(engine) {}

// ─────────────────────────────────────────────────────────────────────────────
//  collect  — main entry point
// ─────────────────────────────────────────────────────────────────────────────
int DomainInfoCollector::collect(const DomainInfoCollectorOptions& opts) {
    fs::create_directories(opts.output_dir);

    const std::string& base_dn = engine_.cfg_.base_dn;
    if (base_dn.empty()) {
        log_err("[DomainInfo] base_dn is empty — connect and set DOMNAME first.");
        return -1;
    }
    const std::string config_nc = "CN=Configuration," + base_dn;
    const std::string domain_nc = base_dn;

    log_info("[DomainInfo] Domain NC  : " + domain_nc);
    log_info("[DomainInfo] Config NC  : " + config_nc);

    const std::string generated_at = now_iso8601();

    DomainInfo info;

    // ── Phase 1: domain root (FQDN, SID, functional level, pwd policy) ────────
    if (!collect_domain_root(domain_nc, config_nc, info)) {
        log_err("[DomainInfo] Failed to read domain root object.");
        return -1;
    }

    // ── Phase 2: domain controllers ───────────────────────────────────────────
    collect_domain_controllers(domain_nc, config_nc, info);

    // ── Phase 3: FSMO role holders ────────────────────────────────────────────
    collect_fsmo_roles(domain_nc, config_nc, info);

    // ── Phase 4: fine-grained password policies ───────────────────────────────
    collect_fine_grained_policies(domain_nc, info);

    // ── Phase 5: kerberos policy ──────────────────────────────────────────────
    collect_kerberos_policy(domain_nc, info);

    // ── Phase 6: enterprise CA detection ──────────────────────────────────────
    collect_enterprise_cas(config_nc, info);

    // ── Phase 7: LAPS detection ───────────────────────────────────────────────
    collect_laps(config_nc, info);

    // ── Phase 8: DNS zone security ────────────────────────────────────────────
    collect_dns_zones(domain_nc, info);

    // ── Phase 9: SMB signing policy presence ──────────────────────────────────
    collect_smb_signing(domain_nc, info);

    // ── Write output ──────────────────────────────────────────────────────────
    output_path_ = fs::path(opts.output_dir) / "raw_domaininfo.ndjson";
    std::ofstream f(output_path_, std::ios::binary);
    if (!f) {
        log_err("[DomainInfo] Failed to open: " + output_path_.string());
        return -1;
    }

    f << domaininfo_to_ndjson(info, generated_at) << "\n";

    if (!f) {
        log_err("[DomainInfo] Write error: " + output_path_.string());
        return -1;
    }

    log_ok("[DomainInfo] raw_domaininfo.ndjson -> " + output_path_.string());
    log_ok("[DomainInfo] FQDN: " + info.fqdn
        + " | DCs: " + std::to_string(info.domain_controllers.size())
        + " | FL: " + functional_level_name(info.functional_level));

    return 1;
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect_domain_root
//  BASE scope on domainNC — reads identity + default password policy
// ─────────────────────────────────────────────────────────────────────────────
bool DomainInfoCollector::collect_domain_root(
    const std::string& domain_nc,
    const std::string& /*config_nc*/,
    DomainInfo& info)
{
    const std::vector<std::string> attrs = {
        "distinguishedName",
        "name",
        "dc",
        "msDS-Behavior-Version",
        "objectSid",
        "nETBIOSName",
        // Default password policy
        "pwdProperties",
        "minPwdLength",
        "maxPwdAge",
        "minPwdAge",
        "lockoutDuration",
        "lockoutThreshold",
        "lockoutObservationWindow",
        "pwdHistoryLength",
        // Machine account quota
        "ms-DS-MachineAccountQuota",
    };

    bool found = false;
    engine_.search_base(domain_nc, attrs,
        [&](const LDAPEngine::AttrMap& e) {
            auto str = [&](const std::string& k) -> std::string {
                auto it = e.find(k);
                return (it != e.end() && !it->second.empty()) ? it->second[0] : "";
            };
            auto ival = [&](const std::string& k, int def = 0) -> int {
                const std::string v = str(k);
                if (v.empty()) return def;
                try { return std::stoi(v); } catch (...) { return def; }
            };

            // Identity
            info.fqdn             = str("name");
            // Reconstruct FQDN from DC= components of DN if "name" is just short name
            {
                const std::string dn = str("distinguishedName");
                std::string fqdn_from_dn;
                std::istringstream ss(dn);
                std::string tok;
                while (std::getline(ss, tok, ',')) {
                    // trim
                    size_t s = tok.find_first_not_of(' ');
                    if (s != std::string::npos) tok = tok.substr(s);
                    if (tok.size() >= 3 &&
                        (tok[0]=='D'||tok[0]=='d') &&
                        (tok[1]=='C'||tok[1]=='c') &&
                        tok[2]=='=')
                    {
                        if (!fqdn_from_dn.empty()) fqdn_from_dn += ".";
                        fqdn_from_dn += tok.substr(3);
                    }
                }
                if (!fqdn_from_dn.empty())
                    info.fqdn = fqdn_from_dn;
            }

            info.functional_level = ival("msDS-Behavior-Version", -1);
            info.domain_sid       = format_sid(str("objectSid"));

            // Default password policy
            info.pwd_properties_raw   = ival("pwdProperties");
            info.pwd_min_length       = ival("minPwdLength");
            info.pwd_complexity       = (info.pwd_properties_raw & 0x01) != 0;
            info.reversible_encryption = (info.pwd_properties_raw & 0x10) != 0;
            info.pwd_history_count    = ival("pwdHistoryLength");
            info.lockout_threshold    = ival("lockoutThreshold");

            // Interval fields (stored as LDAP large-integer strings in 100-ns ticks)
            info.pwd_max_age_secs     = filetime_interval_to_seconds(str("maxPwdAge"));
            info.pwd_min_age_secs     = filetime_interval_to_seconds(str("minPwdAge"));
            info.lockout_duration_secs = filetime_interval_to_seconds(str("lockoutDuration"));
            info.lockout_obs_secs     = filetime_interval_to_seconds(str("lockoutObservationWindow"));

            info.machine_account_quota = ival("ms-DS-MachineAccountQuota", 10);

            found = true;
        });

    // Also try to get NetBIOS name from the Partitions container
    if (found) {
        const std::string partitions_base =
            "CN=Partitions,CN=Configuration," + domain_nc;
        const std::vector<std::string> nb_attrs = { "nETBIOSName", "dnsRoot" };
        const std::string saved = engine_.cfg_.base_dn;
        engine_.cfg_.base_dn = partitions_base;
        engine_.search(
            "(&(objectClass=crossRef)(dnsRoot=" + info.fqdn + "))",
            nb_attrs,
            [&](const LDAPEngine::AttrMap& e) {
                auto it = e.find("nETBIOSName");
                if (it != e.end() && !it->second.empty())
                    info.netbios_name = it->second[0];
            });
        engine_.cfg_.base_dn = saved;
    }

    return found;
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect_domain_controllers
// ─────────────────────────────────────────────────────────────────────────────
bool DomainInfoCollector::collect_domain_controllers(
    const std::string& domain_nc,
    const std::string& /*config_nc*/,
    DomainInfo& info)
{
    const std::vector<std::string> attrs = {
        "distinguishedName",
        "cn",
        "dNSHostName",
        "operatingSystem",
        "operatingSystemVersion",
        "objectSid",
        "userAccountControl",
        "msDS-SupportedEncryptionTypes",
    };

    // userAccountControl:1.2.840.113556.1.4.803:=8192 → SERVER_TRUST_ACCOUNT (DC bit)
    const std::string filter =
        "(userAccountControl:1.2.840.113556.1.4.803:=8192)";

    const std::string saved = engine_.cfg_.base_dn;
    engine_.cfg_.base_dn = domain_nc;
    engine_.search(filter, attrs,
        [&](const LDAPEngine::AttrMap& e) {
            auto str = [&](const std::string& k) -> std::string {
                auto it = e.find(k);
                return (it != e.end() && !it->second.empty()) ? it->second[0] : "";
            };
            auto ival = [&](const std::string& k) -> int {
                const std::string v = str(k);
                if (v.empty()) return 0;
                try { return std::stoi(v); } catch (...) { return 0; }
            };

            DcEntry dc;
            dc.dn        = str("distinguishedName");
            dc.cn        = str("cn");
            dc.dns_name  = str("dNSHostName");
            dc.os        = str("operatingSystem");
            dc.os_version = str("operatingSystemVersion");
            dc.sid       = format_sid(str("objectSid"));
            dc.enc_types = ival("msDS-SupportedEncryptionTypes");

            info.domain_controllers.push_back(dc);
        });
    engine_.cfg_.base_dn = saved;

    log_info("[DomainInfo] Found " + std::to_string(info.domain_controllers.size())
        + " domain controller(s)");
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect_fsmo_roles
//  Reads fSMORoleOwner from 5 well-known objects; resolves ntdsDsa → server CN
// ─────────────────────────────────────────────────────────────────────────────
bool DomainInfoCollector::collect_fsmo_roles(
    const std::string& domain_nc,
    const std::string& config_nc,
    DomainInfo& info)
{
    // PDC Emulator & Infrastructure: on domain NC objects
    // Schema Master: CN=Schema,CN=Configuration,...
    // Domain Naming: CN=Partitions,CN=Configuration,...
    // RID Master: CN=RID Manager$,CN=System,<domainNC>

    const std::string schema_dn    = "CN=Schema," + config_nc;
    const std::string naming_dn    = "CN=Partitions," + config_nc;
    const std::string rid_dn       = "CN=RID Manager$,CN=System," + domain_nc;
    const std::string infra_dn     = "CN=Infrastructure," + domain_nc;

    info.fsmo_schema_master  = ntds_dn_to_server_dn(read_fsmo_role_owner(schema_dn));
    info.fsmo_naming_master  = ntds_dn_to_server_dn(read_fsmo_role_owner(naming_dn));
    info.fsmo_rid_master     = ntds_dn_to_server_dn(read_fsmo_role_owner(rid_dn));
    info.fsmo_infrastructure = ntds_dn_to_server_dn(read_fsmo_role_owner(infra_dn));

    // PDC Emulator is fSMORoleOwner on domain root itself
    info.fsmo_pdc_emulator   = ntds_dn_to_server_dn(read_fsmo_role_owner(domain_nc));

    // Match resolved server DNs to DC entries
    auto upper_dn = [](std::string s) -> std::string {
        for (char& c : s) c = (char)toupper((unsigned char)c);
        return s;
    };

    for (auto& dc : info.domain_controllers) {
        const std::string udc = upper_dn(dc.dn);
        if (!info.fsmo_schema_master .empty() && upper_dn(info.fsmo_schema_master)  == udc) dc.is_schema_master      = true;
        if (!info.fsmo_naming_master .empty() && upper_dn(info.fsmo_naming_master)  == udc) dc.is_naming_master      = true;
        if (!info.fsmo_rid_master    .empty() && upper_dn(info.fsmo_rid_master)     == udc) dc.is_rid_master         = true;
        if (!info.fsmo_pdc_emulator  .empty() && upper_dn(info.fsmo_pdc_emulator)   == udc) dc.is_pdc_emulator       = true;
        if (!info.fsmo_infrastructure.empty() && upper_dn(info.fsmo_infrastructure) == udc) dc.is_infrastructure_master = true;
    }

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect_fine_grained_policies
// ─────────────────────────────────────────────────────────────────────────────
bool DomainInfoCollector::collect_fine_grained_policies(
    const std::string& domain_nc,
    DomainInfo& info)
{
    const std::string pso_base = "CN=Password Settings Container,CN=System," + domain_nc;
    const std::vector<std::string> attrs = {
        "cn",
        "msDS-MinimumPasswordLength",
        "msDS-PasswordComplexityEnabled",
        "msDS-MaximumPasswordAge",
        "msDS-MinimumPasswordAge",
        "msDS-LockoutDuration",
        "msDS-LockoutThreshold",
        "msDS-LockoutObservationWindow",
        "msDS-PasswordHistoryLength",
        "msDS-PasswordSettingsPrecedence",
        "msDS-PSOAppliesTo",
        "msDS-PasswordReversibleEncryptionEnabled",
    };

    const std::string saved = engine_.cfg_.base_dn;
    engine_.cfg_.base_dn = pso_base;
    engine_.search("(objectClass=msDS-PasswordSettings)", attrs,
        [&](const LDAPEngine::AttrMap& e) {
            auto str = [&](const std::string& k) -> std::string {
                auto it = e.find(k);
                return (it != e.end() && !it->second.empty()) ? it->second[0] : "";
            };
            auto strs = [&](const std::string& k) -> std::vector<std::string> {
                auto it = e.find(k);
                return (it != e.end()) ? it->second : std::vector<std::string>{};
            };
            auto ival = [&](const std::string& k, int def = 0) -> int {
                const std::string v = str(k);
                if (v.empty()) return def;
                try { return std::stoi(v); } catch (...) { return def; }
            };
            auto bval = [&](const std::string& k) -> bool {
                const std::string v = str(k);
                if (v.empty()) return false;
                return (v == "TRUE" || v == "true" || v == "1");
            };

            FineGrainedPolicy p;
            p.cn                  = str("cn");
            p.precedence          = ival("msDS-PasswordSettingsPrecedence");
            p.min_length          = ival("msDS-MinimumPasswordLength");
            p.complexity_enabled  = bval("msDS-PasswordComplexityEnabled");
            p.max_age_secs        = filetime_interval_to_seconds(str("msDS-MaximumPasswordAge"));
            p.min_age_secs        = filetime_interval_to_seconds(str("msDS-MinimumPasswordAge"));
            p.lockout_duration_secs = filetime_interval_to_seconds(str("msDS-LockoutDuration"));
            p.lockout_threshold   = ival("msDS-LockoutThreshold");
            p.lockout_obs_secs    = filetime_interval_to_seconds(str("msDS-LockoutObservationWindow"));
            p.history_count       = ival("msDS-PasswordHistoryLength");
            p.applies_to          = strs("msDS-PSOAppliesTo");

            info.fine_grained_policies.push_back(p);
        });
    engine_.cfg_.base_dn = saved;

    if (!info.fine_grained_policies.empty()) {
        log_info("[DomainInfo] Fine-grained policies: "
            + std::to_string(info.fine_grained_policies.size()));
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect_kerberos_policy
//  Reads msDS-MaxTicketAge / msDS-MaxRenewAge from krbtgt account.
//  Falls back to AD default values (10h ticket / 7d renew) if not set.
// ─────────────────────────────────────────────────────────────────────────────
bool DomainInfoCollector::collect_kerberos_policy(
    const std::string& domain_nc,
    DomainInfo& info)
{
    // krbtgt lives in CN=Users,<domainNC>
    const std::string krbtgt_dn = "CN=krbtgt,CN=Users," + domain_nc;
    const std::vector<std::string> attrs = {
        "msDS-MaxTicketAge",    // in hours — integer
        "msDS-MaxRenewAge",     // in days  — integer
        "msDS-MaxServiceAge",   // in minutes — integer
        "msDS-MaxClockSkew",    // in minutes — integer
    };

    engine_.search_base(krbtgt_dn, attrs,
        [&](const LDAPEngine::AttrMap& e) {
            auto ival = [&](const std::string& k, int def) -> int {
                auto it = e.find(k);
                if (it == e.end() || it->second.empty()) return def;
                try { return std::stoi(it->second[0]); } catch (...) { return def; }
            };

            info.krb_max_ticket_age_hours = ival("msDS-MaxTicketAge",  10);
            info.krb_max_renew_age_days   = ival("msDS-MaxRenewAge",    7);
            info.krb_max_service_age_mins = ival("msDS-MaxServiceAge", 600);
            info.krb_max_clock_skew_mins  = ival("msDS-MaxClockSkew",   5);
        });

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect_enterprise_cas
// ─────────────────────────────────────────────────────────────────────────────
bool DomainInfoCollector::collect_enterprise_cas(
    const std::string& config_nc,
    DomainInfo& info)
{
    const std::string enrollment_base =
        "CN=Enrollment Services,CN=Public Key Services,CN=Services," + config_nc;
    const std::vector<std::string> attrs = { "cn", "dNSHostName" };

    const std::string saved = engine_.cfg_.base_dn;
    engine_.cfg_.base_dn = enrollment_base;
    engine_.search("(objectClass=pKIEnrollmentService)", attrs,
        [&](const LDAPEngine::AttrMap& e) {
            auto str = [&](const std::string& k) -> std::string {
                auto it = e.find(k);
                return (it != e.end() && !it->second.empty()) ? it->second[0] : "";
            };
            CaEntry ca;
            ca.cn       = str("cn");
            ca.dns_name = str("dNSHostName");
            info.ca_list.push_back(ca);
        });
    engine_.cfg_.base_dn = saved;

    info.has_enterprise_ca = !info.ca_list.empty();

    if (info.has_enterprise_ca) {
        log_info("[DomainInfo] Enterprise CA(s) found: "
            + std::to_string(info.ca_list.size()));
    } else {
        log_info("[DomainInfo] No Enterprise CA detected.");
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect_laps
//  Detects presence of LAPS schema extensions (legacy and modern Windows LAPS).
//  Uses BASE scope on schema object DNs — if found, schema attribute exists.
// ─────────────────────────────────────────────────────────────────────────────
bool DomainInfoCollector::collect_laps(
    const std::string& config_nc,
    DomainInfo& info)
{
    // Legacy LAPS (Microsoft LAPS extension — ms-Mcs-AdmPwd)
    const std::string legacy_dn =
        "CN=ms-Mcs-AdmPwd,CN=Schema," + config_nc;
    // Windows LAPS (built-in since April 2023 — msLAPS-Password)
    const std::string windows_dn =
        "CN=msLAPS-Password,CN=Schema," + config_nc;

    const std::vector<std::string> attrs = { "cn" };

    engine_.search_base(legacy_dn, attrs,
        [&](const LDAPEngine::AttrMap&) {
            info.laps_legacy = true;
        });

    engine_.search_base(windows_dn, attrs,
        [&](const LDAPEngine::AttrMap&) {
            info.laps_windows = true;
        });

    if (info.laps_legacy || info.laps_windows) {
        log_info("[DomainInfo] LAPS detected — legacy:"
            + std::string(info.laps_legacy  ? "yes" : "no")
            + " windows:" + std::string(info.laps_windows ? "yes" : "no"));
    } else {
        log_info("[DomainInfo] LAPS not detected (schema attributes absent).");
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect_dns_zones
//  Reads dnsZone objects from DomainDnsZones partition.
//  dnsProperty is a multi-valued binary blob; zone type 0x00000001 in property
//  ID 0x00000008 (DSPROPERTY_ZONE_ALLOW_UPDATE) == 0 means secure-only.
// ─────────────────────────────────────────────────────────────────────────────
bool DomainInfoCollector::collect_dns_zones(
    const std::string& domain_nc,
    DomainInfo& info)
{
    const std::string dns_base = "CN=MicrosoftDNS,DC=DomainDnsZones," + domain_nc;
    const std::vector<std::string> attrs = { "name", "dnsProperty" };

    const std::string saved = engine_.cfg_.base_dn;
    engine_.cfg_.base_dn = dns_base;
    engine_.search("(objectClass=dnsZone)", attrs,
        [&](const LDAPEngine::AttrMap& e) {
            auto str = [&](const std::string& k) -> std::string {
                auto it = e.find(k);
                return (it != e.end() && !it->second.empty()) ? it->second[0] : "";
            };

            DnsZone z;
            z.name = str("name");
            if (z.name.empty() || z.name == ".." || z.name == "_msdcs") {
                return; // skip system/internal zones
            }

            // Parse dnsProperty blobs looking for DSPROPERTY_ZONE_ALLOW_UPDATE
            // Property ID 0x00000008 — 4-byte little-endian data value:
            //   0 = no update (read-only)  1 = non-secure  3 = secure+non-secure
            //   The absence of this property or value 1/3 = non-secure
            // Format: Length(4LE) + NameLength(4LE) + Flag(4LE) + Version(4LE)
            //         + Id(4LE) + Data(variable LE)
            bool found_allow_update = false;
            {
                auto pit = e.find("dnsProperty");
                if (pit != e.end()) {
                    for (const auto& blob : pit->second) {
                        const auto* b = reinterpret_cast<const unsigned char*>(blob.data());
                        const size_t len = blob.size();
                        // Minimum property record: 4+4+4+4+4 = 20 bytes
                        if (len < 20) continue;
                        // Property ID is at bytes 16-19 (LE)
                        uint32_t prop_id = (uint32_t)b[16]
                            | ((uint32_t)b[17] << 8)
                            | ((uint32_t)b[18] << 16)
                            | ((uint32_t)b[19] << 24);
                        if (prop_id == 0x00000008 && len >= 24) {
                            // Data starts at byte 20
                            uint32_t allow_update = (uint32_t)b[20]
                                | ((uint32_t)b[21] << 8)
                                | ((uint32_t)b[22] << 16)
                                | ((uint32_t)b[23] << 24);
                            found_allow_update = true;
                            // 0 = no updates (secure-only or locked)
                            // 1 = non-secure and secure
                            // 3 = secure only (Windows DNS "Secure only")
                            z.secure_only = (allow_update == 3);
                        }
                    }
                }
            }
            // If property absent, treat as non-secure (conservative)
            if (!found_allow_update) z.secure_only = false;

            info.dns_zones.push_back(z);
        });
    engine_.cfg_.base_dn = saved;

    log_info("[DomainInfo] DNS zones collected: "
        + std::to_string(info.dns_zones.size()));
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect_smb_signing
//  Detects presence of Default Domain Controllers Policy GPO
//  (GUID {6AC1786C-016F-11D2-945F-00C04fB984F9}).
//  Actual SMB signing value (RequireMessageSigning) lives in the SYSVOL
//  GptTmpl.inf file which requires file-system access — not done here.
//  We record the GPO presence as smb_signing_policy_present and surface the
//  gPCFileSysPath so the offline processor can note it.
// ─────────────────────────────────────────────────────────────────────────────
bool DomainInfoCollector::collect_smb_signing(
    const std::string& domain_nc,
    DomainInfo& info)
{
    const std::string policies_base = "CN=Policies,CN=System," + domain_nc;
    const std::vector<std::string> attrs = { "cn", "gPCFileSysPath" };

    const std::string saved = engine_.cfg_.base_dn;
    engine_.cfg_.base_dn = policies_base;

    // Default Domain Controllers Policy
    engine_.search(
        "(cn={6AC1786C-016F-11D2-945F-00C04fB984F9})",
        attrs,
        [&](const LDAPEngine::AttrMap&) {
            info.smb_signing_policy_present = true;
        });
    engine_.cfg_.base_dn = saved;

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  read_fsmo_role_owner
//  Reads fSMORoleOwner attribute from a single object (BASE scope).
//  Returns the raw ntdsDsa DN string or empty on failure.
// ─────────────────────────────────────────────────────────────────────────────
std::string DomainInfoCollector::read_fsmo_role_owner(const std::string& object_dn) const {
    std::string result;
    const std::vector<std::string> attrs = { "fSMORoleOwner" };
    engine_.search_base(object_dn, attrs,
        [&](const LDAPEngine::AttrMap& e) {
            auto it = e.find("fSMORoleOwner");
            if (it != e.end() && !it->second.empty())
                result = it->second[0];
        });
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  ntds_dn_to_server_dn
//  "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,..."
//   → "CN=DC01,CN=Servers,CN=Default-First-Site-Name,..."
// ─────────────────────────────────────────────────────────────────────────────
std::string DomainInfoCollector::ntds_dn_to_server_dn(const std::string& ntds_dn) {
    if (ntds_dn.empty()) return "";
    // Find the first comma and return everything after it
    auto pos = ntds_dn.find(',');
    if (pos == std::string::npos) return ntds_dn;
    std::string rest = ntds_dn.substr(pos + 1);
    // Trim leading space
    size_t s = rest.find_first_not_of(' ');
    if (s != std::string::npos) rest = rest.substr(s);
    return rest;
}

// ─────────────────────────────────────────────────────────────────────────────
//  functional_level_name
//  msDS-Behavior-Version integer → human-readable Windows Server version.
// ─────────────────────────────────────────────────────────────────────────────
std::string DomainInfoCollector::functional_level_name(int level) {
    switch (level) {
        case 0:  return "Windows 2000";
        case 1:  return "Windows Server 2003 Mixed";
        case 2:  return "Windows Server 2003";
        case 3:  return "Windows Server 2008";
        case 4:  return "Windows Server 2008 R2";
        case 5:  return "Windows Server 2012";
        case 6:  return "Windows Server 2012 R2";
        case 7:  return "Windows Server 2016";
        case 8:  return "Windows Server 2019";   // officially also 7 per MS docs
        case 10: return "Windows Server 2025";
        default:
            if (level < 0) return "Unknown";
            return "Windows Server (level " + std::to_string(level) + ")";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  filetime_interval_to_seconds
//  LDAP large-integer string (100-ns ticks, negative = relative interval)
//  → absolute seconds (positive). Returns 0 on parse error.
// ─────────────────────────────────────────────────────────────────────────────
int64_t DomainInfoCollector::filetime_interval_to_seconds(const std::string& raw_val) {
    if (raw_val.empty()) return 0;
    try {
        int64_t ticks = std::stoll(raw_val);
        if (ticks == 0 || ticks == INT64_MIN) return 0;
        if (ticks < 0) ticks = -ticks;
        return ticks / 10000000LL;
    } catch (...) {
        return 0;
    }
}

int DomainInfoCollector::interval_to_days(const std::string& raw_val) {
    int64_t secs = filetime_interval_to_seconds(raw_val);
    if (secs == 0) return 0;
    return static_cast<int>(secs / 86400);
}

int DomainInfoCollector::interval_to_minutes(const std::string& raw_val) {
    int64_t secs = filetime_interval_to_seconds(raw_val);
    if (secs == 0) return 0;
    return static_cast<int>(secs / 60);
}

// ─────────────────────────────────────────────────────────────────────────────
//  format_sid  — raw binary objectSid → "S-1-5-21-..." string
// ─────────────────────────────────────────────────────────────────────────────
std::string DomainInfoCollector::format_sid(const std::string& raw) {
    if (raw.size() < 8) return "";
    const auto* b = reinterpret_cast<const unsigned char*>(raw.data());

    unsigned int sub_count = b[1];
    if (raw.size() < static_cast<size_t>(8 + sub_count * 4)) return "";

    unsigned long long authority = 0;
    for (int i = 0; i < 6; ++i)
        authority = (authority << 8) | b[2 + i];

    std::string sid = "S-1-" + std::to_string(authority);
    for (unsigned int i = 0; i < sub_count; ++i) {
        uint32_t sub = b[8 + i*4]
            | ((uint32_t)b[9  + i*4] << 8)
            | ((uint32_t)b[10 + i*4] << 16)
            | ((uint32_t)b[11 + i*4] << 24);
        sid += "-" + std::to_string(sub);
    }
    return sid;
}

// ─────────────────────────────────────────────────────────────────────────────
//  generalized_time_to_iso
// ─────────────────────────────────────────────────────────────────────────────
std::string DomainInfoCollector::generalized_time_to_iso(const std::string& gt) {
    if (gt.size() < 14) return gt;
    return gt.substr(0,4)  + "-" + gt.substr(4,2)  + "-" + gt.substr(6,2)
         + "T" + gt.substr(8,2) + ":" + gt.substr(10,2) + ":" + gt.substr(12,2) + "Z";
}

// ─────────────────────────────────────────────────────────────────────────────
//  domaininfo_to_ndjson  — serializes DomainInfo → JSON string
// ─────────────────────────────────────────────────────────────────────────────
std::string DomainInfoCollector::domaininfo_to_ndjson(
    const DomainInfo& info,
    const std::string& generated_at) const
{
    // Helper: seconds → days (for output)
    auto sec_to_days = [](int64_t s) -> int64_t {
        if (s == 0) return 0;
        return s / 86400;
    };
    auto sec_to_mins = [](int64_t s) -> int64_t {
        if (s == 0) return 0;
        return s / 60;
    };

    std::ostringstream o;
    o << "{";

    // ── Identity ──────────────────────────────────────────────────────────────
    o << "\"fqdn\":"                  << je(info.fqdn)                               << ","
      << "\"netbios_name\":"          << je(info.netbios_name)                       << ","
      << "\"domain_sid\":"            << je(info.domain_sid)                         << ","
      << "\"functional_level\":"      << ji(info.functional_level)                   << ","
      << "\"functional_level_name\":" << je(functional_level_name(info.functional_level)) << ","
      << "\"generated_at\":"          << je(generated_at)                            << ",";

    // ── Domain Controllers ────────────────────────────────────────────────────
    o << "\"domain_controllers\":[";
    for (size_t i = 0; i < info.domain_controllers.size(); ++i) {
        if (i) o << ",";
        const auto& dc = info.domain_controllers[i];
        o << "{"
          << "\"dn\":"          << je(dc.dn)       << ","
          << "\"cn\":"          << je(dc.cn)       << ","
          << "\"dns_name\":"    << je(dc.dns_name) << ","
          << "\"os\":"          << je(dc.os)       << ","
          << "\"os_version\":"  << je(dc.os_version) << ","
          << "\"sid\":"         << je(dc.sid)      << ","
          << "\"enc_types\":"   << ji(dc.enc_types) << ","
          << "\"is_schema_master\":"         << jb(dc.is_schema_master)         << ","
          << "\"is_naming_master\":"         << jb(dc.is_naming_master)         << ","
          << "\"is_rid_master\":"            << jb(dc.is_rid_master)            << ","
          << "\"is_pdc_emulator\":"          << jb(dc.is_pdc_emulator)          << ","
          << "\"is_infrastructure_master\":" << jb(dc.is_infrastructure_master)
          << "}";
    }
    o << "],";

    // ── FSMO ──────────────────────────────────────────────────────────────────
    o << "\"fsmo\":{"
      << "\"schema_master\":"  << je(info.fsmo_schema_master)  << ","
      << "\"naming_master\":"  << je(info.fsmo_naming_master)  << ","
      << "\"rid_master\":"     << je(info.fsmo_rid_master)     << ","
      << "\"pdc_emulator\":"   << je(info.fsmo_pdc_emulator)   << ","
      << "\"infrastructure\":" << je(info.fsmo_infrastructure)
      << "},";

    // ── Default Password Policy ───────────────────────────────────────────────
    o << "\"password_policy\":{"
      << "\"min_length\":"               << ji(info.pwd_min_length)                       << ","
      << "\"complexity_enabled\":"       << jb(info.pwd_complexity)                       << ","
      << "\"max_age_days\":"             << jl(sec_to_days(info.pwd_max_age_secs))        << ","
      << "\"min_age_days\":"             << jl(sec_to_days(info.pwd_min_age_secs))        << ","
      << "\"history_count\":"            << ji(info.pwd_history_count)                   << ","
      << "\"lockout_threshold\":"        << ji(info.lockout_threshold)                   << ","
      << "\"lockout_duration_mins\":"    << jl(sec_to_mins(info.lockout_duration_secs))  << ","
      << "\"lockout_observation_mins\":" << jl(sec_to_mins(info.lockout_obs_secs))       << ","
      << "\"reversible_encryption\":"    << jb(info.reversible_encryption)               << ","
      << "\"pwd_properties_raw\":"       << ji(info.pwd_properties_raw)
      << "},";

    // ── Fine-Grained Policies ─────────────────────────────────────────────────
    o << "\"fine_grained_policies\":[";
    for (size_t i = 0; i < info.fine_grained_policies.size(); ++i) {
        if (i) o << ",";
        const auto& p = info.fine_grained_policies[i];
        o << "{"
          << "\"cn\":"                    << je(p.cn)                              << ","
          << "\"precedence\":"            << ji(p.precedence)                      << ","
          << "\"min_length\":"            << ji(p.min_length)                      << ","
          << "\"complexity_enabled\":"    << jb(p.complexity_enabled)              << ","
          << "\"max_age_days\":"          << jl(sec_to_days(p.max_age_secs))       << ","
          << "\"min_age_days\":"          << jl(sec_to_days(p.min_age_secs))       << ","
          << "\"history_count\":"         << ji(p.history_count)                   << ","
          << "\"lockout_threshold\":"     << ji(p.lockout_threshold)               << ","
          << "\"lockout_duration_mins\":" << jl(sec_to_mins(p.lockout_duration_secs)) << ","
          << "\"lockout_obs_mins\":"      << jl(sec_to_mins(p.lockout_obs_secs))   << ","
          << "\"applies_to\":"            << ja(p.applies_to)
          << "}";
    }
    o << "],";

    // ── Kerberos Policy ───────────────────────────────────────────────────────
    o << "\"kerberos_policy\":{"
      << "\"max_ticket_age_hours\":"  << ji(info.krb_max_ticket_age_hours) << ","
      << "\"max_renew_age_days\":"    << ji(info.krb_max_renew_age_days)   << ","
      << "\"max_service_age_mins\":"  << ji(info.krb_max_service_age_mins) << ","
      << "\"max_clock_skew_mins\":"   << ji(info.krb_max_clock_skew_mins)
      << "},";

    // ── Enterprise CA ─────────────────────────────────────────────────────────
    o << "\"has_enterprise_ca\":" << jb(info.has_enterprise_ca) << ",";
    o << "\"ca_list\":[";
    for (size_t i = 0; i < info.ca_list.size(); ++i) {
        if (i) o << ",";
        o << "{"
          << "\"cn\":"       << je(info.ca_list[i].cn)       << ","
          << "\"dns_name\":" << je(info.ca_list[i].dns_name)
          << "}";
    }
    o << "],";

    // ── LAPS ──────────────────────────────────────────────────────────────────
    o << "\"laps_legacy\":"  << jb(info.laps_legacy)                          << ","
      << "\"laps_windows\":" << jb(info.laps_windows)                         << ","
      << "\"laps_enabled\":" << jb(info.laps_legacy || info.laps_windows)     << ",";

    // ── SMB Signing ───────────────────────────────────────────────────────────
    o << "\"smb_signing_policy_present\":" << jb(info.smb_signing_policy_present) << ",";

    // ── Smart Card ────────────────────────────────────────────────────────────
    o << "\"smart_card_required\":" << jb(info.smart_card_required) << ",";

    // ── DNS Zones ─────────────────────────────────────────────────────────────
    o << "\"dns_zones\":[";
    for (size_t i = 0; i < info.dns_zones.size(); ++i) {
        if (i) o << ",";
        o << "{"
          << "\"name\":"        << je(info.dns_zones[i].name)          << ","
          << "\"secure_only\":" << jb(info.dns_zones[i].secure_only)
          << "}";
    }
    o << "],";

    // ── Machine Account Quota ─────────────────────────────────────────────────
    o << "\"machine_account_quota\":" << ji(info.machine_account_quota);

    o << "}";
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  JSON helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string DomainInfoCollector::je(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) {
                    char esc[8];
                    std::snprintf(esc, sizeof(esc), "\\u%04x", (unsigned char)c);
                    out += esc;
                } else {
                    out += c;
                }
        }
    }
    out += "\"";
    return out;
}

std::string DomainInfoCollector::jb(bool v)    { return v ? "true" : "false"; }
std::string DomainInfoCollector::ji(int v)     { return std::to_string(v); }
std::string DomainInfoCollector::jl(int64_t v) { return std::to_string(v); }
std::string DomainInfoCollector::jnull()       { return "null"; }

std::string DomainInfoCollector::ja(const std::vector<std::string>& v) {
    std::string out = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += ",";
        out += je(v[i]);
    }
    out += "]";
    return out;
}

std::string DomainInfoCollector::now_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &t);
#else
    gmtime_r(&t, &utc);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return buf;
}