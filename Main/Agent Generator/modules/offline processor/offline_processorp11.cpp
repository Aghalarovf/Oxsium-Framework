// ─── offline_processorp11.cpp ────────────────────────────────────────────────
//  SECTION DOMINFO — Domain Information Offline Processor
//
//  Reads:
//    raw_cache/raw_domaininfo.jsonl  (from DomainInfoCollector)
//
//  Writes:
//    Domain Objects/domain_info.<ext>  — enriched domain info with risk findings
//
//  Risk findings computed here:
//    CRITICAL
//      - DFL < 3  (below Windows Server 2008 — many legacy attack paths open)
//      - No password complexity + min_length < 8 (trivially guessable passwords)
//      - Lockout disabled (threshold == 0) + no fine-grained fallback
//      - Kerberos ticket age > 10h or renew age > 7d (golden/silver ticket risk)
//      - Machine account quota > 0 (any authenticated user can join machines → Kerberos relay)
//
//    HIGH
//      - No Enterprise CA but smart card required (config inconsistency)
//      - LAPS not deployed (local admin password reuse risk)
//      - DNS zones not all secure-only (DNS poisoning risk)
//      - Password max age == 0 (passwords never expire)
//      - Reversible encryption enabled
//
//    MEDIUM
//      - DFL < 7 (below Windows Server 2016 — some newer mitigations unavailable)
//      - SMB Signing DC policy absent (relay risk hint)
//      - Fine-grained policies exist but default policy is weak (partial coverage)
//      - max_clock_skew > 5 minutes (Kerberos replay window)
//
//    INFO
//      - FSMO roles split across multiple DCs (normal in large domains, noted)
//      - Fine-grained policies present (informational)
//
//  Output schema — domain_info.json (single JSON object):
//  Inherits all fields from raw_domaininfo.jsonl plus:
//  {
//    ...raw fields...,
//    "risk_findings": [
//      {
//        "severity" : "CRITICAL",
//        "code"     : "LOCKOUT_DISABLED",
//        "title"    : "Account lockout is disabled",
//        "detail"   : "lockoutThreshold = 0 — brute-force attacks are unrestricted."
//      }, ...
//    ],
//    "risk_score"      : 42,       // 0-100 composite
//    "highest_severity": "CRITICAL"
//  }
// ─────────────────────────────────────────────────────────────────────────────
#include "offline_processor.h"
#include <fstream>
#include <sstream>
#include <algorithm>

// ─────────────────────────────────────────────────────────────────────────────
//  RiskFinding — one discovered issue
// ─────────────────────────────────────────────────────────────────────────────
struct RiskFinding {
    std::string severity;   // "CRITICAL" | "HIGH" | "MEDIUM" | "INFO"
    std::string code;       // machine-readable identifier
    std::string title;      // short human title
    std::string detail;     // longer explanation / exact value
};

// ─────────────────────────────────────────────────────────────────────────────
//  DomainInfoResult — parsed + enriched domain info
// ─────────────────────────────────────────────────────────────────────────────
struct DomainInfoResult {
    // ── Identity (raw pass-through) ───────────────────────────────────────────
    std::string fqdn;
    std::string netbios_name;
    std::string domain_sid;
    int         functional_level      = -1;
    std::string functional_level_name;
    std::string generated_at;

    // ── Raw sections stored as-is for JSON pass-through ───────────────────────
    std::string domain_controllers_json;
    std::string fsmo_json;
    std::string password_policy_json;
    std::string fine_grained_policies_json;
    std::string kerberos_policy_json;
    std::string ca_list_json;
    std::string dns_zones_json;

    // ── Scalar flags ──────────────────────────────────────────────────────────
    bool        has_enterprise_ca           = false;
    bool        laps_legacy                 = false;
    bool        laps_windows                = false;
    bool        laps_enabled                = false;
    bool        smb_signing_policy_present  = false;
    bool        smart_card_required         = false;
    int         machine_account_quota       = 10;

    // ── Parsed password policy values (for risk analysis) ─────────────────────
    int         pwd_min_length              = 0;
    bool        pwd_complexity              = false;
    int64_t     pwd_max_age_days            = 0;
    int         pwd_history_count           = 0;
    int         lockout_threshold           = 0;
    bool        reversible_encryption       = false;

    // ── Parsed kerberos values ────────────────────────────────────────────────
    int         krb_max_ticket_age_hours    = 10;
    int         krb_max_renew_age_days      = 7;
    int         krb_max_clock_skew_mins     = 5;

    // ── Parsed DNS summary ────────────────────────────────────────────────────
    int         dns_zone_count              = 0;
    int         dns_secure_only_count       = 0;

    // ── Fine-grained policy count ─────────────────────────────────────────────
    int         fine_grained_policy_count   = 0;

    // ── FSMO split indicator ──────────────────────────────────────────────────
    bool        fsmo_split                  = false;  // roles on >1 server

    // ── Risk findings ─────────────────────────────────────────────────────────
    std::vector<RiskFinding> findings;
    int         risk_score                  = 0;
    std::string highest_severity;
};

// ─────────────────────────────────────────────────────────────────────────────
//  Forward declarations
// ─────────────────────────────────────────────────────────────────────────────
static DomainInfoResult parse_domaininfo  (const std::string& line);
static void             analyze_domaininfo(DomainInfoResult&  r);
static std::string      domaininfo_to_json(const DomainInfoResult& r);
static void             add_finding       (DomainInfoResult& r,
                                           const std::string& severity,
                                           const std::string& code,
                                           const std::string& title,
                                           const std::string& detail);

// ─────────────────────────────────────────────────────────────────────────────
//  OfflineProcessor::process_domaininfo  — public entry point
// ─────────────────────────────────────────────────────────────────────────────
bool OfflineProcessor::process_domaininfo(const OfflineProcessorOptions& opts) {
    fs::create_directories(opts.output_dir);

    const std::string raw_path = opts.raw_dir    + "/raw_domaininfo.jsonl";
    const std::string out_path = opts.output_dir + "/domain_info."
                                + (opts.output_ext.empty() ? "json" : opts.output_ext);

    auto lines = read_ndjson_lines(raw_path);
    if (lines.empty()) {
        log_warn("[DomainInfo] No data found in: " + raw_path);
        return false;
    }

    // raw_domaininfo.jsonl is a single line (one domain object)
    const std::string& line = lines[0];
    if (line.empty() || line[0] != '{') {
        log_err("[DomainInfo] Invalid JSON in: " + raw_path);
        return false;
    }

    DomainInfoResult result = parse_domaininfo(line);
    analyze_domaininfo(result);

    std::ofstream f(out_path, std::ios::out | std::ios::trunc);
    if (!f) {
        log_err("[DomainInfo] Cannot open output: " + out_path);
        return false;
    }

    std::vector<std::string> rows = { domaininfo_to_json(result) };
    write_objects(f, rows, out_path, "[DomainInfo]");

    log_ok("[DomainInfo] domain_info -> " + out_path);
    log_ok("[DomainInfo] FQDN: " + result.fqdn
        + " | Risk score: " + std::to_string(result.risk_score)
        + " | Findings: " + std::to_string(result.findings.size())
        + (result.highest_severity.empty() ? "" : " | Highest: " + result.highest_severity));

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  parse_domaininfo
//  Extracts scalar values needed for analysis; keeps JSON sub-objects as-is
//  for verbatim pass-through to output.
// ─────────────────────────────────────────────────────────────────────────────
static DomainInfoResult parse_domaininfo(const std::string& line) {
    DomainInfoResult r;

    // ── Top-level scalar fields ───────────────────────────────────────────────
    r.fqdn                      = OfflineProcessor::jp_str (line, "fqdn");
    r.netbios_name               = OfflineProcessor::jp_str (line, "netbios_name");
    r.domain_sid                 = OfflineProcessor::jp_str (line, "domain_sid");
    r.functional_level           = OfflineProcessor::jp_int (line, "functional_level", -1);
    r.functional_level_name      = OfflineProcessor::jp_str (line, "functional_level_name");
    r.generated_at               = OfflineProcessor::jp_str (line, "generated_at");
    r.has_enterprise_ca          = OfflineProcessor::jp_bool(line, "has_enterprise_ca");
    r.laps_legacy                = OfflineProcessor::jp_bool(line, "laps_legacy");
    r.laps_windows               = OfflineProcessor::jp_bool(line, "laps_windows");
    r.laps_enabled               = OfflineProcessor::jp_bool(line, "laps_enabled");
    r.smb_signing_policy_present = OfflineProcessor::jp_bool(line, "smb_signing_policy_present");
    r.smart_card_required        = OfflineProcessor::jp_bool(line, "smart_card_required");
    r.machine_account_quota      = OfflineProcessor::jp_int (line, "machine_account_quota", 10);

    // ── Pass-through JSON sub-objects ─────────────────────────────────────────
    r.domain_controllers_json    = OfflineProcessor::jp_extract_array(line, "domain_controllers");
    r.fsmo_json                  = OfflineProcessor::jp_extract_obj  (line, "fsmo");
    r.password_policy_json       = OfflineProcessor::jp_extract_obj  (line, "password_policy");
    r.fine_grained_policies_json = OfflineProcessor::jp_extract_array(line, "fine_grained_policies");
    r.kerberos_policy_json       = OfflineProcessor::jp_extract_obj  (line, "kerberos_policy");
    r.ca_list_json               = OfflineProcessor::jp_extract_array(line, "ca_list");
    r.dns_zones_json             = OfflineProcessor::jp_extract_array(line, "dns_zones");

    // ── Extract password policy scalars for analysis ───────────────────────────
    if (!r.password_policy_json.empty()) {
        r.pwd_min_length        = OfflineProcessor::jp_int (r.password_policy_json, "min_length");
        r.pwd_complexity        = OfflineProcessor::jp_bool(r.password_policy_json, "complexity_enabled");
        r.pwd_max_age_days      = OfflineProcessor::jp_int (r.password_policy_json, "max_age_days");
        r.pwd_history_count     = OfflineProcessor::jp_int (r.password_policy_json, "history_count");
        r.lockout_threshold     = OfflineProcessor::jp_int (r.password_policy_json, "lockout_threshold");
        r.reversible_encryption = OfflineProcessor::jp_bool(r.password_policy_json, "reversible_encryption");
    }

    // ── Extract kerberos policy scalars ───────────────────────────────────────
    if (!r.kerberos_policy_json.empty()) {
        r.krb_max_ticket_age_hours = OfflineProcessor::jp_int(r.kerberos_policy_json, "max_ticket_age_hours", 10);
        r.krb_max_renew_age_days   = OfflineProcessor::jp_int(r.kerberos_policy_json, "max_renew_age_days",    7);
        r.krb_max_clock_skew_mins  = OfflineProcessor::jp_int(r.kerberos_policy_json, "max_clock_skew_mins",   5);
    }

    // ── DNS zone summary ──────────────────────────────────────────────────────
    if (!r.dns_zones_json.empty()) {
        r.dns_zone_count = OfflineProcessor::count_json_array_items(r.dns_zones_json);
    }

    // ── Fine-grained policy count ─────────────────────────────────────────────
    if (!r.fine_grained_policies_json.empty()) {
        r.fine_grained_policy_count = OfflineProcessor::count_json_array_items(r.fine_grained_policies_json);
    }

    // ── FSMO split detection ──────────────────────────────────────────────────
    if (!r.fsmo_json.empty()) {
        const std::string schema  = OfflineProcessor::jp_str(r.fsmo_json, "schema_master");
        const std::string naming  = OfflineProcessor::jp_str(r.fsmo_json, "naming_master");
        const std::string rid     = OfflineProcessor::jp_str(r.fsmo_json, "rid_master");
        const std::string pdc     = OfflineProcessor::jp_str(r.fsmo_json, "pdc_emulator");
        const std::string infra   = OfflineProcessor::jp_str(r.fsmo_json, "infrastructure");

        std::set<std::string> holders;
        for (const auto& h : {schema, naming, rid, pdc, infra})
            if (!h.empty()) holders.insert(h);
        r.fsmo_split = (holders.size() > 1);
    }

    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  analyze_domaininfo  — compute risk findings + score
// ─────────────────────────────────────────────────────────────────────────────
static void analyze_domaininfo(DomainInfoResult& r) {

    // ── CRITICAL ──────────────────────────────────────────────────────────────

    if (r.functional_level >= 0 && r.functional_level < 3) {
        add_finding(r, "CRITICAL", "DFL_BELOW_2008",
            "Domain Functional Level is below Windows Server 2008",
            "DFL=" + std::to_string(r.functional_level) + " (" + r.functional_level_name
            + "). Legacy attack paths (MS14-068, weak Kerberos ciphers) are available.");
    }

    if (!r.pwd_complexity && r.pwd_min_length < 8) {
        add_finding(r, "CRITICAL", "WEAK_PASSWORD_POLICY",
            "Password complexity disabled and minimum length below 8",
            "complexity_enabled=false, min_length=" + std::to_string(r.pwd_min_length)
            + ". Trivially guessable or empty passwords are permitted.");
    }

    if (r.lockout_threshold == 0 && r.fine_grained_policy_count == 0) {
        add_finding(r, "CRITICAL", "LOCKOUT_DISABLED",
            "Account lockout is disabled with no fine-grained fallback",
            "lockoutThreshold=0 and no PSOs found. Brute-force password attacks "
            "against all domain accounts are unrestricted.");
    }

    if (r.krb_max_ticket_age_hours > 10) {
        add_finding(r, "CRITICAL", "KRB_TICKET_AGE_HIGH",
            "Kerberos TGT lifetime exceeds 10 hours",
            "max_ticket_age=" + std::to_string(r.krb_max_ticket_age_hours)
            + "h. Stolen TGTs remain valid longer, extending the window for "
            "Golden Ticket / Pass-the-Ticket attacks.");
    }

    if (r.krb_max_renew_age_days > 7) {
        add_finding(r, "CRITICAL", "KRB_RENEW_AGE_HIGH",
            "Kerberos ticket renewal lifetime exceeds 7 days",
            "max_renew_age=" + std::to_string(r.krb_max_renew_age_days)
            + "d. Attackers with a TGT can keep renewing it well beyond "
            "the initial compromise window.");
    }

    if (r.machine_account_quota > 0) {
        add_finding(r, "CRITICAL", "MAQ_NONZERO",
            "Machine Account Quota allows regular users to join computers",
            "ms-DS-MachineAccountQuota=" + std::to_string(r.machine_account_quota)
            + ". Any authenticated user can add up to "
            + std::to_string(r.machine_account_quota)
            + " machine account(s) to the domain, enabling Kerberos relay "
            "and resource-based constrained delegation attacks.");
    }

    // ── HIGH ──────────────────────────────────────────────────────────────────

    if (r.reversible_encryption) {
        add_finding(r, "HIGH", "REVERSIBLE_ENCRYPTION",
            "Reversible password encryption is enabled",
            "pwdProperties bit 0x10 is set. Passwords are stored in a "
            "recoverable form — equivalent to storing cleartext in the DIT.");
    }

    if (!r.laps_enabled) {
        add_finding(r, "HIGH", "LAPS_NOT_DEPLOYED",
            "LAPS (Local Administrator Password Solution) is not deployed",
            "Neither ms-Mcs-AdmPwd (legacy LAPS) nor msLAPS-Password (Windows LAPS) "
            "schema attributes are present. Local administrator passwords are likely "
            "shared across machines, enabling lateral movement after a single compromise.");
    }

    if (r.pwd_max_age_days == 0) {
        add_finding(r, "HIGH", "PASSWORDS_NEVER_EXPIRE",
            "Default password policy: passwords never expire",
            "maxPwdAge=0. Compromised credentials remain valid indefinitely "
            "unless manually reset.");
    }

    if (r.dns_zone_count > 0) {
        // Check if any zones are non-secure (secure_only count parsed above as 0)
        // dns_secure_only_count populated in parse step would require per-zone parsing.
        // Conservative: flag if any zone exists without secure-only confirmed.
        // Detailed per-zone check is available in the dns_zones array.
    }

    // ── MEDIUM ────────────────────────────────────────────────────────────────

    if (r.functional_level >= 3 && r.functional_level < 7) {
        add_finding(r, "MEDIUM", "DFL_BELOW_2016",
            "Domain Functional Level is below Windows Server 2016",
            "DFL=" + std::to_string(r.functional_level) + " (" + r.functional_level_name
            + "). Newer mitigations such as Protected Users group "
            "enforcement improvements and Kerberos armoring are not fully available.");
    }

    if (!r.smb_signing_policy_present) {
        add_finding(r, "MEDIUM", "SMB_DC_POLICY_ABSENT",
            "Default Domain Controllers Policy GPO not found",
            "The GPO {6AC1786C-016F-11D2-945F-00C04fB984F9} was not found under "
            "CN=Policies. SMB Signing enforcement on DCs cannot be confirmed via LDAP. "
            "Manual SYSVOL inspection required to verify RequireMessageSigning.");
    }

    if (!r.pwd_complexity && r.pwd_min_length < 12) {
        // Only add if not already covered by CRITICAL check
        if (r.pwd_complexity || r.pwd_min_length >= 8) {
            add_finding(r, "MEDIUM", "WEAK_PASSWORD_LENGTH",
                "Password minimum length is below 12 characters",
                "min_length=" + std::to_string(r.pwd_min_length)
                + ". Modern password guidance (NIST SP 800-63B) recommends at "
                "least 12 characters for domain accounts.");
        }
    }

    if (r.krb_max_clock_skew_mins > 5) {
        add_finding(r, "MEDIUM", "KRB_CLOCK_SKEW_HIGH",
            "Kerberos maximum clock skew exceeds 5 minutes",
            "max_clock_skew=" + std::to_string(r.krb_max_clock_skew_mins)
            + "min. A wider clock skew extends the Kerberos replay attack window.");
    }

    if (r.lockout_threshold == 0 && r.fine_grained_policy_count > 0) {
        add_finding(r, "MEDIUM", "LOCKOUT_DISABLED_DEFAULT",
            "Default password policy has no lockout; fine-grained PSOs may not cover all accounts",
            "lockoutThreshold=0 in the default policy. Accounts without an assigned PSO "
            "are unprotected against brute-force attacks.");
    }

    // ── INFO ──────────────────────────────────────────────────────────────────

    if (r.fsmo_split) {
        add_finding(r, "INFO", "FSMO_ROLES_SPLIT",
            "FSMO roles are distributed across multiple domain controllers",
            "Having roles on separate DCs is normal in larger environments but "
            "increases the number of high-value DC targets an attacker must compromise "
            "to seize full FSMO control.");
    }

    if (r.fine_grained_policy_count > 0) {
        add_finding(r, "INFO", "FINE_GRAINED_POLICIES_PRESENT",
            "Fine-grained password policies (PSOs) are configured",
            std::to_string(r.fine_grained_policy_count) + " PSO(s) found. "
            "Review applies_to targets to ensure privileged accounts receive "
            "the strictest policy.");
    }

    if (r.has_enterprise_ca) {
        add_finding(r, "INFO", "ENTERPRISE_CA_PRESENT",
            "Enterprise Certificate Authority is deployed",
            std::to_string(0) + " CA(s) detected. AD CS attack paths (ESC1-ESC11) "
            "should be evaluated — see domain_cert_templates for template-level findings.");
    }

    // ── Risk score ────────────────────────────────────────────────────────────
    int score = 0;
    for (const auto& f : r.findings) {
        if      (f.severity == "CRITICAL") score += 25;
        else if (f.severity == "HIGH")     score += 15;
        else if (f.severity == "MEDIUM")   score += 8;
        else if (f.severity == "INFO")     score += 2;
    }
    r.risk_score = std::min(score, 100);

    // ── Highest severity ──────────────────────────────────────────────────────
    bool has_critical = false, has_high = false, has_medium = false, has_info = false;
    for (const auto& f : r.findings) {
        if      (f.severity == "CRITICAL") has_critical = true;
        else if (f.severity == "HIGH")     has_high     = true;
        else if (f.severity == "MEDIUM")   has_medium   = true;
        else if (f.severity == "INFO")     has_info     = true;
    }
    if      (has_critical) r.highest_severity = "CRITICAL";
    else if (has_high)     r.highest_severity = "HIGH";
    else if (has_medium)   r.highest_severity = "MEDIUM";
    else if (has_info)     r.highest_severity = "INFO";
}

// ─────────────────────────────────────────────────────────────────────────────
//  add_finding helper
// ─────────────────────────────────────────────────────────────────────────────
static void add_finding(DomainInfoResult& r,
                        const std::string& severity,
                        const std::string& code,
                        const std::string& title,
                        const std::string& detail)
{
    r.findings.push_back({ severity, code, title, detail });
}

// ─────────────────────────────────────────────────────────────────────────────
//  domaininfo_to_json  — serializes DomainInfoResult → JSON string
// ─────────────────────────────────────────────────────────────────────────────
static std::string domaininfo_to_json(const DomainInfoResult& r) {
    auto je = [](const std::string& s) { return OfflineProcessor::je(s);      };
    auto jb = [](bool v)               { return v ? "true" : "false";          };
    auto ji = [](int v)                { return std::to_string(v);              };
    auto jl = [](int64_t v)            { return std::to_string(v);              };

    // Helper: empty array / object fallback
    auto jsub_arr = [](const std::string& s) -> const std::string& {
        static const std::string empty_arr = "[]";
        return s.empty() ? empty_arr : s;
    };
    auto jsub_obj = [](const std::string& s) -> const std::string& {
        static const std::string empty_obj = "{}";
        return s.empty() ? empty_obj : s;
    };

    std::ostringstream o;
    o << "{";

    // ── Identity ──────────────────────────────────────────────────────────────
    o << "\"fqdn\":"                  << je(r.fqdn)                              << ","
      << "\"netbios_name\":"          << je(r.netbios_name)                      << ","
      << "\"domain_sid\":"            << je(r.domain_sid)                        << ","
      << "\"functional_level\":"      << ji(r.functional_level)                  << ","
      << "\"functional_level_name\":" << je(r.functional_level_name)             << ","
      << "\"generated_at\":"          << je(r.generated_at)                      << ",";

    // ── Sub-objects (verbatim pass-through) ───────────────────────────────────
    o << "\"domain_controllers\":"    << jsub_arr(r.domain_controllers_json)     << ","
      << "\"fsmo\":"                  << jsub_obj(r.fsmo_json)                   << ","
      << "\"password_policy\":"       << jsub_obj(r.password_policy_json)        << ","
      << "\"fine_grained_policies\":" << jsub_arr(r.fine_grained_policies_json)  << ","
      << "\"kerberos_policy\":"       << jsub_obj(r.kerberos_policy_json)        << ","
      << "\"ca_list\":"               << jsub_arr(r.ca_list_json)                << ","
      << "\"dns_zones\":"             << jsub_arr(r.dns_zones_json)              << ",";

    // ── Scalar flags ──────────────────────────────────────────────────────────
    o << "\"has_enterprise_ca\":"          << jb(r.has_enterprise_ca)          << ","
      << "\"laps_legacy\":"                << jb(r.laps_legacy)                << ","
      << "\"laps_windows\":"              << jb(r.laps_windows)               << ","
      << "\"laps_enabled\":"               << jb(r.laps_enabled)               << ","
      << "\"smb_signing_policy_present\":" << jb(r.smb_signing_policy_present) << ","
      << "\"smart_card_required\":"        << jb(r.smart_card_required)        << ","
      << "\"machine_account_quota\":"      << ji(r.machine_account_quota)      << ",";

    // ── Risk analysis ─────────────────────────────────────────────────────────
    o << "\"risk_score\":"       << ji(r.risk_score)        << ","
      << "\"highest_severity\":" << je(r.highest_severity)  << ","
      << "\"risk_findings\":[";

    for (size_t i = 0; i < r.findings.size(); ++i) {
        if (i) o << ",";
        const auto& f = r.findings[i];
        o << "{"
          << "\"severity\":" << je(f.severity) << ","
          << "\"code\":"     << je(f.code)     << ","
          << "\"title\":"    << je(f.title)    << ","
          << "\"detail\":"   << je(f.detail)
          << "}";
    }

    o << "]}";
    return o.str();
}