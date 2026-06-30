// ─── offline_processorp12.cpp ────────────────────────────────────────────────
//  SECTION TRUSTS — Domain Trust Offline Processor
//
//  Reads:
//    raw_cache/raw_trusts.jsonl  (from TrustCollector)
//
//  Writes:
//    Domain Objects/domain_trusts.<ext>
//
//  Each output record = one trust + per-trust risk findings.
//
//  Risk findings computed per trust:
//
//    CRITICAL
//      TRUST_SID_FILTER_DISABLED
//        Forest trust without QUARANTINED_DOMAIN → SID History injection
//        possible → Enterprise Admin impersonation (Golden Ticket escalation).
//      TRUST_DOWNLEVEL
//        NT4-style trust (trustType=1) — no SID filtering, no Kerberos,
//        no modern security controls.  Effectively a full compromise path.
//      TRUST_INBOUND_TRANSITIVE_EXTERNAL
//        Inbound transitive external trust — remote domain users can
//        transitively reach our domain.  Attack surface is unbounded.
//
//    HIGH
//      TRUST_UNCONSTRAINED_TGT_DELEGATION
//        TGT delegation is not blocked (CROSS_ORGANIZATION_NO_TGT_DELEGATION
//        flag absent on a cross-org trust) — unconstrained Kerberos delegation
//        across the trust boundary is possible.
//      TRUST_RC4_ONLY
//        Trust uses RC4 session keys (USES_RC4_ENCRYPTION set, no AES) —
//        vulnerable to Kerberoast-style offline cracking of cross-trust TGTs.
//      TRUST_BIDIRECTIONAL_FOREST_NO_QUARANTINE
//        Two-way forest trust without quarantine — highest-risk combination;
//        any compromise in either forest propagates to the other.
//      TRUST_SELECTIVE_AUTH_DISABLED
//        Cross-organisation trust without selective authentication
//        (CROSS_ORGANIZATION flag absent) — all authenticated users in the
//        trusted domain can access all resources in the trusting domain.
//
//    MEDIUM
//      TRUST_INBOUND_NO_SELECTIVE_AUTH
//        Inbound (or bidirectional) non-forest trust without selective auth —
//        all remote users can attempt authentication against every resource.
//      TRUST_TREAT_AS_EXTERNAL_FOREST
//        TREAT_AS_EXTERNAL on a forest trust — reduces filtering to external-
//        trust rules, potentially weakening the intended forest boundary.
//      TRUST_WITHIN_FOREST_UNEXPECTED
//        Shortcut trust (WITHIN_FOREST) found — legitimate for large forests
//        but worth reviewing; intra-forest trusts bypass SID filtering.
//
//    INFO
//      TRUST_MIT_REALM
//        Non-Windows Kerberos realm trust — requires manual review to confirm
//        realm keying and cross-realm TGT issuance policy.
//      TRUST_OUTBOUND_ONLY
//        Outbound-only trust — our domain trusts them but they don't trust us.
//        Lower risk direction; document for completeness.
//      TRUST_AES_CONFIRMED
//        AES session keys explicitly confirmed (USES_AES_KEYS set).
//
//  Output schema — domain_trusts.<ext>:
//  {
//    "trust_partner"            : "partner.corp",
//    "flat_name"                : "PARTNER",
//    "partner_sid"              : "S-1-5-21-...",
//    "trust_type_raw"           : 2,
//    "trust_type_name"          : "UPLEVEL",
//    "direction_raw"            : 3,
//    "direction_name"           : "BIDIRECTIONAL",
//    "is_inbound"               : true,
//    "is_outbound"              : true,
//    "attributes_raw"           : 8,
//    "is_transitive"            : true,
//    "is_forest_trust"          : true,
//    "is_external"              : false,
//    "is_within_forest"         : false,
//    "is_cross_org"             : false,
//    "quarantine_enabled"       : false,
//    "treat_as_external"        : false,
//    "tgt_delegation_blocked"   : false,
//    "uses_rc4"                 : false,
//    "uses_aes"                 : true,
//    "sid_filtering_effective"  : true,
//    "when_created"             : "2023-01-15T10:30:00Z",
//    "when_changed"             : "2024-03-22T08:15:00Z",
//    "risk_score"               : 65,
//    "highest_severity"         : "CRITICAL",
//    "risk_findings": [
//      {
//        "severity" : "CRITICAL",
//        "code"     : "TRUST_SID_FILTER_DISABLED",
//        "title"    : "SID filtering is not enforced on this forest trust",
//        "detail"   : "..."
//      }
//    ]
//  }
// ─────────────────────────────────────────────────────────────────────────────
#include "offline_processor.h"
#include <fstream>
#include <sstream>
#include <algorithm>

// ─────────────────────────────────────────────────────────────────────────────
//  TrustRecord  — one parsed trust entry
// ─────────────────────────────────────────────────────────────────────────────
struct TrustRecord {
    // Raw LDAP-derived fields (pass-through)
    std::string trust_partner;
    std::string flat_name;
    std::string partner_sid;
    int         trust_type_raw          = 0;
    std::string trust_type_name;
    int         direction_raw           = 0;
    std::string direction_name;
    bool        is_inbound              = false;
    bool        is_outbound             = false;
    int         attributes_raw          = 0;
    bool        is_transitive           = false;
    bool        is_forest_trust         = false;
    bool        is_external             = false;
    bool        is_within_forest        = false;
    bool        is_cross_org            = false;
    bool        quarantine_enabled      = false;
    bool        treat_as_external       = false;
    bool        sid_filtering_effective = false;
    bool        tgt_delegation_blocked  = false;
    bool        uses_rc4                = false;
    bool        uses_aes                = false;
    std::string when_created;
    std::string when_changed;

    // Risk analysis results
    struct Finding {
        std::string severity;  // CRITICAL | HIGH | MEDIUM | INFO
        std::string code;
        std::string title;
        std::string detail;
    };
    std::vector<Finding> findings;
    int         risk_score        = 0;
    std::string highest_severity;
};

// ─────────────────────────────────────────────────────────────────────────────
//  parse_trust_line
//  Parses one NDJSON line into a TrustRecord using OfflineProcessor helpers.
// ─────────────────────────────────────────────────────────────────────────────
static TrustRecord parse_trust_line(const std::string& line) {
    TrustRecord r;
    r.trust_partner          = OfflineProcessor::jp_str (line, "trust_partner");
    r.flat_name              = OfflineProcessor::jp_str (line, "flat_name");
    r.partner_sid            = OfflineProcessor::jp_str (line, "partner_sid");
    r.trust_type_raw         = OfflineProcessor::jp_int (line, "trust_type_raw",    0);
    r.trust_type_name        = OfflineProcessor::jp_str (line, "trust_type_name");
    r.direction_raw          = OfflineProcessor::jp_int (line, "direction_raw",     0);
    r.direction_name         = OfflineProcessor::jp_str (line, "direction_name");
    r.is_inbound             = OfflineProcessor::jp_bool(line, "is_inbound");
    r.is_outbound            = OfflineProcessor::jp_bool(line, "is_outbound");
    r.attributes_raw         = OfflineProcessor::jp_int (line, "attributes_raw",    0);
    r.is_transitive          = OfflineProcessor::jp_bool(line, "is_transitive");
    r.is_forest_trust        = OfflineProcessor::jp_bool(line, "is_forest_trust");
    r.is_external            = OfflineProcessor::jp_bool(line, "is_external");
    r.is_within_forest       = OfflineProcessor::jp_bool(line, "is_within_forest");
    r.is_cross_org           = OfflineProcessor::jp_bool(line, "is_cross_org");
    r.quarantine_enabled     = OfflineProcessor::jp_bool(line, "quarantine_enabled");
    r.treat_as_external      = OfflineProcessor::jp_bool(line, "treat_as_external");
    r.sid_filtering_effective= OfflineProcessor::jp_bool(line, "sid_filtering_effective");
    r.tgt_delegation_blocked = OfflineProcessor::jp_bool(line, "tgt_delegation_blocked");
    r.uses_rc4               = OfflineProcessor::jp_bool(line, "uses_rc4");
    r.uses_aes               = OfflineProcessor::jp_bool(line, "uses_aes");
    r.when_created           = OfflineProcessor::jp_str (line, "when_created");
    r.when_changed           = OfflineProcessor::jp_str (line, "when_changed");
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  analyze_trust
//  Computes risk findings for one trust record.
// ─────────────────────────────────────────────────────────────────────────────
static void analyze_trust(TrustRecord& r) {
    auto add = [&](const char* sev, const char* code,
                   const char* title, std::string detail) {
        r.findings.push_back({sev, code, title, std::move(detail)});
    };

    // ── CRITICAL ──────────────────────────────────────────────────────────────

    // Forest trust without SID Quarantine → SID History injection
    if (r.is_forest_trust && !r.quarantine_enabled && !r.is_within_forest) {
        add("CRITICAL", "TRUST_SID_FILTER_DISABLED",
            "SID filtering is not enforced on this forest trust",
            "Forest trust with '" + r.trust_partner + "' does not have "
            "QUARANTINED_DOMAIN (trustAttributes 0x4) set. An attacker who "
            "compromises any account in the trusted forest can inject "
            "Enterprise Admin or Schema Admin SIDs via SID History, achieving "
            "full control of this forest without further exploitation. "
            "Remediation: run 'netdom trust <domain> /quarantine:yes' or "
            "set trustAttributes |= 0x4 on the trustedDomain object.");
    }

    // Downlevel (NT4) trust — no modern security controls
    if (r.trust_type_raw == 1) {
        add("CRITICAL", "TRUST_DOWNLEVEL",
            "Legacy NT4-style trust — no SID filtering or Kerberos protection",
            "Trust with '" + r.trust_partner + "' uses trustType=1 (DOWNLEVEL / NT4). "
            "NT4 trusts predate SID filtering, Kerberos cross-realm tickets, and "
            "modern auth controls. Any NTLM pass-through authentication across this "
            "trust is unfiltered. Upgrade to an Uplevel trust or remove if unused.");
    }

    // Inbound transitive external trust — remote users can chain inward
    if (r.is_inbound && r.is_transitive && r.is_external && !r.is_forest_trust) {
        add("CRITICAL", "TRUST_INBOUND_TRANSITIVE_EXTERNAL",
            "Inbound transitive external trust creates unbounded authentication path",
            "'" + r.trust_partner + "' trusts us (INBOUND), and the trust is "
            "transitive. Remote users from any domain that trusts '" +
            r.trust_partner + "' can potentially authenticate into our domain via "
            "Kerberos chaining. Restrict with selective authentication "
            "(trustAttributes |= 0x10) or convert to non-transitive.");
    }

    // ── HIGH ──────────────────────────────────────────────────────────────────

    // TGT delegation not blocked on cross-org trust
    if (r.is_outbound && !r.tgt_delegation_blocked && r.is_cross_org) {
        add("HIGH", "TRUST_UNCONSTRAINED_TGT_DELEGATION",
            "TGT delegation is not restricted across this cross-organisation trust",
            "The trust with '" + r.trust_partner + "' is a cross-organisation trust "
            "(CROSS_ORGANIZATION) but the CROSS_ORGANIZATION_NO_TGT_DELEGATION flag "
            "(0x400) is absent. Services with unconstrained delegation in the "
            "trusting domain can request forwardable TGTs for users from the trusted "
            "domain, enabling full credential harvesting. "
            "Set trustAttributes |= 0x400 to block TGT delegation.");
    }

    // RC4-only trust (no AES)
    if (r.uses_rc4 && !r.uses_aes) {
        add("HIGH", "TRUST_RC4_ONLY",
            "Trust session keys use RC4 — vulnerable to offline cracking",
            "Trust with '" + r.trust_partner + "' has USES_RC4_ENCRYPTION (0x80) "
            "set and USES_AES_KEYS (0x200) absent. RC4-encrypted inter-realm TGTs "
            "can be cracked offline (similar to Kerberoasting). "
            "Ensure both DCs support AES and set trustAttributes |= 0x200.");
    }

    // Bidirectional forest trust with no quarantine
    if (r.is_inbound && r.is_outbound && r.is_forest_trust && !r.quarantine_enabled) {
        add("HIGH", "TRUST_BIDIRECTIONAL_FOREST_NO_QUARANTINE",
            "Two-way forest trust without SID quarantine — highest-risk configuration",
            "Bidirectional forest trust with '" + r.trust_partner + "' allows full "
            "mutual authentication and, without QUARANTINED_DOMAIN, SID History "
            "injection in either direction. A single domain compromise propagates "
            "to both forests. Enable quarantine on both sides of the trust.");
    }

    // Cross-org trust without selective authentication
    if (r.is_inbound && !r.is_cross_org && !r.is_within_forest) {
        add("HIGH", "TRUST_SELECTIVE_AUTH_DISABLED",
            "Selective authentication is not enforced — all remote users can authenticate",
            "The inbound trust from '" + r.trust_partner + "' does not enforce "
            "selective authentication (CROSS_ORGANIZATION flag 0x10 absent). "
            "Every authenticated user in the trusted domain can attempt "
            "authentication against every resource in this domain. "
            "Enable selective authentication and grant access explicitly per resource.");
    }

    // ── MEDIUM ────────────────────────────────────────────────────────────────

    // Inbound non-forest trust without selective auth (lower risk than cross-org case)
    if (r.is_inbound && !r.is_cross_org && !r.is_forest_trust && !r.is_within_forest
        && r.trust_type_raw != 1 /* already CRITICAL for downlevel */) {
        add("MEDIUM", "TRUST_INBOUND_NO_SELECTIVE_AUTH",
            "Inbound trust without selective authentication",
            "Inbound trust from '" + r.trust_partner + "' allows any authenticated "
            "user from that domain to attempt access to resources here. Without "
            "selective authentication, access control relies entirely on "
            "resource-level ACLs. Review and consider enabling selective auth.");
    }

    // TREAT_AS_EXTERNAL on a forest trust
    if (r.is_forest_trust && r.treat_as_external) {
        add("MEDIUM", "TRUST_TREAT_AS_EXTERNAL_FOREST",
            "TREAT_AS_EXTERNAL weakens filtering on a forest trust",
            "Forest trust with '" + r.trust_partner + "' has TREAT_AS_EXTERNAL "
            "(0x40) set. This applies external-trust SID filtering rules instead "
            "of the stricter forest-trust rules, potentially allowing SIDs from "
            "child domains in the trusted forest to pass through unfiltered.");
    }

    // Shortcut (within-forest) trust
    if (r.is_within_forest) {
        add("MEDIUM", "TRUST_WITHIN_FOREST_UNEXPECTED",
            "Shortcut (intra-forest) trust detected — review intent",
            "Trust with '" + r.trust_partner + "' is an intra-forest shortcut "
            "trust (WITHIN_FOREST). These are normal in large forests for "
            "authentication performance, but bypass SID filtering entirely. "
            "Confirm this trust is intentional and the partner domain is "
            "expected to be within the same forest.");
    }

    // ── INFO ──────────────────────────────────────────────────────────────────

    // MIT Kerberos realm
    if (r.trust_type_raw == 3) {
        add("INFO", "TRUST_MIT_REALM",
            "Non-Windows Kerberos realm trust",
            "Trust with '" + r.trust_partner + "' is a MIT Kerberos realm trust "
            "(trustType=3). Review cross-realm key strength, ticket lifetimes, "
            "and whether the realm's KDC is secured to the same standard as your DCs.");
    }

    // Outbound-only
    if (r.is_outbound && !r.is_inbound) {
        add("INFO", "TRUST_OUTBOUND_ONLY",
            "Outbound-only trust — our domain trusts the partner",
            "Our domain trusts '" + r.trust_partner + "' (OUTBOUND). Our users "
            "can access resources there, but their users cannot authenticate here. "
            "Confirm this is intentional and the trusted domain's security posture "
            "meets your standards, as a compromise there could affect our users.");
    }

    // AES confirmed
    if (r.uses_aes && !r.uses_rc4) {
        add("INFO", "TRUST_AES_CONFIRMED",
            "AES session keys confirmed for this trust",
            "Trust with '" + r.trust_partner + "' explicitly uses AES encryption "
            "(USES_AES_KEYS). This is the recommended configuration.");
    }

    // ── Compute risk score and highest severity ───────────────────────────────
    int score = 0;
    std::string highest = "NONE";
    const std::vector<std::string> order = {"CRITICAL","HIGH","MEDIUM","INFO"};

    for (const auto& f : r.findings) {
        if (f.severity == "CRITICAL") { score += 40; if (highest == "NONE" || highest == "HIGH" || highest == "MEDIUM" || highest == "INFO") highest = "CRITICAL"; }
        else if (f.severity == "HIGH"  ) { score += 20; if (highest == "NONE" || highest == "MEDIUM" || highest == "INFO") highest = "HIGH"; }
        else if (f.severity == "MEDIUM") { score += 10; if (highest == "NONE" || highest == "INFO")  highest = "MEDIUM"; }
        else if (f.severity == "INFO"  ) { score +=  2; if (highest == "NONE") highest = "INFO"; }
    }
    r.risk_score       = std::min(score, 100);
    r.highest_severity = highest.empty() ? "NONE" : highest;
}

// ─────────────────────────────────────────────────────────────────────────────
//  trust_to_json
//  Serializes a fully-analyzed TrustRecord to a JSON object string.
// ─────────────────────────────────────────────────────────────────────────────
static std::string trust_to_json(const TrustRecord& r) {
    auto je = [](const std::string& s) { return OfflineProcessor::je(s); };
    auto jb = [](bool v)               { return v ? std::string("true") : std::string("false"); };
    auto ji = [](int v)                { return std::to_string(v); };

    std::ostringstream o;
    o << "{"
      // ── Identity & raw fields (pass-through) ─────────────────────────────
      << "\"trust_partner\":"           << je(r.trust_partner)             << ","
      << "\"flat_name\":"               << je(r.flat_name)                 << ","
      << "\"partner_sid\":"             << je(r.partner_sid)               << ","
      << "\"trust_type_raw\":"          << ji(r.trust_type_raw)            << ","
      << "\"trust_type_name\":"         << je(r.trust_type_name)           << ","
      << "\"direction_raw\":"           << ji(r.direction_raw)             << ","
      << "\"direction_name\":"          << je(r.direction_name)            << ","
      << "\"is_inbound\":"              << jb(r.is_inbound)                << ","
      << "\"is_outbound\":"             << jb(r.is_outbound)               << ","
      << "\"attributes_raw\":"          << ji(r.attributes_raw)            << ","
      << "\"is_transitive\":"           << jb(r.is_transitive)             << ","
      << "\"is_forest_trust\":"         << jb(r.is_forest_trust)           << ","
      << "\"is_external\":"             << jb(r.is_external)               << ","
      << "\"is_within_forest\":"        << jb(r.is_within_forest)          << ","
      << "\"is_cross_org\":"            << jb(r.is_cross_org)              << ","
      << "\"quarantine_enabled\":"      << jb(r.quarantine_enabled)        << ","
      << "\"treat_as_external\":"       << jb(r.treat_as_external)         << ","
      << "\"sid_filtering_effective\":" << jb(r.sid_filtering_effective)   << ","
      << "\"tgt_delegation_blocked\":"  << jb(r.tgt_delegation_blocked)    << ","
      << "\"uses_rc4\":"                << jb(r.uses_rc4)                  << ","
      << "\"uses_aes\":"                << jb(r.uses_aes)                  << ","
      << "\"when_created\":"            << je(r.when_created)              << ","
      << "\"when_changed\":"            << je(r.when_changed)              << ","
      // ── Risk analysis ─────────────────────────────────────────────────────
      << "\"risk_score\":"              << ji(r.risk_score)                << ","
      << "\"highest_severity\":"        << je(r.highest_severity)          << ","
      << "\"risk_findings\":[";

    for (size_t i = 0; i < r.findings.size(); ++i) {
        if (i) o << ",";
        const auto& f = r.findings[i];
        o << "{"
          << "\"severity\":"  << je(f.severity) << ","
          << "\"code\":"      << je(f.code)     << ","
          << "\"title\":"     << je(f.title)    << ","
          << "\"detail\":"    << je(f.detail)
          << "}";
    }
    o << "]}";
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  OfflineProcessor::process_trusts  — public entry point
// ─────────────────────────────────────────────────────────────────────────────
bool OfflineProcessor::process_trusts(const OfflineProcessorOptions& opts)
{
    const std::string raw_path = opts.raw_dir    + "/raw_trusts.jsonl";
    const std::string ext      = opts.output_ext.empty() ? "jsonl" : opts.output_ext;
    const std::string out_path = opts.output_dir + "/domain_trusts." + ext;

    std::ifstream raw(raw_path);
    if (!raw) {
        log_warn("[Trust] raw_trusts.jsonl not found: " + raw_path
                 + " — trust processing skipped.");
        return true;  // Non-fatal: domain may have no trusts
    }

    fs::create_directories(opts.output_dir);
    std::ofstream out(out_path, std::ios::out | std::ios::trunc);
    if (!out) {
        log_err("[Trust] Cannot open output: " + out_path);
        return false;
    }

    std::vector<std::string> rows;
    std::string line;
    int total = 0, critical_count = 0, high_count = 0;

    while (std::getline(raw, line)) {
        // Strip carriage return
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        TrustRecord r = parse_trust_line(line);
        if (r.trust_partner.empty()) continue;

        analyze_trust(r);

        if (r.highest_severity == "CRITICAL") ++critical_count;
        else if (r.highest_severity == "HIGH") ++high_count;

        rows.push_back(trust_to_json(r));
        ++total;
    }

    OfflineProcessor::write_objects(out, rows, out_path, "[Trust]");

    if (!out) {
        log_err("[Trust] Write error — output may be incomplete: " + out_path);
        return false;
    }

    log_ok("[Trust] domain_trusts -> " + out_path);
    log_ok("[Trust] " + std::to_string(total)          + " trust(s)  |  "
           + std::to_string(critical_count) + " CRITICAL  |  "
           + std::to_string(high_count)     + " HIGH");

    return true;
}