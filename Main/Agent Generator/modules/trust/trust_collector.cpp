// ─── trust_collector.cpp ─────────────────────────────────────────────────────
//  Phase 1 — Domain Trust Collector
//
//  Collects all trustedDomain objects from CN=System,<domainNC> and extracts
//  every attribute required for a full security analysis:
//    direction, transitivity, SID filtering, quarantine, selective auth,
//    TGT delegation, RC4/AES session keys, forest vs external classification.
//
//  Output: raw_cache/raw_trusts.jsonl  (one JSON object per line)
//  Offline analysis: TrustOfflineProcessor (offline_processorp12.cpp)
// ─────────────────────────────────────────────────────────────────────────────
#include "trust_collector.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <cstring>

// ─────────────────────────────────────────────────────────────────────────────
//  trustAttributes bit-flag constants
// ─────────────────────────────────────────────────────────────────────────────
namespace TrustAttr {
    constexpr int NONTRANSITIVE                    = 0x00000001;
    constexpr int UPLEVEL_ONLY                     = 0x00000002;
    constexpr int QUARANTINED_DOMAIN               = 0x00000004;  // SID filtering ON
    constexpr int FOREST_TRANSITIVE                = 0x00000008;  // forest trust
    constexpr int CROSS_ORGANIZATION               = 0x00000010;  // selective auth
    constexpr int WITHIN_FOREST                    = 0x00000020;  // intra-forest
    constexpr int TREAT_AS_EXTERNAL                = 0x00000040;
    constexpr int USES_RC4_ENCRYPTION              = 0x00000080;
    constexpr int USES_AES_KEYS                    = 0x00000200;
    constexpr int CROSS_ORGANIZATION_NO_TGT_DELEG  = 0x00000400;  // TGT blocked
    constexpr int PIM_TRUST                        = 0x00000800;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Constructor
// ─────────────────────────────────────────────────────────────────────────────
TrustCollector::TrustCollector(LDAPEngine& engine) : engine_(engine) {}

// ─────────────────────────────────────────────────────────────────────────────
//  collect  — main entry point
// ─────────────────────────────────────────────────────────────────────────────
int TrustCollector::collect(const TrustCollectorOptions& opts) {
    fs::create_directories(opts.output_dir);

    const std::string& base_dn = engine_.cfg_.base_dn;
    if (base_dn.empty()) {
        log_err("[Trust] base_dn is empty — connect and set DOMNAME first.");
        return -1;
    }

    // trustedDomain objects live under CN=System,<domainNC>
    const std::string system_base = "CN=System," + base_dn;
    log_info("[Trust] Querying: " + system_base);

    const std::vector<std::string> attrs = {
        "trustPartner",          // FQDN of trusted domain
        "flatName",              // NetBIOS / flat name
        "securityIdentifier",    // partner domain SID (binary)
        "trustType",             // integer: 1=Downlevel,2=Uplevel,3=MIT,4=DCE
        "trustDirection",        // integer: 0=Disabled,1=Inbound,2=Outbound,3=Bidir
        "trustAttributes",       // bitmask (see TrustAttr namespace)
        "whenCreated",
        "whenChanged",
    };

    std::vector<TrustEntry> entries;

    const std::string saved_base = engine_.cfg_.base_dn;
    engine_.cfg_.base_dn = system_base;

    engine_.search(
        "(objectClass=trustedDomain)",
        attrs,
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

            TrustEntry t;
            t.trust_partner   = str("trustPartner");
            t.flat_name       = str("flatName");
            t.partner_sid     = format_sid(str("securityIdentifier"));
            t.trust_type      = ival("trustType");
            t.trust_direction = ival("trustDirection");
            t.trust_attrs     = ival("trustAttributes");
            t.when_created    = generalized_time_to_iso(str("whenCreated"));
            t.when_changed    = generalized_time_to_iso(str("whenChanged"));

            if (!t.trust_partner.empty())
                entries.push_back(std::move(t));
        });

    engine_.cfg_.base_dn = saved_base;

    if (entries.empty()) {
        log_warn("[Trust] No trustedDomain objects found — no external trusts exist "
                 "or the account lacks read permission on CN=System.");
    }

    // ── Write output ──────────────────────────────────────────────────────────
    output_path_ = fs::path(opts.output_dir) / "raw_trusts.jsonl";
    std::ofstream f(output_path_, std::ios::binary);
    if (!f) {
        log_err("[Trust] Failed to open: " + output_path_.string());
        return -1;
    }

    for (const auto& e : entries)
        f << entry_to_json(e) << "\n";

    if (!f) {
        log_err("[Trust] Write error: " + output_path_.string());
        return -1;
    }

    log_ok("[Trust] raw_trusts.jsonl -> " + output_path_.string());
    log_ok("[Trust] " + std::to_string(entries.size()) + " trust relationship(s) collected.");

    return static_cast<int>(entries.size());
}

// ─────────────────────────────────────────────────────────────────────────────
//  entry_to_json
//  Serializes one TrustEntry to a flat JSON object string.
//  All security-derived flags are computed here so the offline processor
//  can focus purely on risk analysis without re-parsing raw integers.
// ─────────────────────────────────────────────────────────────────────────────
std::string TrustCollector::entry_to_json(const TrustEntry& e) {
    const int  a  = e.trust_attrs;
    const int  tt = e.trust_type;
    const int  td = e.trust_direction;

    // ── Derived boolean flags ─────────────────────────────────────────────────
    const bool is_forest_trust  = (a & TrustAttr::FOREST_TRANSITIVE)   != 0;
    const bool is_within_forest = (a & TrustAttr::WITHIN_FOREST)       != 0;
    const bool is_cross_org     = (a & TrustAttr::CROSS_ORGANIZATION)  != 0;
    const bool quarantine       = (a & TrustAttr::QUARANTINED_DOMAIN)  != 0;
    const bool treat_external   = (a & TrustAttr::TREAT_AS_EXTERNAL)   != 0;
    const bool no_tgt_deleg     = (a & TrustAttr::CROSS_ORGANIZATION_NO_TGT_DELEG) != 0;
    const bool uses_rc4         = (a & TrustAttr::USES_RC4_ENCRYPTION) != 0;
    const bool uses_aes         = (a & TrustAttr::USES_AES_KEYS)       != 0;
    const bool non_transitive   = (a & TrustAttr::NONTRANSITIVE)       != 0;

    // is_transitive: forest trusts are always transitive by nature;
    // non-forest trusts are transitive unless NONTRANSITIVE bit is set.
    const bool is_transitive = is_forest_trust || !non_transitive;

    // is_external: TREAT_AS_EXTERNAL or type=1 (Downlevel/NT4) or
    // neither forest nor within-forest and type=2 (Uplevel)
    const bool is_external = treat_external
        || (!is_forest_trust && !is_within_forest && tt == 2)
        || tt == 1;

    // Direction booleans
    const bool is_inbound  = (td == 1) || (td == 3);
    const bool is_outbound = (td == 2) || (td == 3);

    std::ostringstream o;
    o << "{"
      // ── Identity ─────────────────────────────────────────────────────────
      << "\"trust_partner\":"          << je(e.trust_partner)             << ","
      << "\"flat_name\":"              << je(e.flat_name)                 << ","
      << "\"partner_sid\":"            << je(e.partner_sid)               << ","
      // ── Type & Direction ─────────────────────────────────────────────────
      << "\"trust_type_raw\":"         << ji(tt)                          << ","
      << "\"trust_type_name\":"        << je(trust_type_name(tt))         << ","
      << "\"direction_raw\":"          << ji(td)                          << ","
      << "\"direction_name\":"         << je(trust_direction_name(td))    << ","
      << "\"is_inbound\":"             << jb(is_inbound)                  << ","
      << "\"is_outbound\":"            << jb(is_outbound)                 << ","
      // ── Transitivity & classification ────────────────────────────────────
      << "\"attributes_raw\":"         << ji(a)                           << ","
      << "\"is_transitive\":"          << jb(is_transitive)               << ","
      << "\"is_forest_trust\":"        << jb(is_forest_trust)             << ","
      << "\"is_external\":"            << jb(is_external)                 << ","
      << "\"is_within_forest\":"       << jb(is_within_forest)            << ","
      << "\"is_cross_org\":"           << jb(is_cross_org)                << ","
      // ── SID Filtering & Quarantine ───────────────────────────────────────
      << "\"quarantine_enabled\":"     << jb(quarantine)                  << ","
      << "\"treat_as_external\":"      << jb(treat_external)              << ","
      << "\"sid_filtering_effective\":" << jb(sid_filtering_effective(tt, a)) << ","
      // ── TGT Delegation & Encryption ──────────────────────────────────────
      << "\"tgt_delegation_blocked\":" << jb(no_tgt_deleg)               << ","
      << "\"uses_rc4\":"               << jb(uses_rc4)                    << ","
      << "\"uses_aes\":"               << jb(uses_aes)                    << ","
      // ── Timestamps ───────────────────────────────────────────────────────
      << "\"when_created\":"           << je(e.when_created)              << ","
      << "\"when_changed\":"           << je(e.when_changed)
      << "}";
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  sid_filtering_effective
//
//  SID filtering rules (per Microsoft documentation):
//
//  Within-forest trusts (WITHIN_FOREST):
//    → Not applicable. Intra-forest trusts implicitly trust all SIDs.
//      Returning false here is intentional — this is noted as a risk finding
//      only when the trust is unexpected (e.g. a rogue shortcut trust).
//
//  Forest trusts (FOREST_TRANSITIVE):
//    → Filtering is ON when QUARANTINED_DOMAIN bit is set.
//    → Without QUARANTINED_DOMAIN, SID History can be used to inject
//      Enterprise Admin SIDs — critical Golden Ticket escalation path.
//
//  External trusts (non-forest, non-within-forest, or TREAT_AS_EXTERNAL):
//    → Filtering is ON by default for external trusts (Windows 2003+).
//    → TREAT_AS_EXTERNAL alone does not disable filtering; it merely
//      affects which objects are accessible across the trust.
//    → Filtering is considered disabled only when explicitly documented
//      as such — we conservatively mark external trusts as filtered.
//
//  Downlevel (NT4, type=1):
//    → No SID filtering — legacy trusts pass SIDs unfiltered.
// ─────────────────────────────────────────────────────────────────────────────
bool TrustCollector::sid_filtering_effective(int trust_type, int trust_attrs) {
    const bool is_within_forest = (trust_attrs & TrustAttr::WITHIN_FOREST)      != 0;
    const bool is_forest        = (trust_attrs & TrustAttr::FOREST_TRANSITIVE)  != 0;
    const bool quarantine       = (trust_attrs & TrustAttr::QUARANTINED_DOMAIN) != 0;

    // Intra-forest: SID filtering does not apply
    if (is_within_forest) return false;

    // Downlevel (NT4): no filtering
    if (trust_type == 1) return false;

    // Forest trust: filtering only when QUARANTINED_DOMAIN is explicitly set
    if (is_forest) return quarantine;

    // External / uplevel trust: filtering ON by default (Windows 2003+)
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  trust_type_name
// ─────────────────────────────────────────────────────────────────────────────
std::string TrustCollector::trust_type_name(int t) {
    switch (t) {
        case 1:  return "DOWNLEVEL";
        case 2:  return "UPLEVEL";
        case 3:  return "MIT";
        case 4:  return "DCE";
        default: return "UNKNOWN";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  trust_direction_name
// ─────────────────────────────────────────────────────────────────────────────
std::string TrustCollector::trust_direction_name(int d) {
    switch (d) {
        case 0:  return "DISABLED";
        case 1:  return "INBOUND";
        case 2:  return "OUTBOUND";
        case 3:  return "BIDIRECTIONAL";
        default: return "UNKNOWN";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  format_sid  — raw binary objectSid → "S-1-5-21-..." string
// ─────────────────────────────────────────────────────────────────────────────
std::string TrustCollector::format_sid(const std::string& raw) {
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
//  generalized_time_to_iso  — "20230115103000.0Z" → "2023-01-15T10:30:00Z"
// ─────────────────────────────────────────────────────────────────────────────
std::string TrustCollector::generalized_time_to_iso(const std::string& gt) {
    if (gt.size() < 14) return gt;
    return gt.substr(0,4)  + "-" + gt.substr(4,2)  + "-" + gt.substr(6,2)
         + "T" + gt.substr(8,2) + ":" + gt.substr(10,2) + ":" + gt.substr(12,2) + "Z";
}

// ─────────────────────────────────────────────────────────────────────────────
//  JSON helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string TrustCollector::je(const std::string& s) {
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

std::string TrustCollector::jb(bool v)  { return v ? "true" : "false"; }
std::string TrustCollector::ji(int v)   { return std::to_string(v); }