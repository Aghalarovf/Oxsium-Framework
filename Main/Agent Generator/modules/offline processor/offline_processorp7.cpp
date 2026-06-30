// ─── offline_processorp7.cpp ─────────────────────────────────────────────────
// SECTION 31  ProcessedOU struct helpers  — parse + analyze
// SECTION 32  ou_to_json  — serialization
// SECTION 33  load_and_process_ous
// SECTION 34  process_ous  (public entry point)
//             process()  — updated to include OUs
//
//  Input : raw_cache/raw_ous.jsonl   (OUCollector output)
//  Output: Domain Objects/domain_ous.jsonl
//
//  Each output line is one OU object with all enriched fields:
//    - gpo_count / inherited_gpo_count from gPLink parsing
//    - resolved managed_by_name  (DN → sAMAccountName via lookup table)
//    - high_risk flag  (highvalue || privileged_users_count > 0)
//    - depth-aware risk scoring
//
//  Reading (Python):
//    import json
//    with open("domain_ous.jsonl") as f:
//        for line in f:
//            ou = json.loads(line)
// ─────────────────────────────────────────────────────────────────────────────
#include "offline_processor.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <system_error>

// ─────────────────────────────────────────────────────────────────────────────
//  Small JSON helpers for OU pass-through fields
// ─────────────────────────────────────────────────────────────────────────────
std::string OfflineProcessor::jp_extract_array(const std::string& json,
                                               const std::string& key)
{
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "[]";

    size_t start = json.find('[', pos + search.size());
    if (start == std::string::npos) return "[]";

    int depth = 0;
    bool in_string = false;
    bool escape = false;
    for (size_t i = start; i < json.size(); ++i) {
        char ch = json[i];
        if (in_string) {
            if (escape) {
                escape = false;
            } else if (ch == '\\') {
                escape = true;
            } else if (ch == '"') {
                in_string = false;
            }
            continue;
        }

        if (ch == '"') {
            in_string = true;
        } else if (ch == '[') {
            ++depth;
        } else if (ch == ']') {
            --depth;
            if (depth == 0) return json.substr(start, i - start + 1);
        }
    }

    return "[]";
}

std::string OfflineProcessor::jp_extract_obj(const std::string& json,
                                              const std::string& key)
{
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "{}";

    size_t start = json.find('{', pos + search.size());
    if (start == std::string::npos) return "{}";

    int depth = 0;
    bool in_string = false;
    bool escape = false;
    for (size_t i = start; i < json.size(); ++i) {
        char ch = json[i];
        if (in_string) {
            if (escape) {
                escape = false;
            } else if (ch == '\\') {
                escape = true;
            } else if (ch == '"') {
                in_string = false;
            }
            continue;
        }

        if (ch == '"') {
            in_string = true;
        } else if (ch == '{') {
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0) return json.substr(start, i - start + 1);
        }
    }

    return "{}";
}

int OfflineProcessor::count_json_array_items(const std::string& json_array)
{
    if (json_array.empty()) return 0;

    int count = 0;
    bool in_string = false;
    bool escape = false;
    int depth = 0;
    bool saw_item = false;

    for (char ch : json_array) {
        if (in_string) {
            if (escape) {
                escape = false;
            } else if (ch == '\\') {
                escape = true;
            } else if (ch == '"') {
                in_string = false;
            }
            continue;
        }

        if (ch == '"') {
            in_string = true;
            saw_item = true;
        } else if (ch == '[' || ch == '{') {
            ++depth;
            saw_item = true;
        } else if (ch == ']' || ch == '}') {
            if (depth > 0) --depth;
        } else if (ch == ',' && depth == 1) {
            ++count;
        }
    }

    if (!saw_item) return 0;
    return count + 1;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 31 — parse_raw_ou
//
//  Reads one JSONL line (from raw_ous.jsonl) and fills a ProcessedOU.
//  Field names match OUCollector's schema exactly.
// ═════════════════════════════════════════════════════════════════════════════

ProcessedOU OfflineProcessor::parse_raw_ou(const std::string& obj) const
{
    ProcessedOU ou;

    // ── Identity ──────────────────────────────────────────────────────────────
    ou.name         = jp_str(obj, "name");
    ou.dn           = jp_str(obj, "dn");

    // Collector writes "Unknown OU" when the LDAP "name" attribute was absent.
    // Recover the real name from the first RDN of the DN.
    // e.g.  "OU=Domain Controllers,DC=corp,DC=local"  ->  "Domain Controllers"
    if (ou.name.empty() || ou.name == "Unknown OU") {
        const std::string& d = ou.dn;
        size_t eq    = d.find('=');
        size_t comma = d.find(',', eq + 1);
        if (eq != std::string::npos)
            ou.name = d.substr(eq + 1,
                (comma != std::string::npos ? comma : d.size()) - eq - 1);
    }
    ou.description  = jp_str(obj, "description");
    ou.managed_by   = jp_str(obj, "managed_by");
    ou.object_guid  = jp_str(obj, "object_guid");
    ou.object_id    = jp_str(obj, "object_id");

    // ── Resolve managed_by DN → sAMAccountName ────────────────────────────────
    if (!ou.managed_by.empty()) {
        std::string key = upper(ou.managed_by);
        auto it = dn_to_sam_.find(key);
        if (it != dn_to_sam_.end())
            ou.managed_by_name = it->second;
        else
            ou.managed_by_name = cn_from_dn(ou.managed_by);
    }

    // ── Parent / Depth / Children ─────────────────────────────────────────────
    ou.parent_dn  = jp_str(obj, "parent_dn");
    ou.child_ous  = jp_arr(obj, "child_ous");
    ou.depth      = jp_int(obj, "depth", 0);

    // ── GPO ───────────────────────────────────────────────────────────────────
    ou.gpo_links_raw      = jp_str(obj, "gpo_links_raw");
    ou.has_gpo_links      = jp_bool(obj, "has_gpo_links",      false);
    ou.inheritance_blocked = jp_bool(obj, "inheritance_blocked", false);
    ou.blocksinheritance  = jp_bool(obj, "blocksinheritance",  false);
    ou.gp_options         = jp_int(obj,  "gp_options",          0);

    // linked_gpos / gpo_precedence / inherited_gpos are complex nested arrays;
    // we forward the raw JSON sub-strings so they pass through unchanged.
    ou.linked_gpos_raw     = jp_extract_array(obj, "linked_gpos");
    ou.gpo_precedence_raw  = jp_extract_array(obj, "gpo_precedence");
    ou.inherited_gpos_raw  = jp_extract_array(obj, "inherited_gpos");

    // Count linked GPOs from the raw array string (count '{' at depth 1)
    ou.gpo_count = count_json_array_items(ou.linked_gpos_raw);
    ou.inherited_gpo_count = count_json_array_items(ou.inherited_gpos_raw);

    // ── Object count ──────────────────────────────────────────────────────────
    ou.object_count = jp_int(obj, "object_count", 0);

    // ── Privileged objects ────────────────────────────────────────────────────
    ou.privileged_users_count     = jp_int(obj, "privileged_users_count",     0);
    ou.privileged_computers_count = jp_int(obj, "privileged_computers_count", 0);
    // Forward raw JSON arrays as-is
    ou.privileged_users_raw     = jp_extract_array(obj, "privileged_users");
    ou.privileged_computers_raw = jp_extract_array(obj, "privileged_computers");

    // ── Flags ─────────────────────────────────────────────────────────────────
    ou.delegated_permissions = jp_bool(obj, "delegated_permissions", false);
    ou.highvalue             = jp_bool(obj, "highvalue",             false);
    ou.isaclprotected        = jp_bool(obj, "isaclprotected",        false);

    // ── Domain ────────────────────────────────────────────────────────────────
    ou.domain_sid  = jp_str(obj, "domainsid");
    ou.domain_name = domain_name_;

    // ── Timestamps ────────────────────────────────────────────────────────────
    {
        std::string wc = jp_str(obj, "when_created");
        ou.when_created = generalized_time_to_iso(wc);
        if (ou.when_created.empty()) ou.when_created = wc;
    }
    {
        std::string wc = jp_str(obj, "when_changed");
        ou.when_changed = generalized_time_to_iso(wc);
        if (ou.when_changed.empty()) ou.when_changed = wc;
    }

    // ── Risk controls (forwarded from collector) ───────────────────────────────
        ou.risk_controls = jp_arr(obj, "risk_controls"); // Fixed malformed line

    // ── Computed risk fields ──────────────────────────────────────────────────
    analyze_ou_risk(ou);

    return ou;
}

// ─────────────────────────────────────────────────────────────────────────────
//  analyze_ou_risk
//  Populates risk_score and high_risk on a ProcessedOU.
//
//  Scoring (0-100):
//    +25  highvalue OU (name/path matches privileged patterns)
//    +20  privileged_users_count > 0
//    +15  privileged_computers_count > 0  (DCs present)
//    +10  depth == 1  (direct child of domain root — flat structure risk)
//    +10  has_gpo_links  (GPO applied here — misconfiguration blast radius)
//    +10  inheritance_blocked  (policy gap)
//    +10  delegated_permissions  (managedBy set)
//
//  high_risk: score >= 40 OR (highvalue AND privileged_users_count > 0)
// ─────────────────────────────────────────────────────────────────────────────
void OfflineProcessor::analyze_ou_risk(ProcessedOU& ou) const
{
    int score = 0;

    if (ou.highvalue)                       score += 25;
    if (ou.privileged_users_count > 0)      score += 20;
    if (ou.privileged_computers_count > 0)  score += 15;
    if (ou.depth == 1)                      score += 10;
    if (ou.has_gpo_links)                   score += 10;
    if (ou.inheritance_blocked)             score += 10;
    if (ou.delegated_permissions)           score += 10;

    if (score > 100) score = 100;
    ou.risk_score = score;
    ou.high_risk  = (score >= 40)
                 || (ou.highvalue && ou.privileged_users_count > 0);
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 32 — ou_to_json
//
//  Serializes a ProcessedOU to a single JSONL line (no trailing \n).
// ═════════════════════════════════════════════════════════════════════════════
std::string OfflineProcessor::ou_to_json(const ProcessedOU& ou) const
{
    std::ostringstream o;
    o << "{";

    // ── Identity ──────────────────────────────────────────────────────────────
    o << "\"name\":"           << je(ou.name)           << ",";
    o << "\"dn\":"             << je(ou.dn)             << ",";
    o << "\"description\":"    << je(ou.description)    << ",";
    o << "\"managed_by\":"     << je(ou.managed_by)     << ",";
    o << "\"managed_by_name\":" << je(ou.managed_by_name) << ",";
    o << "\"object_guid\":"    << je(ou.object_guid)    << ",";
    o << "\"object_id\":"      << je(ou.object_id)      << ",";

    // ── Parent / Depth / Children ─────────────────────────────────────────────
    o << "\"parent_dn\":"   << je(ou.parent_dn)         << ",";
    o << "\"child_ous\":"   << ja(ou.child_ous)         << ",";
    o << "\"depth\":"       << ji(ou.depth)             << ",";

    // ── GPO ───────────────────────────────────────────────────────────────────
    o << "\"gpo_links_raw\":"           << je(ou.gpo_links_raw)           << ",";
    o << "\"linked_gpos\":"             << ou.linked_gpos_raw             << ",";
    o << "\"gpo_precedence\":"          << ou.gpo_precedence_raw          << ",";
    o << "\"inherited_gpos\":"          << ou.inherited_gpos_raw          << ",";
    o << "\"has_gpo_links\":"           << jb(ou.has_gpo_links)           << ",";
    o << "\"inheritance_blocked\":"     << jb(ou.inheritance_blocked)     << ",";
    o << "\"blocksinheritance\":"       << jb(ou.blocksinheritance)       << ",";
    o << "\"gp_options\":"              << ji(ou.gp_options)              << ",";
    o << "\"gpo_count\":"               << ji(ou.gpo_count)               << ",";
    o << "\"inherited_gpo_count\":"     << ji(ou.inherited_gpo_count)     << ",";

    // ── Object count ──────────────────────────────────────────────────────────
    o << "\"object_count\":"  << ji(ou.object_count) << ",";

    // ── Privileged objects ────────────────────────────────────────────────────
    o << "\"privileged_users\":"            << ou.privileged_users_raw        << ",";
    o << "\"privileged_users_count\":"      << ji(ou.privileged_users_count)  << ",";
    o << "\"privileged_computers\":"        << ou.privileged_computers_raw    << ",";
    o << "\"privileged_computers_count\":"  << ji(ou.privileged_computers_count) << ",";

    // ── Flags ─────────────────────────────────────────────────────────────────
    o << "\"delegated_permissions\":"  << jb(ou.delegated_permissions)  << ",";
    o << "\"highvalue\":"              << jb(ou.highvalue)              << ",";
    o << "\"high_risk\":"              << jb(ou.high_risk)              << ",";
    o << "\"isaclprotected\":"         << jb(ou.isaclprotected)         << ",";

    // ── Risk ──────────────────────────────────────────────────────────────────
    o << "\"risk_score\":"    << ji(ou.risk_score)    << ",";
        o << "\"risk_controls\":" << ja(ou.risk_controls) << ",";

    // ── Domain ────────────────────────────────────────────────────────────────
    o << "\"domainsid\":"    << je(ou.domain_sid)   << ",";
    o << "\"domain_name\":"  << je(ou.domain_name)  << ",";

    // ── Timestamps ────────────────────────────────────────────────────────────
    o << "\"when_created\":" << jnl(ou.when_created) << ",";
    o << "\"when_changed\":" << jnl(ou.when_changed);

    o << "}";
    return o.str();
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 33 — load_and_process_ous  (private)
// ═════════════════════════════════════════════════════════════════════════════
bool OfflineProcessor::load_and_process_ous(const std::string& raw_path,
                                             const std::string& out_path)
{
    log_info("[OfflineProcessor] Reading raw_ous.jsonl: " + raw_path);

    auto raw_lines = read_ndjson_lines(raw_path);
    if (raw_lines.empty()) {
        log_err("[OfflineProcessor] File not found or empty: " + raw_path);
        return false;
    }

    log_ok("[OfflineProcessor] " + std::to_string(raw_lines.size())
           + " raw OUs read. Starting analysis...");

    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        log_err("[OfflineProcessor] Could not open output file: " + out_path);
        return false;
    }

    int gpo_linked_count      = 0;
    int inheritance_blocked_c = 0;
    int high_risk_count       = 0;
    int highvalue_count       = 0;
    int depth1_count          = 0;
    std::vector<std::string> rows;
    rows.reserve(raw_lines.size());

    for (const auto& raw : raw_lines) {
        ProcessedOU ou = parse_raw_ou(raw);

        if (ou.has_gpo_links)       ++gpo_linked_count;
        if (ou.inheritance_blocked) ++inheritance_blocked_c;
        if (ou.high_risk)           ++high_risk_count;
        if (ou.highvalue)           ++highvalue_count;
        if (ou.depth == 1)          ++depth1_count;

        rows.push_back(ou_to_json(ou));
    }
    write_objects(out, rows, out_path, "[OfflineProcessor]");
    out.close();

    log_ok("[OfflineProcessor] domain_ous written -> " + out_path);
    log_ok("[OfflineProcessor] "
        + std::to_string(raw_lines.size())  + " OUs | "
        + std::to_string(highvalue_count)   + " high-value | "
        + std::to_string(high_risk_count)   + " high-risk | "
        + std::to_string(depth1_count)      + " depth-1");
    log_ok("[OfflineProcessor] "
        + std::to_string(gpo_linked_count)      + " with GPO links | "
        + std::to_string(inheritance_blocked_c) + " inheritance-blocked");

    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 34 — Public entry point: process_ous
//               process() updated to include OUs
// ═════════════════════════════════════════════════════════════════════════════

bool OfflineProcessor::process_ous(const OfflineProcessorOptions& opts)
{
    fs::create_directories(opts.output_dir);

    // dn_to_sam_ is needed to resolve managed_by DN → name
    load_raw_users_lookup (opts.raw_dir + "/raw_users.jsonl");
    load_raw_groups_lookup(opts.raw_dir + "/raw_groups.jsonl");

    if (!opts.domain_name.empty()) domain_name_ = opts.domain_name;
    if (domain_name_.empty()) domain_name_ = base_dn_to_domain(base_dn_);

    const std::string& ext7 = opts.output_ext.empty() ? "jsonl" : opts.output_ext;
    const std::string raw_path = opts.raw_dir + "/raw_ous.jsonl";
    bool ok = load_and_process_ous(
        raw_path,
        opts.output_dir + "/domain_ous." + ext7);

    if (ok) {
        std::error_code ec;
        fs::remove(raw_path, ec);
        if (ec) {
            log_warn("[OfflineProcessor] Could not delete raw file: " + raw_path +
                     " — " + ec.message());
        } else {
            log_ok("[OfflineProcessor] Deleted raw file: " + raw_path);
        }
    }

    return ok;
}