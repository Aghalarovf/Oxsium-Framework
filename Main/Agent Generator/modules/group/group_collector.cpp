#include "group_collector.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>

GroupCollector::GroupCollector(LDAPEngine& engine) : engine_(engine) {}

// ─────────────────────────────────────────────────────────────────────────────
//  required_attrs
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> GroupCollector::required_attrs() const {
    return {
        "sAMAccountName", "distinguishedName", "description",
        "objectSid",      "groupType",
        "memberOf",
        "adminCount",     "managedBy",
        "primaryGroupToken",
        "sIDHistory",
        "whenCreated",    "whenChanged",
    };
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect
// ─────────────────────────────────────────────────────────────────────────────
int GroupCollector::collect(const GroupCollectorOptions& opts) {
    fs::create_directories(opts.output_dir);
    output_path_ = fs::path(opts.output_dir) / "raw_groups.jsonl";

    std::ofstream f(output_path_, std::ios::binary);
    if (!f) {
        log_err("[GroupCollector] Fayl açıla bilmədi: " + output_path_.string());
        return -1;
    }

    const std::string generated_at = now_iso8601();

    log_info("[GroupCollector] Query 1/2 — collecting all groups...");

    std::vector<GroupRecord> groups;
    std::unordered_map<std::string, size_t> dn_to_idx;
    int count = 0;

    bool ok = engine_.search("(objectCategory=group)", required_attrs(),
        [&](const LDAPEngine::AttrMap& entry) {
            if (opts.max_results > 0 && count >= opts.max_results) return;

            GroupRecord g;
            g.attrs = entry;

            auto get = [&](const std::string& k) -> std::string {
                auto it = entry.find(k);
                if (it != entry.end() && !it->second.empty()) return it->second[0];
                return "";
            };

            auto sid_it = entry.find("objectSid");
            if (sid_it != entry.end() && !sid_it->second.empty()) {
                g.sid = decode_sid(sid_it->second[0]);
                std::transform(g.sid.begin(), g.sid.end(),
                               g.sid.begin(), ::toupper);
            }

            try { g.group_type_raw = std::stoi(get("groupType")); }
            catch (...) {}

            auto dn_it = entry.find("distinguishedName");
            if (dn_it != entry.end() && !dn_it->second.empty())
                g.dn = dn_it->second[0];

            dn_to_idx[g.dn] = groups.size();
            groups.push_back(std::move(g));
            ++count;
        });

    if (!ok) {
        log_err("[GroupCollector] Query 1 failed.");
        return -1;
    }

    log_ok("[GroupCollector] " + std::to_string(groups.size()) + " groups found.");
    log_info("[GroupCollector] Query 2/2 — collecting memberships (inverse memberOf)...");

    // ── Sorğu 2: inverse memberOf build ─────────────────────────────────────
    engine_.search(
        "(|(objectCategory=person)(objectCategory=group)(objectCategory=computer))",
        {"distinguishedName", "memberOf"},
        [&](const LDAPEngine::AttrMap& entry) {
            auto obj_dn_it = entry.find("distinguishedName");
            auto mof_it    = entry.find("memberOf");
            if (obj_dn_it == entry.end() || obj_dn_it->second.empty()) return;
            if (mof_it    == entry.end() || mof_it->second.empty())    return;

            const std::string& obj_dn = obj_dn_it->second[0];
            for (const auto& group_dn : mof_it->second) {
                auto it = dn_to_idx.find(group_dn);
                if (it != dn_to_idx.end())
                    groups[it->second].direct_member_dns.push_back(obj_dn);
            }
        });

    log_ok("[GroupCollector] Membership data completed.");

    // ── JSONL yaz ───────────────────────────────────────────────────────────
    for (const auto& g : groups) {
        f << group_to_jsonl(g, generated_at) << "\n";
    }

    f.flush();
    f.close();

    log_ok("[GroupCollector] raw_groups.jsonl written -> " + output_path_.string());
    return static_cast<int>(groups.size());
}

// ─────────────────────────────────────────────────────────────────────────────
//  group_to_jsonl  — schema domain_groups.jsonl ilə uyğun
// ─────────────────────────────────────────────────────────────────────────────
std::string GroupCollector::group_to_jsonl(const GroupRecord& g,
                                            const std::string& generated_at) const
{
    auto get = [&](const std::string& k) -> std::string {
        auto it = g.attrs.find(k);
        if (it != g.attrs.end() && !it->second.empty()) return it->second[0];
        return "";
    };
    auto get_all = [&](const std::string& k) -> std::vector<std::string> {
        auto it = g.attrs.find(k);
        if (it != g.attrs.end()) return it->second;
        return {};
    };

    const std::string sam_name    = get("sAMAccountName");
    const std::string description = get("description");
    const std::string managed_by  = get("managedBy");
    const std::string when_created= get("whenCreated");
    const std::string when_changed= get("whenChanged");
    const std::string admin_count = get("adminCount");
    const std::string pg_token_raw= get("primaryGroupToken");

    int pg_token = 0;
    try { if (!pg_token_raw.empty()) pg_token = std::stoi(pg_token_raw); }
    catch (...) {}

    bool is_protected  = (!admin_count.empty() && admin_count != "0");
    bool is_privileged = is_privileged_sid(g.sid) || is_protected;
    bool is_nested     = !get_all("memberOf").empty();

    std::string group_type_str = decode_group_type(g.group_type_raw);
    auto risk = compute_risk_controls(g.sid, g.group_type_raw, is_protected);

    // sid_history — binary SID listinin dönüşümü
    auto sid_hist_raw = get_all("sIDHistory");
    std::vector<std::string> sid_history;
    for (const auto& raw : sid_hist_raw)
        sid_history.push_back(decode_sid(raw));

    int member_count = static_cast<int>(g.direct_member_dns.size());

    std::ostringstream o;
    o << "{"
      << "\"name\":"                    << je(sam_name)            << ","
      << "\"group_name\":"              << je(sam_name)            << ","
      << "\"sam_name\":"                << je(sam_name)            << ","
      << "\"sid\":"                     << je(g.sid)               << ","
      << "\"group_sid\":"               << je(g.sid)               << ","
      << "\"dn\":"                      << je(g.dn)                << ","
      << "\"description\":"             << je(description)         << ","
      << "\"group_type\":"              << je(group_type_str)      << ","
      << "\"group_type_raw\":"          << ji(g.group_type_raw)    << ","
      << "\"member_count\":"            << ji(member_count)        << ","
      << "\"members\":"                 << ja(g.direct_member_dns) << ","
      << "\"member_users\":"            << "[]"                    << ","
      << "\"member_of\":"               << ja(get_all("memberOf")) << ","
      << "\"member_of_count\":"         << ji((int)get_all("memberOf").size()) << ","
      << "\"is_privileged\":"           << jb(is_privileged)       << ","
      << "\"is_protected\":"            << jb(is_protected)        << ","
      << "\"is_nested\":"               << jb(is_nested)           << ","
      << "\"managed_by\":"              << je(managed_by)          << ","
      << "\"primary_group_token\":"     << ji(pg_token)            << ","
      << "\"sid_history\":"             << ja(sid_history)         << ","
      << "\"is_protected_users_group\":" << jb(g.sid == "S-1-5-21-%-525") << ","
      << "\"risk_controls\":"           << ja(risk)                << ","
      << "\"when_created\":"            << je(when_created)        << ","
      << "\"when_changed\":"            << je(when_changed)        << ","
      << "\"generated_at\":"            << je(generated_at)
      << "}";
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  decode_group_type  — groupType int → "Security / Domain Local" kimi string
//  domain_groups.jsonl-dakı group_type dəyərləri ilə eyni format
// ─────────────────────────────────────────────────────────────────────────────
std::string GroupCollector::decode_group_type(int raw) {
    std::string security = (raw & static_cast<int>(0x80000000))
                           ? "Security" : "Distribution";
    std::string scope;
    if      (raw & 0x00000002) scope = "Global";
    else if (raw & 0x00000004) scope = "Domain Local";
    else if (raw & 0x00000008) scope = "Universal";
    else                       scope = "Unknown";
    return security + " / " + scope;
}

// ─────────────────────────────────────────────────────────────────────────────
//  compute_risk_controls  — domain_groups.jsonl-dakı risk_controls ilə eyni
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> GroupCollector::compute_risk_controls(
    const std::string& sid, int /*group_type_raw*/, bool is_protected)
{
    std::vector<std::string> risks;

    // Builtin privileged RID-lər
    static const std::vector<std::string> priv_sids = {
        "S-1-5-32-544",  // Administrators
        "S-1-5-32-548",  // Account Operators
        "S-1-5-32-549",  // Server Operators
        "S-1-5-32-550",  // Print Operators
        "S-1-5-32-551",  // Backup Operators
        "S-1-5-32-552",  // Replicators
        "S-1-5-32-569",  // Cryptographic Operators
    };
    // Domain privileged RID suffix-ləri
    static const std::vector<std::string> priv_rids = {
        "-512",  // Domain Admins
        "-519",  // Enterprise Admins
        "-518",  // Schema Admins
        "-520",  // Group Policy Creator Owners
        "-516",  // Domain Controllers
        "-521",  // Read-only Domain Controllers
        "-525",  // Protected Users
        "-526",  // Key Admins
        "-527",  // Enterprise Key Admins
    };

    bool priv = false;
    for (const auto& ps : priv_sids)
        if (sid == ps) { priv = true; break; }
    if (!priv) {
        for (const auto& suffix : priv_rids)
            if (sid.size() >= suffix.size() &&
                sid.substr(sid.size() - suffix.size()) == suffix)
            { priv = true; break; }
    }

    if (priv)       risks.push_back("Privileged Group");
    if (is_protected) risks.push_back("AdminSDHolder Protected");
    return risks;
}

bool GroupCollector::is_privileged_sid(const std::string& sid) {
    auto risks = compute_risk_controls(sid, 0, false);
    return !risks.empty();
}

// ─────────────────────────────────────────────────────────────────────────────
//  decode_sid
// ─────────────────────────────────────────────────────────────────────────────
std::string GroupCollector::decode_sid(const std::string& raw) {
    if (raw.size() < 8) return "";
    const auto* b = reinterpret_cast<const unsigned char*>(raw.data());
    int rev       = b[0];
    int sub_count = b[1];
    long long auth = 0;
    for (int i = 2; i < 8; ++i) auth = (auth << 8) | b[i];
    std::ostringstream o;
    o << "S-" << rev << "-" << auth;
    for (int i = 0; i < sub_count && (8 + 4*(i+1)) <= (int)raw.size(); ++i) {
        int off = 8 + 4*i;
        unsigned long sub =
              static_cast<unsigned long>(b[off])
            | (static_cast<unsigned long>(b[off+1]) << 8)
            | (static_cast<unsigned long>(b[off+2]) << 16)
            | (static_cast<unsigned long>(b[off+3]) << 24);
        o << "-" << sub;
    }
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  JSON helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string GroupCollector::je(const std::string& s) {
    std::ostringstream o;
    o << '"';
    for (unsigned char ch : s) {
        switch (ch) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b";  break;
            case '\f': o << "\\f";  break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if (ch < 0x20)
                    o << "\\u" << std::hex << std::setw(4)
                      << std::setfill('0') << (int)ch << std::dec;
                else
                    o << static_cast<char>(ch);
        }
    }
    o << '"';
    return o.str();
}

std::string GroupCollector::jb(bool v) { return v ? "true" : "false"; }
std::string GroupCollector::ji(int v)  { return std::to_string(v); }

std::string GroupCollector::ja(const std::vector<std::string>& v) {
    std::ostringstream o;
    o << '[';
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) o << ',';
        o << je(v[i]);
    }
    o << ']';
    return o.str();
}

std::string GroupCollector::now_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream o;
    o << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return o.str();
}