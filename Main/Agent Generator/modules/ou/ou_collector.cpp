#include "ou_collector.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <regex>
#include <set>

// ─────────────────────────────────────────────────────────────────────────────
//  High-value OU name patterns  (mirrors ous.py _HIGH_VALUE_OU_PATTERNS)
// ─────────────────────────────────────────────────────────────────────────────
static const char* HIGH_VALUE_PATTERNS[] = {
    "domain controllers", "domain admins", "enterprise admins",
    "schema admins", "administrators", "privileged",
    "tier 0", "tier0", "protected users",
    nullptr
};

// ─────────────────────────────────────────────────────────────────────────────
//  Constructor
// ─────────────────────────────────────────────────────────────────────────────
OUCollector::OUCollector(LDAPEngine& engine) : engine_(engine) {}

// ─────────────────────────────────────────────────────────────────────────────
//  required_attrs
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> OUCollector::required_attrs() const {
    return {
        "name",
        "distinguishedName",
        "description",
        "ou",
        "managedBy",
        "whenCreated",
        "whenChanged",
        "gPLink",
        "gPOptions",
        "msDS-Approx-Immed-Subordinates",
        "objectGUID",
    };
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect
// ─────────────────────────────────────────────────────────────────────────────
int OUCollector::collect(const OUCollectorOptions& opts) {
    fs::create_directories(opts.output_dir);
    output_path_ = fs::path(opts.output_dir) / "raw_ous.ndjson";

    std::ofstream f(output_path_, std::ios::binary);
    if (!f) {
        log_err("[OUCollector] Failed to open output file: " + output_path_.string());
        return -1;
    }

    log_info("[OUCollector] LDAP query starting — collecting all OUs...");

    const std::string generated_at = now_iso8601();

    // ── Resolve domain SID once ───────────────────────────────────────────────
    std::string domain_sid;
    {
        if (!engine_.cfg_.base_dn.empty()) {
            engine_.search_base(engine_.cfg_.base_dn, {"objectSid"},
                [&](const LDAPEngine::AttrMap& e) {
                    if (!domain_sid.empty()) return;
                    auto it = e.find("objectSid");
                    if (it != e.end() && !it->second.empty())
                        domain_sid = sid_to_string(it->second[0]);
                });
        }
    }

    const std::string filter = "(objectClass=organizationalUnit)";
    int count = 0;

    bool ok = engine_.search(filter, required_attrs(),
        [&](const LDAPEngine::AttrMap& entry) {
            if (opts.max_results > 0 && count >= opts.max_results) return;
            f << ou_to_ndjson(entry, domain_sid, generated_at) << "\n";
            ++count;
        });

    if (!ok) {
        log_err("[OUCollector] LDAP query failed.");
        return -1;
    }

    f.flush();
    f.close();

    log_ok("[OUCollector] " + std::to_string(count)
           + " OUs -> " + output_path_.string());
    return count;
}

// ─────────────────────────────────────────────────────────────────────────────
//  ou_to_ndjson
// ─────────────────────────────────────────────────────────────────────────────
std::string OUCollector::ou_to_ndjson(const LDAPEngine::AttrMap& entry,
                                       const std::string& domain_sid,
                                       const std::string& generated_at) const
{
    auto get = [&](const std::string& k) -> std::string {
        auto it = entry.find(k);
        if (it != entry.end() && !it->second.empty()) return it->second[0];
        return "";
    };

    // ── Identity ─────────────────────────────────────────────────────────────
    const std::string dn       = get("distinguishedName");

    // LDAP "name" attr is sometimes missing; derive from the first RDN of the DN.
    // e.g.  "OU=Sales,OU=Corp,DC=corp,DC=local"  ->  "Sales"
    auto extract_ou_name = [](const std::string& d) -> std::string {
        // Skip optional "OU=" / "ou=" prefix
        size_t eq = d.find('=');
        if (eq == std::string::npos) return d;
        size_t comma = d.find(',', eq + 1);
        return d.substr(eq + 1, (comma != std::string::npos ? comma : d.size()) - eq - 1);
    };
    const std::string raw_name = get("name");
    const std::string ou_name  = raw_name.empty() ? extract_ou_name(dn) : raw_name;
    const std::string desc     = get("description");
    const std::string managed  = get("managedBy");
    const std::string raw_guid = get("objectGUID");
    const std::string guid_str = guid_to_string(raw_guid);

    // ── Timestamps ────────────────────────────────────────────────────────────
    const std::string when_created = generalized_time_to_iso(get("whenCreated"));
    const std::string when_changed = generalized_time_to_iso(get("whenChanged"));

    // ── Parent / Depth ────────────────────────────────────────────────────────
    const std::string parent_dn = extract_parent_dn(dn);
    const int         depth     = calc_depth(dn);

    // ── Child OUs ─────────────────────────────────────────────────────────────
    const std::vector<std::string> child_ous = get_child_ous(dn);

    // ── GPO fields ────────────────────────────────────────────────────────────
    const std::string gp_link_raw = get("gPLink");
    const int         gp_options  = [&]() -> int {
        try { return std::stoi(get("gPOptions")); } catch (...) { return 0; }
    }();
    const bool has_gpo_links      = !gp_link_raw.empty();
    const bool inheritance_blocked = (gp_options & 1) != 0;

    const std::string linked_gpos_json     = parse_gplink_json(gp_link_raw);
    const std::string gpo_precedence_json  = build_gpo_precedence_json(gp_link_raw);

    // Derive domain root DN from ou's own DN
    const std::string domain_dn = [&]() -> std::string {
        std::string d = dn;
        size_t pos = 0;
        while ((pos = d.find(',', pos)) != std::string::npos) {
            std::string tail = d.substr(pos + 1);
            // First DC= component → that is the start of the domain DN
            size_t dc = tail.find("DC=");
            if (dc == std::string::npos) dc = tail.find("dc=");
            if (dc == 0) return tail;
            ++pos;
        }
        return "";
    }();
    const std::string inherited_gpos_json = get_inherited_gpos_json(dn, domain_dn);

    // ── Object count ──────────────────────────────────────────────────────────
    int object_count = -1;
    {
        const std::string approx = get("msDS-Approx-Immed-Subordinates");
        if (!approx.empty()) {
            try { object_count = std::stoi(approx); } catch (...) {}
        }
    }
    if (object_count < 0) {
        // Fallback: count direct children by filtering the full subtree search
        int cnt = 0;
        engine_.search("(objectClass=*)", {"distinguishedName"},
            [&](const LDAPEngine::AttrMap& e) {
                auto it = e.find("distinguishedName");
                if (it == e.end() || it->second.empty()) return;
                if (extract_parent_dn(it->second[0]) == dn) ++cnt;
            });
        object_count = cnt;
    }

    // ── Privileged objects ────────────────────────────────────────────────────
    PrivSummary priv = get_privileged_objects(dn);
    const int priv_user_count     = static_cast<int>(priv.priv_user_json.size());
    const int priv_computer_count = static_cast<int>(priv.priv_computer_json.size());

    // ── Flags ─────────────────────────────────────────────────────────────────
    const bool delegated_permissions = !managed.empty();
    const bool highvalue = is_high_value(ou_name, dn);
    const bool isaclprotected = inheritance_blocked; // mirrors Python: isaclprotected = inheritance_blocked

    // ── Risk controls ─────────────────────────────────────────────────────────
    std::vector<std::string> risk_controls;
    if (has_gpo_links)           risk_controls.push_back("GPO Links");
    if (inheritance_blocked)     risk_controls.push_back("Inheritance Blocked");
    if (delegated_permissions)   risk_controls.push_back("Delegated Permissions");
    if (priv_user_count > 0)     risk_controls.push_back("Privileged Users Present");
    if (priv_computer_count > 0) risk_controls.push_back("Privileged Computers Present");

    // ── Serialise ─────────────────────────────────────────────────────────────
    std::ostringstream o;
    o << "{"
      // Identity
      << "\"name\":"                        << je(ou_name)              << ","
      << "\"dn\":"                          << je(dn)                   << ","
      << "\"description\":"                 << je(desc)                 << ","
      << "\"managed_by\":"                  << je(managed)              << ","
      << "\"object_guid\":"                 << je(guid_str)             << ","
      << "\"object_id\":"                   << je(guid_str)             << ","
      // Parent / Depth / Children
      << "\"parent_dn\":"                   << je(parent_dn)            << ","
      << "\"child_ous\":"                   << ja(child_ous)            << ","
      << "\"depth\":"                       << ji(depth)                << ","
      // GPO
      << "\"gpo_links_raw\":"               << je(gp_link_raw)          << ","
      << "\"linked_gpos\":"                 << linked_gpos_json         << ","
      << "\"gpo_precedence\":"              << gpo_precedence_json      << ","
      << "\"inherited_gpos\":"              << inherited_gpos_json      << ","
      << "\"has_gpo_links\":"               << jb(has_gpo_links)        << ","
      << "\"inheritance_blocked\":"         << jb(inheritance_blocked)  << ","
      << "\"gp_options\":"                  << ji(gp_options)           << ","
      // Object count
      << "\"object_count\":"                << ji(object_count)         << ","
      // Privileged objects
      << "\"privileged_users\":"            << ja_obj(priv.priv_user_json)     << ","
      << "\"privileged_users_count\":"      << ji(priv_user_count)      << ","
      << "\"privileged_computers\":"        << ja_obj(priv.priv_computer_json) << ","
      << "\"privileged_computers_count\":"  << ji(priv_computer_count)  << ","
      // Flags
      << "\"delegated_permissions\":"       << jb(delegated_permissions)<< ","
      << "\"highvalue\":"                   << jb(highvalue)            << ","
      << "\"isaclprotected\":"              << jb(isaclprotected)       << ","
      << "\"blocksinheritance\":"           << jb(inheritance_blocked)  << ","
      // Domain
      << "\"domainsid\":"                   << je(domain_sid)           << ","
      // Timestamps
      << "\"when_created\":"                << je(when_created)         << ","
      << "\"when_changed\":"                << je(when_changed)         << ","
      // Risk
      << "\"risk_controls\":"               << ja(risk_controls)        << ","
      // Metadata
      << "\"generated_at\":"                << je(generated_at)
      << "}";

    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  get_child_ous
//  LEVEL-scope search: direct OU children of parent_dn
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> OUCollector::get_child_ous(const std::string& parent_dn) const {
    std::vector<std::string> result;
    engine_.search("(objectClass=organizationalUnit)", {"distinguishedName"},
        [&](const LDAPEngine::AttrMap& e) {
            auto it = e.find("distinguishedName");
            if (it != e.end() && !it->second.empty())
                if (extract_parent_dn(it->second[0]) == parent_dn)
                    result.push_back(it->second[0]);
        });
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  sid_to_string
//  Converts a Windows SID to the canonical "S-R-I-S1-S2-..." string form.
//
//  Two input encodings are handled:
//
//  (A) Raw binary — LDAPEngine returns objectSid as raw bytes in a std::string:
//        b[0]    = Revision (1)
//        b[1]    = SubAuthorityCount (N)
//        b[2..7] = IdentifierAuthority (6 bytes, big-endian)
//        b[8..]  = N × SubAuthority (4 bytes each, little-endian)
//
//  (B) Double-escaped \\uXXXX notation — produced when the je() helper
//      serialises binary bytes as JSON escape sequences and the string is
//      later read back verbatim (e.g. "\\u0001\\u0004\\u0000...").
//      Each \\uXXXX token is treated as a single byte (low 8 bits).
//      Latin-1 characters (e.g. ñ = 0xf1) embedded in the string are
//      also decoded correctly.
//
//  If the string already starts with "S-", it is returned unchanged.
// ─────────────────────────────────────────────────────────────────────────────
static std::string sid_bytes_to_str(const unsigned char* b, size_t len) {
    if (len < 8 || b[0] != 1) return "";
    const int revision  = b[0];
    const int sub_count = b[1];
    uint64_t  authority = 0;
    for (int i = 2; i < 8; ++i) authority = (authority << 8) | b[i];
    if (static_cast<size_t>(8 + sub_count * 4) > len) return "";
    std::ostringstream o;
    o << "S-" << revision << "-" << authority;
    for (int i = 0; i < sub_count; ++i) {
        uint32_t sub = 0;
        sub |= static_cast<uint32_t>(b[8 + i*4 + 0]);
        sub |= static_cast<uint32_t>(b[8 + i*4 + 1]) << 8;
        sub |= static_cast<uint32_t>(b[8 + i*4 + 2]) << 16;
        sub |= static_cast<uint32_t>(b[8 + i*4 + 3]) << 24;
        o << "-" << sub;
    }
    return o.str();
}

std::string OUCollector::sid_to_string(const std::string& raw) {
    if (raw.empty()) return "";
    if (raw.size() >= 2 && raw[0] == 'S' && raw[1] == '-') return raw;

    // ── Case B: double-escaped \\uXXXX notation ───────────────────────────────
    if (raw.find("\\u") != std::string::npos) {
        std::vector<unsigned char> buf;
        buf.reserve(28);
        size_t i = 0;
        while (i < raw.size()) {
            if (raw[i] == '\\' && i + 5 < raw.size() && raw[i+1] == 'u') {
                const char* hex = raw.c_str() + i + 2;
                bool all_hex = true;
                for (int k = 0; k < 4; ++k)
                    if (!std::isxdigit(static_cast<unsigned char>(hex[k])))
                    { all_hex = false; break; }
                if (all_hex) {
                    buf.push_back(static_cast<unsigned char>(
                        std::stoi(std::string(hex, 4), nullptr, 16) & 0xFF));
                    i += 6;
                    continue;
                }
            }
            buf.push_back(static_cast<unsigned char>(raw[i]));
            ++i;
        }
        if (!buf.empty()) {
            std::string r = sid_bytes_to_str(buf.data(), buf.size());
            if (!r.empty()) return r;
        }
    }

    // ── Case A: raw binary bytes ──────────────────────────────────────────────
    const auto* b = reinterpret_cast<const unsigned char*>(raw.data());
    return sid_bytes_to_str(b, raw.size());
}

// ─────────────────────────────────────────────────────────────────────────────
//  get_privileged_objects
//  adminCount=1 users and DC computers within ou_dn (SUBTREE)
// ─────────────────────────────────────────────────────────────────────────────
OUCollector::PrivSummary OUCollector::get_privileged_objects(
    const std::string& ou_dn) const
{
    PrivSummary s;

    // ── Privileged Users (adminCount=1) ──────────────────────────────────────
    engine_.search(
        "(&(objectClass=user)(objectCategory=person)(adminCount=1))",
        {"sAMAccountName", "distinguishedName", "objectSid"},
        [&](const LDAPEngine::AttrMap& e) {
            auto sam = e.find("sAMAccountName");
            auto dn  = e.find("distinguishedName");
            auto sid = e.find("objectSid");
            std::string s_sam = (sam != e.end() && !sam->second.empty()) ? sam->second[0] : "";
            std::string s_dn  = (dn  != e.end() && !dn->second.empty())  ? dn->second[0]  : "";
            std::string s_sid = (sid != e.end() && !sid->second.empty()) ? sid_to_string(sid->second[0]) : "";
            if (extract_parent_dn(s_dn) != ou_dn) return;
            std::ostringstream o;
            o << "{\"sam_name\":" << je(s_sam)
              << ",\"dn\":"       << je(s_dn)
              << ",\"sid\":"      << je(s_sid)
              << "}";
            s.priv_user_json.push_back(o.str());
        });

    // ── Privileged Computers (Domain Controllers: SERVER_TRUST_ACCOUNT=0x2000) ─
    engine_.search(
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        {"cn", "distinguishedName", "objectSid", "dNSHostName"},
        [&](const LDAPEngine::AttrMap& e) {
            auto cn      = e.find("cn");
            auto dn      = e.find("distinguishedName");
            auto sid     = e.find("objectSid");
            auto dns     = e.find("dNSHostName");
            std::string s_cn  = (cn  != e.end() && !cn->second.empty())  ? cn->second[0]  : "";
            std::string s_dn  = (dn  != e.end() && !dn->second.empty())  ? dn->second[0]  : "";
            std::string s_sid = (sid != e.end() && !sid->second.empty()) ? sid_to_string(sid->second[0]) : "";
            std::string s_dns = (dns != e.end() && !dns->second.empty()) ? dns->second[0] : "";
            if (extract_parent_dn(s_dn) != ou_dn) return;
            std::ostringstream o;
            o << "{\"cn\":"       << je(s_cn)
              << ",\"dn\":"       << je(s_dn)
              << ",\"sid\":"      << je(s_sid)
              << ",\"dns_name\":" << je(s_dns)
              << "}";
            s.priv_computer_json.push_back(o.str());
        });

    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
//  parse_gplink_json
//  "[LDAP://CN={GUID},CN=Policies,...;FLAG][...]"
//  → JSON array of GPO link objects, highest-precedence last
//    (AD applies sağdan sola: list içinde sondakı = OU-ya ən yaxın = yüksək priority)
// ─────────────────────────────────────────────────────────────────────────────
std::string OUCollector::parse_gplink_json(const std::string& gplink_raw) {
    if (gplink_raw.empty()) return "[]";

    // Extract each [...] block
    std::vector<std::string> blocks;
    size_t i = 0;
    while (i < gplink_raw.size()) {
        size_t open = gplink_raw.find('[', i);
        if (open == std::string::npos) break;
        size_t close = gplink_raw.find(']', open + 1);
        if (close == std::string::npos) break;
        blocks.push_back(gplink_raw.substr(open + 1, close - open - 1));
        i = close + 1;
    }

    int total = static_cast<int>(blocks.size());
    std::ostringstream o;
    o << "[";
    for (int idx = 0; idx < total; ++idx) {
        if (idx) o << ",";
        const std::string& block = blocks[idx];
        // Split on ';'
        size_t semi  = block.find(';');
        std::string gpo_dn_raw = (semi != std::string::npos) ? block.substr(0, semi) : block;
        std::string flag_str   = (semi != std::string::npos) ? block.substr(semi + 1) : "0";

        // Strip "LDAP://"
        if (gpo_dn_raw.substr(0, 7) == "LDAP://")
            gpo_dn_raw = gpo_dn_raw.substr(7);
        // Trim whitespace
        while (!gpo_dn_raw.empty() && std::isspace(static_cast<unsigned char>(gpo_dn_raw.front())))
            gpo_dn_raw.erase(gpo_dn_raw.begin());
        while (!flag_str.empty()   && std::isspace(static_cast<unsigned char>(flag_str.back())))
            flag_str.pop_back();

        int flag = 0;
        try { flag = std::stoi(flag_str); } catch (...) {}

        // Extract GUID from CN={GUID}
        std::string gpo_guid;
        size_t lb = gpo_dn_raw.find('{');
        size_t rb = gpo_dn_raw.find('}', lb);
        if (lb != std::string::npos && rb != std::string::npos) {
            gpo_guid = gpo_dn_raw.substr(lb + 1, rb - lb - 1);
            // Uppercase
            std::transform(gpo_guid.begin(), gpo_guid.end(), gpo_guid.begin(),
                [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
        }

        // order: total - idx  (sondakı = order 1 = yüksək precedence)
        int order  = total - idx;
        bool enforced = (flag & 2) != 0;
        bool disabled = (flag & 1) != 0;

        o << "{\"gpo_dn\":"    << je(gpo_dn_raw)
          << ",\"gpo_guid\":"  << je(gpo_guid)
          << ",\"order\":"     << ji(order)
          << ",\"enforced\":"  << jb(enforced)
          << ",\"disabled\":"  << jb(disabled)
          << ",\"link_flag\":" << ji(flag)
          << "}";
    }
    o << "]";
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  build_gpo_precedence_json
//  Extracts { gpo_guid, order, enforced } from the same gPLink string
// ─────────────────────────────────────────────────────────────────────────────
std::string OUCollector::build_gpo_precedence_json(const std::string& gplink_raw) {
    if (gplink_raw.empty()) return "[]";

    std::vector<std::string> blocks;
    size_t i = 0;
    while (i < gplink_raw.size()) {
        size_t open  = gplink_raw.find('[', i);
        if (open == std::string::npos) break;
        size_t close = gplink_raw.find(']', open + 1);
        if (close == std::string::npos) break;
        blocks.push_back(gplink_raw.substr(open + 1, close - open - 1));
        i = close + 1;
    }

    int total = static_cast<int>(blocks.size());
    std::ostringstream o;
    o << "[";
    for (int idx = 0; idx < total; ++idx) {
        if (idx) o << ",";
        const std::string& block = blocks[idx];
        size_t semi     = block.find(';');
        std::string gpo_dn_raw = (semi != std::string::npos) ? block.substr(0, semi) : block;
        std::string flag_str   = (semi != std::string::npos) ? block.substr(semi + 1) : "0";
        if (gpo_dn_raw.substr(0, 7) == "LDAP://") gpo_dn_raw = gpo_dn_raw.substr(7);
        int flag = 0;
        try { flag = std::stoi(flag_str); } catch (...) {}

        std::string gpo_guid;
        size_t lb = gpo_dn_raw.find('{');
        size_t rb = gpo_dn_raw.find('}', lb);
        if (lb != std::string::npos && rb != std::string::npos) {
            gpo_guid = gpo_dn_raw.substr(lb + 1, rb - lb - 1);
            std::transform(gpo_guid.begin(), gpo_guid.end(), gpo_guid.begin(),
                [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
        }

        o << "{\"gpo_guid\":"  << je(gpo_guid)
          << ",\"order\":"     << ji(total - idx)
          << ",\"enforced\":"  << jb((flag & 2) != 0)
          << "}";
    }
    o << "]";
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  get_inherited_gpos_json
//  Walks parent OU chain upward collecting gPLink entries.
//  Stops when:
//    - we reach the domain root DN, or
//    - a parent OU has gPOptions & 1 set (inheritance blocked)
// ─────────────────────────────────────────────────────────────────────────────
std::string OUCollector::get_inherited_gpos_json(const std::string& ou_dn,
                                                   const std::string& domain_dn) const
{
    std::vector<std::string> result_objs;
    std::string current = extract_parent_dn(ou_dn);
    std::set<std::string> visited;

    auto upper_dn = [](std::string s) -> std::string {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
        return s;
    };

    while (!current.empty()
           && upper_dn(current) != upper_dn(domain_dn)
           && !visited.count(current))
    {
        visited.insert(current);

        // Only query if current is itself an OU
        if (upper_dn(current).find("OU=") == std::string::npos) break;

        std::string p_gplink;
        int p_gpopts = 0;

        engine_.search_base(current,
            {"gPLink", "gPOptions"},
            [&](const LDAPEngine::AttrMap& e) {
                auto gl = e.find("gPLink");
                auto go = e.find("gPOptions");
                if (gl != e.end() && !gl->second.empty()) p_gplink  = gl->second[0];
                if (go != e.end() && !go->second.empty()) {
                    try { p_gpopts = std::stoi(go->second[0]); } catch (...) {}
                }
            });

        if (!p_gplink.empty()) {
            // Parse blocks from this parent's gPLink
            size_t i = 0;
            int total_blocks = 0;
            {
                size_t tmp = 0;
                while (tmp < p_gplink.size()) {
                    size_t op = p_gplink.find('[', tmp);
                    if (op == std::string::npos) break;
                    size_t cl = p_gplink.find(']', op + 1);
                    if (cl == std::string::npos) break;
                    ++total_blocks;
                    tmp = cl + 1;
                }
            }
            int blk_idx = 0;
            while (i < p_gplink.size()) {
                size_t open  = p_gplink.find('[', i);
                if (open == std::string::npos) break;
                size_t close = p_gplink.find(']', open + 1);
                if (close == std::string::npos) break;
                std::string block = p_gplink.substr(open + 1, close - open - 1);
                i = close + 1;

                size_t semi     = block.find(';');
                std::string gpo_dn_raw = (semi != std::string::npos) ? block.substr(0, semi) : block;
                std::string flag_str   = (semi != std::string::npos) ? block.substr(semi + 1) : "0";
                if (gpo_dn_raw.substr(0, 7) == "LDAP://") gpo_dn_raw = gpo_dn_raw.substr(7);
                int flag = 0;
                try { flag = std::stoi(flag_str); } catch (...) {}

                std::string gpo_guid;
                size_t lb = gpo_dn_raw.find('{');
                size_t rb = gpo_dn_raw.find('}', lb);
                if (lb != std::string::npos && rb != std::string::npos) {
                    gpo_guid = gpo_dn_raw.substr(lb + 1, rb - lb - 1);
                    std::transform(gpo_guid.begin(), gpo_guid.end(), gpo_guid.begin(),
                        [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
                }

                std::ostringstream obj;
                obj << "{\"gpo_dn\":"          << je(gpo_dn_raw)
                    << ",\"gpo_guid\":"         << je(gpo_guid)
                    << ",\"order\":"            << ji(total_blocks - blk_idx)
                    << ",\"enforced\":"         << jb((flag & 2) != 0)
                    << ",\"disabled\":"         << jb((flag & 1) != 0)
                    << ",\"link_flag\":"        << ji(flag)
                    << ",\"inherited_from\":"   << je(current)
                    << "}";
                result_objs.push_back(obj.str());
                ++blk_idx;
            }
        }

        if (p_gpopts & 1) break;  // Inheritance blocked at this level
        current = extract_parent_dn(current);
    }

    return ja_obj(result_objs);
}

// ─────────────────────────────────────────────────────────────────────────────
//  extract_parent_dn
//  "OU=Sales,OU=Corp,DC=corp,DC=local" → "OU=Corp,DC=corp,DC=local"
// ─────────────────────────────────────────────────────────────────────────────
std::string OUCollector::extract_parent_dn(const std::string& dn) {
    if (dn.empty()) return "";
    size_t comma = dn.find(',');
    if (comma == std::string::npos) return "";
    return dn.substr(comma + 1);
}

// ─────────────────────────────────────────────────────────────────────────────
//  calc_depth
//  Counts OU= components in the DN; first OU under domain root = depth 1
// ─────────────────────────────────────────────────────────────────────────────
int OUCollector::calc_depth(const std::string& dn) {
    if (dn.empty()) return 0;
    int depth = 0;
    size_t pos = 0;
    while (pos < dn.size()) {
        // Case-insensitive OU= check
        if ((dn[pos] == 'O' || dn[pos] == 'o') &&
            pos + 1 < dn.size() && (dn[pos+1] == 'U' || dn[pos+1] == 'u') &&
            pos + 2 < dn.size() && dn[pos+2] == '=')
        {
            ++depth;
        }
        pos = dn.find(',', pos);
        if (pos == std::string::npos) break;
        ++pos;
    }
    return depth;
}

// ─────────────────────────────────────────────────────────────────────────────
//  guid_to_string
//  Converts raw binary GUID bytes (16 bytes, little-endian) to standard
//  UUID format "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" (uppercase).
//  If the input is already a formatted string (ldap3 sometimes returns that),
//  returns it uppercased.
// ─────────────────────────────────────────────────────────────────────────────
std::string OUCollector::guid_to_string(const std::string& raw) {
    if (raw.empty()) return "";
    // Already a UUID string?
    if (raw.size() > 16) {
        std::string up = raw;
        std::transform(up.begin(), up.end(), up.begin(),
            [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
        return up;
    }
    if (raw.size() != 16) return "";

    const auto* b = reinterpret_cast<const unsigned char*>(raw.data());
    // GUID layout: Data1(4 LE) + Data2(2 LE) + Data3(2 LE) + Data4(8 BE)
    std::ostringstream o;
    o << std::hex << std::uppercase << std::setfill('0');
    // Data1 — 4 bytes, little-endian
    for (int i : {3,2,1,0}) o << std::setw(2) << (int)b[i];
    o << "-";
    // Data2 — 2 bytes, little-endian
    for (int i : {5,4}) o << std::setw(2) << (int)b[i];
    o << "-";
    // Data3 — 2 bytes, little-endian
    for (int i : {7,6}) o << std::setw(2) << (int)b[i];
    o << "-";
    // Data4 — 8 bytes, big-endian, split 2+6
    for (int i = 8; i < 10; ++i) o << std::setw(2) << (int)b[i];
    o << "-";
    for (int i = 10; i < 16; ++i) o << std::setw(2) << (int)b[i];
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  generalized_time_to_iso
//  "YYYYMMDDHHmmss.0Z" → "YYYY-MM-DDTHH:MM:SSZ"
// ─────────────────────────────────────────────────────────────────────────────
std::string OUCollector::generalized_time_to_iso(const std::string& gt) {
    if (gt.size() < 14) return gt;
    for (int i = 0; i < 14; ++i)
        if (!std::isdigit(static_cast<unsigned char>(gt[i]))) return gt;
    return gt.substr(0,4) + "-" + gt.substr(4,2) + "-" + gt.substr(6,2)
         + "T" + gt.substr(8,2) + ":" + gt.substr(10,2) + ":" + gt.substr(12,2) + "Z";
}

// ─────────────────────────────────────────────────────────────────────────────
//  is_high_value
//  Matches name or DN (lowercased) against known privileged OU patterns
// ─────────────────────────────────────────────────────────────────────────────
bool OUCollector::is_high_value(const std::string& name, const std::string& dn) {
    std::string nl = name, dl = dn;
    std::transform(nl.begin(), nl.end(), nl.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    std::transform(dl.begin(), dl.end(), dl.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    for (int i = 0; HIGH_VALUE_PATTERNS[i] != nullptr; ++i) {
        if (nl.find(HIGH_VALUE_PATTERNS[i]) != std::string::npos) return true;
        if (dl.find(HIGH_VALUE_PATTERNS[i]) != std::string::npos) return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  JSON helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string OUCollector::je(const std::string& s) {
    std::ostringstream o; o << '"';
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
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)ch << std::dec;
                else
                    o << (char)ch;
        }
    }
    o << '"'; return o.str();
}
std::string OUCollector::jb(bool v)    { return v ? "true" : "false"; }
std::string OUCollector::ji(int v)     { return std::to_string(v); }
std::string OUCollector::jnull()       { return "null"; }
std::string OUCollector::ja(const std::vector<std::string>& v) {
    std::ostringstream o; o << '[';
    for (size_t i = 0; i < v.size(); ++i) { if (i) o << ','; o << je(v[i]); }
    o << ']'; return o.str();
}
// ja_obj: array of pre-serialized JSON object strings (not re-escaped)
std::string OUCollector::ja_obj(const std::vector<std::string>& v) {
    std::ostringstream o; o << '[';
    for (size_t i = 0; i < v.size(); ++i) { if (i) o << ','; o << v[i]; }
    o << ']'; return o.str();
}
std::string OUCollector::now_iso8601() {
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