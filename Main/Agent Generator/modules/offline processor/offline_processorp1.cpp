#include "offline_processor.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <functional>

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 1 — Generic string / JSON helpers
// ═════════════════════════════════════════════════════════════════════════════

std::string OfflineProcessor::upper(std::string s) {
    for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}
std::string OfflineProcessor::lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
std::string OfflineProcessor::trim(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))  s.pop_back();
    return s;
}

// "CN=Domain Admins,CN=Users,DC=..." → "Domain Admins"
std::string OfflineProcessor::cn_from_dn(const std::string& dn) {
    if (dn.size() > 3 &&
        (dn[0]=='C'||dn[0]=='c') && (dn[1]=='N'||dn[1]=='n') && dn[2]=='=') {
        size_t comma = dn.find(',');
        return (comma == std::string::npos) ? dn.substr(3) : dn.substr(3, comma - 3);
    }
    return dn;
}

// "DC=corp,DC=local" → "corp.local"
std::string OfflineProcessor::base_dn_to_domain(const std::string& base_dn) {
    std::string result, part;
    for (size_t i = 0; i <= base_dn.size(); ++i) {
        char ch = (i < base_dn.size()) ? base_dn[i] : ',';
        if (ch == ',') {
            std::string t = trim(part);
            if (t.size() > 3 &&
                (t[0]=='D'||t[0]=='d') && (t[1]=='C'||t[1]=='c') && t[2]=='=') {
                if (!result.empty()) result += '.';
                result += t.substr(3);
            }
            part.clear();
        } else { part += ch; }
    }
    return result;
}

// Windows FILETIME (100ns intervals since 1601-01-01) → ISO-8601
std::string OfflineProcessor::filetime_to_iso(const std::string& ft_raw) {
    if (ft_raw.empty() || ft_raw == "9223372036854775807" || ft_raw == "null") return "";
    try {
        long long ft = std::stoll(ft_raw);
        if (ft < 0) return "";
        if (ft == 0) return "1601-01-01T00:00:00Z";
        long long us     = ft / 10LL - 11644473600LL * 1000000LL;
        long long unix_s = us / 1000000LL;
        long long frac   = us % 1000000LL;
        if (unix_s <= 0) return "1601-01-01T00:00:00Z";
        std::time_t t = static_cast<std::time_t>(unix_s);
        char buf[32]; std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", std::gmtime(&t));
        char fb[16];  std::snprintf(fb, sizeof(fb), ".%06lldZ", (long long)(frac < 0 ? 0 : frac));
        return std::string(buf) + fb;
    } catch (...) { return ""; }
}

// "20230415123045.0Z" → "2023-04-15T12:30:45Z"
std::string OfflineProcessor::generalized_time_to_iso(const std::string& gt) {
    if (gt.size() < 14) return "";
    std::string s = gt.substr(0, 14);
    for (char c : s) if (!std::isdigit(static_cast<unsigned char>(c))) return gt;
    return s.substr(0,4)+"-"+s.substr(4,2)+"-"+s.substr(6,2)
          +"T"+s.substr(8,2)+":"+s.substr(10,2)+":"+s.substr(12,2)+"Z";
}

// "S-1-5-21-x-y-z-RID" → RID
int OfflineProcessor::rid_from_sid(const std::string& sid) {
    auto pos = sid.rfind('-');
    if (pos == std::string::npos) return -1;
    try { return std::stoi(sid.substr(pos + 1)); } catch (...) { return -1; }
}

// ── JSON output helpers ───────────────────────────────────────────────────────
std::string OfflineProcessor::je(const std::string& s) {
    std::ostringstream o; o << '"';
    for (unsigned char ch : s) {
        switch (ch) {
            case '"':  o << "\\\""; break; case '\\': o << "\\\\"; break;
            case '\b': o << "\\b";  break; case '\f': o << "\\f";  break;
            case '\n': o << "\\n";  break; case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if (ch < 0x20)
                    o << "\\u" << std::hex << std::setw(4)
                      << std::setfill('0') << (int)ch << std::dec;
                else o << (char)ch;
        }
    }
    o << '"'; return o.str();
}
std::string OfflineProcessor::jb(bool v)  { return v ? "true" : "false"; }
std::string OfflineProcessor::ji(int v)   { return std::to_string(v); }
std::string OfflineProcessor::jnl(const std::string& s) {
    if (s.empty() || s == "Never" || s == "null") return "null";
    return je(s);
}
std::string OfflineProcessor::ja(const std::vector<std::string>& v) {
    std::ostringstream o; o << '[';
    for (size_t i = 0; i < v.size(); ++i) { if (i) o << ", "; o << je(v[i]); }
    o << ']'; return o.str();
}
std::string OfflineProcessor::json_rights_arr(const std::vector<std::string>& v) {
    // alias — same as ja, separate for readability
    std::ostringstream o; o << '[';
    for (size_t i = 0; i < v.size(); ++i) { if (i) o << ", "; o << je(v[i]); }
    o << ']'; return o.str();
}


bool OfflineProcessor::is_json_ext(const std::string& out_path) {
    if (out_path.size() < 5) return false;
    std::string tail = out_path.substr(out_path.size() - 5);
    for (char& c : tail)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return tail == ".json";
}

bool OfflineProcessor::write_objects(std::ofstream& out,
                                     const std::vector<std::string>& rows,
                                     const std::string& out_path,
                                     const std::string& /*log_tag*/)
{
    if (!out) return false;

    if (!is_json_ext(out_path)) {
        for (const auto& row : rows)
            out << row << '\n';
        out.flush();
        return static_cast<bool>(out);
    }

    // Re-indent a compact single-line JSON object to human-readable form.
    auto reindent = [](const std::string& compact) -> std::string {
        std::string r;
        r.reserve(compact.size() * 2);
        int  depth   = 0;
        bool in_str  = false;
        bool escaped = false;

        auto nl = [&]() {
            r += '\n';
            for (int i = 0; i < depth * 2; ++i) r += ' ';
        };

        for (size_t i = 0; i < compact.size(); ++i) {
            const char ch = compact[i];
            if (escaped)               { r += ch; escaped = false; continue; }
            if (in_str && ch == '\\')  { r += ch; escaped = true;  continue; }
            if (ch == '"')             { in_str = !in_str; r += ch; continue; }
            if (in_str)                { r += ch;                   continue; }
            switch (ch) {
                case '{': case '[': r += ch; ++depth; nl(); break;
                case '}': case ']': --depth; nl(); r += ch; break;
                case ',':           r += ch; nl();          break;
                case ':':           r += ':'; r += ' ';     break;
                default:            r += ch;                break;
            }
        }
        return r;
    };

    auto prefix_lines = [](const std::string& block,
                            const std::string& pfx) -> std::string {
        std::string result;
        result.reserve(block.size() + 64);
        result += pfx;
        for (size_t i = 0; i < block.size(); ++i) {
            result += block[i];
            if (block[i] == '\n' && i + 1 < block.size())
                result += pfx;
        }
        return result;
    };

    out << "[\n";
    for (size_t i = 0; i < rows.size(); ++i) {
        out << prefix_lines(reindent(rows[i]), "  ");
        if (i + 1 < rows.size()) out << ',';
        out << '\n';
    }
    out << "]\n";
    out.flush();
    return static_cast<bool>(out);
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 2 — Minimal JSON parser
// ═════════════════════════════════════════════════════════════════════════════

std::string OfflineProcessor::jp_str(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";

    size_t colon = json.find(':', pos + search.size());
    if (colon == std::string::npos) return "";

    size_t val_start = colon + 1;
    while (val_start < json.size() && std::isspace(static_cast<unsigned char>(json[val_start])))
        ++val_start;
    if (val_start >= json.size()) return "";

    if (json[val_start] == '"') {
        size_t end = val_start + 1;
        while (end < json.size()) {
            if (json[end] == '\\') { end += 2; continue; }
            if (json[end] == '"')  { break; }
            ++end;
        }
        std::string raw = json.substr(val_start + 1, end - val_start - 1);
        std::string result;
        for (size_t i = 0; i < raw.size(); ++i) {
            if (raw[i] == '\\' && i + 1 < raw.size()) {
                switch (raw[i+1]) {
                    case '"':  result += '"';  ++i; break;
                    case '\\': result += '\\'; ++i; break;
                    case 'n':  result += '\n'; ++i; break;
                    case 'r':  result += '\r'; ++i; break;
                    case 't':  result += '\t'; ++i; break;
                    default:   result += raw[i]; break;
                }
            } else { result += raw[i]; }
        }
        return result;
    } else {
        size_t end = val_start;
        while (end < json.size() &&
               json[end] != ',' && json[end] != '\n' &&
               json[end] != '}' && json[end] != ']')
            ++end;
        return trim(json.substr(val_start, end - val_start));
    }
}

int OfflineProcessor::jp_int(const std::string& json, const std::string& key, int def) {
    std::string v = trim(jp_str(json, key));
    if (v.empty() || v == "null") return def;
    try { return std::stoi(v); } catch (...) { return def; }
}

bool OfflineProcessor::jp_bool(const std::string& json, const std::string& key, bool def) {
    std::string v = lower(trim(jp_str(json, key)));
    if (v == "true")  return true;
    if (v == "false") return false;
    return def;
}

std::vector<std::string> OfflineProcessor::jp_arr(const std::string& json,
                                                    const std::string& key)
{
    std::vector<std::string> result;
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return result;

    size_t bracket = json.find('[', pos + search.size());
    if (bracket == std::string::npos) return result;

    // Find closing bracket (no nested array support — not needed for raw JSON)
    size_t end_bracket = json.find(']', bracket + 1);
    if (end_bracket == std::string::npos) return result;

    size_t i = bracket + 1;
    while (i < end_bracket) {
        while (i < end_bracket && std::isspace(static_cast<unsigned char>(json[i]))) ++i;
        if (i >= end_bracket) break;

        if (json[i] == '"') {
            size_t end = i + 1;
            while (end < end_bracket) {
                if (json[end] == '\\') { end += 2; continue; }
                if (json[end] == '"')  { break; }
                ++end;
            }
            std::string raw = json.substr(i + 1, end - i - 1);
            std::string val;
            for (size_t k = 0; k < raw.size(); ++k) {
                if (raw[k] == '\\' && k + 1 < raw.size()) {
                    switch (raw[k+1]) {
                        case '"':  val += '"';  ++k; break;
                        case '\\': val += '\\'; ++k; break;
                        case 'n':  val += '\n'; ++k; break;
                        case 'r':  val += '\r'; ++k; break;
                        case 't':  val += '\t'; ++k; break;
                        default:   val += raw[k]; break;
                    }
                } else { val += raw[k]; }
            }
            if (!val.empty()) result.push_back(val);
            i = end + 1;
        } else if (json[i] == ',') {
            ++i;
        } else {
            ++i;
        }
    }
    return result;
}


std::vector<std::string> OfflineProcessor::read_ndjson_lines(const std::string& path)
{
    std::vector<std::string> lines;
    std::ifstream f(path);
    if (!f) { log_err("[OfflineProcessor] Could not open file: " + path); return lines; }

    std::string line;
    while (std::getline(f, line)) {
        // Windows-style \r\n
        if (!line.empty() && line.back() == '\r') line.pop_back();
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;
        // Must start with a JSON object
        size_t s = 0;
        while (s < line.size() && std::isspace(static_cast<unsigned char>(line[s]))) ++s;
        if (s >= line.size() || line[s] != '{') continue;
        lines.push_back(std::move(line));
    }
    return lines;
}

std::vector<std::string> OfflineProcessor::read_json_array(const std::string& path,
                                                             const std::string& array_key)
{
    std::vector<std::string> objects;

    std::ifstream f(path);
    if (!f) { log_err("[OfflineProcessor] Could not open file: " + path); return objects; }

    std::ostringstream ss; ss << f.rdbuf();
    std::string content = ss.str();

    std::string search = "\"" + array_key + "\"";
    size_t pos = content.find(search);
    if (pos == std::string::npos) return objects;

    size_t bracket = content.find('[', pos + search.size());
    if (bracket == std::string::npos) return objects;

    size_t i = bracket + 1;
    while (i < content.size()) {
        while (i < content.size() && std::isspace(static_cast<unsigned char>(content[i]))) ++i;
        if (i >= content.size() || content[i] == ']') break;
        if (content[i] != '{') { ++i; continue; }

        int depth = 0;
        size_t start = i;
        bool in_str = false;
        while (i < content.size()) {
            char c = content[i];
            if (in_str) {
                if (c == '\\') { ++i; }
                else if (c == '"') in_str = false;
            } else {
                if (c == '"') in_str = true;
                else if (c == '{') ++depth;
                else if (c == '}') {
                    --depth;
                    if (depth == 0) { ++i; break; }
                }
            }
            ++i;
        }
        objects.push_back(content.substr(start, i - start));
    }
    return objects;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 4 — Lookup tables  (NDJSON version)
//
//  All raw files are in .jsonl format:
//    raw_users.jsonl  — each line is a user JSON object
//    raw_groups.jsonl — each line is a group JSON object
//    raw_aces.jsonl   — each line is an ACE JSON object
//
//  Field name mapping (collector → offline processor):
//    UserCollector:
//      "username"        → sam_account_name (jp_str)
//      "dn"              → distinguished_name
//      "sid"             → object_sid
//      "display_name"    → display_name
//      "member_of"       → member_of (DN array)
//
//    GroupCollector:
//      "name" / "sam_name" → sam_account_name
//      "dn"                → distinguished_name
//      "sid" / "group_sid" → object_sid
//      "display_name"      → display_name (absent, use sam_name)
//      "members"           → direct_member_dns
//
//    AceCollector:
//      "principal_sid"     → trustee_sid
//      "target_dn"         → dn  (DN of the target object)
//      "target_type"       → object_class
//      "object_ace_type"   → object_type_guid  (GUID string)
//      "rights_display"    → mask (human-readable → keep, no raw mask)
//      "ace_qualifier"     → "Allow"/"Deny" → is_allow
//      "is_inherited"      → is_inherited
// ═════════════════════════════════════════════════════════════════════════════

// ── load_raw_users_lookup ─────────────────────────────────────────────────────
bool OfflineProcessor::load_raw_users_lookup(const std::string& path) {
    auto objs = read_ndjson_lines(path);
    if (objs.empty()) {
        log_warn("[OfflineProcessor] raw_users.jsonl empty or not found: " + path);
        return false;
    }

    // Extract domain metadata from the first line (add extra processing here if needed)

    for (const auto& obj : objs) {
        // UserCollector field names: "dn", "sid", "username", "display_name"
        std::string dn      = jp_str(obj, "dn");
        std::string sid     = upper(jp_str(obj, "sid"));
        std::string sam     = jp_str(obj, "username");
        std::string display = jp_str(obj, "display_name");
        if (dn.empty() || sid.empty()) continue;

        sid_to_dn_[sid]         = dn;
        dn_to_sid_[upper(dn)]   = sid;
        dn_to_class_[upper(dn)] = "user";
        if (!sam.empty())     dn_to_sam_[upper(dn)]     = sam;
        if (!display.empty()) sid_to_display_[sid]       = display;

        // base_dn_: extract the DC= portion from the user DN
        // e.g.: "CN=Alice,CN=Users,DC=corp,DC=local" → "DC=corp,DC=local"
        if (base_dn_.empty() && !dn.empty()) {
            // Find the first "DC=" component in the DN
            std::string udn_tmp = upper(dn);
            size_t dc_pos = udn_tmp.find(",DC=");
            if (dc_pos == std::string::npos) dc_pos = udn_tmp.find(", DC=");
            if (dc_pos != std::string::npos) {
                // The part after the comma is the base_dn
                base_dn_ = dn.substr(dc_pos + 1);
            } else if (udn_tmp.size() > 3 &&
                       udn_tmp[0]=='D' && udn_tmp[1]=='C' && udn_tmp[2]=='=') {
                // DN itself starts with DC= — it is the domain root
                base_dn_ = dn;
            }
        }
    }

    log_ok("[OfflineProcessor] User lookup table loaded (" +
           std::to_string(objs.size()) + " users).");
    return true;
}

// ── load_raw_groups_lookup ────────────────────────────────────────────────────
bool OfflineProcessor::load_raw_groups_lookup(const std::string& path) {
    auto objs = read_ndjson_lines(path);
    if (objs.empty()) {
        log_warn("[OfflineProcessor] raw_groups.jsonl empty or not found: " + path);
        return false;
    }

    // ── Phase 1: Populate basic lookup tables ───────────────────────────
    // GroupCollector field names: "dn", "sid"/"group_sid", "name"/"sam_name", "members"
    std::unordered_map<std::string, std::vector<std::string>> group_direct_member_dns;

    for (const auto& obj : objs) {
        std::string dn  = jp_str(obj, "dn");
        // "sid" or "group_sid" — collector writes both
        std::string sid = upper(jp_str(obj, "sid"));
        if (sid.empty()) sid = upper(jp_str(obj, "group_sid"));
        // "name" or "sam_name"
        std::string sam = jp_str(obj, "sam_name");
        if (sam.empty()) sam = jp_str(obj, "name");
        if (dn.empty() || sid.empty()) continue;

        sid_to_dn_[sid]         = dn;
        dn_to_sid_[upper(dn)]   = sid;
        dn_to_class_[upper(dn)] = "group";
        if (!sam.empty())  dn_to_sam_[upper(dn)]  = sam;
        sid_to_display_[sid] = sam;  // for groups, displayName = samName

        // "members" → direct member DNs
        auto member_dns = jp_arr(obj, "members");
        if (!member_dns.empty())
            group_direct_member_dns[sid] = std::move(member_dns);
    }

    // ── Phase 2: Convert DN → SID, build graph ─────────────────────────
    std::unordered_map<std::string, std::set<std::string>> group_direct_sids;

    for (auto& [gsid, dns] : group_direct_member_dns) {
        auto& sids = group_direct_sids[gsid];
        for (const auto& dn : dns) {
            auto it = dn_to_sid_.find(upper(dn));
            if (it != dn_to_sid_.end())
                sids.insert(it->second);
        }
    }

    // ── Phase 3: Compute transitive members with DFS ───────────────────
    std::unordered_map<std::string, bool> computed;

    std::function<void(const std::string&, std::set<std::string>&)> dfs =
        [&](const std::string& gsid, std::set<std::string>& visited_groups) {
            if (computed.count(gsid)) return;

            auto& transitive = group_transitive_sids_[gsid];
            auto it = group_direct_sids.find(gsid);
            if (it == group_direct_sids.end()) {
                computed[gsid] = true;
                return;
            }

            for (const auto& member_sid : it->second) {
                transitive.insert(member_sid);

                if (group_direct_sids.count(member_sid) &&
                    !visited_groups.count(member_sid)) {
                    visited_groups.insert(member_sid);
                    dfs(member_sid, visited_groups);
                    auto sub_it = group_transitive_sids_.find(member_sid);
                    if (sub_it != group_transitive_sids_.end())
                        transitive.insert(sub_it->second.begin(),
                                          sub_it->second.end());
                }
            }
            computed[gsid] = true;
        };

    for (const auto& obj : objs) {
        std::string sid = upper(jp_str(obj, "sid"));
        if (sid.empty()) sid = upper(jp_str(obj, "group_sid"));
        if (sid.empty()) continue;
        std::set<std::string> visited;
        visited.insert(sid);
        dfs(sid, visited);
    }

    log_info("[OfflineProcessor] DFS complete — transitive membership computed for " +
             std::to_string(group_transitive_sids_.size()) + " groups.");

    // ── Phase 4: Find DnsAdmins + Admin group SIDs ────────────────────
    for (const auto& obj : objs) {
        std::string sam = lower(jp_str(obj, "sam_name"));
        if (sam.empty()) sam = lower(jp_str(obj, "name"));
        if (sam == "dnsadmins") {
            std::string sid = upper(jp_str(obj, "sid"));
            if (sid.empty()) sid = upper(jp_str(obj, "group_sid"));
            if (!sid.empty()) dns_admins_sids_.insert(sid);
        }
    }

    static const int ADMIN_RIDS[] = {
        OfflineAdminRID::DOMAIN_ADMINS,   OfflineAdminRID::ENTERPRISE_ADMINS,
        OfflineAdminRID::SCHEMA_ADMINS,   OfflineAdminRID::BUILTIN_ADMINS,
        OfflineAdminRID::DOMAIN_CONTROLLERS,
        OfflineAdminRID::ENTERPRISE_READONLY_CONTROLLERS,
        OfflineAdminRID::ACCOUNT_OPERATORS, OfflineAdminRID::SERVER_OPERATORS,
        OfflineAdminRID::BACKUP_OPERATORS,  OfflineAdminRID::PRINT_OPERATORS,
        OfflineAdminRID::GROUP_POLICY_CREATORS,
        OfflineAdminRID::CRYPTOGRAPHIC_OPERATORS,
        OfflineAdminRID::HYPERV_ADMINISTRATORS,
        OfflineAdminRID::KEY_ADMINS, OfflineAdminRID::ENTERPRISE_KEY_ADMINS, 0
    };
    for (const auto& obj : objs) {
        std::string sid = upper(jp_str(obj, "sid"));
        if (sid.empty()) sid = upper(jp_str(obj, "group_sid"));
        if (sid.empty()) continue;
        int r = rid_from_sid(sid);
        for (int i = 0; ADMIN_RIDS[i]; ++i) {
            if (r == ADMIN_RIDS[i]) { admin_group_sids_.insert(sid); break; }
        }
    }

    log_ok("[OfflineProcessor] Group lookup table loaded (" +
           std::to_string(objs.size()) + " groups, " +
           std::to_string(group_transitive_sids_.size()) + " transitive maps, " +
           std::to_string(admin_group_sids_.size()) + " admin groups).");
    return true;
}

// ── load_raw_aces_lookup ──────────────────────────────────────────────────────
//  Stores only domain root + AdminSDHolder ACEs from raw_aces.jsonl.
//  Each line: {"target_dn":"...", "target_type":"...", "principal_sid":"...",
//              "ace_qualifier":"Allow", "object_ace_type":"...", "is_inherited":false, ...}
bool OfflineProcessor::load_raw_aces_lookup(const std::string& path) {
    auto lines = read_ndjson_lines(path);
    if (lines.empty()) {
        log_warn("[OfflineProcessor] raw_aces.jsonl not found: " + path +
                 " — ACE-based admin rules (3,4,6,7,9) will be disabled.");
        return false;
    }

    for (const auto& line : lines) {
        std::string target_dn = jp_str(line, "target_dn");
        if (target_dn.empty()) continue;
        std::string udn = upper(target_dn);

        // If base_dn_ is still empty, auto-detect from target_dn:
        // the shortest target_dn starting with DC= is the domain root
        if (base_dn_.empty()) {
            std::string utmp = upper(target_dn);
            // "DC=x,DC=y" form (no CN/OU prefix)
            if (utmp.size() > 3 &&
                utmp[0]=='D' && utmp[1]=='C' && utmp[2]=='=') {
                base_dn_ = target_dn;
            }
        }

        bool is_domain_root   = (!base_dn_.empty() && udn == upper(base_dn_));
        std::string ashdn     = "CN=ADMINSDHOLDER,CN=SYSTEM," + upper(base_dn_);
        bool is_adminsdholder = (udn == ashdn);
        // Configuration NC: "CN=CONFIGURATION,DC=..." — also a DCSync ACE source
        std::string config_nc_dn = "CN=CONFIGURATION," + upper(base_dn_);
        bool is_config_nc     = (!base_dn_.empty() && udn == config_nc_dn);

        // DC object: target_type == "computer" and found in dn_to_class_ as "computer"
        // Machines under OU=Domain Controllers are DCs.
        // Most reliable: check target_type field == "domaincontroller" or "computer"
        // + check DN contains "OU=DOMAIN CONTROLLERS".
        bool is_dc_object = false;
        {
            std::string tt = lower(jp_str(line, "target_type"));
            if (tt == "domaincontroller") {
                is_dc_object = true;
            } else if (tt == "computer") {
                // Does the DN contain "OU=Domain Controllers"?
                std::string udn_check = upper(target_dn);
                if (udn_check.find("OU=DOMAIN CONTROLLERS") != std::string::npos)
                    is_dc_object = true;
            }
            // Fallback: check via class lookup
            if (!is_dc_object) {
                auto cit = dn_to_class_.find(udn);
                if (cit != dn_to_class_.end() && lower(cit->second) == "computer") {
                    if (udn.find("OU=DOMAIN CONTROLLERS") != std::string::npos)
                        is_dc_object = true;
                }
            }
        }

        if (!is_domain_root && !is_adminsdholder && !is_dc_object && !is_config_nc) continue;

        // Convert ACE to RawAceEntry
        RawAceEntry ace;
        ace.trustee_sid = upper(jp_str(line, "principal_sid"));
        if (ace.trustee_sid.empty()) continue;

        // rights_display → direct mask conversion is not possible,
        // mask is not needed here — ace_has_dangerous_right checks the mask.
        // AceCollector raw_aces.jsonl has no mask, but we build a
        // heuristic mask from rights_display:
        const std::string& rd = jp_str(line, "rights_display");
        unsigned int mask = 0;
        if      (rd == "Full-Control")               mask = 0x001F01FF;
        else if (rd == "Write-DACL")                 mask = 0x00040000;
        else if (rd == "Write-Owner")                mask = 0x00080000;
        else if (rd == "Write-Property")             mask = 0x00000020;
        else if (rd == "Write-Account-Restrictions") mask = 0x00000028;
        else if (rd == "GenericAll")                 mask = 0x10000000;
        else if (rd == "Control-Access"     ||
                 rd == "AllExtendedRights"  ||
                 rd == "All-Extended-Rights"||
                 rd == "ExtendedRight"      ||
                 rd.find("DS-Replication-") != std::string::npos)
                                                     mask = 0x00000100;
        else if (rd == "GenericWrite")               mask = OfflineAceRight::ACE_GENERIC_WRITE;
        else if (rd == "GenericRead")                mask = 0x00020094;
        else {
            // Combined values
            if (rd.find("WriteDACL")    != std::string::npos) mask |= 0x00040000;
            if (rd.find("WriteOwner")   != std::string::npos) mask |= 0x00080000;
            if (rd.find("AllExtended")  != std::string::npos) mask |= 0x00000100;
            if (rd.find("GenericWrite") != std::string::npos) mask |= OfflineAceRight::ACE_GENERIC_WRITE;
        }
        ace.mask = mask;

        std::string qualifier = jp_str(line, "ace_qualifier");
        ace.is_allow     = (qualifier != "Deny");
        ace.is_inherited = jp_bool(line, "is_inherited", false);

        // object_ace_type → object_type_guid
        std::string guid = jp_str(line, "object_ace_type");
        // lowercase
        for (char& c : guid) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        ace.object_type_guid = guid;

        if (is_domain_root)   domain_root_aces_.push_back(ace);
        if (is_adminsdholder) adminsdholder_aces_.push_back(ace);
        if (is_config_nc)     config_nc_aces_.push_back(ace);
        if (is_dc_object)     dc_object_aces_[udn].push_back(ace);
    }

    log_ok("[OfflineProcessor] ACE lookup: domain root=" +
           std::to_string(domain_root_aces_.size()) +
           " ACEs, AdminSDHolder=" +
           std::to_string(adminsdholder_aces_.size()) +
           " ACEs, Config NC=" +
           std::to_string(config_nc_aces_.size()) +
           " ACEs, DC objects=" +
           std::to_string(dc_object_aces_.size()) + " objects.");
    return true;
}

// ── build_lookup_tables ───────────────────────────────────────────────────────
bool OfflineProcessor::build_lookup_tables(const std::string& raw_dir) {
    // .jsonl files
    load_raw_users_lookup (raw_dir + "/raw_users.jsonl");
    bool groups_ok = load_raw_groups_lookup(raw_dir + "/raw_groups.jsonl");
    bool aces_ok   = load_raw_aces_lookup  (raw_dir + "/raw_aces.jsonl");
    (void)aces_ok;
    return groups_ok;  // groups is mandatory, aces is optional
}