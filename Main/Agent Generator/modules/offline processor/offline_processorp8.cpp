// ─── offline_processorp8.cpp ─────────────────────────────────────────────────
// SECTION 35  parse_raw_gpo    — raw_gpos.ndjson → ProcessedGPO
//             All transformation logic lives here. GPOCollector is a pure
//             extractor that writes verbatim LDAP data; this file does:
//               • hex → binary decode for objectGUID, ntSecurityDescriptor, objectSid
//               • GUID binary → UUID string
//               • SD binary  → isaclprotected + owner_sid
//               • objectSid binary → "S-1-5-21-..." string (domain_sid)
//               • DN extraction of "name" when LDAP attr was absent
//               • generalized-time → ISO-8601 conversion
//               • versionNumber integer split → user_version / computer_version
//               • flags integer → user_settings_disabled / computer_settings_disabled
//               • gPLink raw records → linked_containers / enforced / link_disabled
//               • extension GUID strings → [{guid,name}] JSON arrays
//               • high-value detection
//               • risk_controls list
//               • owner_sid → owner_name via lookup tables
// SECTION 36  analyze_gpo_risk — risk scoring
// SECTION 37  gpo_to_json      — serialization
// SECTION 38  load_and_process_gpos
// SECTION 39  process_gpos + process()
//
//  Input : raw_cache/raw_gpos.ndjson   (GPOCollector pure-extract output)
//  Output: Domain Objects/domain_gpos.ndjson
// ─────────────────────────────────────────────────────────────────────────────
#include "offline_processor.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <regex>
#include <set>
#include <iomanip>

// ═════════════════════════════════════════════════════════════════════════════
//  Local helpers  (file-scope, not exposed in header)
// ═════════════════════════════════════════════════════════════════════════════

// ── hex_to_bytes ─────────────────────────────────────────────────────────────
// "0102ff" → "\x01\x02\xff"
static std::string hex_to_bytes(const std::string& hex) {
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        const char hi = hex[i], lo = hex[i + 1];
        auto v = [](char c) -> unsigned char {
            if (c >= '0' && c <= '9') return (unsigned char)(c - '0');
            if (c >= 'a' && c <= 'f') return (unsigned char)(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return (unsigned char)(c - 'A' + 10);
            return 0;
        };
        out += (char)((v(hi) << 4) | v(lo));
    }
    return out;
}

// ── sid_bytes_to_string ───────────────────────────────────────────────────────
static std::string sid_bytes_to_string(const std::string& raw) {
    if (raw.size() < 8) return "";
    const auto* b = reinterpret_cast<const unsigned char*>(raw.data());
    if (b[0] != 1) return "";
    const int sub_count = b[1];
    uint64_t authority = 0;
    for (int i = 2; i < 8; ++i) authority = (authority << 8) | b[i];
    if (static_cast<size_t>(8 + sub_count * 4) > raw.size()) return "";
    std::ostringstream o;
    o << "S-1-" << authority;
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

// ── guid_bytes_to_string ──────────────────────────────────────────────────────
// 16-byte little-endian binary GUID → "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
static std::string guid_bytes_to_string(const std::string& raw) {
    if (raw.size() != 16) return "";
    const auto* b = reinterpret_cast<const unsigned char*>(raw.data());
    std::ostringstream o;
    o << std::hex << std::uppercase << std::setfill('0');
    for (int i : {3,2,1,0}) o << std::setw(2) << (int)b[i];
    o << "-";
    for (int i : {5,4})     o << std::setw(2) << (int)b[i];
    o << "-";
    for (int i : {7,6})     o << std::setw(2) << (int)b[i];
    o << "-";
    for (int i = 8;  i < 10; ++i) o << std::setw(2) << (int)b[i];
    o << "-";
    for (int i = 10; i < 16; ++i) o << std::setw(2) << (int)b[i];
    return o.str();
}

// ── parse_isaclprotected ──────────────────────────────────────────────────────
// SE_DACL_PROTECTED = bit 0x1000 in the Control field (bytes 2-3 LE) of the SD.
static bool parse_isaclprotected(const std::string& sd) {
    if (sd.size() < 4) return false;
    const auto* b = reinterpret_cast<const unsigned char*>(sd.data());
    uint16_t ctrl = static_cast<uint16_t>(b[2]) | (static_cast<uint16_t>(b[3]) << 8);
    return (ctrl & 0x1000) != 0;
}

// ── parse_sd_owner ────────────────────────────────────────────────────────────
// OffsetOwner is at bytes 4-7 (LE) in the SD binary.
static std::string parse_sd_owner(const std::string& sd) {
    if (sd.size() < 20) return "";
    const auto* b = reinterpret_cast<const unsigned char*>(sd.data());
    uint32_t off = static_cast<uint32_t>(b[4])
                 | (static_cast<uint32_t>(b[5]) << 8)
                 | (static_cast<uint32_t>(b[6]) << 16)
                 | (static_cast<uint32_t>(b[7]) << 24);
    if (off == 0 || off >= sd.size()) return "";
    return sid_bytes_to_string(sd.substr(off));
}

// ── generalized_time_to_iso ───────────────────────────────────────────────────
// "20260101100000.0Z" → "2026-01-01T10:00:00Z"
static std::string generalized_time_to_iso(const std::string& gt) {
    if (gt.size() < 14) return gt;
    for (int i = 0; i < 14; ++i)
        if (!std::isdigit(static_cast<unsigned char>(gt[i]))) return gt;
    return gt.substr(0,4) + "-" + gt.substr(4,2) + "-" + gt.substr(6,2)
         + "T" + gt.substr(8,2) + ":" + gt.substr(10,2) + ":" + gt.substr(12,2) + "Z";
}

// ── extract_domain_from_base_dn ───────────────────────────────────────────────
// "DC=corp,DC=local" → "corp.local"
static std::string extract_domain_from_base_dn(const std::string& base_dn) {
    std::string result, dn = base_dn;
    std::transform(dn.begin(), dn.end(), dn.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    size_t pos = 0;
    while (pos < dn.size()) {
        size_t eq    = dn.find('=', pos);
        if (eq == std::string::npos) break;
        size_t comma = dn.find(',', eq + 1);
        std::string comp = dn.substr(eq + 1,
            (comma != std::string::npos ? comma : dn.size()) - eq - 1);
        if (!result.empty()) result += ".";
        result += comp;
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return result;
}

// ── EXTENSION_GUID_MAP ────────────────────────────────────────────────────────
static const std::pair<const char*, const char*> EXT_GUID_MAP[] = {
    {"{35378EAC-683F-11D2-A89A-00C04FBBCFA2}", "Registry Settings"},
    {"{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", "Security Settings"},
    {"{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}", "EFS Recovery Policy"},
    {"{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}", "Scripts (Startup/Shutdown)"},
    {"{42B5FAAE-6536-11D2-AE5A-0000F87571E3}", "Scripts (Logon/Logoff)"},
    {"{00000000-0000-0000-0000-000000000000}", "Core GPO"},
    {"{25537BA6-77A8-11D2-9B6C-0000F8080861}", "Folder Redirection"},
    {"{3610EDA5-77EF-11D2-8DC5-00C04FA31A66}", "Microsoft Disk Quota"},
    {"{516FC620-5D34-4B08-8165-6A06B623EDEB}", "Scheduled Tasks"},
    {"{C6DC5466-785A-11D2-84D0-00C04FB169F7}", "Software Installation"},
    {"{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}", "Scheduled Tasks (Immediate)"},
    {"{E437BC1C-AA7D-11D2-A382-00C04F991E27}", "IP Security"},
    {"{40B6664F-4972-11D1-A7CA-0000F87571E3}", "Scripts"},
    {"{AADCED64-746C-4633-A97C-D61349046527}", "Group Policy Scheduled Tasks"},
    {"{B087BE9D-ED37-454F-AF9C-04291E351182}", "Group Policy Registry"},
    {"{FD500BEF-9F03-4F58-97B8-2E51C2218566}", "Group Policy Local Users and Groups"},
    {"{F581DAE7-8064-444A-AEB3-1875662A61CE}", "Group Policy Services"},
    {"{4D2F9B6F-1E52-4711-A5BE-012D73A3A073}", "Drive Maps"},
    {"{5794DAFD-BE60-433F-88A2-1A31939AC01F}", "Drive Mappings"},
    {"{FB2CA36D-0B40-4307-821B-A13B252DE56C}", "Group Policy Environment"},
    {nullptr, nullptr}
};

// ── parse_extension_guids_json ────────────────────────────────────────────────
// "[{GUID1}{GUID2}][{GUID3}]" → [{"guid":"...","name":"..."}]
static std::string parse_extension_guids_json(const std::string& ext_str) {
    if (ext_str.empty()) return "[]";
    std::regex guid_re(R"(\{([0-9A-Fa-f\-]{36})\})");
    std::vector<std::string> objs;
    std::set<std::string> seen;
    auto begin = std::sregex_iterator(ext_str.begin(), ext_str.end(), guid_re);
    for (auto it = begin; it != std::sregex_iterator(); ++it) {
        std::string guid = "{" + (*it)[1].str() + "}";
        std::transform(guid.begin(), guid.end(), guid.begin(),
            [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
        if (!seen.insert(guid).second) continue;
        std::string name = "Unknown Extension";
        for (int i = 0; EXT_GUID_MAP[i].first; ++i)
            if (guid == EXT_GUID_MAP[i].first) { name = EXT_GUID_MAP[i].second; break; }
        std::ostringstream o;
        o << "{\"guid\":\"" << guid << "\",\"name\":\"" << name << "\"}";
        objs.push_back(o.str());
    }
    std::ostringstream out;
    out << "[";
    for (size_t i = 0; i < objs.size(); ++i) { if (i) out << ","; out << objs[i]; }
    out << "]";
    return out.str();
}

// ── HIGH_VALUE_GUIDS ──────────────────────────────────────────────────────────
static const char* HIGH_VALUE_GUIDS[] = {
    "{31B2F340-016D-11D2-945F-00C04FB984F9}",  // Default Domain Policy
    "{6AC1786C-016F-11D2-945F-00C04FB984F9}",  // Default Domain Controllers Policy
    nullptr
};

static bool is_high_value_gpo(const std::string& name,
                               const std::string& user_ext,
                               const std::string& machine_ext) {
    for (int i = 0; HIGH_VALUE_GUIDS[i]; ++i)
        if (name == HIGH_VALUE_GUIDS[i]) return true;
    std::string combined = user_ext + " " + machine_ext;
    std::transform(combined.begin(), combined.end(), combined.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    if (combined.find("script")   != std::string::npos) return true;
    if (combined.find("registry") != std::string::npos) return true;
    if (combined.find("password") != std::string::npos) return true;
    return false;
}

// ── parse_gp_links ────────────────────────────────────────────────────────────
// Reads the "raw_gp_links" JSON array from a raw GPO line and populates:
//   linked_containers, enforced, link_disabled
// gPLink flag format: [LDAP://CN={GUID},...;N]  bit1=link-disabled, bit2=enforced
struct GpLinkResult {
    std::vector<std::string> containers;
    bool enforced     = false;
    bool link_disabled = false;
};

static GpLinkResult parse_gp_links(const std::string& json_obj,
                                    const std::string& cn_guid) {
    GpLinkResult r;

    // Extract raw_gp_links array as sub-string
    const std::string key = "\"raw_gp_links\"";
    size_t kpos = json_obj.find(key);
    if (kpos == std::string::npos) return r;
    size_t arr_start = json_obj.find('[', kpos + key.size());
    if (arr_start == std::string::npos) return r;

    // Walk each { } object inside the array
    std::regex guid_block_re(
        R"(\[LDAP://[^\]]*)" + cn_guid + R"([^\]]*;(\d+)\])",
        std::regex::icase);

    size_t pos = arr_start + 1;
    while (pos < json_obj.size()) {
        // Find next object start
        size_t obj_start = json_obj.find('{', pos);
        if (obj_start == std::string::npos) break;

        // Find matching }
        int depth = 1;
        size_t obj_end = obj_start + 1;
        bool in_str = false, esc = false;
        while (obj_end < json_obj.size() && depth > 0) {
            char c = json_obj[obj_end];
            if (esc) { esc = false; }
            else if (c == '\\' && in_str) { esc = true; }
            else if (c == '"') { in_str = !in_str; }
            else if (!in_str) {
                if (c == '{') ++depth;
                else if (c == '}') --depth;
            }
            ++obj_end;
        }
        if (depth != 0) break;

        std::string obj = json_obj.substr(obj_start, obj_end - obj_start);

        // Extract container_dn
        auto extract_str = [&](const std::string& field) -> std::string {
            std::string fkey = "\"" + field + "\":\"";
            size_t fp = obj.find(fkey);
            if (fp == std::string::npos) return "";
            fp += fkey.size();
            size_t ep = fp;
            bool es = false;
            while (ep < obj.size()) {
                if (es) { es = false; }
                else if (obj[ep] == '\\') { es = true; }
                else if (obj[ep] == '"') break;
                ++ep;
            }
            return obj.substr(fp, ep - fp);
        };

        std::string container_dn  = extract_str("container_dn");
        std::string gp_link_value = extract_str("gp_link_value");

        if (!container_dn.empty())
            r.containers.push_back(container_dn);

        // Parse enforced / link_disabled flags from gp_link_value
        auto begin = std::sregex_iterator(
            gp_link_value.begin(), gp_link_value.end(), guid_block_re);
        for (auto it = begin; it != std::sregex_iterator(); ++it) {
            int flags = 0;
            try { flags = std::stoi((*it)[1].str()); } catch (...) {}
            if (flags & 2) r.enforced      = true;
            if (flags & 1) r.link_disabled = true;
        }

        pos = obj_end;
        // Stop if we hit the closing ] of the array
        while (pos < json_obj.size() && json_obj[pos] != '{' && json_obj[pos] != ']')
            ++pos;
        if (pos < json_obj.size() && json_obj[pos] == ']') break;
    }

    return r;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 35 — parse_raw_gpo
//
//  Reads one raw NDJSON line (GPOCollector pure-extract output) and fills a
//  ProcessedGPO.  All derivation / parsing happens here.
// ═════════════════════════════════════════════════════════════════════════════

ProcessedGPO OfflineProcessor::parse_raw_gpo(const std::string& json_obj) const
{
    ProcessedGPO g;

    // ── Identity ──────────────────────────────────────────────────────────────
    g.dn           = jp_str(json_obj, "dn");
    g.name         = jp_str(json_obj, "name");
    g.display_name = jp_str(json_obj, "display_name");
    g.description  = jp_str(json_obj, "description");
    g.path         = jp_str(json_obj, "path");
    g.managed_by   = jp_str(json_obj, "managed_by");

    // name fallback: extract from DN if missing
    if (g.name.empty() && !g.dn.empty()) {
        size_t eq  = g.dn.find('=');
        size_t com = g.dn.find(',', eq + 1);
        if (eq != std::string::npos)
            g.name = g.dn.substr(eq + 1,
                (com != std::string::npos ? com : g.dn.size()) - eq - 1);
    }
    std::transform(g.name.begin(), g.name.end(), g.name.begin(),
        [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
    if (!g.name.empty() && g.name.front() != '{')
        g.name = "{" + g.name + "}";

    if (g.display_name.empty()) g.display_name = g.name;

    // ── objectGUID binary → UUID string ──────────────────────────────────────
    {
        std::string raw = hex_to_bytes(jp_str(json_obj, "object_guid_raw"));
        if (raw.size() == 16) {
            std::string uuid = guid_bytes_to_string(raw);
            g.guid = "{" + uuid + "}";
        }
        if (g.guid.empty()) g.guid = g.name;   // CN IS the string GUID
    }

    // ── Domain SID: objectSid binary → "S-1-5-21-..." ────────────────────────
    {
        std::string raw = hex_to_bytes(jp_str(json_obj, "object_sid_raw"));
        g.domain_sid = sid_bytes_to_string(raw);
    }

    // ── Domain name: extract from base_dn ────────────────────────────────────
    {
        std::string base_dn = jp_str(json_obj, "base_dn");
        g.domain_name = extract_domain_from_base_dn(base_dn);
        if (g.domain_name.empty()) g.domain_name = domain_name_;
    }

    // ── Timestamps: generalized time → ISO-8601 ───────────────────────────────
    g.when_created = generalized_time_to_iso(jp_str(json_obj, "when_created"));
    g.when_changed = generalized_time_to_iso(jp_str(json_obj, "when_changed"));

    // ── Version number → user_version / computer_version ──────────────────────
    {
        std::string vs = jp_str(json_obj, "version_number");
        g.version = 0;
        if (!vs.empty()) try { g.version = std::stoi(vs); } catch (...) {}
        g.user_version     = (g.version >> 16) & 0xFFFF;
        g.computer_version =  g.version        & 0xFFFF;
    }

    // ── GPO flags → user/computer settings disabled ────────────────────────────
    {
        std::string fs = jp_str(json_obj, "flags");
        g.flags = 0;
        if (!fs.empty()) try { g.flags = std::stoi(fs); } catch (...) {}
        g.user_settings_disabled     = (g.flags & 1) != 0;
        g.computer_settings_disabled = (g.flags & 2) != 0;
    }

    // ── Security Descriptor binary → isaclprotected + owner_sid ──────────────
    {
        std::string sd = hex_to_bytes(jp_str(json_obj, "nt_sd_raw"));
        if (sd.size() >= 20) {
            g.isaclprotected = parse_isaclprotected(sd);
            g.owner_sid      = parse_sd_owner(sd);
        } else {
            // SD not available: GPO containers are always ACL-protected in AD.
            g.isaclprotected = true;
            g.owner_sid      = (!g.domain_sid.empty()) ? g.domain_sid + "-512" : "";
        }
    }

    // ── Resolve owner_sid → owner_name via lookup tables ─────────────────────
    if (!g.owner_sid.empty()) {
        std::string uowner = upper(g.owner_sid);
        auto sit = sid_to_dn_.find(uowner);
        if (sit != sid_to_dn_.end()) {
            auto nit = dn_to_sam_.find(upper(sit->second));
            g.owner_name = (nit != dn_to_sam_.end())
                           ? nit->second
                           : cn_from_dn(sit->second);
        }
    }

    // ── gPLink raw records → linked_containers / enforced / link_disabled ─────
    {
        GpLinkResult lr = parse_gp_links(json_obj, g.name);
        g.linked_containers = lr.containers;
        g.linked_count      = static_cast<int>(lr.containers.size());
        g.enforced          = lr.enforced;
        g.link_disabled     = lr.link_disabled;
    }

    // ── Extension GUIDs: raw string → [{guid,name}] JSON arrays ──────────────
    {
        std::string uext = jp_str(json_obj, "user_ext_names");
        std::string mext = jp_str(json_obj, "machine_ext_names");
        g.user_extensions_raw    = parse_extension_guids_json(uext);
        g.machine_extensions_raw = parse_extension_guids_json(mext);

        // High-value detection (needs extension strings before they are parsed)
        g.highvalue = is_high_value_gpo(g.name, uext, mext);
    }

    // ── Risk controls ─────────────────────────────────────────────────────────
    if (g.highvalue)                                   g.risk_controls.push_back("High Value Target");
    if (g.enforced)                                    g.risk_controls.push_back("Enforced");
    if (g.isaclprotected)                              g.risk_controls.push_back("ACL Inheritance Blocked");
    if (g.user_settings_disabled)                      g.risk_controls.push_back("User Settings Disabled");
    if (g.computer_settings_disabled)                  g.risk_controls.push_back("Computer Settings Disabled");
    if (!g.managed_by.empty())                         g.risk_controls.push_back("Delegated Management");
    if (g.link_disabled && g.linked_count > 0)         g.risk_controls.push_back("Link Disabled");

    // ── Risk scoring ──────────────────────────────────────────────────────────
    analyze_gpo_risk(g);

    return g;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 36 — analyze_gpo_risk
// ═════════════════════════════════════════════════════════════════════════════

void OfflineProcessor::analyze_gpo_risk(ProcessedGPO& g) const
{
    int score = 0;
    if (g.highvalue)  score += 30;
    if (g.enforced)   score += 20;

    for (const auto& c : g.linked_containers) {
        std::string uc = upper(c);
        if (uc.size() >= 3 && uc[0]=='D' && uc[1]=='C' && uc[2]=='=') { score += 15; break; }
        if (uc.find("OU=DOMAIN CONTROLLERS") != std::string::npos)     { score += 15; break; }
    }

    if (g.isaclprotected)            score += 10;
    if (g.user_settings_disabled)    score += 10;
    if (g.computer_settings_disabled)score += 10;
    if (g.version == 0)              score += 10;
    if (g.link_disabled && g.linked_count > 0) score += 10;
    if (!g.managed_by.empty())       score +=  5;
    if (g.linked_count == 0)         score -= 10;

    if (score < 0)   score = 0;
    if (score > 100) score = 100;

    g.risk_score = score;
    g.high_risk  = (score >= 40);
    g.orphaned   = (g.linked_count == 0);
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 37 — gpo_to_json
// ═════════════════════════════════════════════════════════════════════════════

std::string OfflineProcessor::gpo_to_json(const ProcessedGPO& g) const
{
    std::ostringstream o;
    o << "{";
    o << "\"name\":"         << je(g.name)         << ",";
    o << "\"guid\":"         << je(g.guid)         << ",";
    o << "\"display_name\":" << je(g.display_name) << ",";
    o << "\"description\":"  << je(g.description)  << ",";
    o << "\"dn\":"           << je(g.dn)           << ",";
    o << "\"path\":"         << je(g.path)         << ",";
    o << "\"managed_by\":"   << je(g.managed_by)   << ",";
    o << "\"domain\":"       << je(g.domain_name)  << ",";
    o << "\"domainsid\":"    << je(g.domain_sid)   << ",";
    o << "\"created\":"      << jnl(g.when_created) << ",";
    o << "\"modified\":"     << jnl(g.when_changed) << ",";
    o << "\"version\":"          << ji(g.version)          << ",";
    o << "\"user_version\":"     << ji(g.user_version)     << ",";
    o << "\"computer_version\":" << ji(g.computer_version) << ",";
    o << "\"flags\":"                      << ji(g.flags)                      << ",";
    o << "\"user_settings_disabled\":"     << jb(g.user_settings_disabled)     << ",";
    o << "\"computer_settings_disabled\":" << jb(g.computer_settings_disabled) << ",";
    o << "\"linked_containers\":" << ja(g.linked_containers) << ",";
    o << "\"linked_count\":"      << ji(g.linked_count)      << ",";
    o << "\"enforced\":"          << jb(g.enforced)          << ",";
    o << "\"link_disabled\":"     << jb(g.link_disabled)     << ",";
    o << "\"isaclprotected\":" << jb(g.isaclprotected) << ",";
    o << "\"owner_sid\":"      << je(g.owner_sid)      << ",";
    o << "\"owner_name\":"     << je(g.owner_name)     << ",";
    o << "\"user_extensions\":"    << g.user_extensions_raw    << ",";
    o << "\"machine_extensions\":" << g.machine_extensions_raw << ",";
    o << "\"highvalue\":"     << jb(g.highvalue)       << ",";
    o << "\"risk_controls\":" << ja(g.risk_controls)   << ",";
    o << "\"risk_score\":"    << ji(g.risk_score)       << ",";
    o << "\"high_risk\":"     << jb(g.high_risk)        << ",";
    o << "\"orphaned\":"      << jb(g.orphaned)         << ",";
    o << "\"domain_name\":"   << je(g.domain_name);
    o << "}";
    return o.str();
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 38 — load_and_process_gpos  (private)
// ═════════════════════════════════════════════════════════════════════════════

bool OfflineProcessor::load_and_process_gpos(const std::string& raw_path,
                                              const std::string& out_path)
{
    log_info("[OfflineProcessor] Reading raw_gpos.ndjson: " + raw_path);

    auto raw_lines = read_ndjson_lines(raw_path);
    if (raw_lines.empty()) {
        log_warn("[OfflineProcessor] raw_gpos.ndjson empty or missing: " + raw_path);
        return false;
    }

    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        log_err("[OfflineProcessor] Could not open output file: " + out_path);
        return false;
    }

    int highvalue_count    = 0;
    int high_risk_count    = 0;
    int enforced_count     = 0;
    int orphaned_count     = 0;
    int disabled_gpo_count = 0;
    int linked_count       = 0;
    std::vector<std::string> rows;
    rows.reserve(raw_lines.size());

    for (const auto& raw : raw_lines) {
        ProcessedGPO g = parse_raw_gpo(raw);
        if (g.highvalue)                                          ++highvalue_count;
        if (g.high_risk)                                          ++high_risk_count;
        if (g.enforced)                                           ++enforced_count;
        if (g.orphaned)                                           ++orphaned_count;
        if (g.user_settings_disabled && g.computer_settings_disabled) ++disabled_gpo_count;
        if (g.linked_count > 0)                                   ++linked_count;
        rows.push_back(gpo_to_json(g));
    }
    write_objects(out, rows, out_path, "[OfflineProcessor]");
    out.close();

    log_ok("[OfflineProcessor] domain_gpos written -> " + out_path);
    log_ok("[OfflineProcessor] "
        + std::to_string(raw_lines.size()) + " GPOs | "
        + std::to_string(linked_count)     + " linked | "
        + std::to_string(orphaned_count)   + " orphaned | "
        + std::to_string(enforced_count)   + " enforced");
    log_ok("[OfflineProcessor] "
        + std::to_string(highvalue_count)    + " high-value | "
        + std::to_string(high_risk_count)    + " high-risk | "
        + std::to_string(disabled_gpo_count) + " fully-disabled");

    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 39 — process_gpos + process()
// ═════════════════════════════════════════════════════════════════════════════

bool OfflineProcessor::process_gpos(const OfflineProcessorOptions& opts)
{
    fs::create_directories(opts.output_dir);
    load_raw_users_lookup (opts.raw_dir + "/raw_users.ndjson");
    load_raw_groups_lookup(opts.raw_dir + "/raw_groups.ndjson");
    if (!opts.domain_name.empty()) domain_name_ = opts.domain_name;
    if (domain_name_.empty()) domain_name_ = base_dn_to_domain(base_dn_);
    const std::string& ext8 = opts.output_ext.empty() ? "ndjson" : opts.output_ext;
    return load_and_process_gpos(
        opts.raw_dir    + "/raw_gpos.ndjson",
        opts.output_dir + "/domain_gpos." + ext8);
}

bool OfflineProcessor::process(const OfflineProcessorOptions& opts)
{
    fs::create_directories(opts.output_dir);
    log_info("[OfflineProcessor] Building lookup tables from: " + opts.raw_dir);
    if (!build_lookup_tables(opts.raw_dir)) {
        log_err("[OfflineProcessor] Failed to build lookup tables — aborting.");
        return false;
    }
    if (!opts.domain_name.empty()) domain_name_ = opts.domain_name;
    if (domain_name_.empty()) domain_name_ = base_dn_to_domain(base_dn_);

    bool all_ok = true;
    const std::string& ext = opts.output_ext.empty() ? "ndjson" : opts.output_ext;
    all_ok &= load_and_process_users    (opts.raw_dir + "/raw_users.ndjson",     opts.output_dir + "/domain_users."     + ext);
    all_ok &= load_and_process_groups   (opts.raw_dir + "/raw_groups.ndjson",    opts.output_dir + "/domain_groups."    + ext);
    load_and_process_aces               (opts.raw_dir + "/raw_aces.ndjson",      opts.output_dir + "/domain_aces."      + ext);
    all_ok &= load_and_process_computers(opts.raw_dir + "/raw_computers.ndjson", opts.output_dir + "/domain_computers." + ext);
    all_ok &= load_and_process_ous      (opts.raw_dir + "/raw_ous.ndjson",       opts.output_dir + "/domain_ous."       + ext);
    load_and_process_gpos               (opts.raw_dir + "/raw_gpos.ndjson",      opts.output_dir + "/domain_gpos."      + ext);
    process_network                     (opts);
    all_ok &= load_and_process_cert_templates(opts.raw_dir + "/raw_cert_templates.ndjson", opts.output_dir + "/domain_cert_templates." + ext);
    all_ok &= load_and_process_pki_objects   (opts.raw_dir + "/raw_pki_objects.ndjson",    opts.output_dir + "/domain_pki_objects."    + ext);
    all_ok &= process_domaininfo(opts);
    process_trusts              (opts);
    return all_ok;
}