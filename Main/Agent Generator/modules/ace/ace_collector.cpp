#include "ace_collector.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>

AceCollector::AceCollector(LDAPEngine& engine) : engine_(engine) {}

// ─────────────────────────────────────────────────────────────────────────────
//  collect
// ─────────────────────────────────────────────────────────────────────────────
int AceCollector::collect(const AceCollectorOptions& opts) {
    fs::create_directories(opts.output_dir);
    output_path_ = fs::path(opts.output_dir) / "raw_aces.ndjson";

    std::ofstream f(output_path_, std::ios::binary);
    if (!f) {
        log_err("[AceCollector] Fayl açıla bilmədi: " + output_path_.string());
        return -1;
    }

    log_info("[AceCollector] LDAP query starting — collecting security descriptors for all objects...");

    const std::string generated_at = now_iso8601();
    const std::string filter = "(objectClass=*)";
    const std::vector<std::string> attrs = {
        "distinguishedName", "objectClass", "objectSid",
        "nTSecurityDescriptor", "displayName", "sAMAccountName",
        "whenChanged"
    };

    int total_aces = 0;
    int obj_count  = 0;

    bool ok = engine_.search(filter, attrs,
        [&](const LDAPEngine::AttrMap& entry) {
            if (opts.max_objects > 0 && obj_count >= opts.max_objects) return;

            auto get = [&](const std::string& k) -> std::string {
                auto it = entry.find(k);
                if (it != entry.end() && !it->second.empty()) return it->second[0];
                return "";
            };

            const std::string dn           = get("distinguishedName");
            const std::string when_changed = get("whenChanged");

            // target_name: displayName > sAMAccountName > DN-in ilk komponenti
            std::string target_name = get("displayName");
            if (target_name.empty()) target_name = get("sAMAccountName");
            if (target_name.empty() && !dn.empty()) {
                // "CN=Foo,..." → "Foo"
                size_t eq = dn.find('=');
                size_t cm = dn.find(',');
                if (eq != std::string::npos)
                    target_name = dn.substr(eq + 1,
                        cm == std::string::npos ? std::string::npos : cm - eq - 1);
            }

            // target_sid
            std::string target_sid;
            auto sid_it = entry.find("objectSid");
            if (sid_it != entry.end() && !sid_it->second.empty())
                target_sid = decode_sid(sid_it->second[0]);

            // target_type
            auto cls_it = entry.find("objectClass");
            std::string target_type;
            if (cls_it != entry.end())
                target_type = primary_class(cls_it->second);

            // nTSecurityDescriptor
            auto sd_it = entry.find("nTSecurityDescriptor");
            if (sd_it == entry.end() || sd_it->second.empty()) {
                ++obj_count;
                return;
            }

            auto aces = parse_sd(sd_it->second[0],
                                 target_name, dn, target_sid, target_type,
                                 when_changed, generated_at);

            for (const auto& ace : aces) {
                f << ace_to_ndjson(ace) << "\n";
                ++total_aces;
            }
            ++obj_count;
        });

    if (!ok) {
        log_err("[AceCollector] LDAP query failed.");
        return -1;
    }

    f.flush();
    f.close();

        log_ok("[AceCollector] " + std::to_string(obj_count) + " objects, " +
            std::to_string(total_aces) + " ACEs -> " + output_path_.string());
    return total_aces;
}

// ─────────────────────────────────────────────────────────────────────────────
//  ace_to_ndjson  — schema domain_aces.parquet ilə uyğun
// ─────────────────────────────────────────────────────────────────────────────
std::string AceCollector::ace_to_ndjson(const RawAce& a) const {
    std::ostringstream o;
    o << "{"
      << "\"target_name\":"    << je(a.target_name)    << ","
      << "\"target_dn\":"      << je(a.target_dn)      << ","
      << "\"target_sid\":"     << je(a.target_sid)     << ","
      << "\"target_type\":"    << je(a.target_type)    << ","
      << "\"principal_sid\":"  << je(a.principal_sid)  << ","
      << "\"ace_qualifier\":"  << je(a.ace_qualifier)  << ","
      << "\"ace_type_raw\":"   << ji(a.ace_type_raw)   << ","
      << "\"object_ace_type\":" << je(a.object_ace_type) << ","
      << "\"rights_display\":" << je(a.rights_display) << ","
      << "\"is_inherited\":"   << jb(a.is_inherited)   << ","
      << "\"ace_flags\":"      << ji(a.ace_flags)      << ","
      << "\"modified\":"       << je(a.modified)       << ","
      << "\"generated_at\":"   << je(a.generated_at)
      << "}";
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  parse_sd  — binary Security Descriptor → RawAce list
// ─────────────────────────────────────────────────────────────────────────────
std::vector<AceCollector::RawAce> AceCollector::parse_sd(
    const std::string& sd_bytes,
    const std::string& target_name,
    const std::string& target_dn,
    const std::string& target_sid,
    const std::string& target_type,
    const std::string& when_changed,
    const std::string& generated_at) const
{
    std::vector<RawAce> result;
    const auto* b = reinterpret_cast<const unsigned char*>(sd_bytes.data());
    const size_t len = sd_bytes.size();

    if (len < 20) return result;

    // SECURITY_DESCRIPTOR header
    // offset 4: DACL offset (uint32 LE)
    uint32_t dacl_off = read_u32(b, 16, len);
    if (dacl_off == 0 || dacl_off + 8 > len) return result;

    // ACL header: revision(1) sbz1(1) size(2) count(2) sbz2(2)
    uint16_t ace_count = read_u16(b, dacl_off + 4, len);
    size_t   pos       = dacl_off + 8;

    for (uint16_t i = 0; i < ace_count && pos + 4 <= len; ++i) {
        uint8_t  ace_type  = b[pos];
        uint8_t  ace_flags = b[pos + 1];
        uint16_t ace_size  = read_u16(b, pos + 2, len);
        if (ace_size < 4 || pos + ace_size > len) break;

        // ace_type:
        //   0x00 = ACCESS_ALLOWED_ACE_TYPE
        //   0x01 = ACCESS_DENIED_ACE_TYPE
        //   0x05 = ACCESS_ALLOWED_OBJECT_ACE_TYPE
        //   0x06 = ACCESS_DENIED_OBJECT_ACE_TYPE
        bool is_allow  = (ace_type == 0x00 || ace_type == 0x05);
        bool is_object = (ace_type == 0x05 || ace_type == 0x06);

        uint32_t mask = read_u32(b, pos + 4, len);

        RawAce ace;
        ace.target_name   = target_name;
        ace.target_dn     = target_dn;
        ace.target_sid    = target_sid;
        ace.target_type   = target_type;
        ace.ace_qualifier = is_allow ? "Allow" : "Deny";
        ace.ace_type_raw  = static_cast<int>(ace_type);
        ace.is_inherited  = (ace_flags & 0x10) != 0;
        ace.ace_flags     = ace_flags;
        ace.rights_display = mask_to_rights(mask);
        ace.modified      = when_changed;
        ace.generated_at  = generated_at;

        size_t sid_off = pos + 8;
        if (is_object && pos + 12 <= len) {
            uint32_t obj_flags = read_u32(b, pos + 8, len);
            sid_off = pos + 12;
            if (obj_flags & 0x01) {
                // ObjectType GUID mevcut
                if (sid_off + 16 <= len) {
                    ace.object_ace_type = guid_bytes_to_str(b + sid_off);
                    sid_off += 16;
                }
            }
            if (obj_flags & 0x02) {
                // InheritedObjectType GUID mevcut — atla
                if (sid_off + 16 <= len) sid_off += 16;
            }
        }

        if (sid_off < pos + ace_size)
            ace.principal_sid = decode_sid(
                std::string(reinterpret_cast<const char*>(b + sid_off),
                            (pos + ace_size) - sid_off));

        result.push_back(std::move(ace));
        pos += ace_size;
    }

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  mask_to_rights  — bitmask → human-readable string
//  domain_aces.parquet-dəki rights_display sütununa uyğun
// ─────────────────────────────────────────────────────────────────────────────
std::string AceCollector::mask_to_rights(unsigned int mask) {
    // Tam hüquq adları (domain_aces.parquet-dəki dəyərlərlə eyni)
    if (mask == 0x001F01FF) return "Full-Control";
    if (mask == 0x00020014) return "Write-Property";
    if (mask == 0x00020028) return "Write-Account-Restrictions";
    if (mask == 0x00040000) return "Write-DACL";
    if (mask == 0x00080000) return "Write-Owner";
    if (mask == 0x00020000) return "Read-Control";
    if (mask == 0x00010000) return "Delete";
    if (mask == 0x00000100) return "GenericRead";
    if (mask == 0x00000200) return "GenericWrite";
    if (mask == 0x00000400) return "GenericExecute";
    if (mask == 0x00000800) return "GenericAll";
    if (mask == 0x00000001) return "Create-Child";
    if (mask == 0x00000002) return "Delete-Child";
    if (mask == 0x00000004) return "List-Contents";
    if (mask == 0x00000008) return "Write-Self";
    if (mask == 0x00000010) return "Read-Property";
    if (mask == 0x00000020) return "List-Object";
    if (mask == 0x00000040) return "Delete-Tree";
    if (mask == 0x00000100) return "Control-Access";

    // Tanınmayan — hex
    std::ostringstream o;
    o << "0x" << std::hex << std::uppercase << std::setw(8)
      << std::setfill('0') << mask;
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  decode_sid
// ─────────────────────────────────────────────────────────────────────────────
std::string AceCollector::decode_sid(const std::string& raw) {
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
//  guid_bytes_to_str  — 16 byte → "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
// ─────────────────────────────────────────────────────────────────────────────
std::string AceCollector::guid_bytes_to_str(const unsigned char* b) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    // Data1 (LE uint32)
    o << std::setw(2) << (int)b[3] << std::setw(2) << (int)b[2]
      << std::setw(2) << (int)b[1] << std::setw(2) << (int)b[0] << '-';
    // Data2 (LE uint16)
    o << std::setw(2) << (int)b[5] << std::setw(2) << (int)b[4] << '-';
    // Data3 (LE uint16)
    o << std::setw(2) << (int)b[7] << std::setw(2) << (int)b[6] << '-';
    // Data4[0..1] (BE)
    o << std::setw(2) << (int)b[8] << std::setw(2) << (int)b[9] << '-';
    // Data4[2..7] (BE)
    for (int i = 10; i < 16; ++i) o << std::setw(2) << (int)b[i];
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  primary_class  — objectClass siyahısından ən spesifik tipi seç
// ─────────────────────────────────────────────────────────────────────────────
std::string AceCollector::primary_class(const std::vector<std::string>& classes) {
    // Prioritet sırası — domain_aces.parquet-dəki target_type dəyərlərinə uyğun
    static const std::vector<std::pair<std::string,std::string>> priority = {
        {"user",                    "User"},
        {"computer",                "Computer"},
        {"group",                   "Group"},
        {"groupPolicyContainer",    "GPO"},
        {"organizationalUnit",      "OU"},
        {"domainDNS",               "Domain"},
        {"container",               "Container"},
        {"trustedDomain",           "TrustedDomain"},
        {"msDS-GroupManagedServiceAccount", "GMSA"},
        {"serviceConnectionPoint",  "ServiceConnectionPoint"},
    };
    for (const auto& [cls, label] : priority)
        for (const auto& c : classes)
            if (c == cls) return label;
    return classes.empty() ? "Unknown" : classes.back();
}

// ─────────────────────────────────────────────────────────────────────────────
//  read helpers
// ─────────────────────────────────────────────────────────────────────────────
uint16_t AceCollector::read_u16(const unsigned char* b, size_t off, size_t len) {
    if (off + 2 > len) return 0;
    return static_cast<uint16_t>(b[off]) |
           (static_cast<uint16_t>(b[off+1]) << 8);
}

uint32_t AceCollector::read_u32(const unsigned char* b, size_t off, size_t len) {
    if (off + 4 > len) return 0;
    return static_cast<uint32_t>(b[off])        |
           (static_cast<uint32_t>(b[off+1]) << 8)  |
           (static_cast<uint32_t>(b[off+2]) << 16) |
           (static_cast<uint32_t>(b[off+3]) << 24);
}

// ─────────────────────────────────────────────────────────────────────────────
//  JSON helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string AceCollector::je(const std::string& s) {
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

std::string AceCollector::jb(bool v) { return v ? "true" : "false"; }
std::string AceCollector::ji(int v)  { return std::to_string(v); }

std::string AceCollector::now_iso8601() {
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