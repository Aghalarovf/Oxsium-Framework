#pragma once
#include "../../include/core.h"
#include "../../include/ldap_engine.h"
#include <filesystem>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <cstdint>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  AceCollectorOptions
// ─────────────────────────────────────────────────────────────────────────────
struct AceCollectorOptions {
    std::string output_dir  = "raw_cache";
    int         max_objects = 0;     // 0 = limitsiz
    int         page_size   = 1000;  // LDAP paging
    // Python guid_map ilə ekvivalent: object GUID → human-readable ad
    // Boş olduqda raw GUID yazılır (Python-da guid_map=None ilə eyni davranış)
    std::map<std::string, std::string> guid_map;
};

// ─────────────────────────────────────────────────────────────────────────────
//  AceCollector  — Phase 1 / Extract
//
//  Output schema (raw_aces.jsonl) — Python parsers.py ilə tam uyğun:
//
//  {
//    "target_name"           : "Administrator",
//    "target_dn"             : "CN=Administrator,CN=Users,DC=...",
//    "target_sid"            : "S-1-5-21-...-500",
//    "target_type"           : "User",
//    "principal"             : "DOMAIN\\SomeUser",
//    "principal_sid"         : "S-1-5-32-554",
//    "principal_scope"       : "Privileged",   // "Privileged"|"Broad"|"Custom"
//    "principal_is_disabled" : false,
//    "object_acetype"        : "4c164200-...", // boş = yoxdur
//    "object_ace_type"       : "4c164200-...", // object_acetype ilə eyni
//    "ace_qualifier"         : "Allow",        // "Allow" | "Deny"
//    "ace_type_raw"          : 5,
//    "rights"                : ["WriteProperty", "Self"],
//    "rights_display"        : "WriteProperty, Self",
//    "edge_rights"           : ["WriteProperty"],
//    "is_edge"               : true,
//    "edge_kind"             : "Edge",         // "Edge" | "ACL"
//    "is_inherited"          : false,
//    "ace_flags"             : 0,
//    "modified"              : "2026-05-29T07:47:34+00:00",
//    "generated_at"          : "2026-05-29T07:50:48Z"
//  }
// ─────────────────────────────────────────────────────────────────────────────
class AceCollector {
public:
    explicit AceCollector(LDAPEngine& engine);

    // LDAP-dan çəkir, raw_aces.jsonl-a sətir-sətir yazır.
    // Qaytarır: yazılan ACE sayı, xəta halında -1
    int      collect(const AceCollectorOptions& opts = {});
    fs::path output_path() const { return output_path_; }

private:
    LDAPEngine& engine_;
    fs::path    output_path_;

    // ── SID map: sid → sAMAccountName ────────────────────────────────────────
    std::map<std::string, std::string> sid_map_;
    std::set<std::string>              disabled_sids_;

    void build_sid_map();   // LDAP-dan bütün user/group/computer SID-lərini yığır

    // ── Binary SD → ACE list ─────────────────────────────────────────────────
    struct RawAce {
        // target
        std::string  target_name;
        std::string  target_dn;
        std::string  target_sid;
        std::string  target_type;
        // principal
        std::string  principal;             // resolved name (sAMAccountName)
        std::string  principal_sid;
        std::string  principal_scope;       // "Privileged" | "Broad" | "Custom"
        bool         principal_is_disabled = false;
        // object type GUID — Python-da hər ikisi expanded_obj dəyərini daşıyır
        // (guid_map.get(obj_guid, obj_guid) ilə ekvivalent)
        std::string  object_acetype;        // Python "object_acetype" sahəsi
        std::string  object_ace_type;       // Python "object_ace_type" sahəsi (eyni dəyər)
        // ACE meta
        std::string  ace_qualifier;         // "Allow" | "Deny"
        int          ace_type_raw    = 0;
        // rights
        std::vector<std::string> rights;        // list
        std::string              rights_display; // ", ".join(rights)
        std::vector<std::string> edge_rights;   // rights ∩ INTERESTING_RIGHTS
        bool         is_edge     = false;
        std::string  edge_kind;             // "Edge" | "ACL"
        // flags
        bool         is_inherited = false;
        uint8_t      ace_flags    = 0;
        // timestamps
        std::string  modified;              // whenChanged atributundan
        std::string  generated_at;          // collection timestamp
    };

    std::vector<RawAce> parse_sd(
        const std::string& sd_bytes,
        const std::string& target_name,
        const std::string& target_dn,
        const std::string& target_sid,
        const std::string& target_type,
        const std::string& when_changed,
        const std::string& generated_at) const;

    // Bir RawAce-i JSONL sətrinə çevirir (sonunda \n yoxdur)
    std::string ace_to_jsonl(const RawAce& ace) const;

    // ── Rights parsing (Python _parse_rights() ilə ekvivalent) ───────────────
    std::vector<std::string> parse_rights(uint32_t mask,
                                          const std::string& obj_guid) const;
    static std::string       classify_principal(const std::string& sid,
                                                const std::string& name);
    static std::string       classify_target   (const std::string& dn,
                                                const std::vector<std::string>& classes);

    // ── Helpers ───────────────────────────────────────────────────────────────
    static std::string decode_sid       (const std::string& raw_bytes);
    static std::string guid_bytes_to_str(const unsigned char* b);
    static std::string primary_class    (const std::vector<std::string>& classes);

    static uint16_t read_u16(const unsigned char* b, size_t off, size_t len);
    static uint32_t read_u32(const unsigned char* b, size_t off, size_t len);

    static std::string je (const std::string& s);       // JSON string escape
    static std::string jb (bool v);                     // JSON bool
    static std::string ji (int v);                      // JSON int
    static std::string jsa(const std::vector<std::string>& v); // JSON string array
    static std::string now_iso8601();                   // current UTC timestamp
    static std::string ldap_ts_to_iso(const std::string& raw); // LDAP ts → ISO-8601

    // ── Sabitlər (Python constants.py ilə uyğun) ─────────────────────────────
    static const std::map<std::string, uint32_t>      INDIVIDUAL_RIGHTS;
    static const std::map<std::string, std::string>   OBJECT_TYPE_RIGHTS;
    static const std::set<std::string>                INTERESTING_RIGHTS;
    static const std::map<std::string, std::string>   WELL_KNOWN_SIDS;
    static const std::map<std::string, std::string>   AD_OBJECT_TYPE_MAP;
    static const std::set<std::string>                PRIVILEGED_RIDS;
    static const std::set<std::string>                BROAD_RIDS;
    static const std::set<std::string>                BROAD_SIDS;

    static constexpr uint32_t GENERIC_ALL_RAW      = 0x10000000u;
    static constexpr uint32_t GENERIC_ALL_COMPOSED = 0x000F01FFu;
    static constexpr uint32_t RAW_GENERIC_WRITE    = 0x40000000u;
    static constexpr uint32_t GENERIC_WRITE_COMPOSED = 0x00000028u;
    static constexpr uint32_t WRITE_PROPERTY_BIT  = 0x00000020u;
    static constexpr uint32_t SELF_BIT             = 0x00000008u;
    static constexpr uint32_t READ_PROPERTY_BIT    = 0x00000010u;
    static constexpr uint32_t CONTROL_ACCESS_RIGHT = 0x00000100u;
    static constexpr uint8_t  ACE_FLAG_INHERITED   = 0x10u;
    static constexpr uint8_t  ACE_FLAG_INHERIT_ONLY= 0x08u;
};