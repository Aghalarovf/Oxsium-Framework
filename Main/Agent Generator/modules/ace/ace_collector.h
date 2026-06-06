#pragma once
#include "../../include/core.h"
#include "../../include/ldap_engine.h"
#include <filesystem>
#include <string>
#include <vector>
#include <cstdint>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  AceCollectorOptions
// ─────────────────────────────────────────────────────────────────────────────
struct AceCollectorOptions {
    std::string output_dir  = "raw_cache";
    int         max_objects = 0;     // 0 = limitsiz
    int         page_size   = 1000;  // LDAP paging
};

// ─────────────────────────────────────────────────────────────────────────────
//  AceCollector  — Phase 1 / Extract
//
//  Output schema (raw_aces.ndjson) — hər sətir bir ACE obyekti:
//
//  {
//    "target_name"      : "Administrator",
//    "target_dn"        : "CN=Administrator,CN=Users,DC=...",
//    "target_sid"       : "S-1-5-21-...-500",
//    "target_type"      : "User",
//    "principal_sid"    : "S-1-5-32-554",
//    "ace_qualifier"    : "Allow",          // "Allow" | "Deny"
//    "ace_type_raw"     : 5,
//    "object_ace_type"  : "4c164200-...",   // boş = yoxdur
//    "rights_display"   : "Write-Account-Restrictions",
//    "is_inherited"     : false,
//    "ace_flags"        : 0,
//    "modified"         : "2026-05-29T07:47:34+00:00",
//    "generated_at"     : "2026-05-29T07:50:48Z"
//  }
//
//  Bu schema domain_aces.parquet ilə uyğundur:
//    target_name, target_dn, target_sid, target_type,
//    principal_sid, ace_qualifier, ace_type_raw,
//    object_ace_type, rights_display, is_inherited,
//    ace_flags, modified, generated_at
// ─────────────────────────────────────────────────────────────────────────────
class AceCollector {
public:
    explicit AceCollector(LDAPEngine& engine);

    // LDAP-dan çəkir, raw_aces.ndjson-a sətir-sətir yazır.
    // Qaytarır: yazılan ACE sayı, xəta halında -1
    int      collect(const AceCollectorOptions& opts = {});
    fs::path output_path() const { return output_path_; }

private:
    LDAPEngine& engine_;
    fs::path    output_path_;

    // ── Binary SD → ACE list ─────────────────────────────────────────────────
    struct RawAce {
        std::string  target_name;
        std::string  target_dn;
        std::string  target_sid;
        std::string  target_type;
        std::string  principal_sid;
        std::string  ace_qualifier;          // "Allow" | "Deny"
        int          ace_type_raw    = 0;
        std::string  object_ace_type;        // boş = yoxdur
        std::string  rights_display;         // human-readable rights
        bool         is_inherited    = false;
        uint8_t      ace_flags       = 0;
        std::string  modified;               // whenChanged atributundan
        std::string  generated_at;           // collection timestamp
    };

    std::vector<RawAce> parse_sd(
        const std::string& sd_bytes,
        const std::string& target_name,
        const std::string& target_dn,
        const std::string& target_sid,
        const std::string& target_type,
        const std::string& when_changed,
        const std::string& generated_at) const;

    // Bir RawAce-i NDJSON sətrinə çevirir (sonunda \n yoxdur)
    std::string ace_to_ndjson(const RawAce& ace) const;

    // ── Helpers ───────────────────────────────────────────────────────────────
    static std::string decode_sid       (const std::string& raw_bytes);
    static std::string guid_bytes_to_str(const unsigned char* b);
    static std::string primary_class    (const std::vector<std::string>& classes);
    static std::string mask_to_rights   (unsigned int mask);  // human-readable

    static uint16_t read_u16(const unsigned char* b, size_t off, size_t len);
    static uint32_t read_u32(const unsigned char* b, size_t off, size_t len);

    static std::string je(const std::string& s);  // JSON string escape
    static std::string jb(bool v);                // JSON bool
    static std::string ji(int v);                 // JSON int
    static std::string now_iso8601();             // current UTC timestamp
};