#pragma once
#include "../../include/core.h"
#include "../../include/ldap_engine.h"
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
//  TrustCollectorOptions
// ─────────────────────────────────────────────────────────────────────────────
struct TrustCollectorOptions {
    std::string output_dir = "raw_cache";
};

// ─────────────────────────────────────────────────────────────────────────────
//  TrustCollector  — Phase 1 / Extract
//
//  Queries the domain's System container for all trustedDomain objects and
//  collects every attribute needed for a full security analysis:
//
//  LDAP query:
//    base   : CN=System,<domainNC>
//    filter : (objectClass=trustedDomain)
//    scope  : ONE
//    attrs  : trustPartnerDomain, flatName, securityIdentifier,
//             trustType, trustDirection, trustAttributes,
//             msDS-TrustForestTrustInfo, whenCreated, whenChanged
//
//  trustType values (raw integer → name):
//    1  → DOWNLEVEL       (NT 4.0 / legacy)
//    2  → UPLEVEL         (Active Directory — most common)
//    3  → MIT             (non-Windows Kerberos realm)
//    4  → DCE             (rare; DCE/NCA)
//
//  trustDirection values:
//    0  → DISABLED
//    1  → INBOUND         (remote domain trusts us — they can authenticate here)
//    2  → OUTBOUND        (we trust remote — our users can access them)
//    3  → BIDIRECTIONAL   (two-way)
//
//  trustAttributes bit flags (hex):
//    0x00000001  NONTRANSITIVE            — kills Kerberos chaining
//    0x00000002  UPLEVEL_ONLY             — Win2000+ DCs only
//    0x00000004  QUARANTINED_DOMAIN       — SID filtering enforced (Quarantine ON)
//    0x00000008  FOREST_TRANSITIVE        — cross-forest trust
//    0x00000010  CROSS_ORGANIZATION       — selective authentication enforced
//    0x00000020  WITHIN_FOREST            — intra-forest (auto-created)
//    0x00000040  TREAT_AS_EXTERNAL        — SID filtering as if external
//    0x00000080  USES_RC4_ENCRYPTION      — RC4 (weaker) session keys
//    0x00000200  USES_AES_KEYS            — AES session keys preferred
//    0x00000400  CROSS_ORGANIZATION_NO_TGT_DELEGATION — TGT delegation blocked
//    0x00000800  PIM_TRUST                — Privileged Identity Mgmt forest trust
//
//  SID Filtering behaviour derived from attributes:
//    External trust  : filtering ON by default unless TREAT_AS_EXTERNAL + no QUARANTINED
//    Forest trust    : filtering ON when QUARANTINED_DOMAIN is set
//    Shortcut trust  : within-forest, no SID filtering applies
//
//  Output schema — raw_trusts.ndjson (one object per line):
//  {
//    "trust_partner"           : "partner.corp",        // FQDN of trusted domain
//    "flat_name"               : "PARTNER",             // NetBIOS / flat name
//    "partner_sid"             : "S-1-5-21-...",        // SID of partner domain (may be empty)
//    "trust_type_raw"          : 2,
//    "trust_type_name"         : "UPLEVEL",
//    "direction_raw"           : 3,
//    "direction_name"          : "BIDIRECTIONAL",
//    "is_inbound"              : true,
//    "is_outbound"             : true,
//    "attributes_raw"          : 8,
//    "is_transitive"           : true,
//    "is_forest_trust"         : true,
//    "is_external"             : false,
//    "is_within_forest"        : false,
//    "is_cross_org"            : false,                 // selective auth enforced
//    "quarantine_enabled"      : false,                 // QUARANTINED_DOMAIN bit
//    "treat_as_external"       : false,
//    "tgt_delegation_blocked"  : false,
//    "uses_rc4"                : false,
//    "uses_aes"                : true,
//    "sid_filtering_effective" : true,                  // derived safety flag
//    "when_created"            : "2023-01-15T10:30:00Z",
//    "when_changed"            : "2024-03-22T08:15:00Z"
//  }
//
//  Offline analysis: TrustOfflineProcessor (offline_processorp12.cpp)
//    reads raw_trusts.ndjson and emits domain_trusts.json with risk findings.
// ─────────────────────────────────────────────────────────────────────────────
class TrustCollector {
public:
    explicit TrustCollector(LDAPEngine& engine);

    // Main entry point. Returns count of trusts written (≥0), -1 on fatal error.
    int collect(const TrustCollectorOptions& opts = {});

    fs::path output_path() const { return output_path_; }

private:
    LDAPEngine& engine_;
    fs::path    output_path_;

    // ── Internal trust record ─────────────────────────────────────────────────
    struct TrustEntry {
        // Raw LDAP fields
        std::string trust_partner;       // trustPartner attribute
        std::string flat_name;           // flatName attribute
        std::string partner_sid;         // securityIdentifier (hex bytes → S-1-5-21-...)
        int         trust_type      = 0; // trustType
        int         trust_direction = 0; // trustDirection
        int         trust_attrs     = 0; // trustAttributes (bitmask)
        std::string when_created;
        std::string when_changed;
    };

    // ── Helpers ───────────────────────────────────────────────────────────────
    static std::string trust_type_name     (int t);
    static std::string trust_direction_name(int d);

    // Derives whether SID filtering is effectively enforced given type+attrs.
    // External trusts: filtering always on unless explicitly disabled.
    // Forest trusts  : filtering on when QUARANTINED_DOMAIN (0x4) is set.
    // Within-forest  : not applicable (intra-forest, always trusted).
    static bool        sid_filtering_effective(int trust_type, int trust_attrs);

    // Converts raw objectSid bytes (LDAP binary value) to "S-1-5-21-..." string.
    static std::string format_sid(const std::string& raw_bytes);

    // Converts LDAP generalizedTime ("20230115103000.0Z") to ISO-8601.
    static std::string generalized_time_to_iso(const std::string& gt);

    // JSON helpers
    static std::string je (const std::string& s);
    static std::string jb (bool v);
    static std::string ji (int v);

    // Serializes one TrustEntry to a flat JSON object string.
    static std::string entry_to_json(const TrustEntry& e);
};