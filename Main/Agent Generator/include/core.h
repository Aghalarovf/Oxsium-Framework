#pragma once

#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <sstream>
#include <cstring>

// ─────────────────────────────────────────────
//  ANSI Color Codes
// ─────────────────────────────────────────────
#define CLR_RESET   "\033[0m"
#define CLR_RED     "\033[38;5;160m"
#define CLR_GREEN   "\033[38;5;28m"
#define CLR_YELLOW  "\033[38;5;214m"
#define CLR_CYAN    "\033[38;5;67m"
#define CLR_ORANGE  "\033[38;5;202m"
#define CLR_GREY    "\033[38;5;244m"
#define CLR_BOLD    "\033[1m"
#define CLR_DIM     "\033[2m"

// ─────────────────────────────────────────────
//  Verbosity switch  (single source of truth)
//
//  TRUE  (default) — full mechanism trace: every collector / offline
//                     processor step is printed, exactly like before.
//  FALSE            — mechanism logs (log_info / log_ok) are suppressed.
//                     Only warnings, errors, and explicit summary lines
//                     (log_summary) are printed.
//
//  Toggle from the REPL with: set VERBOSE TRUE | FALSE
// ─────────────────────────────────────────────
inline bool& verbose_flag() {
    static bool g_verbose = true;
    return g_verbose;
}
inline void set_verbose(bool v) { verbose_flag() = v; }
inline bool is_verbose()        { return verbose_flag(); }

// ─────────────────────────────────────────────
//  Log Helpers
//
//  log_info / log_ok   — mechanism / progress detail. Hidden when
//                         verbose == false.
//  log_warn / log_err  — always shown regardless of verbosity, since
//                         problems should never be silently hidden.
//  log_summary         — always shown regardless of verbosity. Used for
//                         the short, human-readable one-line results
//                         printed in non-verbose mode (e.g. "User module
//                         completed — 55 users found").
// ─────────────────────────────────────────────
inline void log_info(const std::string& msg) {
    if (!is_verbose()) return;
    std::cout << "\033[38;5;67m"  << "  [*] " << CLR_RESET << "\033[38;5;250m" << msg << CLR_RESET << "\n";
}
inline void log_ok(const std::string& msg) {
    if (!is_verbose()) return;
    std::cout << "\033[38;5;28m"  << "  [+] " << CLR_RESET << "\033[38;5;250m" << msg << CLR_RESET << "\n";
}
inline void log_warn(const std::string& msg) {
    std::cout << "\033[38;5;214m" << "  [!] " << CLR_RESET << "\033[38;5;244m" << msg << CLR_RESET << "\n";
}
inline void log_err(const std::string& msg) {
    std::cout << "\033[38;5;160m" << "  [-] " << CLR_RESET << "\033[38;5;250m" << msg << CLR_RESET << "\n";
}
inline void log_summary(const std::string& msg) {
    std::cout << "\033[38;5;28m"  << "  [+] " << CLR_RESET << "\033[38;5;250m" << msg << CLR_RESET << "\n";
}

// ─────────────────────────────────────────────
//  Output Mode  (shared by all modules)
// ─────────────────────────────────────────────
enum class OutputMode {
    TERMINAL,
    JSON,
    CSV
};

// ─────────────────────────────────────────────
//  LDAP Connection Config
// ─────────────────────────────────────────────
struct LDAPConfig {
    std::string host;
    int         port     = 389;
    bool        use_tls  = false;
    std::string bind_dn;
    std::string password;
    std::string base_dn;
    int         timeout  = 10;
};

// ─────────────────────────────────────────────
//  UAC Flag Masks  (complete set for all modules)
// ─────────────────────────────────────────────
namespace UAC {
    constexpr int ACCOUNTDISABLE           = 0x0002;
    constexpr int LOCKOUT                  = 0x0010;
    constexpr int PASSWD_NOTREQD           = 0x0020;
    constexpr int PASSWD_CANT_CHANGE       = 0x0040;
    constexpr int NORMAL_ACCOUNT           = 0x0200;
    constexpr int DONT_EXPIRE_PASSWORD     = 0x10000;
    constexpr int SMARTCARD_REQUIRED       = 0x40000;
    constexpr int TRUSTED_FOR_DELEGATION   = 0x80000;
    constexpr int NOT_DELEGATED            = 0x100000;
    constexpr int USE_DES_KEY_ONLY         = 0x200000;
    constexpr int DONT_REQ_PREAUTH         = 0x400000;
    constexpr int PASSWORD_EXPIRED         = 0x800000;
    constexpr int TRUSTED_TO_AUTH_FOR_DEL  = 0x1000000;
    constexpr int NO_AUTH_DATA_REQUIRED    = 0x2000000;
}

// =============================================================
//  AD OBJECT STRUCTS  (one per module)
// =============================================================
// NOTE: ADUser is fully defined in modules/user/user_enum.h

// ── GROUP ────────────────────────────────────
struct ADGroup {
    std::string sam_account_name;
    std::string display_name;
    std::string description;
    std::string distinguished_name;
    std::string object_sid;
    std::string group_type;       // Security / Distribution
    std::string group_scope;      // Global / DomainLocal / Universal
    std::vector<std::string> members;       // member DNs
    std::vector<std::string> member_of;     // nested groups
};

// ── COMPUTER ─────────────────────────────────
struct ADComputer {
    std::string sam_account_name;   // ends with $
    std::string dns_hostname;
    std::string operating_system;
    std::string os_version;
    std::string description;
    std::string distinguished_name;
    std::string object_sid;
    std::string last_logon;
    std::string pwd_last_set;
    std::vector<std::string> spns;  // servicePrincipalName list
    bool        is_enabled         = true;
    bool        trusted_delegation = false;
    int         uac_flags          = 0;
};

// ── OU (Organizational Unit) ─────────────────
struct ADOU {
    std::string name;
    std::string distinguished_name;
    std::string description;
    std::string gpo_link;           // gPLink raw value
    std::vector<std::string> linked_gpos;
};

// ── GPO (Group Policy Object) ────────────────
struct ADGPO {
    std::string name;               // displayName
    std::string gpo_id;             // cn = {GUID}
    std::string distinguished_name;
    std::string file_sys_path;      // gPCFileSysPath -> SYSVOL path
    std::string created;
    std::string modified;
    int         flags = 0;          // flags: 0=enabled, 1=user disabled, 2=comp disabled, 3=all disabled
    std::vector<std::string> linked_to_ous;  // populated by cross-ref with OUs
};

// ── CERTIFICATE (AD CS) ──────────────────────
struct ADCertTemplate {
    std::string name;               // cn
    std::string display_name;       // displayName
    std::string distinguished_name;
    std::string oid;                // msPKI-Cert-Template-OID
    std::string validity_period;    // pKIExpirationPeriod
    std::vector<std::string> enroll_flags;    // msPKI-Enrollment-Flag decoded
    std::vector<std::string> extended_key_usage;
    std::vector<std::string> enroll_acl;      // who can enroll
    bool        requires_manager_approval = false;
    bool        san_in_request            = false;  // ESC1 flag
    bool        enrollee_supplies_subject = false;  // ESC1 flag
};

// ── ACE (Access Control Entry) ───────────────
struct ADACE {
    std::string object_dn;          // object this ACE is on
    std::string trustee_sid;        // who has the right
    std::string trustee_name;       // resolved name if possible
    std::string right_type;         // GenericAll, WriteDACL, etc.
    std::string ace_type;           // Allow / Deny
    bool        is_inherited = false;
    // Raw nTSecurityDescriptor is binary; parser fills above fields
};