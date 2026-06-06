#include "user_collector.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>

// ── userAccountControl bit maskları ──────────────────────────────────────────
static constexpr unsigned int UAC_ACCOUNTDISABLE          = 0x00000002;
static constexpr unsigned int UAC_LOCKOUT                 = 0x00000010;
static constexpr unsigned int UAC_PASSWD_NOTREQD          = 0x00000020;
static constexpr unsigned int UAC_PASSWD_CANT_CHANGE      = 0x00000040;
static constexpr unsigned int UAC_NORMAL_ACCOUNT          = 0x00000200;
static constexpr unsigned int UAC_DONT_EXPIRE_PASSWD      = 0x00010000;
static constexpr unsigned int UAC_SMARTCARD_REQUIRED      = 0x00040000;
static constexpr unsigned int UAC_TRUSTED_FOR_DELEGATION  = 0x00080000;
static constexpr unsigned int UAC_NOT_DELEGATED           = 0x00100000;
static constexpr unsigned int UAC_USE_DES_KEY_ONLY        = 0x00200000;
static constexpr unsigned int UAC_DONT_REQ_PREAUTH        = 0x00400000;
static constexpr unsigned int UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000;

UserCollector::UserCollector(LDAPEngine& engine) : engine_(engine) {}

// ─────────────────────────────────────────────────────────────────────────────
//  required_attrs
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> UserCollector::required_attrs() const {
    return {
        "sAMAccountName",        "distinguishedName",
        "displayName",           "objectSid",
        "userPrincipalName",     "description",
        "mail",                  "telephoneNumber",
        "department",            "title",
        "userAccountControl",
        "servicePrincipalName",
        "msDS-AllowedToDelegateTo",
        "msDS-SupportedEncryptionTypes",
        "msDS-ResultantPSO",
        "memberOf",
        "primaryGroupID",
        "whenCreated",           "whenChanged",
        "lastLogon",             "pwdLastSet",
        "logonCount",            "badPwdCount",
        "badPasswordTime",       "accountExpires",
        "scriptPath",            "homeDirectory",
        "homeDrive",
        "msDS-KeyCredentialLink",
    };
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect
// ─────────────────────────────────────────────────────────────────────────────
int UserCollector::collect(const UserCollectorOptions& opts) {
    fs::create_directories(opts.output_dir);
    output_path_ = fs::path(opts.output_dir) / "raw_users.ndjson";

    std::ofstream f(output_path_, std::ios::binary);
    if (!f) {
        log_err("[UserCollector] Fayl açıla bilmədi: " + output_path_.string());
        return -1;
    }

    log_info("[UserCollector] LDAP query starting — collecting all users...");

    const std::string generated_at = now_iso8601();
    // Computer account-ları xaric etmək üçün: sAMAccountType=805306368
    const std::string filter =
        "(&(objectCategory=person)(objectClass=user)"
        "(!(objectClass=computer)))";

    int count = 0;
    bool ok = engine_.search(filter, required_attrs(),
        [&](const LDAPEngine::AttrMap& entry) {
            if (opts.max_results > 0 && count >= opts.max_results) return;
            f << user_to_ndjson(entry, generated_at) << "\n";
            ++count;
        });

    if (!ok) {
        log_err("[UserCollector] LDAP query failed.");
        return -1;
    }

    f.flush();
    f.close();

        log_ok("[UserCollector] " + std::to_string(count) +
            " users -> " + output_path_.string());
    return count;
}

// ─────────────────────────────────────────────────────────────────────────────
//  user_to_ndjson  — schema domain_users.ndjson ilə uyğun
// ─────────────────────────────────────────────────────────────────────────────
std::string UserCollector::user_to_ndjson(const LDAPEngine::AttrMap& entry,
                                          const std::string& generated_at) const
{
    auto get = [&](const std::string& k) -> std::string {
        auto it = entry.find(k);
        if (it != entry.end() && !it->second.empty()) return it->second[0];
        return "";
    };
    auto get_all = [&](const std::string& k) -> std::vector<std::string> {
        auto it = entry.find(k);
        if (it != entry.end()) return it->second;
        return {};
    };

    // UAC
    unsigned int uac = 0;
    try { uac = static_cast<unsigned int>(std::stoul(get("userAccountControl"))); }
    catch (...) {}

    bool disabled           = uac_flag(uac, UAC_ACCOUNTDISABLE);
    bool locked_out         = uac_flag(uac, UAC_LOCKOUT);
    bool pwd_not_required   = uac_flag(uac, UAC_PASSWD_NOTREQD);
    bool pwd_cant_change    = uac_flag(uac, UAC_PASSWD_CANT_CHANGE);
    bool normal_account     = uac_flag(uac, UAC_NORMAL_ACCOUNT);
    bool pwd_never_expires  = uac_flag(uac, UAC_DONT_EXPIRE_PASSWD);
    bool smartcard_required = uac_flag(uac, UAC_SMARTCARD_REQUIRED);
    bool trusted_for_deleg  = uac_flag(uac, UAC_TRUSTED_FOR_DELEGATION);
    bool not_delegated      = uac_flag(uac, UAC_NOT_DELEGATED);
    bool dont_req_preauth   = uac_flag(uac, UAC_DONT_REQ_PREAUTH);
    bool trusted_to_auth    = uac_flag(uac, UAC_TRUSTED_TO_AUTH_FOR_DELEGATION);
    bool preauth_required   = !dont_req_preauth;  // asreproasting
    bool asrep              = dont_req_preauth;

    // SPN → kerberoastable
    auto spn_list = get_all("servicePrincipalName");
    bool kerberoastable = !spn_list.empty() && !disabled;

    // Delegation
    auto delegate_to = get_all("msDS-AllowedToDelegateTo");
    bool constrained_delegation = !delegate_to.empty();
    bool unconstrained_delegation = trusted_for_deleg && !constrained_delegation;

    // Encryption types
    unsigned int enc_types = 0;
    try { enc_types = static_cast<unsigned int>(std::stoul(
              get("msDS-SupportedEncryptionTypes"))); }
    catch (...) {}
    bool enc_implicit_rc4 = is_rc4_implicit(enc_types);

    // SID
    std::string sid;
    auto sid_it = entry.find("objectSid");
    if (sid_it != entry.end() && !sid_it->second.empty())
        sid = decode_sid(sid_it->second[0]);
    std::string domain_sid = domain_sid_from_user_sid(sid);

    // Primary group SID
    int pgid = 0;
    try { pgid = std::stoi(get("primaryGroupID")); } catch (...) {}
    std::string primary_group_sid;
    if (!domain_sid.empty() && pgid > 0)
        primary_group_sid = domain_sid + "-" + std::to_string(pgid);

    // Timestamps (Windows FILETIME → ISO)
    std::string last_logon    = filetime_to_iso(get("lastLogon"));
    std::string pwd_last_set  = filetime_to_iso(get("pwdLastSet"));
    std::string bad_pwd_time  = filetime_to_iso(get("badPasswordTime"));
    std::string acct_expires  = filetime_to_iso(get("accountExpires"));
    bool acct_never_expires   = (get("accountExpires") == "0" ||
                                 get("accountExpires") == "9223372036854775807");

    int logon_count   = 0;
    int bad_pwd_count = 0;
    try { logon_count   = std::stoi(get("logonCount"));   } catch (...) {}
    try { bad_pwd_count = std::stoi(get("badPwdCount"));  } catch (...) {}

    // Key credential link
    bool has_kcl = !get("msDS-KeyCredentialLink").empty();

    // member_of — DN listini group adına çevirmək OfflineProcessor işidir.
    // Burada raw DN siyahısını saxlayırıq.
    auto member_of_dns = get_all("memberOf");

    std::ostringstream o;
    o << "{"
      << "\"username\":"              << je(get("sAMAccountName"))      << ","
      << "\"dn\":"                    << je(get("distinguishedName"))    << ","
      << "\"display_name\":"          << je(get("displayName"))          << ","
      << "\"sid\":"                   << je(sid)                         << ","
      << "\"upn\":"                   << je(get("userPrincipalName"))    << ","
      << "\"description\":"           << je(get("description"))          << ","
      << "\"mail\":"                  << je(get("mail"))                 << ","
      << "\"phone\":"                 << je(get("telephoneNumber"))      << ","
      << "\"department\":"            << je(get("department"))           << ","
      << "\"title\":"                 << je(get("title"))                << ","
      << "\"disabled\":"              << jb(disabled)                    << ","
      << "\"locked_out\":"            << jb(locked_out)                  << ","
      << "\"must_change_pwd\":"       << "false"                         << ","
      << "\"smartcard_required\":"    << jb(smartcard_required)          << ","
      << "\"normal_account\":"        << jb(normal_account)              << ","
      << "\"pwd_never_expires\":"     << jb(pwd_never_expires)           << ","
      << "\"pwd_not_required\":"      << jb(pwd_not_required)            << ","
      << "\"pwd_cant_change\":"       << jb(pwd_cant_change)             << ","
      << "\"preauth_required\":"      << jb(preauth_required)            << ","
      << "\"dcsync\":"               << "false"                         << ","
      << "\"asrep\":"                << jb(asrep)                       << ","
      << "\"kerberoastable\":"        << jb(kerberoastable)              << ","
      << "\"spn\":"                   << ja(spn_list)                    << ","
      << "\"trusted_for_delegation\":" << jb(trusted_for_deleg)         << ","
      << "\"unconstrained_delegation\":" << jb(unconstrained_delegation) << ","
      << "\"constrained_delegation\":"   << jb(constrained_delegation)  << ","
      << "\"trusted_to_auth_for_delegation\":" << jb(trusted_to_auth)   << ","
      << "\"not_delegated\":"         << jb(not_delegated)              << ","
      << "\"msds_allowedtodelegateto\":" << ja(delegate_to)             << ","
      << "\"enc_implicit_rc4\":"      << jb(enc_implicit_rc4)           << ","
      << "\"member_of\":"             << ja(member_of_dns)              << ","
      << "\"primary_group_id\":"      << ji(pgid)                       << ","
      << "\"primary_group_sid\":"     << je(primary_group_sid)          << ","
      << "\"domain_sid\":"            << je(domain_sid)                 << ","
      << "\"when_created\":"          << je(get("whenCreated"))         << ","
      << "\"when_changed\":"          << je(get("whenChanged"))         << ","
      << "\"last_logon\":"            << je(last_logon)                 << ","
      << "\"pwd_last_set\":"          << je(pwd_last_set)               << ","
      << "\"logon_count\":"           << ji(logon_count)                << ","
      << "\"bad_pwd_count\":"         << ji(bad_pwd_count)              << ","
      << "\"bad_pwd_time\":"          << je(bad_pwd_time)               << ","
      << "\"account_expires\":"       << je(acct_expires)               << ","
      << "\"account_never_expires\":" << jb(acct_never_expires)         << ","
      << "\"script_path\":"           << je(get("scriptPath"))          << ","
      << "\"home_directory\":"        << je(get("homeDirectory"))        << ","
      << "\"home_drive\":"            << je(get("homeDrive"))            << ","
      << "\"has_key_credential_link\":" << jb(has_kcl)                  << ","
      << "\"msds_resultant_pso\":"    << je(get("msDS-ResultantPSO"))   << ","
      << "\"generated_at\":"          << je(generated_at)
      << "}";
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  uac_flag
// ─────────────────────────────────────────────────────────────────────────────
bool UserCollector::uac_flag(unsigned int uac, unsigned int bit) {
    return (uac & bit) != 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  filetime_to_iso  — Windows FILETIME (100ns intervals since 1601-01-01) → ISO
// ─────────────────────────────────────────────────────────────────────────────
std::string UserCollector::filetime_to_iso(const std::string& ft_str) {
    if (ft_str.empty() || ft_str == "0" || ft_str == "9223372036854775807")
        return "";
    long long ft = 0;
    try { ft = std::stoll(ft_str); } catch (...) { return ""; }
    if (ft <= 0) return "";
    // FILETIME epoch: 1601-01-01. Unix epoch: 1970-01-01.
    // Diff = 11644473600 seconds
    long long unix_sec = (ft / 10000000LL) - 11644473600LL;
    if (unix_sec < 0) return "";
    std::time_t t = static_cast<std::time_t>(unix_sec);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream o;
    o << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S+00:00");
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  decode_sid
// ─────────────────────────────────────────────────────────────────────────────
std::string UserCollector::decode_sid(const std::string& raw) {
    if (raw.size() < 8) return "";
    const auto* b = reinterpret_cast<const unsigned char*>(raw.data());
    int rev = b[0], sub_count = b[1];
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
//  domain_sid_from_user_sid  — "S-1-5-21-x-y-z-RID" → "S-1-5-21-x-y-z"
// ─────────────────────────────────────────────────────────────────────────────
std::string UserCollector::domain_sid_from_user_sid(const std::string& sid) {
    auto pos = sid.rfind('-');
    if (pos == std::string::npos || pos < 2) return "";
    return sid.substr(0, pos);
}

// ─────────────────────────────────────────────────────────────────────────────
//  is_rc4_implicit  — msDS-SupportedEncryptionTypes 0 veya yoxdur → RC4 implicit
// ─────────────────────────────────────────────────────────────────────────────
bool UserCollector::is_rc4_implicit(unsigned int enc_types) {
    // 0 = heç bir şey təyin edilməyib → domain default = RC4 aktiv
    // Bit 2 (0x4) = RC4-HMAC. Bit 4 (0x10) = AES128. Bit 8 (0x18) = AES256.
    if (enc_types == 0) return true;
    // Yalnız DES varsa — RC4 implicit var
    if ((enc_types & 0x1C) == 0) return true;  // heç bir AES/RC4 yoxdur
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  JSON helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string UserCollector::je(const std::string& s) {
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

std::string UserCollector::jb(bool v) { return v ? "true" : "false"; }
std::string UserCollector::ji(int v)  { return std::to_string(v); }

std::string UserCollector::ja(const std::vector<std::string>& v) {
    std::ostringstream o;
    o << '[';
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) o << ',';
        o << je(v[i]);
    }
    o << ']';
    return o.str();
}

std::string UserCollector::now_iso8601() {
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