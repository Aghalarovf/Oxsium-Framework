#include "computer_collector.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <cstring>

// ─────────────────────────────────────────────────────────────────────────────
//  userAccountControl bit masks  (computer-relevant subset)
// ─────────────────────────────────────────────────────────────────────────────
static constexpr unsigned int UAC_ACCOUNTDISABLE               = 0x00000002;
static constexpr unsigned int UAC_WORKSTATION_TRUST_ACCOUNT    = 0x00001000;
static constexpr unsigned int UAC_SERVER_TRUST_ACCOUNT         = 0x00002000;
static constexpr unsigned int UAC_TRUSTED_FOR_DELEGATION       = 0x00080000;
static constexpr unsigned int UAC_NOT_DELEGATED                = 0x00100000;
static constexpr unsigned int UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000;

// ─────────────────────────────────────────────────────────────────────────────
//  Privileged primary group RIDs  (mirrors computers.py)
// ─────────────────────────────────────────────────────────────────────────────
static const int POTENTIAL_PRIVILEGED_RIDS[] = {
    548, 549, 551, 520, 550, 569, 578, 582, 526, 527, 553, 557, 0 /*sentinel*/
};

// ─────────────────────────────────────────────────────────────────────────────
//  LAPS attribute names  (mirrors computers.py)
// ─────────────────────────────────────────────────────────────────────────────
static const char* LAPS_ATTRS[] = {
    "ms-Mcs-AdmPwd",
    "msLAPS-Password",
    "msLAPS-PasswordHistory",
    "msLAPS-EncryptedPassword",
    "msLAPS-EncryptedPasswordHistory",
    "msLAPS-EncryptedDSRoot",
    nullptr
};
static const char* LAPS_EXPIRY_ATTRS[] = {
    "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-PasswordExpirationTime",
    nullptr
};

// ─────────────────────────────────────────────────────────────────────────────
//  ComputerCollector — constructor
// ─────────────────────────────────────────────────────────────────────────────
ComputerCollector::ComputerCollector(LDAPEngine& engine) : engine_(engine) {}

// ─────────────────────────────────────────────────────────────────────────────
//  required_attrs
//  Single query — all attributes fetched in one LDAP round trip.
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> ComputerCollector::required_attrs() const {
    return {
        // Identity
        "sAMAccountName",
        "distinguishedName",
        "displayName",
        "objectSid",
        "dnsHostName",
        "description",
        // UAC + delegation
        "userAccountControl",
        "servicePrincipalName",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",   // RBCD
        // OS
        "operatingSystem",
        "operatingSystemVersion",
        "operatingSystemServicePack",
        // Timestamps
        "pwdLastSet",
        "whenCreated",
        "whenChanged",
        "lastLogonTimestamp",
        // Misc
        "primaryGroupID",
        "location",
        // ACL / SID history
        "nTSecurityDescriptor",   // isaclprotected
        "sIDHistory",
        // LAPS
        "ms-Mcs-AdmPwd",
        "msLAPS-Password",
        "msLAPS-PasswordHistory",
        "msLAPS-EncryptedPassword",
        "msLAPS-EncryptedPasswordHistory",
        "msLAPS-EncryptedDSRoot",
        "ms-Mcs-AdmPwdExpirationTime",
        "msLAPS-PasswordExpirationTime",
    };
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect
// ─────────────────────────────────────────────────────────────────────────────
int ComputerCollector::collect(const ComputerCollectorOptions& opts) {
    fs::create_directories(opts.output_dir);
    output_path_ = fs::path(opts.output_dir) / "raw_computers.ndjson";

    std::ofstream f(output_path_, std::ios::binary);
    if (!f) {
        log_err("[ComputerCollector] Failed to open output file: "
                + output_path_.string());
        return -1;
    }

    log_info("[ComputerCollector] LDAP query starting — collecting all computers...");

    const std::string generated_at = now_iso8601();
    // Fetch every computer object — no server-side attribute filter needed
    // because we request only what we need via required_attrs().
    const std::string filter = "(&(objectClass=computer))";

    int count = 0;
    bool ok = engine_.search(filter, required_attrs(),
        [&](const LDAPEngine::AttrMap& entry) {
            if (opts.max_results > 0 && count >= opts.max_results) return;
            f << computer_to_ndjson(entry, generated_at, opts.stale_days) << "\n";
            ++count;
        });

    if (!ok) {
        log_err("[ComputerCollector] LDAP query failed.");
        return -1;
    }

    f.flush();
    f.close();

    log_ok("[ComputerCollector] " + std::to_string(count)
           + " computers -> " + output_path_.string());
    return count;
}

// ─────────────────────────────────────────────────────────────────────────────
//  computer_to_ndjson
// ─────────────────────────────────────────────────────────────────────────────
std::string ComputerCollector::computer_to_ndjson(
    const LDAPEngine::AttrMap& entry,
    const std::string& generated_at,
    int stale_days) const
{
    // ── Attribute accessors ──────────────────────────────────────────────────
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

    // ── UAC ──────────────────────────────────────────────────────────────────
    unsigned int uac = 0;
    try { uac = static_cast<unsigned int>(std::stoul(get("userAccountControl"))); }
    catch (...) {}

    bool disabled              = uac_flag(uac, UAC_ACCOUNTDISABLE);
    bool trusted_for_deleg     = uac_flag(uac, UAC_TRUSTED_FOR_DELEGATION);
    bool trusted_to_auth       = uac_flag(uac, UAC_TRUSTED_TO_AUTH_FOR_DELEGATION);
    bool is_workstation        = uac_flag(uac, UAC_WORKSTATION_TRUST_ACCOUNT);
    bool is_server             = uac_flag(uac, UAC_SERVER_TRUST_ACCOUNT);

    // ── SPN + delegation ─────────────────────────────────────────────────────
    auto spn_list              = get_all("servicePrincipalName");
    bool has_spn               = !spn_list.empty();
    auto allowed_to_delegate   = get_all("msDS-AllowedToDelegateTo");
    bool constrained_delegation= !allowed_to_delegate.empty();
    // Unconstrained = TrustedForDelegation AND no constrained list
    bool unconstrained_delegation = trusted_for_deleg && !constrained_delegation;

    // ── RBCD ─────────────────────────────────────────────────────────────────
    std::string rbcd_raw       = get("msDS-AllowedToActOnBehalfOfOtherIdentity");
    bool rbcd_enabled          = !rbcd_raw.empty();
    std::vector<std::string> rbcd_principals;
    std::string rbcd_sddl;
    if (rbcd_enabled) {
        rbcd_principals        = decode_rbcd_sids(rbcd_raw);
        rbcd_sddl              = build_rbcd_sddl(rbcd_principals);
    }

    // ── SID + domain SID ─────────────────────────────────────────────────────
    std::string sid;
    {
        auto it = entry.find("objectSid");
        if (it != entry.end() && !it->second.empty())
            sid = decode_sid(it->second[0]);
    }
    std::string domainsid = domain_sid_from_sid(sid);

    // ── Primary group ────────────────────────────────────────────────────────
    int primary_group_id = 0;
    try { primary_group_id = std::stoi(get("primaryGroupID")); } catch (...) {}

    bool potential_privileged  = is_potential_privileged_by_rid(primary_group_id);

    // ── DC detection (mirrors computers.py logic) ────────────────────────────
    const std::string dn_value = get("distinguishedName");
    bool is_domain_controller  =
        (dn_value.find("OU=Domain Controllers") != std::string::npos)
        || (primary_group_id == 516)
        || is_server;

    // ── OS ───────────────────────────────────────────────────────────────────
    std::string os_name        = get("operatingSystem");
    std::string os_bucket_val  = os_bucket(os_name);

    // ── Stale detection ──────────────────────────────────────────────────────
    bool stale_by_pwd          = is_stale_filetime(get("pwdLastSet"),          stale_days);
    bool stale_by_logon        = is_stale_filetime(get("lastLogonTimestamp"),  stale_days);
    bool is_stale              = stale_by_pwd && stale_by_logon;

    // ── ACL protection ───────────────────────────────────────────────────────
    bool isaclprotected        = parse_isaclprotected(get("nTSecurityDescriptor"));

    // ── SID history ──────────────────────────────────────────────────────────
    std::vector<std::string> sid_history = decode_sid_history(get_all("sIDHistory"));

    // ── LAPS ─────────────────────────────────────────────────────────────────
    bool has_laps              = detect_laps(entry, {});
    std::string laps_exp       = laps_expiration(entry);

    // ── Timestamps ───────────────────────────────────────────────────────────
    std::string last_logon     = filetime_to_iso(get("lastLogonTimestamp"));
    std::string pwd_last_set   = filetime_to_iso(get("pwdLastSet"));

    // ── Risk controls (mirrors computers.py) ─────────────────────────────────
    std::vector<std::string> risk_controls;
    if (trusted_for_deleg)       risk_controls.push_back("Unconstrained Delegation");
    if (constrained_delegation)  risk_controls.push_back("Constrained Delegation");
    if (rbcd_enabled)            risk_controls.push_back("RBCD Enabled");
    if (has_laps)                risk_controls.push_back("LAPS Enabled");
    if (is_domain_controller)    risk_controls.push_back("Domain Controller");
    if (is_stale)                risk_controls.push_back("Stale Account");
    if (!sid_history.empty())    risk_controls.push_back("SID History Present");
    if (isaclprotected)          risk_controls.push_back("ACL Protected");

    // ─────────────────────────────────────────────────────────────────────────
    //  Build NDJSON line
    // ─────────────────────────────────────────────────────────────────────────
    std::ostringstream o;
    o << "{"
      // Identity
      << "\"computer_name\":"              << je(get("sAMAccountName"))              << ","
      << "\"dns_name\":"                   << je(get("dnsHostName"))                 << ","
      << "\"dn\":"                         << je(dn_value)                           << ","
      << "\"display_name\":"               << je(get("displayName"))                 << ","
      << "\"sid\":"                        << je(sid)                                << ","
      << "\"description\":"               << je(get("description"))                 << ","
      // State
      << "\"disabled\":"                   << jb(disabled)                           << ","
      // OS
      << "\"os\":"                         << je(os_name)                            << ","
      << "\"os_version\":"                 << je(get("operatingSystemVersion"))      << ","
      << "\"os_service_pack\":"            << je(get("operatingSystemServicePack"))  << ","
      << "\"os_bucket\":"                  << je(os_bucket_val)                      << ","
      // SPN / delegation
      << "\"spn\":"                        << ja(spn_list)                           << ","
      << "\"has_spn\":"                    << jb(has_spn)                            << ","
      << "\"trusted_for_delegation\":"     << jb(trusted_for_deleg)                 << ","
      << "\"trusted_to_auth_for_delegation\":" << jb(trusted_to_auth)               << ","
      << "\"unconstrained_delegation\":"   << jb(unconstrained_delegation)           << ","
      << "\"constrained_delegation\":"     << jb(constrained_delegation)             << ","
      << "\"allowed_to_delegate_to\":"     << ja(allowed_to_delegate)               << ","
      // RBCD
      << "\"rbcd_enabled\":"               << jb(rbcd_enabled)                       << ","
      << "\"rbcd_sddl\":"                  << je(rbcd_sddl)                          << ","
      << "\"rbcd_principals\":"            << ja(rbcd_principals)                    << ","
      // LAPS
      << "\"has_laps\":"                   << jb(has_laps)                           << ","
      << "\"haslaps\":"                    << jb(has_laps)                           << ","
      << "\"laps_expiration\":"            << je(laps_exp)                           << ","
      << "\"laps_attributes\":"            << build_laps_attributes_json(entry)      << ","
      // Role
      << "\"is_workstation\":"             << jb(is_workstation)                     << ","
      << "\"is_server\":"                  << jb(is_server)                          << ","
      << "\"is_domain_controller\":"       << jb(is_domain_controller)               << ","
      << "\"potential_privileged\":"       << jb(potential_privileged)               << ","
      // Stale
      << "\"is_stale\":"                   << jb(is_stale)                           << ","
      << "\"stale_by_pwd\":"               << jb(stale_by_pwd)                       << ","
      << "\"stale_by_logon\":"             << jb(stale_by_logon)                     << ","
      // ACL / SID history
      << "\"isaclprotected\":"             << jb(isaclprotected)                     << ","
      << "\"sid_history\":"               << ja(sid_history)                        << ","
      << "\"domainsid\":"                  << je(domainsid)                          << ","
      << "\"primary_group_id\":"           << ji(primary_group_id)                   << ","
      // Location
      << "\"location\":"                   << je(get("location"))                    << ","
      // Timestamps — whenCreated/whenChanged are LDAP Generalized Time
      // (e.g. "20260426104633.0Z"); convert to ISO-8601 here so
      // OfflineProcessor receives a consistent format.
      << "\"when_created\":"               << je(generalized_time_to_iso(get("whenCreated")))  << ","
      << "\"when_changed\":"               << je(generalized_time_to_iso(get("whenChanged")))  << ","
      << "\"last_logon\":"                 << je(last_logon)                         << ","
      << "\"pwd_last_set\":"               << je(pwd_last_set)                       << ","
      // Risk summary
      << "\"risk_controls\":"              << ja(risk_controls)                      << ","
      // ── Network stubs (populated by future network probe stage) ────────────
      << "\"is_ip_only\":"                 << jnull()                                << ","
      << "\"ipv4_addresses\":"             << "[]"                                   << ","
      << "\"ipv6_addresses\":"             << "[]"                                   << ","
      << "\"smb_port_open\":"              << jnull()                                << ","
      << "\"smb_signing_required\":"       << jnull()                                << ","
      << "\"smb_version\":"               << jnull()                                << ","
      // ── Metadata ──────────────────────────────────────────────────────────
      << "\"generated_at\":"               << je(generated_at)
      << "}";
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  uac_flag
// ─────────────────────────────────────────────────────────────────────────────
bool ComputerCollector::uac_flag(unsigned int uac, unsigned int bit) {
    return (uac & bit) != 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  filetime_to_unix
// ─────────────────────────────────────────────────────────────────────────────
long long ComputerCollector::filetime_to_unix(const std::string& ft_str) {
    if (ft_str.empty() || ft_str == "0" || ft_str == "9223372036854775807")
        return 0;
    long long ft = 0;
    try { ft = std::stoll(ft_str); } catch (...) { return 0; }
    if (ft <= 0) return 0;
    long long unix_sec = (ft / 10000000LL) - 11644473600LL;
    return (unix_sec > 0) ? unix_sec : 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  filetime_to_iso
// ─────────────────────────────────────────────────────────────────────────────
std::string ComputerCollector::filetime_to_iso(const std::string& ft_str) {
    long long unix_sec = filetime_to_unix(ft_str);
    if (unix_sec == 0) return "";
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
//  is_stale_filetime
//  Returns true when the FILETIME is missing, zero, or older than stale_days.
// ─────────────────────────────────────────────────────────────────────────────
bool ComputerCollector::is_stale_filetime(const std::string& ft_str, int stale_days) {
    long long unix_sec = filetime_to_unix(ft_str);
    if (unix_sec == 0) return true;   // missing → treat as stale (mirrors Python)
    long long now_sec = static_cast<long long>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    long long threshold = static_cast<long long>(stale_days) * 86400LL;
    return (now_sec - unix_sec) > threshold;
}

// ─────────────────────────────────────────────────────────────────────────────
//  decode_sid  — binary objectSid → "S-1-5-21-..."
// ─────────────────────────────────────────────────────────────────────────────
std::string ComputerCollector::decode_sid(const std::string& raw) {
    return decode_sid_from_buf(
        reinterpret_cast<const unsigned char*>(raw.data()), raw.size(), 0);
}

std::string ComputerCollector::decode_sid_from_buf(
    const unsigned char* buf, size_t buf_len, size_t offset)
{
    if (buf_len < offset + 8) return "";
    const unsigned char* b = buf + offset;
    int rev       = b[0];
    int sub_count = b[1];
    long long auth = 0;
    for (int i = 2; i < 8; ++i) auth = (auth << 8) | b[i];
    std::ostringstream o;
    o << "S-" << rev << "-" << auth;
    for (int i = 0; i < sub_count; ++i) {
        size_t off = 8 + static_cast<size_t>(i) * 4;
        if (offset + off + 4 > buf_len) break;
        unsigned long sub =
              static_cast<unsigned long>(b[off])
            | (static_cast<unsigned long>(b[off + 1]) << 8)
            | (static_cast<unsigned long>(b[off + 2]) << 16)
            | (static_cast<unsigned long>(b[off + 3]) << 24);
        o << "-" << sub;
    }
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  domain_sid_from_sid  — "S-1-5-21-x-y-z-RID" → "S-1-5-21-x-y-z"
// ─────────────────────────────────────────────────────────────────────────────
std::string ComputerCollector::domain_sid_from_sid(const std::string& sid) {
    auto pos = sid.rfind('-');
    if (pos == std::string::npos || pos < 2) return "";
    return sid.substr(0, pos);
}

// ─────────────────────────────────────────────────────────────────────────────
//  parse_isaclprotected
//  Reads SE_DACL_PROTECTED (0x1000) from Security Descriptor Control word.
//  Layout: Revision(1) + Sbz1(1) + Control(2) + ...
// ─────────────────────────────────────────────────────────────────────────────
bool ComputerCollector::parse_isaclprotected(const std::string& raw_sd) {
    if (raw_sd.size() < 4) return false;
    const auto* b = reinterpret_cast<const unsigned char*>(raw_sd.data());
    unsigned int control = static_cast<unsigned int>(b[2])
                         | (static_cast<unsigned int>(b[3]) << 8);
    return (control & 0x1000u) != 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  decode_rbcd_sids
//  Minimal portable SECURITY_DESCRIPTOR DACL parser — no external dependencies.
//
//  Security Descriptor layout (self-relative):
//    Revision  (1B) | Sbz1  (1B) | Control (2B)
//    OffsetOwner(4B) | OffsetGroup(4B) | OffsetSacl(4B) | OffsetDacl(4B)
//
//  ACL header: AclRevision(1) | Sbz1(1) | AclSize(2) | AceCount(2) | Sbz2(2)
//  ACE header:  AceType(1) | AceFlags(1) | AceSize(2)
//  ACCESS_ALLOWED_ACE: header(4) + Mask(4) + SID(variable)
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> ComputerCollector::decode_rbcd_sids(const std::string& raw_sd) {
    std::vector<std::string> sids;
    const size_t len = raw_sd.size();
    if (len < 20) return sids;

    const auto* b = reinterpret_cast<const unsigned char*>(raw_sd.data());

    // OffsetDacl is at bytes 16-19 (little-endian)
    size_t dacl_offset =
          static_cast<size_t>(b[16])
        | (static_cast<size_t>(b[17]) << 8)
        | (static_cast<size_t>(b[18]) << 16)
        | (static_cast<size_t>(b[19]) << 24);

    if (dacl_offset == 0 || dacl_offset + 8 > len) return sids;

    const unsigned char* acl = b + dacl_offset;
    size_t acl_size  =
          static_cast<size_t>(acl[2]) | (static_cast<size_t>(acl[3]) << 8);
    size_t ace_count =
          static_cast<size_t>(acl[4]) | (static_cast<size_t>(acl[5]) << 8);

    size_t pos = dacl_offset + 8;   // skip ACL header

    for (size_t i = 0; i < ace_count; ++i) {
        if (pos + 4 > dacl_offset + acl_size) break;
        if (pos + 4 > len) break;

        // uint8_t ace_type  = b[pos];
        // uint8_t ace_flags = b[pos + 1];
        size_t ace_size =
              static_cast<size_t>(b[pos + 2])
            | (static_cast<size_t>(b[pos + 3]) << 8);

        if (ace_size < 8 || pos + ace_size > len) break;

        // ACCESS_ALLOWED_ACE (type 0) and ACCESS_ALLOWED_OBJECT_ACE (type 5)
        // — SID starts at offset 8 from ACE start for type 0.
        // For type 5 the layout is more complex; read only type 0 for RBCD.
        if (b[pos] == 0x00) {
            // Mask(4) + SID at pos+8
            if (ace_size >= 12) {
                std::string sid = decode_sid_from_buf(b, len, pos + 8);
                if (!sid.empty()) sids.push_back(std::move(sid));
            }
        }
        pos += ace_size;
    }
    return sids;
}

// ─────────────────────────────────────────────────────────────────────────────
//  decode_sid_history
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> ComputerCollector::decode_sid_history(
    const std::vector<std::string>& raw_values)
{
    std::vector<std::string> result;
    for (const auto& raw : raw_values) {
        std::string s = decode_sid(raw);
        if (!s.empty()) result.push_back(std::move(s));
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  is_potential_privileged_by_rid
// ─────────────────────────────────────────────────────────────────────────────
bool ComputerCollector::is_potential_privileged_by_rid(int rid) {
    for (int i = 0; POTENTIAL_PRIVILEGED_RIDS[i] != 0; ++i)
        if (POTENTIAL_PRIVILEGED_RIDS[i] == rid) return true;
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  detect_laps
//  Returns true if any LAPS password attribute is non-empty.
// ─────────────────────────────────────────────────────────────────────────────
bool ComputerCollector::detect_laps(const LDAPEngine::AttrMap& entry,
                                    const std::vector<std::string>& /*unused*/)
{
    for (int i = 0; LAPS_ATTRS[i] != nullptr; ++i) {
        auto it = entry.find(LAPS_ATTRS[i]);
        if (it != entry.end() && !it->second.empty()
                && !it->second[0].empty())
            return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  laps_expiration
//  Returns the FILETIME-converted expiration string, preferring
//  msLAPS-PasswordExpirationTime over ms-Mcs-AdmPwdExpirationTime.
// ─────────────────────────────────────────────────────────────────────────────
std::string ComputerCollector::laps_expiration(const LDAPEngine::AttrMap& entry) {
    for (int i = 0; LAPS_EXPIRY_ATTRS[i] != nullptr; ++i) {
        auto it = entry.find(LAPS_EXPIRY_ATTRS[i]);
        if (it != entry.end() && !it->second.empty()) {
            std::string iso = filetime_to_iso(it->second[0]);
            if (!iso.empty()) return iso;
        }
    }
    return "";
}

// ─────────────────────────────────────────────────────────────────────────────
//  generalized_time_to_iso
//  Converts LDAP Generalized Time "YYYYMMDDHHmmss.0Z" → "YYYY-MM-DDTHH:MM:SSZ"
//  Returns the original string unchanged if it is not in this format.
// ─────────────────────────────────────────────────────────────────────────────
std::string ComputerCollector::generalized_time_to_iso(const std::string& gt) {
    if (gt.size() < 14) return gt;
    for (int i = 0; i < 14; ++i)
        if (!std::isdigit(static_cast<unsigned char>(gt[i]))) return gt;
    // "YYYYMMDDHHmmss"
    return gt.substr(0,4) + "-" + gt.substr(4,2) + "-" + gt.substr(6,2)
         + "T" + gt.substr(8,2) + ":" + gt.substr(10,2) + ":" + gt.substr(12,2) + "Z";
}

// ─────────────────────────────────────────────────────────────────────────────
//  build_rbcd_sddl
//  Reconstructs a minimal SDDL string from decoded RBCD ACE SIDs.
//  Format mirrors what Windows ConvertSecurityDescriptorToStringSecurityDescriptor
//  produces for a typical RBCD descriptor:
//    O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SID)...
// ─────────────────────────────────────────────────────────────────────────────
std::string ComputerCollector::build_rbcd_sddl(const std::vector<std::string>& sids) {
    if (sids.empty()) return "";
    std::ostringstream o;
    o << "O:BAD:";
    for (const auto& sid : sids)
        o << "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" << sid << ")";
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  build_laps_attributes_json
//  Serializes all LAPS-related attributes (password + expiry) as a JSON object.
//  Each key maps to an array of its raw string values (empty array if absent).
// ─────────────────────────────────────────────────────────────────────────────
std::string ComputerCollector::build_laps_attributes_json(const LDAPEngine::AttrMap& entry) {
    // Full list: password attrs first, then expiry attrs
    static const char* ALL_LAPS[] = {
        "ms-Mcs-AdmPwd",
        "msLAPS-Password",
        "msLAPS-PasswordHistory",
        "msLAPS-EncryptedPassword",
        "msLAPS-EncryptedPasswordHistory",
        "msLAPS-EncryptedDSRoot",
        "ms-Mcs-AdmPwdExpirationTime",
        "msLAPS-PasswordExpirationTime",
        nullptr
    };
    std::ostringstream o;
    o << "{";
    bool first = true;
    for (int i = 0; ALL_LAPS[i] != nullptr; ++i) {
        if (!first) o << ",";
        first = false;
        o << je(ALL_LAPS[i]) << ":";
        auto it = entry.find(ALL_LAPS[i]);
        if (it == entry.end() || it->second.empty()) {
            o << "[]";
        } else {
            o << "[";
            for (size_t j = 0; j < it->second.size(); ++j) {
                if (j) o << ",";
                o << je(it->second[j]);
            }
            o << "]";
        }
    }
    o << "}";
    return o.str();
}
// ─────────────────────────────────────────────────────────────────────────────
std::string ComputerCollector::os_bucket(const std::string& os_name) {
    if (os_name.empty()) return "unknown";
    std::string lower = os_name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower.find("server") != std::string::npos) return "server";
    return "workstation";
}

// ─────────────────────────────────────────────────────────────────────────────
//  JSON helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string ComputerCollector::je(const std::string& s) {
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
                      << std::setfill('0') << static_cast<int>(ch) << std::dec;
                else
                    o << static_cast<char>(ch);
        }
    }
    o << '"';
    return o.str();
}

std::string ComputerCollector::jb(bool v)  { return v ? "true" : "false"; }
std::string ComputerCollector::ji(int v)   { return std::to_string(v); }
std::string ComputerCollector::jnull()     { return "null"; }

std::string ComputerCollector::ja(const std::vector<std::string>& v) {
    std::ostringstream o;
    o << '[';
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) o << ',';
        o << je(v[i]);
    }
    o << ']';
    return o.str();
}

std::string ComputerCollector::now_iso8601() {
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