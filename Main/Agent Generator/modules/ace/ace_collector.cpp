#include "ace_collector.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>

// ═════════════════════════════════════════════════════════════════════════════
//  Sabitlər — Python constants.py ilə tam uyğun
// ═════════════════════════════════════════════════════════════════════════════

const std::map<std::string, uint32_t> AceCollector::INDIVIDUAL_RIGHTS = {
    {"WriteDACL",        0x00040000u},
    {"WriteOwner",       0x00080000u},
    {"WriteProperty",    0x00000020u},
    {"ReadProperty",     0x00000010u},
    {"Self",             0x00000008u},
    {"ListChildObjects", 0x00000004u},
    {"DeleteChild",      0x00000002u},
    {"CreateChild",      0x00000001u},
    {"Delete",           0x00010000u},
    {"DeleteTree",       0x00000040u},
    {"ListObject",       0x00000080u},
};

const std::map<std::string, std::string> AceCollector::OBJECT_TYPE_RIGHTS = {
    {"bf9679c0-0de6-11d0-a285-00aa003049e2", "AddMember"},
    {"00299570-246d-11d0-a768-00aa006e0529", "ForceChangePassword"},
    {"ab721a53-1e2f-11d0-9819-00aa0040529b", "ChangePassword"},
    {"00299572-246d-11d0-a768-00aa006e0529", "Reanimate-Tombstone"},
    {"5f202010-79a5-11d0-9020-00c04fc2d4cf", "Email-Information"},
    {"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes-All"},
    {"1131f6ae-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes-In-Filtered-Set"},
    {"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Synchronize"},
    {"1131f6ac-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Manage-Topology"},
    {"1131f6af-9c07-11d1-f79f-00c04fc2dcd2", "DS-Check-Stale-Phantoms"},
    {"89e95b76-444d-4c62-991a-0facbeda640c", "DS-Replication-Get-Changes-In-Filtered-Set-Alt"},
    {"72e39547-7b18-11d1-adef-00c04fd8d5cd", "Validated-DNS-Host-Name"},
    {"f3a64788-5306-11d1-a9c5-0000f80367c1", "Validated-Write-SPN"},
    {"9b026da6-0d3c-465c-8bee-5199d7165cba", "Validated-Write-Computer"},
    {"05c74c5e-4deb-43b4-bf69-fa65ac53a05e", "Self-Membership"},
    {"bf967950-0de6-11d0-a285-00aa003049e2", "General-Information"},
    {"3e0abfd0-126a-11d0-a060-00aa006c33ed", "Personal-Information"},
    {"4c164200-20c0-11d0-a768-00aa006e0529", "Write-Account-Restrictions"},
    {"bf967a7f-0de6-11d0-a285-00aa003049e2", "Public-Information"},
    {"5b47d60f-6090-40b2-9f37-2a4de88f3063", "Write-msDS-KeyCredentialLink"},
    {"3f78c3e5-f79a-46bd-a0b8-9d18116ddc79", "Write-msDS-AllowedToActOnBehalfOfOtherIdentity"},
    {"800d94d7-b7a1-42a1-b14d-7cae1423d07f", "Write-msDS-AllowedToDelegateTo"},
    {"f30e3bbe-9ff0-11d1-b603-0000f80367c1", "Write-gPLink"},
    {"f30e3bbf-9ff0-11d1-b603-0000f80367c1", "Write-gPOptions"},
    {"bf967953-0de6-11d0-a285-00aa003049e2", "Write-logonHours"},
    {"bf967a0a-0de6-11d0-a285-00aa003049e2", "Write-accountExpires"},
    {"46a9b11d-60ae-405a-b7e8-ff8a58d456d2", "Key-Credential-Link-Roaming"},
    {"bf967aa8-0de6-11d0-a285-00aa003049e2", "Write-userAccountControl"},
    {"bc0ac240-79a9-11d0-9020-00c04fc2d4cf", "Membership (Property Set)"},
    {"ab721a54-1e2f-11d0-9819-00aa0040529b", "Send-As"},
    {"ab721a56-1e2f-11d0-9819-00aa0040529b", "Receive-As"},
    {"edacfd8f-ffb3-11d1-b41d-00a0c968f939", "Apply-Group-Policy"},
    {"771727b1-31b8-4281-b546-253150959f4c", "Read-gMSA-Password"},
    {"9923a32a-3607-11d2-b9be-0000f87a36b2", "DS-Install-Replica"},
    {"be2bb760-7f46-11d2-b9ad-00c04f79f805", "Update-Schema-Cache"},
    {"69ae6200-7f46-11d2-b9ad-00c04f79f805", "Reload-SSL-Certificate"},
    {"1f298a89-de98-47b8-b5cd-572ad53d267e", "ms-Mcs-AdmPwd"},
    {"d3676f01-8e45-45a3-8f1a-8b2de2563a24", "ms-Mcs-AdmPwdExpirationTime"},
    {"e081f117-4944-4367-bb67-d5e2b56e3571", "msLAPS-Password"},
    {"3ff5040d-fed4-4fd0-8b83-9b9e57a76e4b", "msLAPS-PasswordExpirationTime"},
    {"f3531ec6-6330-4f8e-8d39-7a671fbac605", "msLAPS-EncryptedPassword"},
};

const std::set<std::string> AceCollector::INTERESTING_RIGHTS = {
    "GenericAll", "GenericWrite",
    "WriteDACL", "WriteOwner",
    "WriteProperty", "Self", "CreateChild", "DeleteChild",
    "ListChildObjects", "Delete",
    "All-Extended-Rights", "ExtendedRights", "Other Rights",
    // INDIVIDUAL_RIGHTS keys
    "WriteDACL","WriteOwner","WriteProperty","ReadProperty","Self",
    "ListChildObjects","DeleteChild","CreateChild","Delete","DeleteTree","ListObject",
    // OBJECT_TYPE_RIGHTS values
    "AddMember","ForceChangePassword","ChangePassword","Reanimate-Tombstone",
    "Email-Information","DS-Replication-Get-Changes-All",
    "DS-Replication-Get-Changes-In-Filtered-Set","DS-Replication-Synchronize",
    "DS-Replication-Manage-Topology","DS-Check-Stale-Phantoms",
    "DS-Replication-Get-Changes-In-Filtered-Set-Alt","Validated-DNS-Host-Name",
    "Validated-Write-SPN","Validated-Write-Computer","Self-Membership",
    "General-Information","Personal-Information","Write-Account-Restrictions",
    "Public-Information","Write-msDS-KeyCredentialLink",
    "Write-msDS-AllowedToActOnBehalfOfOtherIdentity","Write-msDS-AllowedToDelegateTo",
    "Write-gPLink","Write-gPOptions","Write-logonHours","Write-accountExpires",
    "Key-Credential-Link-Roaming","Write-userAccountControl",
    "Membership (Property Set)","Send-As","Receive-As","Apply-Group-Policy",
    "Read-gMSA-Password","DS-Install-Replica","Update-Schema-Cache",
    "Reload-SSL-Certificate","ms-Mcs-AdmPwd","ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-Password","msLAPS-PasswordExpirationTime","msLAPS-EncryptedPassword",
};

const std::map<std::string, std::string> AceCollector::WELL_KNOWN_SIDS = {
    {"S-1-1-0",      "Everyone"},
    {"S-1-5-7",      "Anonymous Logon"},
    {"S-1-5-10",     "Principal Self"},
    {"S-1-5-11",     "Authenticated Users"},
    {"S-1-5-18",     "NT AUTHORITY\\SYSTEM"},
    {"S-1-5-19",     "NT AUTHORITY\\Local Service"},
    {"S-1-5-20",     "NT AUTHORITY\\Network Service"},
    {"S-1-5-32-544", "BUILTIN\\Administrators"},
    {"S-1-5-32-545", "BUILTIN\\Users"},
    {"S-1-5-32-546", "BUILTIN\\Guests"},
    {"S-1-5-32-548", "BUILTIN\\Account Operators"},
    {"S-1-5-32-549", "BUILTIN\\Server Operators"},
    {"S-1-5-32-550", "BUILTIN\\Print Operators"},
    {"S-1-5-32-551", "BUILTIN\\Backup Operators"},
    {"S-1-5-32-552", "BUILTIN\\Replicators"},
    {"S-1-5-32-554", "BUILTIN\\Pre-Windows 2000 Compatible Access"},
    {"S-1-5-32-560", "BUILTIN\\Windows Authorization Access Group"},
    {"S-1-5-32-561", "BUILTIN\\Terminal Server License Servers"},
    {"S-1-5-9",      "Enterprise Domain Controllers"},
    {"S-1-3-0",      "Creator Owner"},
    {"S-1-3-1",      "Creator Group"},
};

const std::map<std::string, std::string> AceCollector::AD_OBJECT_TYPE_MAP = {
    {"group",                "Group"},
    {"computer",             "Computer"},
    {"user",                 "User"},
    {"organizationalunit",   "OU"},
    {"grouppolicycontainer", "GPO"},
    {"domaindns",            "Domain"},
};

// Python: _PRIVILEGED_RIDS = {"-500","-502","-512","-516","-517","-518","-519","-520","-544"}
const std::set<std::string> AceCollector::PRIVILEGED_RIDS = {
    "-500","-502","-512","-516","-517","-518","-519","-520","-544"
};
// Python: _BROAD_RIDS = {"-513","-515","-545"}
const std::set<std::string> AceCollector::BROAD_RIDS = {"-513","-515","-545"};
// Python: _BROAD_SIDS = {"S-1-1-0","S-1-5-11"}
const std::set<std::string> AceCollector::BROAD_SIDS = {"S-1-1-0","S-1-5-11"};

// ═════════════════════════════════════════════════════════════════════════════
//  Constructor
// ═════════════════════════════════════════════════════════════════════════════
AceCollector::AceCollector(LDAPEngine& engine) : engine_(engine) {}

// ═════════════════════════════════════════════════════════════════════════════
//  build_sid_map — Python _build_sid_map() ilə ekvivalent
//  user/group/computer obyektlərinin SID → sAMAccountName xəritəsini qurur
// ═════════════════════════════════════════════════════════════════════════════
void AceCollector::build_sid_map() {
    // Well-known SID-ləri əvvəlcədən yüklə
    sid_map_.insert(WELL_KNOWN_SIDS.begin(), WELL_KNOWN_SIDS.end());

    constexpr uint32_t UF_ACCOUNTDISABLE = 0x2u;

    engine_.search(
        "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
        {"sAMAccountName", "objectSid", "userAccountControl"},
        [&](const LDAPEngine::AttrMap& entry) {
            auto sid_it  = entry.find("objectSid");
            auto name_it = entry.find("sAMAccountName");
            if (sid_it == entry.end() || sid_it->second.empty()) return;

            std::string sid  = decode_sid(sid_it->second[0]);
            std::string name = (name_it != entry.end() && !name_it->second.empty())
                               ? name_it->second[0] : sid;
            if (sid.empty()) return;

            sid_map_[sid] = name;

            auto uac_it = entry.find("userAccountControl");
            if (uac_it != entry.end() && !uac_it->second.empty()) {
                try {
                    uint32_t uac = static_cast<uint32_t>(
                        std::stoul(uac_it->second[0]));
                    if (uac & UF_ACCOUNTDISABLE)
                        disabled_sids_.insert(sid);
                } catch (...) {}
            }
        }
    );
}

// ═════════════════════════════════════════════════════════════════════════════
//  collect
// ═════════════════════════════════════════════════════════════════════════════
int AceCollector::collect(const AceCollectorOptions& opts) {
    fs::create_directories(opts.output_dir);
    output_path_ = fs::path(opts.output_dir) / "raw_aces.jsonl";

    std::ofstream f(output_path_, std::ios::binary);
    if (!f) {
        log_err("[AceCollector] Fayl açıla bilmədi: " + output_path_.string());
        return -1;
    }

    log_info("[AceCollector] Building SID map...");
    build_sid_map();
    log_info("[AceCollector] SID map built: " + std::to_string(sid_map_.size()) + " entries.");

    log_info("[AceCollector] LDAP query starting — collecting security descriptors...");

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

            const std::string dn          = get("distinguishedName");
            const std::string when_changed = get("whenChanged");

            // target_name: displayName > sAMAccountName > DN-in ilk komponenti
            std::string target_name = get("displayName");
            if (target_name.empty()) target_name = get("sAMAccountName");
            if (target_name.empty() && !dn.empty()) {
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

            // target_type — Python classify_target() ilə ekvivalent
            auto cls_it = entry.find("objectClass");
            std::vector<std::string> classes;
            if (cls_it != entry.end()) classes = cls_it->second;
            std::string target_type = classify_target(dn, classes);

            // nTSecurityDescriptor
            auto sd_it = entry.find("nTSecurityDescriptor");
            if (sd_it == entry.end() || sd_it->second.empty()) {
                ++obj_count;
                return;
            }

            auto aces = parse_sd(sd_it->second[0],
                                 target_name, dn, target_sid, target_type,
                                 when_changed, generated_at);

            // Python: expanded_obj = guid_map.get(obj_guid, obj_guid) if (guid_map and obj_guid)
            // guid_map boş deyilsə hər ACE-in GUID-ini expand et
            if (!opts.guid_map.empty()) {
                for (auto& ace : aces) {
                    if (!ace.object_acetype.empty()) {
                        auto gm_it = opts.guid_map.find(ace.object_acetype);
                        if (gm_it != opts.guid_map.end()) {
                            ace.object_acetype  = gm_it->second;
                            ace.object_ace_type = gm_it->second;
                        }
                    }
                }
            }

            for (const auto& ace : aces) {
                f << ace_to_jsonl(ace) << "\n";
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

// ═════════════════════════════════════════════════════════════════════════════
//  ace_to_jsonl — Python _parse_dacl_to_records() çıxış strukturu ilə uyğun
// ═════════════════════════════════════════════════════════════════════════════
std::string AceCollector::ace_to_jsonl(const RawAce& a) const {
    std::ostringstream o;
    o << "{"
      << "\"target_name\":"           << je(a.target_name)           << ","
      << "\"target_dn\":"             << je(a.target_dn)             << ","
      << "\"target_sid\":"            << je(a.target_sid)            << ","
      << "\"target_type\":"           << je(a.target_type)           << ","
      << "\"principal\":"             << je(a.principal)             << ","
      << "\"principal_sid\":"         << je(a.principal_sid)         << ","
      << "\"principal_scope\":"       << je(a.principal_scope)       << ","
      << "\"principal_is_disabled\":" << jb(a.principal_is_disabled) << ","
      << "\"object_acetype\":"        << je(a.object_acetype)        << ","
      << "\"object_ace_type\":"       << je(a.object_ace_type)       << ","
      << "\"ace_qualifier\":"         << je(a.ace_qualifier)         << ","
      << "\"ace_type_raw\":"          << ji(a.ace_type_raw)          << ","
      << "\"rights\":"                << jsa(a.rights)               << ","
      << "\"rights_display\":"        << je(a.rights_display)        << ","
      << "\"edge_rights\":"           << jsa(a.edge_rights)          << ","
      << "\"is_edge\":"               << jb(a.is_edge)               << ","
      << "\"edge_kind\":"             << je(a.edge_kind)             << ","
      << "\"is_inherited\":"          << jb(a.is_inherited)          << ","
      << "\"ace_flags\":"             << ji(a.ace_flags)             << ","
      << "\"modified\":"              << (a.modified.empty() ? "null" : je(a.modified)) << ","
      << "\"generated_at\":"          << je(a.generated_at)
      << "}";
    return o.str();
}

// ═════════════════════════════════════════════════════════════════════════════
//  parse_rights — Python _parse_rights() ilə tam ekvivalent
// ═════════════════════════════════════════════════════════════════════════════
std::vector<std::string> AceCollector::parse_rights(
    uint32_t mask, const std::string& obj_guid) const
{
    // GenericAll yoxlanışı
    bool is_generic_all =
        (mask & GENERIC_ALL_RAW) ||
        ((mask & GENERIC_ALL_COMPOSED) == GENERIC_ALL_COMPOSED);
    if (is_generic_all)
        return {"GenericAll"};

    bool has_obj_guid = !obj_guid.empty();

    bool is_generic_write =
        (mask & RAW_GENERIC_WRITE) ||
        (!has_obj_guid && (mask & GENERIC_WRITE_COMPOSED) == GENERIC_WRITE_COMPOSED);

    std::vector<std::string> rights;

    if (is_generic_write) {
        rights.push_back("GenericWrite");
        std::set<std::string> skip = {"WriteProperty", "Self"};
        for (const auto& [name, val] : INDIVIDUAL_RIGHTS) {
            if (!skip.count(name) && (mask & val))
                rights.push_back(name);
        }
    } else {
        for (const auto& [name, val] : INDIVIDUAL_RIGHTS) {
            if (mask & val)
                rights.push_back(name);
        }
    }

    if (has_obj_guid) {
        auto it = OBJECT_TYPE_RIGHTS.find(obj_guid);
        // Hər iki halda (tanınan/tanınmayan GUID) WriteProperty, Self, ReadProperty silinir
        std::set<std::string> to_remove;
        if (mask & WRITE_PROPERTY_BIT) to_remove.insert("WriteProperty");
        if (mask & SELF_BIT)           to_remove.insert("Self");
        if (mask & READ_PROPERTY_BIT)  to_remove.insert("ReadProperty");

        rights.erase(std::remove_if(rights.begin(), rights.end(),
            [&](const std::string& r){ return to_remove.count(r); }), rights.end());

        if (it != OBJECT_TYPE_RIGHTS.end()) {
            // Tanınan GUID → spesifik hüquq adı
            const std::string& specific = it->second;
            if (std::find(rights.begin(), rights.end(), specific) == rights.end())
                rights.push_back(specific);
        } else {
            // Tanınmayan GUID → ExtendedRights
            if (std::find(rights.begin(), rights.end(), "ExtendedRights") == rights.end())
                rights.push_back("ExtendedRights");
        }
    }

    // CONTROL_ACCESS_RIGHT biti, GUID olmadan → All-Extended-Rights
    if ((mask & CONTROL_ACCESS_RIGHT) && !has_obj_guid) {
        if (std::find(rights.begin(), rights.end(), "All-Extended-Rights") == rights.end())
            rights.push_back("All-Extended-Rights");
    }

    // Python ilə eyni sıralama
    static const std::vector<std::string> ORDER = {
        "GenericAll","GenericWrite","WriteDACL","WriteOwner",
        "WriteProperty","Self","Delete",
        "AddMember","ForceChangePassword","ChangePassword",
        "DS-Replication-Get-Changes","DS-Replication-Get-Changes-All",
        "DS-Replication-Get-Changes-In-Filtered-Set",
        "DS-Replication-Manage-Topology","DS-Replication-Synchronize",
        "Write-msDS-KeyCredentialLink",
        "Write-msDS-AllowedToActOnBehalfOfOtherIdentity",
        "Write-msDS-AllowedToDelegateTo",
        "Write-gPLink","Write-gPOptions",
        "Validated-Write-SPN","Validated-DNS-Host-Name",
        "Send-As","Receive-As","Apply-Group-Policy","Self-Membership",
        "Validated-Write-Computer","Read-gMSA-Password",
        "All-Extended-Rights","ExtendedRights",
    };

    std::set<std::string> rights_set(rights.begin(), rights.end());
    std::vector<std::string> ordered;
    for (const auto& r : ORDER)
        if (rights_set.count(r)) { ordered.push_back(r); rights_set.erase(r); }
    for (const auto& r : rights)
        if (rights_set.count(r)) { ordered.push_back(r); rights_set.erase(r); }

    if (ordered.empty() && mask)
        ordered.push_back("Other Rights");

    return ordered;
}

// ═════════════════════════════════════════════════════════════════════════════
//  classify_principal — Python classify_principal() ilə ekvivalent
// ═════════════════════════════════════════════════════════════════════════════
std::string AceCollector::classify_principal(
    const std::string& sid, const std::string& name)
{
    // RID: SID-in son komponenti
    std::string last_rid;
    auto pos = sid.rfind('-');
    if (pos != std::string::npos)
        last_rid = "-" + sid.substr(pos + 1);

    // BUILTIN\Administrators
    if (sid == "S-1-5-32-544") return "Privileged";

    // Privileged RID-lər (domain SID-ləri üçün, BUILTIN xaricində)
    if (!sid.rfind("S-1-5-32-", 0) == 0 && PRIVILEGED_RIDS.count(last_rid))
        return "Privileged";
    if (PRIVILEGED_RIDS.count(last_rid) && sid.find("S-1-5-32-") == std::string::npos)
        return "Privileged";

    // Broad SID/RID
    if (BROAD_SIDS.count(sid) || BROAD_RIDS.count(last_rid))
        return "Broad";

    // Ad ilə yoxlanış
    std::string n = name;
    std::transform(n.begin(), n.end(), n.begin(), ::toupper);
    for (const auto& kw : {"DOMAIN ADMINS","ENTERPRISE ADMINS","SCHEMA ADMINS","ADMINISTRATORS"})
        if (n.find(kw) != std::string::npos) return "Privileged";
    for (const auto& kw : {"EVERYONE","AUTHENTICATED USERS","DOMAIN USERS","DOMAIN COMPUTERS"})
        if (n == kw) return "Broad";

    return "Custom";
}

// ═════════════════════════════════════════════════════════════════════════════
//  classify_target — Python classify_target() ilə ekvivalent
// ═════════════════════════════════════════════════════════════════════════════
std::string AceCollector::classify_target(
    const std::string& dn, const std::vector<std::string>& classes)
{
    // Kiçik hərflə müqayisə üçün set
    std::set<std::string> cs;
    for (const auto& c : classes) {
        std::string low = c;
        std::transform(low.begin(), low.end(), low.begin(), ::tolower);
        cs.insert(low);
    }

    // AD_OBJECT_TYPE_MAP-dən əvvəlcə yoxla
    for (const auto& [cls, label] : AD_OBJECT_TYPE_MAP)
        if (cs.count(cls)) return label;

    // Extra type map (Python _EXTRA_TYPE_MAP)
    static const std::vector<std::pair<std::string,std::string>> EXTRA = {
        {"msds-groupmanagedserviceaccount", "gMSA"},
        {"msds-managedserviceaccount",      "MSA"},
        {"pkicertificatetemplate",          "CertTemplate"},
        {"pkienrollmentservice",            "CA"},
        {"certificationauthority",          "CA"},
        {"trusteddomain",                   "Trust"},
        {"dnszone",                         "DNSZone"},
        {"dnsnode",                         "DNSNode"},
        {"serviceconnectionpoint",          "SCP"},
        {"msds-passwordsettings",           "PSO"},
        {"ntdsdsa",                         "DCService"},
        {"server",                          "Server"},
        {"site",                            "Site"},
        {"sitelink",                        "SiteLink"},
        {"subnet",                          "Subnet"},
        {"crossref",                        "CrossRef"},
        {"crossrefcontainer",               "CrossRefContainer"},
        {"foreignsecurityprincipal",        "ForeignPrincipal"},
        {"msexchmailboxdatabase",           "ExchangeDB"},
        {"msexchserver",                    "ExchangeServer"},
        {"publicfolder",                    "PublicFolder"},
    };
    for (const auto& [cls, label] : EXTRA)
        if (cs.count(cls)) return label;

    // Ən spesifik class-ı tap (Python reversed(classes) ilə eyni)
    static const std::set<std::string> SKIP = {"top","classschema","attributeschema"};
    for (auto it = classes.rbegin(); it != classes.rend(); ++it) {
        std::string low = *it;
        std::transform(low.begin(), low.end(), low.begin(), ::tolower);
        if (!SKIP.count(low)) return "Other:" + *it;
    }

    std::string dn_up = dn.substr(0, 3);
    std::transform(dn_up.begin(), dn_up.end(), dn_up.begin(), ::toupper);
    if (dn_up == "CN=") return "Container";
    return "Object";
}

// ═════════════════════════════════════════════════════════════════════════════
//  parse_sd — binary Security Descriptor → RawAce list
//  Python _parse_dacl_to_records() ilə ekvivalent
// ═════════════════════════════════════════════════════════════════════════════
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
    const auto*  b   = reinterpret_cast<const unsigned char*>(sd_bytes.data());
    const size_t len = sd_bytes.size();

    if (len < 20) return result;

    uint32_t dacl_off = read_u32(b, 16, len);
    if (dacl_off == 0 || dacl_off + 8 > len) return result;

    uint16_t ace_count = read_u16(b, dacl_off + 4, len);
    size_t   pos       = dacl_off + 8;

    for (uint16_t i = 0; i < ace_count && pos + 4 <= len; ++i) {
        uint8_t  ace_type  = b[pos];
        uint8_t  ace_flags = b[pos + 1];
        uint16_t ace_size  = read_u16(b, pos + 2, len);
        if (ace_size < 4 || pos + ace_size > len) break;

        // Python ilə eyni ACE tipi yoxlanışı
        // 0x00=ALLOWED, 0x01=DENIED, 0x05=ALLOWED_OBJECT, 0x06=DENIED_OBJECT
        bool is_allow  = (ace_type == 0x00 || ace_type == 0x05);
        bool is_object = (ace_type == 0x05 || ace_type == 0x06);

        uint32_t mask = read_u32(b, pos + 4, len);

        // Object GUID
        std::string obj_guid;
        size_t sid_off = pos + 8;
        if (is_object && pos + 12 <= len) {
            uint32_t obj_flags = read_u32(b, pos + 8, len);
            sid_off = pos + 12;
            if (obj_flags & 0x01) {
                if (sid_off + 16 <= len) {
                    obj_guid = guid_bytes_to_str(b + sid_off);
                    sid_off += 16;
                }
            }
            if (obj_flags & 0x02) {
                if (sid_off + 16 <= len) sid_off += 16;
            }
        }

        // Principal SID
        std::string principal_sid;
        if (sid_off < pos + ace_size)
            principal_sid = decode_sid(
                std::string(reinterpret_cast<const char*>(b + sid_off),
                            (pos + ace_size) - sid_off));

        if (principal_sid.empty()) { pos += ace_size; continue; }

        // Rights — Python _parse_rights() ilə ekvivalent
        auto rights = parse_rights(mask, obj_guid);
        if (rights.empty()) { pos += ace_size; continue; }

        // Principal name resolution
        std::string principal = principal_sid;
        auto it = sid_map_.find(principal_sid);
        if (it != sid_map_.end()) principal = it->second;

        bool is_inherited  = (ace_flags & ACE_FLAG_INHERITED) != 0;
        bool is_disabled   = disabled_sids_.count(principal_sid) > 0;
        std::string scope  = classify_principal(principal_sid, principal);

        // edge_rights = rights ∩ INTERESTING_RIGHTS
        std::vector<std::string> edge_rights;
        for (const auto& r : rights)
            if (INTERESTING_RIGHTS.count(r)) edge_rights.push_back(r);
        bool is_edge = !edge_rights.empty();

        // rights_display = ", ".join(rights)  — Python ilə eyni
        std::string rights_display;
        for (size_t ri = 0; ri < rights.size(); ++ri) {
            if (ri) rights_display += ", ";
            rights_display += rights[ri];
        }

        RawAce ace;
        ace.target_name           = target_name;
        ace.target_dn             = target_dn;
        ace.target_sid            = target_sid;
        ace.target_type           = target_type;
        ace.principal             = principal;
        ace.principal_sid         = principal_sid;
        ace.principal_scope       = scope;
        ace.principal_is_disabled = is_disabled;
        // Python: expanded_obj = guid_map.get(obj_guid, obj_guid) if (guid_map and obj_guid) else obj_guid
        // Hər iki sahə eyni expanded dəyəri daşıyır
        ace.object_acetype        = obj_guid;  // collect() içərisində guid_map tətbiq ediləcək
        ace.object_ace_type       = obj_guid;  // collect() içərisində guid_map tətbiq ediləcək
        ace.ace_qualifier         = is_allow ? "Allow" : "Deny";
        ace.ace_type_raw          = static_cast<int>(ace_type);
        ace.rights                = rights;
        ace.rights_display        = rights_display;
        ace.edge_rights           = edge_rights;
        ace.is_edge               = is_edge;
        ace.edge_kind             = is_edge ? "Edge" : "ACL";
        ace.is_inherited          = is_inherited;
        ace.ace_flags             = ace_flags;
        ace.modified              = ldap_ts_to_iso(when_changed);  // Python ldap_ts_to_iso() ilə eyni
        ace.generated_at          = generated_at;

        result.push_back(std::move(ace));
        pos += ace_size;
    }

    return result;
}

// ═════════════════════════════════════════════════════════════════════════════
//  decode_sid
// ═════════════════════════════════════════════════════════════════════════════
std::string AceCollector::decode_sid(const std::string& raw) {
    if (raw.size() < 8) return "";
    const auto* b  = reinterpret_cast<const unsigned char*>(raw.data());
    int rev        = b[0];
    int sub_count  = b[1];
    long long auth = 0;
    for (int i = 2; i < 8; ++i) auth = (auth << 8) | b[i];

    std::ostringstream o;
    o << "S-" << rev << "-" << auth;
    for (int i = 0; i < sub_count && (8 + 4*(i+1)) <= (int)raw.size(); ++i) {
        int off = 8 + 4*i;
        unsigned long sub =
              (unsigned long)(b[off])
            | ((unsigned long)(b[off+1]) << 8)
            | ((unsigned long)(b[off+2]) << 16)
            | ((unsigned long)(b[off+3]) << 24);
        o << "-" << sub;
    }
    return o.str();
}

// ═════════════════════════════════════════════════════════════════════════════
//  guid_bytes_to_str — 16 byte → "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
//  Python uuid.UUID(bytes_le=...) ilə eyni çıxış
// ═════════════════════════════════════════════════════════════════════════════
std::string AceCollector::guid_bytes_to_str(const unsigned char* b) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    // Data1 (LE uint32)
    o << std::setw(2)<<(int)b[3] << std::setw(2)<<(int)b[2]
      << std::setw(2)<<(int)b[1] << std::setw(2)<<(int)b[0] << '-';
    // Data2 (LE uint16)
    o << std::setw(2)<<(int)b[5] << std::setw(2)<<(int)b[4] << '-';
    // Data3 (LE uint16)
    o << std::setw(2)<<(int)b[7] << std::setw(2)<<(int)b[6] << '-';
    // Data4[0..1] (BE)
    o << std::setw(2)<<(int)b[8] << std::setw(2)<<(int)b[9] << '-';
    // Data4[2..7] (BE)
    for (int i = 10; i < 16; ++i) o << std::setw(2)<<(int)b[i];
    return o.str();
}

// ═════════════════════════════════════════════════════════════════════════════
//  primary_class — artıq istifadə edilmir; classify_target() tərəfindən əvəzlənib
// ═════════════════════════════════════════════════════════════════════════════
std::string AceCollector::primary_class(const std::vector<std::string>& classes) {
    return classify_target("", classes);
}

// ═════════════════════════════════════════════════════════════════════════════
//  read helpers
// ═════════════════════════════════════════════════════════════════════════════
uint16_t AceCollector::read_u16(const unsigned char* b, size_t off, size_t len) {
    if (off + 2 > len) return 0;
    return (uint16_t)b[off] | ((uint16_t)b[off+1] << 8);
}

uint32_t AceCollector::read_u32(const unsigned char* b, size_t off, size_t len) {
    if (off + 4 > len) return 0;
    return (uint32_t)b[off]         | ((uint32_t)b[off+1] << 8)
         | ((uint32_t)b[off+2]<<16) | ((uint32_t)b[off+3] << 24);
}

// ═════════════════════════════════════════════════════════════════════════════
//  JSON helpers
// ═════════════════════════════════════════════════════════════════════════════
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
                    o << (char)ch;
        }
    }
    o << '"';
    return o.str();
}

std::string AceCollector::jb(bool v)  { return v ? "true" : "false"; }
std::string AceCollector::ji(int v)   { return std::to_string(v); }

// JSON string array: ["a","b","c"]
std::string AceCollector::jsa(const std::vector<std::string>& v) {
    std::ostringstream o;
    o << '[';
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) o << ',';
        o << je(v[i]);
    }
    o << ']';
    return o.str();
}

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
std::string AceCollector::ldap_ts_to_iso(const std::string& raw) {
    if (raw.empty()) return "";

    if (raw.size() >= 14) {
        bool all_digits = true;
        for (int i = 0; i < 14; ++i)
            if (!std::isdigit((unsigned char)raw[i])) { all_digits = false; break; }

        if (all_digits) {
            std::tm tm{};
            auto sub = [&](int from, int len) -> int {
                return std::stoi(raw.substr(from, len));
            };
            tm.tm_year = sub(0, 4) - 1900;
            tm.tm_mon  = sub(4, 2) - 1;
            tm.tm_mday = sub(6, 2);
            tm.tm_hour = sub(8, 2);
            tm.tm_min  = sub(10, 2);
            tm.tm_sec  = sub(12, 2);

            std::ostringstream o;
            o << std::setfill('0')
              << std::setw(4) << (tm.tm_year + 1900) << "-"
              << std::setw(2) << (tm.tm_mon  + 1)    << "-"
              << std::setw(2) << tm.tm_mday           << "T"
              << std::setw(2) << tm.tm_hour            << ":"
              << std::setw(2) << tm.tm_min             << ":"
              << std::setw(2) << tm.tm_sec             << "+00:00";
            return o.str();
        }
    }
    return raw;
}