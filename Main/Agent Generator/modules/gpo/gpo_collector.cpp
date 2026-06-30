// ─── gpo_collector.cpp ───────────────────────────────────────────────────────
//  Phase 1 — Extract: collects all GPOs via LDAP and writes raw_gpos.jsonl.
//
//  Mirrors gpos.py::get_domain_gpos() — LDAP-only path (no SMB/SYSVOL).
//  SYSVOL content (cPassword, scripts, security settings) is intentionally
//  left to a separate SYSVOL collector; this module focuses on the AD objects.
//
//  Input : LDAPEngine (already bound)
//  Output: raw_cache/raw_gpos.jsonl  — one GPO per line
// ─────────────────────────────────────────────────────────────────────────────
#include "gpo_collector.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <regex>
#include <map>
#include <set>

// ─────────────────────────────────────────────────────────────────────────────
//  Well-known high-value GPO CN GUIDs
//  Default Domain Policy  : {31B2F340-016D-11D2-945F-00C04FB984F9}
//  Default Domain Controllers Policy: {6AC1786C-016F-11D2-945F-00C04FB984F9}
// ─────────────────────────────────────────────────────────────────────────────
const char* GPOCollector::HIGH_VALUE_GUIDS[] = {
    "{31B2F340-016D-11D2-945F-00C04FB984F9}",
    "{6AC1786C-016F-11D2-945F-00C04FB984F9}",
    nullptr
};

// ─────────────────────────────────────────────────────────────────────────────
//  Extension GUID → human-readable name  (mirrors gpos.py EXTENSION_GUID_MAP)
// ─────────────────────────────────────────────────────────────────────────────
const std::pair<const char*, const char*> GPOCollector::EXTENSION_GUID_MAP[] = {
    {"{35378EAC-683F-11D2-A89A-00C04FBBCFA2}", "Registry Settings"},
    {"{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", "Security Settings"},
    {"{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}", "EFS Recovery Policy"},
    {"{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}", "Scripts (Startup/Shutdown)"},
    {"{42B5FAAE-6536-11D2-AE5A-0000F87571E3}", "Scripts (Logon/Logoff)"},
    {"{00000000-0000-0000-0000-000000000000}", "Core GPO"},
    {"{0F6B957E-509E-11D1-A7CC-0000F87571E3}", "Tool Extension Policy"},
    {"{0F6B957D-509E-11D1-A7CC-0000F87571E3}", "Tool Extension Policy"},
    {"{1612B55C-243C-48DD-A449-FFC097B19776}", "Deployed Printer Connections"},
    {"{1A6364EB-776B-4120-ADE1-B63A406A76B5}", "Offline Files"},
    {"{25537BA6-77A8-11D2-9B6C-0000F8080861}", "Folder Redirection"},
    {"{2BFCC077-22D2-48DE-BDE1-2F618D9B476D}", "AppV Policy"},
    {"{3610EDA5-77EF-11D2-8DC5-00C04FA31A66}", "Microsoft Disk Quota"},
    {"{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}", "Internet Explorer Zonemapping"},
    {"{4D2F9B6F-1E52-4711-A5BE-012D73A3A073}", "Drive Maps"},
    {"{516FC620-5D34-4B08-8165-6A06B623EDEB}", "Scheduled Tasks"},
    {"{53D6AB1B-2488-11D1-A28C-00C04FB94F17}", "EFS Recovery"},
    {"{5794DAFD-BE60-433F-88A2-1A31939AC01F}", "Drive Mappings"},
    {"{6232C319-91AC-4931-9385-E70C2B099F0E}", "Group Policy Folders"},
    {"{6A4C88C6-C502-4F74-8F60-2CB23EDC9E0A}", "Group Policy Network Options"},
    {"{728EE579-943C-4519-9EF7-AB56765798ED}", "Group Policy Data Sources"},
    {"{74EE6C03-5363-4554-B161-627540339CAB}", "Group Policy ini Files"},
    {"{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}", "Group Policy Files"},
    {"{7933F41E-56F8-41D6-A31C-4148A711EE93}", "Group Policy Internet Settings"},
    {"{A3F3E39B-5D83-4940-B954-28315B82F0A8}", "Group Policy Folder Options"},
    {"{AADCED64-746C-4633-A97C-D61349046527}", "Group Policy Scheduled Tasks"},
    {"{B087BE9D-ED37-454F-AF9C-04291E351182}", "Group Policy Registry"},
    {"{B9CCA4DE-E2B9-4CBD-BF7D-11B6EBFBDDF7}", "Group Policy Printers"},
    {"{BA649533-0AAC-4E04-B9B8-3D492B3CC60A}", "Group Policy Network Shares"},
    {"{C6DC5466-785A-11D2-84D0-00C04FB169F7}", "Software Installation"},
    {"{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}", "Scheduled Tasks (Immediate)"},
    {"{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}", "Internet Explorer"},
    {"{E437BC1C-AA7D-11D2-A382-00C04F991E27}", "IP Security"},
    {"{F9C77450-3A41-477E-9310-9ACD617BD9E3}", "Group Policy Applications"},
    {"{FB2CA36D-0B40-4307-821B-A13B252DE56C}", "Group Policy Environment"},
    {"{FBF687E6-F063-4D9F-9F4F-FD9A26ACDD5F}", "Group Policy Shortcuts"},
    {"{169EBF44-942F-4C43-87CE-13C93996EBBE}", "Group Policy Wireless (Vista+)"},
    {"{91FBB303-0CD5-4055-BF42-E512A681B325}", "Group Policy Wired Policy"},
    {"{40B6664F-4972-11D1-A7CA-0000F87571E3}", "Scripts"},
    {"{CDEAFC3D-948D-49DD-AB12-E578BA4AF7AA}", "TCPIP"},
    {"{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}", "Group Policy Wireless"},
    {"{E5094040-C46C-4115-B030-04FB2E545B6F}", "Group Policy Regional Options"},
    {"{E62688F0-25FD-4C90-BFF5-F508B9D2E31F}", "Group Policy Power Options"},
    {"{EC4828A8-A768-4A2E-9EDD-A73165B7D600}", "Group Policy Start Menu"},
    {"{F0DB2806-FD46-45B7-81BD-AA0B4B6E7AEB}", "Group Policy Task Bar"},
    {"{F581DAE7-8064-444A-AEB3-1875662A61CE}", "Group Policy Services"},
    {"{FD500BEF-9F03-4F58-97B8-2E51C2218566}", "Group Policy Local Users and Groups"},
    {nullptr, nullptr}
};

// ─────────────────────────────────────────────────────────────────────────────
//  Constructor
// ─────────────────────────────────────────────────────────────────────────────
GPOCollector::GPOCollector(LDAPEngine& engine) : engine_(engine) {}

// ─────────────────────────────────────────────────────────────────────────────
//  required_attrs
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> GPOCollector::required_attrs() const {
    return {
        "name",
        "displayName",
        "description",
        "gPCFileSysPath",
        "whenCreated",
        "whenChanged",
        "versionNumber",
        "gPCUserExtensionNames",
        "gPCMachineExtensionNames",
        "flags",
        "objectGUID",
        "ntSecurityDescriptor",
        "managedBy",
        "distinguishedName",
    };
}

// ─────────────────────────────────────────────────────────────────────────────
//  collect  — public entry point
// ─────────────────────────────────────────────────────────────────────────────
int GPOCollector::collect(const GPOCollectorOptions& opts) {
    fs::create_directories(opts.output_dir);
    output_path_ = fs::path(opts.output_dir) / "raw_gpos.jsonl";

    std::ofstream f(output_path_, std::ios::binary);
    if (!f) {
        log_err("[GPOCollector] Failed to open output file: " + output_path_.string());
        return -1;
    }

    log_info("[GPOCollector] LDAP query starting — collecting all GPOs...");

    const std::string generated_at = now_iso8601();
    const std::string base_dn      = engine_.cfg_.base_dn;

    // ── Resolve domain SID once ───────────────────────────────────────────────
    std::string domain_sid;
    {
        engine_.search_base(base_dn, {"objectSid"},
            [&](const LDAPEngine::AttrMap& e) {
                if (!domain_sid.empty()) return;
                auto it = e.find("objectSid");
                if (it != e.end() && !it->second.empty())
                    domain_sid = sid_to_string(it->second[0]);
            });
    }

    const std::string domain_name = extract_domain_name(base_dn);
    const std::string gpo_container = "CN=Policies,CN=System," + base_dn;

    // ── Query 1: all GPO objects ──────────────────────────────────────────────
    // Collect entries into a local list first so that subsequent LDAP queries
    // (for link map) do not overwrite engine_'s result set.
    //
    // NOTE: GPOs live under CN=Policies,CN=System,<base_dn> — we must scope
    // the search to gpo_container, not the domain root, to avoid missing results
    // when the engine's default search base is the root NC.
    struct GPOEntry {
        LDAPEngine::AttrMap attrs;
    };
    std::vector<GPOEntry> entries;

    // Temporarily redirect the engine's search base to the GPO container so
    // that search() (which uses cfg_.base_dn internally) finds only GPO objects.
    // We restore the original base_dn immediately after the query.
    const std::string saved_base = engine_.cfg_.base_dn;
    engine_.cfg_.base_dn = gpo_container;

    bool ok = engine_.search(
        "(objectClass=groupPolicyContainer)",
        required_attrs(),
        [&](const LDAPEngine::AttrMap& e) {
            entries.push_back({e});
        });

    engine_.cfg_.base_dn = saved_base;   // always restore

    if (!ok) {
        log_err("[GPOCollector] LDAP query failed (base: " + gpo_container + ").");
        return -1;
    }

    if (entries.empty()) {
        log_warn("[GPOCollector] No GPO objects found under: " + gpo_container);
        // Write an empty file so OfflineProcessor does not treat this as a
        // hard error — the domain may simply have no custom GPOs.
        f.flush();
        f.close();
        return 0;
    }

    // ── Query 2+3: build link map (gPLink → containers) ──────────────────────
    LinkMap link_map = build_link_map();

    // ── Serialise each GPO ────────────────────────────────────────────────────
    int count = 0;
    for (const auto& ge : entries) {
        if (opts.max_results > 0 && count >= opts.max_results) break;

        // The CN of the GPO is in the "name" attribute, which equals the {GUID}
        // path component used in gPLink.  Normalise to upper-case with braces.
        const auto& e = ge.attrs;
        auto get = [&](const std::string& k) -> std::string {
            auto it = e.find(k);
            if (it != e.end() && !it->second.empty()) return it->second[0];
            return "";
        };

        std::string cn_guid = get("name");
        std::transform(cn_guid.begin(), cn_guid.end(), cn_guid.begin(),
            [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
        if (!cn_guid.empty() && cn_guid.front() != '{')
            cn_guid = "{" + cn_guid + "}";

        // Gather link info for this GPO
        std::vector<std::string> linked_containers;
        bool enforced     = false;
        bool link_disabled = false;

        auto it = link_map.find(cn_guid);
        if (it != link_map.end()) {
            linked_containers = it->second.containers;
            enforced      = is_enforced    (it->second.link_texts, cn_guid);
            link_disabled = is_link_disabled(it->second.link_texts, cn_guid);
        }

        f << gpo_to_jsonl(e, domain_sid, domain_name,
                            linked_containers, enforced, link_disabled,
                            generated_at)
          << "\n";
        ++count;
    }

    f.flush();
    f.close();

    log_ok("[GPOCollector] " + std::to_string(count)
           + " GPOs -> " + output_path_.string());
    return count;
}

// ─────────────────────────────────────────────────────────────────────────────
//  gpo_to_jsonl
// ─────────────────────────────────────────────────────────────────────────────
std::string GPOCollector::gpo_to_jsonl(
    const LDAPEngine::AttrMap& entry,
    const std::string&         domain_sid,
    const std::string&         domain_name,
    const std::vector<std::string>& linked_containers,
    bool                        enforced,
    bool                        link_disabled,
    const std::string&          generated_at) const
{
    auto get = [&](const std::string& k) -> std::string {
        auto it = entry.find(k);
        if (it != entry.end() && !it->second.empty()) return it->second[0];
        return "";
    };

    // ── Identity ──────────────────────────────────────────────────────────────
    // CN of the GPO object, e.g. "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    std::string cn_name = get("name");
    std::transform(cn_name.begin(), cn_name.end(), cn_name.begin(),
        [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
    if (!cn_name.empty() && cn_name.front() != '{')
        cn_name = "{" + cn_name + "}";

    // objectGUID from LDAP (binary → UUID string)
    const std::string raw_guid = get("objectGUID");
    const std::string obj_guid = guid_to_string(raw_guid);
    // Normalise to {GUID} form
    std::string guid_str = obj_guid;
    std::transform(guid_str.begin(), guid_str.end(), guid_str.begin(),
        [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
    if (!guid_str.empty() && guid_str.front() != '{')
        guid_str = "{" + guid_str + "}";

    const std::string display_name  = get("displayName");
    const std::string description   = get("description");
    const std::string dn            = get("distinguishedName");
    const std::string gpc_fs_path   = get("gPCFileSysPath");
    const std::string managed_by    = get("managedBy");
    const std::string user_ext_raw  = get("gPCUserExtensionNames");
    const std::string mach_ext_raw  = get("gPCMachineExtensionNames");

    // ── Timestamps ────────────────────────────────────────────────────────────
    const std::string created  = generalized_time_to_iso(get("whenCreated"));
    const std::string modified = generalized_time_to_iso(get("whenChanged"));

    // ── Version ───────────────────────────────────────────────────────────────
    int version_num = 0;
    {
        const std::string vs = get("versionNumber");
        if (!vs.empty()) try { version_num = std::stoi(vs); } catch (...) {}
    }
    const int u_ver  = user_version(version_num);
    const int c_ver  = computer_version(version_num);

    // ── Flags ─────────────────────────────────────────────────────────────────
    int gpo_flags = 0;
    {
        const std::string fs = get("flags");
        if (!fs.empty()) try { gpo_flags = std::stoi(fs); } catch (...) {}
    }
    const bool user_settings_disabled     = (gpo_flags & 1) != 0;
    const bool computer_settings_disabled = (gpo_flags & 2) != 0;

    // ── Security Descriptor ───────────────────────────────────────────────────
    const std::string sd_raw       = get("ntSecurityDescriptor");
    const bool        isaclprotected = parse_isaclprotected(sd_raw);
    const std::string owner_sid    = parse_sd_owner(sd_raw);

    // ── Extension GUIDs ───────────────────────────────────────────────────────
    const std::string user_ext_json = parse_extension_guids_json(user_ext_raw);
    const std::string mach_ext_json = parse_extension_guids_json(mach_ext_raw);

    // ── High-value ────────────────────────────────────────────────────────────
    const bool highvalue = is_high_value(cn_name, user_ext_raw, mach_ext_raw);

    // ── Risk controls ─────────────────────────────────────────────────────────
    std::vector<std::string> risk_controls;
    if (highvalue)                     risk_controls.push_back("High Value Target");
    if (enforced)                      risk_controls.push_back("Enforced");
    if (isaclprotected)                risk_controls.push_back("ACL Inheritance Blocked");
    if (user_settings_disabled)        risk_controls.push_back("User Settings Disabled");
    if (computer_settings_disabled)    risk_controls.push_back("Computer Settings Disabled");
    if (!managed_by.empty())           risk_controls.push_back("Delegated Management");
    if (link_disabled && !linked_containers.empty())
                                       risk_controls.push_back("Link Disabled");

    // ── Linked containers → JSON array ────────────────────────────────────────
    const std::string linked_json = ja(linked_containers);

    // ── Serialise ─────────────────────────────────────────────────────────────
    std::ostringstream o;
    o << "{"
      // Identity
      << "\"name\":"           << je(cn_name)                        << ","
      << "\"guid\":"           << je(guid_str)                       << ","
      << "\"display_name\":"   << je(display_name.empty() ? cn_name : display_name) << ","
      << "\"description\":"    << je(description)                    << ","
      << "\"dn\":"             << je(dn)                             << ","
      << "\"path\":"           << je(gpc_fs_path)                    << ","
      << "\"managed_by\":"     << je(managed_by)                     << ","
      // Domain
      << "\"domain\":"         << je(domain_name)                    << ","
      << "\"domainsid\":"      << je(domain_sid)                     << ","
      // Timestamps
      << "\"created\":"        << je(created)                        << ","
      << "\"modified\":"       << je(modified)                       << ","
      // Version
      << "\"version\":"           << ji(version_num)                 << ","
      << "\"user_version\":"      << ji(u_ver)                       << ","
      << "\"computer_version\":"  << ji(c_ver)                       << ","
      // Flags / status
      << "\"flags\":"                        << ji(gpo_flags)                    << ","
      << "\"user_settings_disabled\":"       << jb(user_settings_disabled)       << ","
      << "\"computer_settings_disabled\":"   << jb(computer_settings_disabled)   << ","
      // Link data
      << "\"linked_containers\":"  << linked_json                    << ","
      << "\"linked_count\":"       << ji(static_cast<int>(linked_containers.size())) << ","
      << "\"enforced\":"           << jb(enforced)                   << ","
      << "\"link_disabled\":"      << jb(link_disabled)              << ","
      // ACL / Owner
      << "\"isaclprotected\":"  << jb(isaclprotected)                << ","
      << "\"owner_sid\":"       << je(owner_sid)                     << ","
      // Extensions
      << "\"user_extensions\":"    << user_ext_json                  << ","
      << "\"machine_extensions\":" << mach_ext_json                  << ","
      // Risk
      << "\"highvalue\":"      << jb(highvalue)                      << ","
      << "\"risk_controls\":"  << ja(risk_controls)                  << ","
      // Metadata
      << "\"generated_at\":"   << je(generated_at)
      << "}";

    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  build_link_map
//  Query 2: (gPLink=*)  → containers that reference at least one GPO
//  Query 3: (&(gpOptions=1)(!(gPLink=*)))  → inheritance-blocked with no links
//
//  Maps each CN-GUID (upper, braced) → LinkInfo { containers, link_texts }.
//
//  NOTE: gPLink uses the GPO's CN (= {GUID}), NOT objectGUID.  The CN is what
//        gpos.py calls "name" and what SYSVOL folders are named after.
// ─────────────────────────────────────────────────────────────────────────────
GPOCollector::LinkMap GPOCollector::build_link_map() const {
    LinkMap lmap;
    const std::string base_dn = engine_.cfg_.base_dn;

    // Regex to extract all {GUID} tokens from a gPLink string
    std::regex guid_re(R"(\{([0-9A-Fa-f\-]{36})\})");

    // ── Query 2: containers with gPLink ──────────────────────────────────────
    // search() uses cfg_.base_dn — temporarily set to domain root so the
    // subtree search covers all sites, domains, and OUs that carry gPLink.
    const std::string saved_base2 = engine_.cfg_.base_dn;
    engine_.cfg_.base_dn = base_dn;

    engine_.search(
        "(gPLink=*)",
        {"distinguishedName", "gPLink", "gPOptions"},
        [&](const LDAPEngine::AttrMap& e) {
            auto dn_it = e.find("distinguishedName");
            auto lk_it = e.find("gPLink");
            if (dn_it == e.end() || dn_it->second.empty()) return;
            if (lk_it == e.end() || lk_it->second.empty()) return;

            const std::string container_dn = dn_it->second[0];
            const std::string gp_link      = lk_it->second[0];

            auto begin = std::sregex_iterator(gp_link.begin(), gp_link.end(), guid_re);
            auto end   = std::sregex_iterator();
            for (auto it = begin; it != end; ++it) {
                std::string guid_key = "{" + (*it)[1].str() + "}";
                std::transform(guid_key.begin(), guid_key.end(), guid_key.begin(),
                    [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
                lmap[guid_key].containers.push_back(container_dn);
                lmap[guid_key].link_texts.push_back(gp_link);
            }
        });

    engine_.cfg_.base_dn = saved_base2;  // always restore

    return lmap;
}

// ─────────────────────────────────────────────────────────────────────────────
//  is_enforced
//  A GPO link is enforced when the flag after the semicolon has bit 2 set.
//  gPLink format: "[LDAP://CN={GUID},...;FLAG][...]"
// ─────────────────────────────────────────────────────────────────────────────
bool GPOCollector::is_enforced(const std::vector<std::string>& link_texts,
                                const std::string& cn_guid)
{
    // Build a regex that matches the block containing this CN-GUID
    // Pattern: [LDAP://...{GUID}...;N] where N & 2 != 0
    // Escape { and } since they are special in std::regex
    std::string escaped;
    escaped.reserve(cn_guid.size() + 4);
    for (char c : cn_guid) {
        if (c == '{' || c == '}') escaped += '\\';
        escaped += c;
    }
    std::string pattern_str =
        R"(\[LDAP://[^\]]*)" + escaped + R"([^\]]*;(\d+)\])";
    std::regex pat(pattern_str, std::regex::icase);

    for (const auto& text : link_texts) {
        auto begin = std::sregex_iterator(text.begin(), text.end(), pat);
        auto end   = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            int flags = std::stoi((*it)[1].str());
            if (flags & 2) return true;
        }
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  is_link_disabled
//  A GPO link is disabled when flag bit 1 is set.
// ─────────────────────────────────────────────────────────────────────────────
bool GPOCollector::is_link_disabled(const std::vector<std::string>& link_texts,
                                     const std::string& cn_guid)
{
    // Escape { and } since they are special in std::regex
    std::string escaped_ld;
    escaped_ld.reserve(cn_guid.size() + 4);
    for (char c : cn_guid) {
        if (c == '{' || c == '}') escaped_ld += '\\';
        escaped_ld += c;
    }
    std::string pattern_str =
        R"(\[LDAP://[^\]]*)" + escaped_ld + R"([^\]]*;(\d+)\])";
    std::regex pat(pattern_str, std::regex::icase);

    for (const auto& text : link_texts) {
        auto begin = std::sregex_iterator(text.begin(), text.end(), pat);
        auto end   = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            int flags = std::stoi((*it)[1].str());
            if (flags & 1) return true;
        }
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  parse_isaclprotected
//  Checks SE_DACL_PROTECTED (0x1000) in the Control field of the Security
//  Descriptor binary blob.  Mirrors gpos.py::_parse_isaclprotected().
//
//  SD layout:
//    Offset 0  : Revision (1 byte)
//    Offset 1  : Sbz1     (1 byte)
//    Offset 2-3: Control  (2 bytes, LE)
// ─────────────────────────────────────────────────────────────────────────────
bool GPOCollector::parse_isaclprotected(const std::string& sd_raw) {
    if (sd_raw.size() < 4) return false;
    const auto* b = reinterpret_cast<const unsigned char*>(sd_raw.data());
    uint16_t control = static_cast<uint16_t>(b[2]) | (static_cast<uint16_t>(b[3]) << 8);
    return (control & 0x1000) != 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  parse_sd_owner
//  Extracts the Owner SID from a binary Security Descriptor.
//  Mirrors gpos.py::_parse_sd_owner().
//
//  SD layout (offsets):
//    4-7  : OffsetOwner (4 bytes, LE)
// ─────────────────────────────────────────────────────────────────────────────
std::string GPOCollector::parse_sd_owner(const std::string& sd_raw) {
    if (sd_raw.size() < 20) return "";
    const auto* b = reinterpret_cast<const unsigned char*>(sd_raw.data());
    uint32_t offset_owner = static_cast<uint32_t>(b[4])
                          | (static_cast<uint32_t>(b[5]) << 8)
                          | (static_cast<uint32_t>(b[6]) << 16)
                          | (static_cast<uint32_t>(b[7]) << 24);
    if (offset_owner == 0 || offset_owner >= sd_raw.size()) return "";

    const auto* sid_b = reinterpret_cast<const unsigned char*>(sd_raw.data() + offset_owner);
    const size_t sid_len = sd_raw.size() - offset_owner;
    return sid_to_string(std::string(reinterpret_cast<const char*>(sid_b), sid_len));
}

// ─────────────────────────────────────────────────────────────────────────────
//  sid_to_string
//  Handles raw binary and double-escaped \\uXXXX forms.
//  See ou_collector.cpp for full commentary.
// ─────────────────────────────────────────────────────────────────────────────
static std::string sid_bytes_to_str_gpo(const unsigned char* b, size_t len) {
    if (len < 8 || b[0] != 1) return "";
    const int revision  = b[0];
    const int sub_count = b[1];
    uint64_t  authority = 0;
    for (int i = 2; i < 8; ++i) authority = (authority << 8) | b[i];
    if (static_cast<size_t>(8 + sub_count * 4) > len) return "";
    std::ostringstream o;
    o << "S-" << revision << "-" << authority;
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

std::string GPOCollector::sid_to_string(const std::string& raw) {
    if (raw.empty()) return "";
    if (raw.size() >= 2 && raw[0] == 'S' && raw[1] == '-') return raw;

    // Double-escaped \\uXXXX
    if (raw.find("\\u") != std::string::npos) {
        std::vector<unsigned char> buf;
        buf.reserve(28);
        size_t i = 0;
        while (i < raw.size()) {
            if (raw[i] == '\\' && i + 5 <= raw.size() && raw[i+1] == 'u') {
                const char* hex = raw.c_str() + i + 2;
                bool all_hex = true;
                for (int k = 0; k < 4; ++k)
                    if (!std::isxdigit(static_cast<unsigned char>(hex[k])))
                    { all_hex = false; break; }
                if (all_hex) {
                    buf.push_back(static_cast<unsigned char>(
                        std::stoi(std::string(hex, 4), nullptr, 16) & 0xFF));
                    i += 6;
                    continue;
                }
            }
            buf.push_back(static_cast<unsigned char>(raw[i]));
            ++i;
        }
        if (!buf.empty()) {
            std::string r = sid_bytes_to_str_gpo(buf.data(), buf.size());
            if (!r.empty()) return r;
        }
    }

    // Raw binary
    const auto* b = reinterpret_cast<const unsigned char*>(raw.data());
    return sid_bytes_to_str_gpo(b, raw.size());
}

// ─────────────────────────────────────────────────────────────────────────────
//  parse_extension_guids_json
//  Parses gPCUserExtensionNames / gPCMachineExtensionNames.
//  Format: [{GUID1}{GUID2...}][{GUID3}...]
//  Returns a JSON array: [{"guid":"{...}","name":"Registry Settings"}, ...]
//  Deduplicates GUIDs.
// ─────────────────────────────────────────────────────────────────────────────
std::string GPOCollector::parse_extension_guids_json(const std::string& ext_str) {
    if (ext_str.empty()) return "[]";

    std::regex guid_re(R"(\{([0-9A-Fa-f\-]{36})\})");
    std::vector<std::string> objs;
    std::set<std::string> seen;

    auto begin = std::sregex_iterator(ext_str.begin(), ext_str.end(), guid_re);
    auto end   = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        std::string guid = "{" + (*it)[1].str() + "}";
        std::transform(guid.begin(), guid.end(), guid.begin(),
            [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
        if (seen.count(guid)) continue;
        seen.insert(guid);

        // Look up human name
        std::string ext_name = "Unknown Extension";
        for (int i = 0; EXTENSION_GUID_MAP[i].first != nullptr; ++i) {
            if (guid == EXTENSION_GUID_MAP[i].first) {
                ext_name = EXTENSION_GUID_MAP[i].second;
                break;
            }
        }
        std::ostringstream o;
        o << "{\"guid\":" << je(guid) << ",\"name\":" << je(ext_name) << "}";
        objs.push_back(o.str());
    }

    return ja_obj(objs);
}

// ─────────────────────────────────────────────────────────────────────────────
//  is_high_value
//  Mirrors gpos.py HIGH_VALUE_GUIDS check + settings-text heuristic.
// ─────────────────────────────────────────────────────────────────────────────
bool GPOCollector::is_high_value(const std::string& cn_guid,
                                  const std::string& user_ext,
                                  const std::string& machine_ext)
{
    // Check well-known GUIDs
    for (int i = 0; HIGH_VALUE_GUIDS[i] != nullptr; ++i) {
        if (cn_guid == HIGH_VALUE_GUIDS[i]) return true;
    }
    // Extension heuristic: script / registry / password markers
    std::string combined = user_ext + " " + machine_ext;
    std::transform(combined.begin(), combined.end(), combined.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    if (combined.find("script") != std::string::npos)   return true;
    if (combined.find("registry") != std::string::npos) return true;
    if (combined.find("password") != std::string::npos) return true;
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  guid_to_string
//  Converts 16-byte little-endian binary GUID to UUID string.
//  If the input is already a string (> 16 chars), returns it uppercased.
// ─────────────────────────────────────────────────────────────────────────────
std::string GPOCollector::guid_to_string(const std::string& raw) {
    if (raw.empty()) return "";
    if (raw.size() > 16) {
        std::string up = raw;
        std::transform(up.begin(), up.end(), up.begin(),
            [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
        return up;
    }
    if (raw.size() != 16) return "";
    const auto* b = reinterpret_cast<const unsigned char*>(raw.data());
    std::ostringstream o;
    o << std::hex << std::uppercase << std::setfill('0');
    // Data1: 4 bytes LE
    for (int i : {3,2,1,0}) o << std::setw(2) << (int)b[i];
    o << "-";
    // Data2: 2 bytes LE
    for (int i : {5,4}) o << std::setw(2) << (int)b[i];
    o << "-";
    // Data3: 2 bytes LE
    for (int i : {7,6}) o << std::setw(2) << (int)b[i];
    o << "-";
    // Data4: 8 bytes BE, split 2+6
    for (int i = 8; i < 10; ++i) o << std::setw(2) << (int)b[i];
    o << "-";
    for (int i = 10; i < 16; ++i) o << std::setw(2) << (int)b[i];
    return o.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  generalized_time_to_iso
//  "YYYYMMDDHHmmss.0Z" → "YYYY-MM-DDTHH:MM:SSZ"
// ─────────────────────────────────────────────────────────────────────────────
std::string GPOCollector::generalized_time_to_iso(const std::string& gt) {
    if (gt.size() < 14) return gt;
    for (int i = 0; i < 14; ++i)
        if (!std::isdigit(static_cast<unsigned char>(gt[i]))) return gt;
    return gt.substr(0,4) + "-" + gt.substr(4,2) + "-" + gt.substr(6,2)
         + "T" + gt.substr(8,2) + ":" + gt.substr(10,2) + ":" + gt.substr(12,2) + "Z";
}

// ─────────────────────────────────────────────────────────────────────────────
//  extract_domain_name
//  "DC=corp,DC=local" → "corp.local"
// ─────────────────────────────────────────────────────────────────────────────
std::string GPOCollector::extract_domain_name(const std::string& base_dn) {
    std::string result;
    std::string dn = base_dn;
    std::transform(dn.begin(), dn.end(), dn.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    size_t pos = 0;
    while (pos < dn.size()) {
        size_t eq = dn.find('=', pos);
        if (eq == std::string::npos) break;
        size_t comma = dn.find(',', eq + 1);
        std::string component = dn.substr(eq + 1,
            (comma != std::string::npos ? comma : dn.size()) - eq - 1);
        if (!result.empty()) result += ".";
        result += component;
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  JSON helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string GPOCollector::je(const std::string& s) {
    std::ostringstream o; o << '"';
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
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                      << (int)ch << std::dec;
                else
                    o << (char)ch;
        }
    }
    o << '"'; return o.str();
}
std::string GPOCollector::jb(bool v)    { return v ? "true" : "false"; }
std::string GPOCollector::ji(int v)     { return std::to_string(v); }
std::string GPOCollector::jnull()       { return "null"; }
std::string GPOCollector::ja(const std::vector<std::string>& v) {
    std::ostringstream o; o << '[';
    for (size_t i = 0; i < v.size(); ++i) { if (i) o << ','; o << je(v[i]); }
    o << ']'; return o.str();
}
std::string GPOCollector::ja_obj(const std::vector<std::string>& v) {
    std::ostringstream o; o << '[';
    for (size_t i = 0; i < v.size(); ++i) { if (i) o << ','; o << v[i]; }
    o << ']'; return o.str();
}
std::string GPOCollector::now_iso8601() {
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