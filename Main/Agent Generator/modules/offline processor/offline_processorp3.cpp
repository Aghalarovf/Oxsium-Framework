// ─── offline_processor_p3.cpp ───────────────────────────────────────────────
// parse_raw_user, user JSON serialization, group processing
// ─────────────────────────────────────────────────────────────────────────────
#include "offline_processor.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <ctime>

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 9 — parse_raw_user
//  Converts one user JSON object from raw_users.jsonl into a ProcessedUser.
//
//  UserCollector field names (jsonl):
//    "username"        → sAMAccountName
//    "dn"              → distinguishedName
//    "display_name"    → displayName
//    "sid"             → decoded objectSid
//    "upn"             → userPrincipalName
//    "description"     → description
//    "mail"            → mail
//    "phone"           → telephoneNumber
//    "department"      → department
//    "title"           → title
//    "disabled/locked_out/..." → UAC flag booleans (already decoded)
//    "spn"             → servicePrincipalName array
//    "member_of"       → memberOf DN array
//    "primary_group_id"→ primaryGroupID int
//    "domain_sid"      → domain SID string
//    "when_created/when_changed" → generalized time (already ISO)
//    "last_logon/pwd_last_set"   → filetime (already ISO by collector)
//    "logon_count/bad_pwd_count" → int
//    "msds_allowedtodelegateto"  → array
//    "has_key_credential_link"   → bool
//    "msds_resultant_pso"        → string
//    "script_path/home_directory/home_drive" → strings
// ═════════════════════════════════════════════════════════════════════════════
ProcessedUser OfflineProcessor::parse_raw_user(const std::string& obj) const {
    ProcessedUser u;

    // Identity — UserCollector field names
    u.username     = jp_str(obj, "username");
    u.dn           = jp_str(obj, "dn");
    u.display_name = jp_str(obj, "display_name");
    u.upn          = jp_str(obj, "upn");
    u.description  = jp_str(obj, "description");
    u.mail         = jp_str(obj, "mail");
    u.phone        = jp_str(obj, "phone");
    u.department   = jp_str(obj, "department");
    u.title        = jp_str(obj, "title");
    u.script_path  = jp_str(obj, "script_path");
    u.home_directory = jp_str(obj, "home_directory");
    u.home_drive   = jp_str(obj, "home_drive");
    u.msds_resultant_pso = jp_str(obj, "msds_resultant_pso");

    // SID — collector has already decoded and written as a string
    u.sid = upper(jp_str(obj, "sid"));
    u.domain_sid  = jp_str(obj, "domain_sid");
    if (u.domain_sid.empty() && !u.sid.empty()) {
        auto pos = u.sid.rfind('-');
        if (pos != std::string::npos) u.domain_sid = u.sid.substr(0, pos);
    }

    // UAC flags — collector has already written as booleans
    u.disabled           = jp_bool(obj, "disabled",          false);
    u.locked_out         = jp_bool(obj, "locked_out",         false);
    u.smartcard_required = jp_bool(obj, "smartcard_required", false);
    u.normal_account     = jp_bool(obj, "normal_account",     true);
    u.pwd_never_expires  = jp_bool(obj, "pwd_never_expires",  false);
    u.pwd_not_required   = jp_bool(obj, "pwd_not_required",   false);
    u.pwd_cant_change    = jp_bool(obj, "pwd_cant_change",    false);
    u.preauth_required   = jp_bool(obj, "preauth_required",   true);

    // must_change_pwd: collector writes "false" as constant; derive from pwd_last_set==0
    u.must_change_pwd = jp_bool(obj, "must_change_pwd", false);
    // Additional check: if pwd_last_set is "0"
    if (!u.must_change_pwd) {
        std::string pls = jp_str(obj, "pwd_last_set");
        if (pls == "0") u.must_change_pwd = true;
    }

    // Timestamps — collector may write generalized-time (20230415T123045.0Z) or
    // ISO-8601 with +00:00 timezone.  Normalise both to "…Z" (Python convention).
    auto norm_ts = [](const std::string& ts) -> std::string {
        if (ts.empty()) return ts;
        // "+00:00" → "Z"
        if (ts.size() >= 6 && ts.substr(ts.size() - 6) == "+00:00")
            return ts.substr(0, ts.size() - 6) + "Z";
        return ts;
    };
    {
        std::string wc = jp_str(obj, "when_created");
        std::string iso = generalized_time_to_iso(wc);
        u.when_created = iso.empty() ? norm_ts(wc) : iso;
    }
    {
        std::string wc = jp_str(obj, "when_changed");
        std::string iso = generalized_time_to_iso(wc);
        u.when_changed = iso.empty() ? norm_ts(wc) : iso;
    }
    u.last_logon   = norm_ts(jp_str(obj, "last_logon"));
    u.pwd_last_set = norm_ts(jp_str(obj, "pwd_last_set"));
    u.bad_pwd_time = norm_ts(jp_str(obj, "bad_pwd_time"));

    // account_expires
    {
        std::string ae = jp_str(obj, "account_expires");
        u.account_expires       = ae;
        u.account_never_expires = jp_bool(obj, "account_never_expires", true);
    }

    // Counts
    u.logon_count   = jp_int(obj, "logon_count",   0);
    u.bad_pwd_count = jp_int(obj, "bad_pwd_count",  0);

    // Primary group
    u.primary_group_id = jp_int(obj, "primary_group_id", 0);
    {
        std::string pgs = jp_str(obj, "primary_group_sid");
        if (!pgs.empty()) {
            u.primary_group_sid = pgs;
        } else if (!u.domain_sid.empty() && u.primary_group_id > 0) {
            u.primary_group_sid = u.domain_sid + "-" +
                                  std::to_string(u.primary_group_id);
        }
    }

    // memberOf — collector writes DN array; convert to CN
    for (const auto& dn : jp_arr(obj, "member_of"))
        u.member_of.push_back(cn_from_dn(dn));

    // token_group_sids — computed from DFS table
    if (!u.sid.empty()) {
        for (const auto& [gsid, members] : group_transitive_sids_) {
            if (members.count(u.sid))
                u.token_group_sids.push_back(gsid);
        }
        if (!u.primary_group_sid.empty())
            u.token_group_sids.push_back(upper(u.primary_group_sid));
    }

    // SPNs
    u.spn            = jp_arr(obj, "spn");
    u.kerberoastable = jp_bool(obj, "kerberoastable", false);
    // If kerberoastable is absent from NDJSON, compute it ourselves
    if (!u.kerberoastable && !u.spn.empty() && !u.disabled)
        u.kerberoastable = true;

    // ASREPRoast
    u.asrep = jp_bool(obj, "asrep", false);
    if (!u.asrep) u.asrep = !u.preauth_required;

    // Delegation
    u.msds_allowedtodelegateto       = jp_arr(obj, "msds_allowedtodelegateto");
    u.trusted_for_delegation         = jp_bool(obj, "trusted_for_delegation",         false);
    u.unconstrained_delegation       = jp_bool(obj, "unconstrained_delegation",       false);
    u.constrained_delegation         = jp_bool(obj, "constrained_delegation",         false);
    u.not_delegated                  = jp_bool(obj, "not_delegated",                  false);
    u.trusted_to_auth_for_delegation = jp_bool(obj, "trusted_to_auth_for_delegation", false);

    // Encryption — read raw integer from JSONL (collector now writes it)
    // -1 sentinel = attribute was absent from LDAP (null in JSONL)
    {
        std::string enc_raw = jp_str(obj, "msds_supportedencryptiontypes");
        if (enc_raw.empty() || enc_raw == "null")
            u.msds_supportedencryptiontypes = -1;
        else {
            try { u.msds_supportedencryptiontypes = std::stoi(enc_raw); }
            catch (...) { u.msds_supportedencryptiontypes = -1; }
        }
    }
    // enc_implicit_rc4 from collector is a quick sanity check; analyze_encryption overwrites it
    u.enc_implicit_rc4 = jp_bool(obj, "enc_implicit_rc4", false);

    // Shadow credentials — check both raw list and bool flag
    {
        auto kcl = jp_arr(obj, "key_credential_link");
        u.has_key_credential_link = !kcl.empty() || jp_bool(obj, "has_key_credential_link", false);
    }

    // Domain name
    u.domain_name = base_dn_to_domain(base_dn_);
    if (u.domain_name.empty() && !u.domain_sid.empty()) {
        // Fallback: use ldap_target
        u.domain_name = ldap_target_;
    }

    // Analysis
    analyze_delegation(u);
    analyze_encryption(u);
    analyze_admin(u);

    return u;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 10 — JSON serialization helpers for admin rules
// ═════════════════════════════════════════════════════════════════════════════

std::string OfflineProcessor::json_rule_detail(const PAdminRuleDetail& d) {
    std::ostringstream o;
    o << "{";
    o << "\"matched_rids\":[";
    for (size_t i = 0; i < d.matched_rids.size(); ++i) {
        if (i) { o << ","; } o << d.matched_rids[i];
    }
    o << "],";
    o << "\"matched_sids\":[";
    for (size_t i = 0; i < d.matched_sids.size(); ++i) {
        if (i) { o << ","; } o << je(d.matched_sids[i]);
    }
    o << "],";
    o << "\"matched_groups\":[";
    for (size_t i = 0; i < d.matched_groups.size(); ++i) {
        if (i) { o << ","; } o << je(d.matched_groups[i]);
    }
    o << "],";
    o << "\"match_sources\":[";
    for (size_t i = 0; i < d.match_sources.size(); ++i) {
        if (i) { o << ","; } o << je(d.match_sources[i]);
    }
    o << "]}";
    return o.str();
}

std::string OfflineProcessor::json_admin_rules(const std::vector<PAdminRule>& rules) {
    std::ostringstream o; o << '[';
    for (size_t i = 0; i < rules.size(); ++i) {
        if (i) o << ", ";
        const auto& r = rules[i];
        o << "{\"level\":" << r.level
          << ",\"severity\":" << je(r.severity)
          << ",\"label\":"    << je(r.label);
        if (r.has_detail) o << ",\"detail\":" << json_rule_detail(r.detail);
        o << "}";
    }
    o << ']'; return o.str();
}

std::string OfflineProcessor::json_delegation_arr(const std::vector<PDelegationTarget>& v) {
    std::ostringstream o; o << '[';
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) o << ", ";
        o << "{\"raw\":"          << je(v[i].raw)
          << ",\"service\":"      << je(v[i].service)
          << ",\"hostname\":"     << je(v[i].hostname)
          << ",\"host_fqdn\":"    << je(v[i].host_fqdn)
          << ",\"domain\":"       << je(v[i].domain)
          << ",\"domain_short\":" << je(v[i].domain_short)
          << "}";
    }
    o << ']'; return o.str();
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 11 — user_to_json  (same format as user_enum.cpp user_to_json)
// ═════════════════════════════════════════════════════════════════════════════
std::string OfflineProcessor::user_to_json(const ProcessedUser& u) const {
    std::ostringstream o;
    o << "{";
    o << "\"username\":"           << je(u.username)       << ",";
    o << "\"dn\":"                 << je(u.dn)             << ",";
    o << "\"display_name\":"       << je(u.display_name)   << ",";
    o << "\"sid\":"                << je(u.sid)            << ",";
    o << "\"upn\":"                << je(u.upn)            << ",";
    o << "\"description\":"        << je(u.description)    << ",";
    o << "\"mail\":"               << je(u.mail)           << ",";
    o << "\"phone\":"              << je(u.phone)          << ",";
    o << "\"department\":"         << je(u.department)     << ",";
    o << "\"title\":"              << je(u.title)          << ",";

    o << "\"disabled\":"           << jb(u.disabled)            << ",";
    o << "\"locked_out\":"         << jb(u.locked_out)          << ",";
    o << "\"must_change_pwd\":"    << jb(u.must_change_pwd)     << ",";
    o << "\"smartcard_required\":" << jb(u.smartcard_required)  << ",";
    o << "\"normal_account\":"     << jb(u.normal_account)      << ",";
    o << "\"pwd_never_expires\":"  << jb(u.pwd_never_expires)   << ",";
    o << "\"pwd_not_required\":"   << jb(u.pwd_not_required)    << ",";
    o << "\"pwd_cant_change\":"    << jb(u.pwd_cant_change)     << ",";
    o << "\"preauth_required\":"   << jb(u.preauth_required)    << ",";

    o << "\"is_admin\":"           << jb(u.is_admin)            << ",";
    o << "\"potential_admin\":"    << je(u.potential_admin)     << ",";
    o << "\"is_direct_admin\":"    << jb(u.is_direct_admin)     << ",";
    o << "\"is_nested_admin\":"    << jb(u.is_nested_admin)     << ",";
    o << "\"admin_rules\":"        << json_admin_rules(u.admin_rules) << ",";

    o << "\"dcsync\":"             << jb(u.dcsync)              << ",";
    o << "\"asrep\":"              << jb(u.asrep)               << ",";
    o << "\"kerberoastable\":"     << jb(u.kerberoastable)      << ",";

    o << "\"spn\":"                << ja(u.spn)                 << ",";
    o << "\"trusted_for_delegation\":"         << jb(u.trusted_for_delegation)         << ",";
    o << "\"unconstrained_delegation\":"       << jb(u.unconstrained_delegation)       << ",";
    o << "\"constrained_delegation\":"         << jb(u.constrained_delegation)         << ",";
    o << "\"delegation_effective\":"           << jb(u.delegation_effective)           << ",";
    o << "\"delegation_blocked\":"             << jb(u.delegation_blocked)             << ",";
    o << "\"trusted_to_auth_for_delegation\":" << jb(u.trusted_to_auth_for_delegation) << ",";
    o << "\"protocol_transition_delegation\":" << jb(u.protocol_transition_delegation) << ",";
    o << "\"not_delegated\":"                  << jb(u.not_delegated)                  << ",";
    o << "\"msds_allowedtodelegateto\":"        << ja(u.msds_allowedtodelegateto)      << ",";
    o << "\"msds_allowedtodelegateto_structurized\":"
      << json_delegation_arr(u.msds_allowedtodelegateto_structurized) << ",";

    if (u.msds_supportedencryptiontypes == -1)
        o << "\"msds_supportedencryptiontypes\":null,";
    else
        o << "\"msds_supportedencryptiontypes\":" << ji(u.msds_supportedencryptiontypes) << ",";

    // msds_supportedencryptiontypesname entries are pre-built JSON objects
    // (e.g. {"name":"RC4-HMAC","risk":700,"is_weak":true}) — emit raw, not re-escaped.
    {
        auto emit_enc_arr = [&]() {
            o << '[';
            for (size_t i = 0; i < u.msds_supportedencryptiontypesname.size(); ++i) {
                if (i) o << ',';
                o << u.msds_supportedencryptiontypesname[i]; // already valid JSON
            }
            o << ']';
        };
        o << "\"msds_supportedencryptiontypesname\":";  emit_enc_arr(); o << ',';
        o << "\"msds_supportedencryptiontypes_name\":"; emit_enc_arr(); o << ',';
    }
    o << "\"enc_risk_score\":"    << ji(u.enc_risk_score)   << ",";
    o << "\"enc_implicit_rc4\":"  << jb(u.enc_implicit_rc4) << ",";

    o << "\"member_of\":"         << ja(u.member_of)        << ",";

    o << "\"when_created\":"      << jnl(u.when_created)    << ",";
    o << "\"when_changed\":"      << jnl(u.when_changed)    << ",";
    o << "\"last_logon\":"        << jnl(u.last_logon)      << ",";
    o << "\"pwd_last_set\":"      << jnl(u.pwd_last_set)    << ",";
    o << "\"logon_count\":"       << ji(u.logon_count)      << ",";
    o << "\"domain_sid\":"        << je(u.domain_sid)       << ",";
    o << "\"primary_group_id\":"  << ji(u.primary_group_id) << ",";
    o << "\"primary_group_sid\":" << je(u.primary_group_sid)<< ",";
    o << "\"bad_pwd_count\":"     << ji(u.bad_pwd_count)    << ",";
    o << "\"bad_pwd_time\":"      << jnl(u.bad_pwd_time)    << ",";

    if (u.account_never_expires)
        o << "\"account_expires\":null,";
    else
        o << "\"account_expires\":"  << jnl(u.account_expires) << ",";

    o << "\"account_never_expires\":" << jb(u.account_never_expires) << ",";
    o << "\"msds_resultant_pso\":"    << je(u.msds_resultant_pso)    << ",";
    o << "\"pwd_expiry_time\":"       << jnl(u.pwd_expiry_time)      << ",";

    o << "\"key_credential_link\":"
      << (u.has_key_credential_link ? "[\"<present>\"]" : "[]") << ",";
    o << "\"has_key_credential_link\":" << jb(u.has_key_credential_link) << ",";

    o << "\"script_path\":"    << je(u.script_path)    << ",";
    o << "\"home_directory\":" << je(u.home_directory)  << ",";
    o << "\"home_drive\":"     << je(u.home_drive);
    o << "}";
    return o.str();
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 12 — load_and_process_users
// ═════════════════════════════════════════════════════════════════════════════
bool OfflineProcessor::load_and_process_users(const std::string& raw_path,
                                               const std::string& out_path)
{
    log_info("[OfflineProcessor] Reading raw_users.jsonl: " + raw_path);

    // base_dn — no wrapper in NDJSON, extract from domain_sid
    // First pass reads all lines
    auto raw_users = read_ndjson_lines(raw_path);
    if (raw_users.empty()) {
        log_err("[OfflineProcessor] File not found or empty: " + raw_path);
        return false;
    }

    // If base_dn is still unknown, try to get domain_name from the first user's domain_sid.
    // NDJSON has no base_dn or ldap_target; rebuilding "corp.local" from a SID is not
    // possible, so we leave ldap_target empty.
    // domain_name may already be set from build_lookup_tables (groups lookup).
    if (domain_name_.empty()) {
        // Fallback: store ldap_target as domain placeholder (may remain empty)
        domain_name_ = ldap_target_;
    }

    log_ok("[OfflineProcessor] " + std::to_string(raw_users.size()) +
           " raw users read. Starting analysis...");

    std::ofstream out(out_path, std::ios::binary);
    if (!out) { log_err("[OfflineProcessor] Could not open output file: " + out_path); return false; }

    int dcsync_count = 0;
    std::vector<std::string> rows;
    rows.reserve(raw_users.size());
    for (const auto& raw : raw_users) {
        ProcessedUser u = parse_raw_user(raw);
        if (u.dcsync) ++dcsync_count;
        rows.push_back(user_to_json(u));
    }

    if (is_json_ext(out_path)) {        // JSON mode: full collector-compatible envelope with meta + error
        std::time_t now = std::time(nullptr);
        char ts_buf[32] = {};
        std::strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%S", std::gmtime(&now));
        std::string generated_at = std::string(ts_buf) + ".000000Z";

        // Minimal re-indent for record items (4-space base)
        auto reindent_item = [](const std::string& compact,
                                const std::string& base) -> std::string {
            std::string r; r.reserve(compact.size() * 2);
            int depth = 0; bool in_str = false, escaped = false;
            auto nl = [&]() { r+='\n'; r+=base; for(int i=0;i<depth*2;++i) r+=' '; };
            for (size_t i = 0; i < compact.size(); ++i) {
                const char ch = compact[i];
                if (escaped)            { r+=ch; escaped=false; continue; }
                if (in_str && ch=='\\') { r+=ch; escaped=true;  continue; }
                if (ch=='"')            { in_str=!in_str; r+=ch; continue; }
                if (in_str)             { r+=ch; continue; }
                switch(ch) {
                    case '{': case '[': r+=ch; ++depth; nl(); break;
                    case '}': case ']': --depth; nl(); r+=ch;  break;
                    case ',':           r+=ch; nl();            break;
                    case ':':           r+=':'; r+=' ';         break;
                    default:            r+=ch;                  break;
                }
            }
            return r;
        };

        // meta block
        std::ostringstream meta_ss;
        meta_ss << "{\"dcsync\":{\"enabled\":true"
                << ",\"resolved_sid_count\":" << sid_to_dn_.size()
                << ",\"principal_count\":"    << rows.size()
                << ",\"dcsync_users_count\":" << dcsync_count
                << ",\"error\":null}}";

        out << "{\n";
        out << "  \"generated_at\": \"" << generated_at << "\",\n";
        out << "  \"source\": \"domain\",\n";
        out << "  \"success\": true,\n";
        out << "  \"count\": " << rows.size() << ",\n";
        out << "  \"users\": [\n";
        for (size_t i = 0; i < rows.size(); ++i) {
            out << "    " << reindent_item(rows[i], "    ");
            if (i + 1 < rows.size()) out << ',';
            out << '\n';
        }
        out << "  ],\n";
        out << "  \"meta\": " << reindent_item(meta_ss.str(), "  ") << ",\n";
        out << "  \"error\": null\n";
        out << "}\n";
        out.flush();
    } else {
        // NDJSON mode — write Python-compatible meta header line first,
        // then one JSON object per line (matches Python domain_users.jsonl format).
        std::time_t now_ndjson = std::time(nullptr);
        char ts_ndjson[32] = {};
        std::strftime(ts_ndjson, sizeof(ts_ndjson),
                      "%Y-%m-%dT%H:%M:%S.000000Z", std::gmtime(&now_ndjson));
        out << "{\"generated_at\":\"" << ts_ndjson << "\""
            << ",\"source\":\"domain\""
            << ",\"success\":true"
            << ",\"count\":"            << rows.size()
            << ",\"meta\":{\"dcsync\":{\"enabled\":true"
            << ",\"resolved_sid_count\":" << sid_to_dn_.size()
            << ",\"principal_count\":"    << (sid_to_dn_.size() + rows.size())
            << ",\"dcsync_users_count\":" << dcsync_count
            << ",\"error\":null}}"
            << ",\"error\":null}\n";
        write_objects(out, rows, out_path, "[OfflineProcessor]");
    }
    out.close();

    log_ok("[OfflineProcessor] domain_users written -> " + out_path);
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 13 — Group processing
// ═════════════════════════════════════════════════════════════════════════════

void OfflineProcessor::compute_group_stats(ProcessedGroup& g) const {
    g.member_user_count     = 0;
    g.member_group_count    = 0;
    g.member_computer_count = 0;

    for (const auto& dn : g.transitive_member_dns) {
        std::string udn = upper(dn);
        auto it = dn_to_class_.find(udn);
        if (it == dn_to_class_.end()) {
            // Class unknown — heuristic from DN: ends with "$" → computer
            if (!dn.empty() && (dn.back() == '$' || dn.find("CN=Computers") != std::string::npos))
                ++g.member_computer_count;
            else
                ++g.member_user_count;
        } else {
            std::string cls = lower(it->second);
            if (cls == "user")     ++g.member_user_count;
            else if (cls == "group")    ++g.member_group_count;
            else if (cls == "computer") ++g.member_computer_count;
            else                        ++g.member_user_count;
        }
    }

    // Admin group flag
    static const int ADMIN_RIDS[] = {
        OfflineAdminRID::DOMAIN_ADMINS, OfflineAdminRID::ENTERPRISE_ADMINS,
        OfflineAdminRID::SCHEMA_ADMINS, OfflineAdminRID::BUILTIN_ADMINS,
        OfflineAdminRID::DOMAIN_CONTROLLERS,
        OfflineAdminRID::ENTERPRISE_READONLY_CONTROLLERS,
        OfflineAdminRID::ONLY_DOMAIN_CONTROLLERS, 0
    };
    static const int OPER_RIDS[] = {
        OfflineAdminRID::ACCOUNT_OPERATORS, OfflineAdminRID::SERVER_OPERATORS,
        OfflineAdminRID::BACKUP_OPERATORS,  OfflineAdminRID::PRINT_OPERATORS,
        OfflineAdminRID::CRYPTOGRAPHIC_OPERATORS, OfflineAdminRID::HYPERV_ADMINISTRATORS,
        OfflineAdminRID::STORAGE_REPLICA_ADMINISTRATORS,
        OfflineAdminRID::KEY_ADMINS, OfflineAdminRID::ENTERPRISE_KEY_ADMINS, 0
    };
    for (int i = 0; ADMIN_RIDS[i]; ++i) if (g.rid == ADMIN_RIDS[i]) { g.is_admin_group    = true; break; }
    for (int i = 0; OPER_RIDS[i];  ++i) if (g.rid == OPER_RIDS[i])  { g.is_operator_group = true; break; }
}

ProcessedGroup OfflineProcessor::parse_raw_group(const std::string& obj) const {
    ProcessedGroup g;
    // GroupCollector field names: "name"/"sam_name", "dn", "sid"/"group_sid"
    g.sam_account_name = jp_str(obj, "sam_name");
    if (g.sam_account_name.empty()) g.sam_account_name = jp_str(obj, "name");
    g.dn               = jp_str(obj, "dn");
    g.display_name     = g.sam_account_name;  // GroupCollector does not write displayName
    g.description      = jp_str(obj, "description");
    g.sid              = upper(jp_str(obj, "sid"));
    if (g.sid.empty()) g.sid = upper(jp_str(obj, "group_sid"));
    g.rid              = rid_from_sid(g.sid);
    // group_type: string like "Security / Domain Local"
    g.group_type       = jp_str(obj, "group_type");
    // group_scope: extract from group_type string
    {
        const std::string& gt = g.group_type;
        if      (gt.find("Global")       != std::string::npos) g.group_scope = "Global";
        else if (gt.find("Domain Local") != std::string::npos) g.group_scope = "Domain Local";
        else if (gt.find("Universal")    != std::string::npos) g.group_scope = "Universal";
        else                                                    g.group_scope = "Unknown";
        if      (gt.find("Security")     != std::string::npos) g.group_type = gt;
    }
    g.managed_by       = jp_str(obj, "managed_by");
    // admin_count: extract from risk_controls
    {
        auto risks = jp_arr(obj, "risk_controls");
        bool prot = false;
        for (const auto& r : risks)
            if (r == "AdminSDHolder Protected") { prot = true; break; }
        g.admin_count  = prot ? "1" : "0";
        g.is_protected = jp_bool(obj, "is_protected", false) || prot;
    }
    g.when_created     = generalized_time_to_iso(jp_str(obj, "when_created"));
    if (g.when_created.empty()) g.when_created = jp_str(obj, "when_created");
    g.when_changed     = generalized_time_to_iso(jp_str(obj, "when_changed"));
    if (g.when_changed.empty()) g.when_changed = jp_str(obj, "when_changed");

    // members: "members" array — direct member DNs
    g.direct_member_dns  = jp_arr(obj, "members");
    // member_of: groups that this group itself belongs to
    g.member_of          = jp_arr(obj, "member_of");

    // transitive_member_dns — populated from lookup table
    {
        const auto& tm_it = group_transitive_sids_.find(g.sid);
        if (tm_it != group_transitive_sids_.end()) {
            g.transitive_member_count = static_cast<int>(tm_it->second.size());
            for (const auto& msid : tm_it->second) {
                g.transitive_member_sids.push_back(msid);
                auto dn_it = sid_to_dn_.find(msid);
                if (dn_it != sid_to_dn_.end())
                    g.transitive_member_dns.push_back(dn_it->second);
            }
        } else {
            g.transitive_member_count = static_cast<int>(g.direct_member_dns.size());
        }
    }

    compute_group_stats(g);
    return g;
}

std::string OfflineProcessor::group_to_json(const ProcessedGroup& g) const {
    std::ostringstream o;
    o << "{";
    o << "\"sam_account_name\": "           << je(g.sam_account_name)           << ",";
    o << "\"distinguished_name\": "         << je(g.dn)                         << ",";
    o << "\"display_name\": "               << je(g.display_name)               << ",";
    o << "\"description\": "                << je(g.description)                << ",";
    o << "\"object_sid\": "                 << je(g.sid)                        << ",";
    o << "\"rid\": "                        << ji(g.rid)                        << ",";
    o << "\"group_type\": "                 << je(g.group_type)                 << ",";
    o << "\"group_scope\": "                << je(g.group_scope)                << ",";
    o << "\"managed_by\": "                 << je(g.managed_by)                 << ",";
    o << "\"admin_count\": "                << je(g.admin_count)                << ",";
    o << "\"is_protected_by_sdprop\": "     << jb(g.is_protected)               << ",";
    o << "\"is_admin_group\": "             << jb(g.is_admin_group)             << ",";
    o << "\"is_operator_group\": "          << jb(g.is_operator_group)          << ",";
    o << "\"when_created\": "               << jnl(g.when_created)              << ",";
    o << "\"when_changed\": "               << jnl(g.when_changed)              << ",";
    o << "\"direct_member_count\": "        << ji((int)g.direct_member_dns.size()) << ",";
    o << "\"direct_member_dns\": "          << ja(g.direct_member_dns)          << ",";
    o << "\"member_of\": "                  << ja(g.member_of)                  << ",";
    o << "\"transitive_member_count\": "    << ji(g.transitive_member_count)    << ",";
    o << "\"member_user_count\": "          << ji(g.member_user_count)          << ",";
    o << "\"member_group_count\": "         << ji(g.member_group_count)         << ",";
    o << "\"member_computer_count\": "      << ji(g.member_computer_count)      << ",";
    o << "\"transitive_member_dns\": "      << ja(g.transitive_member_dns)      << ",";
    o << "\"transitive_member_sids\": "     << ja(g.transitive_member_sids)     ;
    o << "}";
    return o.str();
}

bool OfflineProcessor::load_and_process_groups(const std::string& raw_path,
                                                const std::string& out_path)
{
    log_info("[OfflineProcessor] Reading raw_groups.jsonl: " + raw_path);
    auto raw_groups = read_ndjson_lines(raw_path);
    log_ok("[OfflineProcessor] " + std::to_string(raw_groups.size()) +
           " raw groups read. Starting analysis...");

    std::ofstream out(out_path, std::ios::binary);
    if (!out) { log_err("[OfflineProcessor] Could not open output file: " + out_path); return false; }

    int admin_count = 0, oper_count = 0;
    std::vector<std::string> rows;
    rows.reserve(raw_groups.size());
    for (const auto& raw : raw_groups) {
        ProcessedGroup g = parse_raw_group(raw);
        if (g.is_admin_group)    ++admin_count;
        if (g.is_operator_group) ++oper_count;
        rows.push_back(group_to_json(g));
    }
    write_objects(out, rows, out_path, "[OfflineProcessor]");
    out.close();

    log_ok("[OfflineProcessor] domain_groups written -> " + out_path);
    return true;
}
//  (process_users, process_groups, process_aces, process)
// ─────────────────────────────────────────────────────────────────────────────