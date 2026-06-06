// ─── offline_processorp6.cpp ─────────────────────────────────────────────────
// SECTION 24  Delegation target parser
// SECTION 25  parse_raw_computer  — raw_computers.ndjson → ProcessedComputer
// SECTION 26  analyze_computer_delegation — Kerberos delegation analysis
// SECTION 27  analyze_computer_risk  — attack path / risk scoring
// SECTION 28  computer_to_json  — serialization
// SECTION 29  load_and_process_computers
// SECTION 30  process_computers  (public entry point)
//             process()  — updated to include computers
//
//  Input : raw_cache/raw_computers.ndjson   (ComputerCollector output)
//  Output: Domain Objects/domain_computers.ndjson
//
//  Each output line is one computer object with all enriched fields.
//
//  Reading (Python):
//    import json
//    with open("domain_computers.ndjson") as f:
//        for line in f:
//            computer = json.loads(line)
// ─────────────────────────────────────────────────────────────────────────────
#include "offline_processor.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 24 — Delegation target parser  (mirrors analyze_delegation for users)
// ═════════════════════════════════════════════════════════════════════════════

// Parses "service/hostname.domain.local" → PDelegationTarget
static PDelegationTarget parse_delegation_target(const std::string& raw) {
    PDelegationTarget t;
    t.raw = raw;

    // Split on first '/'
    auto slash = raw.find('/');
    if (slash == std::string::npos) {
        t.service  = raw;
        t.hostname = raw;
        return t;
    }

    t.service = raw.substr(0, slash);

    // Everything after slash: hostname.domain.local  or  hostname:port
    std::string rest = raw.substr(slash + 1);

    // Strip port if present (hostname:port/extra)
    auto colon = rest.find(':');
    std::string host_full = (colon != std::string::npos) ? rest.substr(0, colon) : rest;
    // Strip trailing /...
    auto slash2 = host_full.find('/');
    if (slash2 != std::string::npos) host_full = host_full.substr(0, slash2);

    t.host_fqdn = host_full;

    // Split hostname vs domain at first dot
    auto dot = host_full.find('.');
    if (dot != std::string::npos) {
        t.hostname     = host_full.substr(0, dot);
        t.domain       = host_full.substr(dot + 1);
        // Short domain: first label before the next dot
        auto dot2 = t.domain.find('.');
        t.domain_short = (dot2 != std::string::npos) ? t.domain.substr(0, dot2) : t.domain;
    } else {
        t.hostname = host_full;
    }

    return t;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 25 — parse_raw_computer
//
//  Reads one NDJSON line (from raw_computers.ndjson) and fills a
//  ProcessedComputer. Field names match ComputerCollector's schema exactly
//  (see computer_collector.h).
// ═════════════════════════════════════════════════════════════════════════════
ProcessedComputer OfflineProcessor::parse_raw_computer(const std::string& obj) const
{
    ProcessedComputer c;

    // ── Identity ──────────────────────────────────────────────────────────────
    c.computer_name = jp_str(obj, "computer_name");
    c.dns_name      = jp_str(obj, "dns_name");
    c.dn            = jp_str(obj, "dn");
    c.display_name  = jp_str(obj, "display_name");
    c.description   = jp_str(obj, "description");
    c.location      = jp_str(obj, "location");

    c.sid = upper(jp_str(obj, "sid"));
    {
        std::string ds = jp_str(obj, "domainsid");
        if (!ds.empty()) {
            c.domain_sid = ds;
        } else if (!c.sid.empty()) {
            auto pos = c.sid.rfind('-');
            if (pos != std::string::npos) c.domain_sid = c.sid.substr(0, pos);
        }
    }

    // ── State ─────────────────────────────────────────────────────────────────
    c.disabled = jp_bool(obj, "disabled", false);

    // ── OS ────────────────────────────────────────────────────────────────────
    c.os              = jp_str(obj, "os");
    c.os_version      = jp_str(obj, "os_version");
    c.os_service_pack = jp_str(obj, "os_service_pack");
    c.os_bucket       = jp_str(obj, "os_bucket");

    // ── Type flags ────────────────────────────────────────────────────────────
    c.is_workstation       = jp_bool(obj, "is_workstation",       false);
    c.is_server            = jp_bool(obj, "is_server",            false);
    c.is_domain_controller = jp_bool(obj, "is_domain_controller", false);
    c.potential_privileged = jp_bool(obj, "potential_privileged", false);

    // ── Stale ─────────────────────────────────────────────────────────────────
    c.is_stale       = jp_bool(obj, "is_stale",       false);
    c.stale_by_pwd   = jp_bool(obj, "stale_by_pwd",   false);
    c.stale_by_logon = jp_bool(obj, "stale_by_logon", false);

    // ── SPN ───────────────────────────────────────────────────────────────────
    c.spn     = jp_arr(obj, "spn");
    c.has_spn = jp_bool(obj, "has_spn", !c.spn.empty());

    // ── Delegation ────────────────────────────────────────────────────────────
    c.trusted_for_delegation         = jp_bool(obj, "trusted_for_delegation",         false);
    c.trusted_to_auth_for_delegation = jp_bool(obj, "trusted_to_auth_for_delegation", false);
    c.unconstrained_delegation       = jp_bool(obj, "unconstrained_delegation",       false);
    c.constrained_delegation         = jp_bool(obj, "constrained_delegation",         false);
    c.allowed_to_delegate_to         = jp_arr(obj,  "allowed_to_delegate_to");

    // ── RBCD ──────────────────────────────────────────────────────────────────
    c.rbcd_enabled    = jp_bool(obj, "rbcd_enabled",   false);
    c.rbcd_sddl       = jp_str (obj, "rbcd_sddl");
    c.rbcd_principals = jp_arr (obj,  "rbcd_principals");

    // ── LAPS ──────────────────────────────────────────────────────────────────
    c.has_laps        = jp_bool(obj, "has_laps",  false);
    c.haslaps         = jp_bool(obj, "haslaps",   false);
    c.laps_expiration = jp_str(obj,  "laps_expiration");

    // laps_attributes: parse each known key from the nested JSON object.
    // The field is a JSON object: {"ms-Mcs-AdmPwd":[], "msLAPS-Password":[], ...}
    // We extract it as a sub-string and call jp_arr per key.
    {
        static const char* LAPS_ATTR_KEYS[] = {
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
        // Locate the laps_attributes object within the NDJSON line
        const std::string la_key = "\"laps_attributes\"";
        size_t la_pos = obj.find(la_key);
        if (la_pos != std::string::npos) {
            size_t brace = obj.find('{', la_pos + la_key.size());
            if (brace != std::string::npos) {
                // Find matching closing brace (no nesting beyond arrays inside)
                size_t depth = 1, end = brace + 1;
                while (end < obj.size() && depth > 0) {
                    if (obj[end] == '{') ++depth;
                    else if (obj[end] == '}') --depth;
                    ++end;
                }
                std::string la_obj = obj.substr(brace, end - brace);
                for (int i = 0; LAPS_ATTR_KEYS[i] != nullptr; ++i) {
                    c.laps_attributes[LAPS_ATTR_KEYS[i]] = jp_arr(la_obj, LAPS_ATTR_KEYS[i]);
                }
            }
        }
        // Ensure all keys are present even if object was absent
        for (int i = 0; LAPS_ATTR_KEYS[i] != nullptr; ++i) {
            if (c.laps_attributes.find(LAPS_ATTR_KEYS[i]) == c.laps_attributes.end())
                c.laps_attributes[LAPS_ATTR_KEYS[i]] = {};
        }
    }

    // ── ACL ───────────────────────────────────────────────────────────────────
    c.isaclprotected = jp_bool(obj, "isaclprotected", false);

    // ── SID history ───────────────────────────────────────────────────────────
    c.sid_history = jp_arr(obj, "sid_history");

    // ── Primary group ─────────────────────────────────────────────────────────
    c.primary_group_id = jp_int(obj, "primary_group_id", 0);
    if (!c.domain_sid.empty() && c.primary_group_id > 0)
        c.primary_group_sid = c.domain_sid + "-" + std::to_string(c.primary_group_id);

    // ── Token group SIDs (built from transitive membership table) ─────────────
    if (!c.sid.empty()) {
        for (const auto& [gsid, members] : group_transitive_sids_) {
            if (members.count(c.sid))
                c.token_group_sids.push_back(gsid);
        }
        if (!c.primary_group_sid.empty())
            c.token_group_sids.push_back(upper(c.primary_group_sid));
    }

    // ── Risk controls (forwarded as-is from collector) ─────────────────────────
    c.risk_controls = jp_arr(obj, "risk_controls");

    // ── Network stubs ─────────────────────────────────────────────────────────
    // Collector writes null for unprobed fields; detect presence via string check
    {
        std::string probe = jp_str(obj, "smb_port_open");
        c.net_probed = (!probe.empty() && probe != "null");
        if (c.net_probed) {
            c.smb_port_open        = jp_bool(obj, "smb_port_open",        false);
            c.smb_signing_required = jp_bool(obj, "smb_signing_required", false);
        }
    }
    c.smb_version    = jp_str(obj, "smb_version");
    c.ipv4_addresses = jp_arr(obj, "ipv4_addresses");
    c.ipv6_addresses = jp_arr(obj, "ipv6_addresses");
    {
        std::string is_ip = jp_str(obj, "is_ip_only");
        c.is_ip_only = (is_ip == "true");
    }

    // ── Timestamps ────────────────────────────────────────────────────────────
    // when_created / when_changed come from ComputerCollector as ISO-8601 already
    // (collector now calls generalized_time_to_iso). Apply it defensively here
    // too so that any legacy raw_computers.ndjson with the old "YYYYMMDDHHmmss.0Z"
    // format is also handled correctly, mirroring how groups are parsed.
    {
        std::string wc = jp_str(obj, "when_created");
        c.when_created = generalized_time_to_iso(wc);
        if (c.when_created.empty()) c.when_created = wc;
    }
    {
        std::string wch = jp_str(obj, "when_changed");
        c.when_changed = generalized_time_to_iso(wch);
        if (c.when_changed.empty()) c.when_changed = wch;
    }
    c.last_logon   = jp_str(obj, "last_logon");
    c.pwd_last_set = jp_str(obj, "pwd_last_set");

    // ── Domain name ───────────────────────────────────────────────────────────
    c.domain_name = base_dn_to_domain(base_dn_);
    if (c.domain_name.empty()) c.domain_name = ldap_target_;

    // ── Enrichment passes ─────────────────────────────────────────────────────
    analyze_computer_delegation(c);
    analyze_computer_risk(c);

    return c;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 26 — analyze_computer_delegation
//
//  Populates:
//    - unconstrained_delegation          : TRUSTED_FOR_DELEGATION && !DC
//    - constrained_delegation            : msDS-AllowedToDelegateTo non-empty
//    - protocol_transition_delegation    : TRUSTED_TO_AUTH_FOR_DELEGATION && constrained
//    - delegation_effective              : any active delegation form
//    - allowed_to_delegate_to_structured : parsed PDelegationTarget list
//    - rbcd_principal_names              : SID → SAM name resolution
// ═════════════════════════════════════════════════════════════════════════════
void OfflineProcessor::analyze_computer_delegation(ProcessedComputer& c) const
{
    // Unconstrained delegation: TRUSTED_FOR_DELEGATION set and not a DC.
    // DCs always carry this bit as part of normal operation — not a finding.
    c.unconstrained_delegation = c.trusted_for_delegation && !c.is_domain_controller;

    // Constrained delegation: msDS-AllowedToDelegateTo is non-empty
    c.constrained_delegation = !c.allowed_to_delegate_to.empty();

    // Protocol transition: TRUSTED_TO_AUTH_FOR_DELEGATION + constrained targets
    c.protocol_transition_delegation =
        c.trusted_to_auth_for_delegation && c.constrained_delegation;

    // Effective delegation flag — any active delegation form is present
    c.delegation_effective =
        c.unconstrained_delegation ||
        c.constrained_delegation   ||
        c.rbcd_enabled;

    // Structured delegation targets
    c.allowed_to_delegate_to_structured.clear();
    for (const auto& raw : c.allowed_to_delegate_to)
        c.allowed_to_delegate_to_structured.push_back(parse_delegation_target(raw));

    // RBCD principal name resolution: SID → sAMAccountName / CN / well-known
    c.rbcd_principal_names.clear();
    for (const auto& sid : c.rbcd_principals) {
        std::string usid = upper(sid);

        // Try SAM via sid_to_dn_ + dn_to_sam_
        auto dit = sid_to_dn_.find(usid);
        if (dit != sid_to_dn_.end()) {
            std::string udn = upper(dit->second);
            auto sit = dn_to_sam_.find(udn);
            if (sit != dn_to_sam_.end() && !sit->second.empty()) {
                c.rbcd_principal_names.push_back(sit->second);
                continue;
            }
            // Fall back to CN extracted from DN
            c.rbcd_principal_names.push_back(cn_from_dn(dit->second));
            continue;
        }

        // Try well-known SID table
        const std::string& wk = well_known_sid_name(usid);
        if (!wk.empty()) { c.rbcd_principal_names.push_back(wk); continue; }

        // Try display name cache
        auto disp = sid_to_display_.find(usid);
        if (disp != sid_to_display_.end() && !disp->second.empty()) {
            c.rbcd_principal_names.push_back(disp->second);
            continue;
        }

        // Last resort: keep raw SID
        c.rbcd_principal_names.push_back(sid);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 27 — analyze_computer_risk
//
//  Sets attack-path flags and computes a composite risk score (0–100).
//  Each factor contributes a fixed weight; total is clamped to 100.
//  Disabled computers always receive a score of 0.
//
//  Weights:
//    unconstrained_delegation         +35
//    protocol_transition_delegation   +25
//    constrained_delegation           +15
//    rbcd_enabled                     +20
//    stale (enabled)                  +20
//    no_laps && !dc                   +10
//    kerberoastable                   +15
//    asrep                            +20
//    has_shadow_credential            +25
//    isaclprotected                   +5
//    smb_signing_not_required && !dc  +10
// ═════════════════════════════════════════════════════════════════════════════
void OfflineProcessor::analyze_computer_risk(ProcessedComputer& c) const
{
    // Attack path flags
    c.kerberoastable = c.has_spn && !c.disabled;
    c.asrep          = !c.preauth_required;  // rare for computers; tracked anyway

    // Shadow credential — inferred from risk_controls until ComputerCollector
    // emits a dedicated boolean field
    c.has_shadow_credential = false;
    for (const auto& rc : c.risk_controls) {
        if (rc.find("Shadow")        != std::string::npos ||
            rc.find("KeyCredential") != std::string::npos)
        { c.has_shadow_credential = true; break; }
    }

    // Disabled machines carry no active risk
    if (c.disabled) {
        c.risk_score = 0;
        c.risk_factors.clear();
        return;
    }

    int score = 0;
    c.risk_factors.clear();

    if (c.unconstrained_delegation) {
        score += 35;
        c.risk_factors.push_back("Unconstrained Kerberos delegation");
    }
    if (c.protocol_transition_delegation) {
        score += 25;
        c.risk_factors.push_back("Protocol-transition constrained delegation");
    } else if (c.constrained_delegation) {
        score += 15;
        c.risk_factors.push_back("Constrained Kerberos delegation");
    }
    if (c.rbcd_enabled) {
        score += 20;
        c.risk_factors.push_back("Resource-based constrained delegation (RBCD)");
    }
    if (c.is_stale) {
        score += 20;
        std::string reason = "Stale account (";
        if (c.stale_by_logon && c.stale_by_pwd) reason += "no recent logon or password change";
        else if (c.stale_by_logon)              reason += "no recent logon";
        else                                    reason += "no recent password change";
        reason += ")";
        c.risk_factors.push_back(reason);
    }
    if (!c.has_laps && !c.haslaps && !c.is_domain_controller) {
        score += 10;
        c.risk_factors.push_back("No LAPS — local admin password not managed");
    }
    if (c.kerberoastable) {
        score += 15;
        c.risk_factors.push_back("Kerberoastable (has SPN)");
    }
    if (c.asrep) {
        score += 20;
        c.risk_factors.push_back("AS-REP roastable (no pre-authentication required)");
    }
    if (c.has_shadow_credential) {
        score += 25;
        c.risk_factors.push_back("Shadow credentials present (msDS-KeyCredentialLink)");
    }
    if (c.isaclprotected) {
        // ACL-protected blocks AdminSDHolder propagation — minor additional exposure
        // when combined with dangerous delegation settings
        score += 5;
        c.risk_factors.push_back("ACL protected (AdminSDHolder inheritance blocked)");
    }
    if (c.net_probed && !c.smb_signing_required && !c.is_domain_controller) {
        score += 10;
        c.risk_factors.push_back("SMB signing not required — relay attack surface");
    }

    // Clamp to 100
    c.risk_score = (score > 100) ? 100 : score;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 28 — computer_to_json
//
//  Serializes a ProcessedComputer to a single NDJSON line (no trailing \n).
//  Field order: identity → state → OS → type → stale → spn → delegation →
//               rbcd → laps → acl → sid_history → group → attack →
//               risk → network → timestamps → domain.
// ═════════════════════════════════════════════════════════════════════════════
std::string OfflineProcessor::computer_to_json(const ProcessedComputer& c) const
{
    std::ostringstream o;
    o << "{";

    // ── Identity ──────────────────────────────────────────────────────────────
    o << "\"computer_name\":"   << je(c.computer_name)  << ",";
    o << "\"dns_name\":"        << je(c.dns_name)        << ",";
    o << "\"dn\":"              << je(c.dn)              << ",";
    o << "\"display_name\":"    << je(c.display_name)    << ",";
    o << "\"sid\":"             << je(c.sid)             << ",";
    o << "\"domainsid\":"       << je(c.domain_sid)      << ",";
    o << "\"description\":"     << je(c.description)     << ",";
    o << "\"location\":"        << je(c.location)        << ",";

    // ── State ─────────────────────────────────────────────────────────────────
    o << "\"disabled\":"        << jb(c.disabled) << ",";

    // ── OS ────────────────────────────────────────────────────────────────────
    o << "\"os\":"              << je(c.os)               << ",";
    o << "\"os_version\":"      << je(c.os_version)       << ",";
    o << "\"os_service_pack\":" << je(c.os_service_pack)  << ",";
    o << "\"os_bucket\":"       << je(c.os_bucket)        << ",";

    // ── Type ──────────────────────────────────────────────────────────────────
    o << "\"is_workstation\":"       << jb(c.is_workstation)       << ",";
    o << "\"is_server\":"            << jb(c.is_server)            << ",";
    o << "\"is_domain_controller\":" << jb(c.is_domain_controller) << ",";
    o << "\"potential_privileged\":" << jb(c.potential_privileged) << ",";

    // ── Stale ─────────────────────────────────────────────────────────────────
    o << "\"is_stale\":"        << jb(c.is_stale)       << ",";
    o << "\"stale_by_pwd\":"    << jb(c.stale_by_pwd)   << ",";
    o << "\"stale_by_logon\":"  << jb(c.stale_by_logon) << ",";

    // ── SPN ───────────────────────────────────────────────────────────────────
    o << "\"spn\":"     << ja(c.spn)     << ",";
    o << "\"has_spn\":" << jb(c.has_spn) << ",";

    // ── Delegation ────────────────────────────────────────────────────────────
    o << "\"trusted_for_delegation\":"          << jb(c.trusted_for_delegation)         << ",";
    o << "\"trusted_to_auth_for_delegation\":"  << jb(c.trusted_to_auth_for_delegation) << ",";
    o << "\"unconstrained_delegation\":"        << jb(c.unconstrained_delegation)       << ",";
    o << "\"constrained_delegation\":"          << jb(c.constrained_delegation)         << ",";
    o << "\"protocol_transition_delegation\":"  << jb(c.protocol_transition_delegation) << ",";
    o << "\"delegation_effective\":"            << jb(c.delegation_effective)           << ",";
    o << "\"allowed_to_delegate_to\":"          << ja(c.allowed_to_delegate_to)         << ",";
    o << "\"allowed_to_delegate_to_structured\":"
      << json_delegation_arr(c.allowed_to_delegate_to_structured) << ",";

    // ── RBCD ──────────────────────────────────────────────────────────────────
    o << "\"rbcd_enabled\":"          << jb(c.rbcd_enabled)         << ",";
    o << "\"rbcd_sddl\":"             << je(c.rbcd_sddl)            << ",";
    o << "\"rbcd_principals\":"       << ja(c.rbcd_principals)      << ",";
    o << "\"rbcd_principal_names\":"  << ja(c.rbcd_principal_names) << ",";

    // ── LAPS ──────────────────────────────────────────────────────────────────
    o << "\"has_laps\":"        << jb(c.has_laps)        << ",";
    o << "\"haslaps\":"         << jb(c.haslaps)         << ",";
    o << "\"laps_expiration\":" << je(c.laps_expiration) << ",";
    // Full laps_attributes object
    o << "\"laps_attributes\":{";
    {
        bool first = true;
        for (const auto& kv : c.laps_attributes) {
            if (!first) o << ",";
            first = false;
            o << je(kv.first) << ":" << ja(kv.second);
        }
    }
    o << "},";

    // ── ACL ───────────────────────────────────────────────────────────────────
    o << "\"isaclprotected\":" << jb(c.isaclprotected) << ",";

    // ── SID History ───────────────────────────────────────────────────────────
    o << "\"sid_history\":" << ja(c.sid_history) << ",";

    // ── Group / Token ─────────────────────────────────────────────────────────
    o << "\"primary_group_id\":"   << ji(c.primary_group_id)  << ",";
    o << "\"primary_group_sid\":"  << je(c.primary_group_sid) << ",";
    o << "\"token_group_sids\":"   << ja(c.token_group_sids)  << ",";

    // ── Attack paths ──────────────────────────────────────────────────────────
    o << "\"kerberoastable\":"        << jb(c.kerberoastable)        << ",";
    o << "\"asrep\":"                 << jb(c.asrep)                 << ",";
    o << "\"has_shadow_credential\":" << jb(c.has_shadow_credential) << ",";

    // ── Risk ──────────────────────────────────────────────────────────────────
    o << "\"risk_score\":"    << ji(c.risk_score)    << ",";
    o << "\"risk_factors\":"  << ja(c.risk_factors)  << ",";
    o << "\"risk_controls\":" << ja(c.risk_controls) << ",";

    // ── Network stubs ─────────────────────────────────────────────────────────
    // Fields that may be null (not yet probed) are emitted as JSON null
    o << "\"ipv4_addresses\":" << ja(c.ipv4_addresses) << ",";
    o << "\"ipv6_addresses\":" << ja(c.ipv6_addresses) << ",";

    if (!c.net_probed) {
        o << "\"smb_port_open\":null,";
        o << "\"smb_signing_required\":null,";
    } else {
        o << "\"smb_port_open\":"        << jb(c.smb_port_open)        << ",";
        o << "\"smb_signing_required\":"  << jb(c.smb_signing_required) << ",";
    }
    o << "\"smb_version\":" << je(c.smb_version) << ",";

    if (!c.net_probed)
        o << "\"is_ip_only\":null,";
    else
        o << "\"is_ip_only\":" << jb(c.is_ip_only) << ",";

    // ── Timestamps ────────────────────────────────────────────────────────────
    o << "\"when_created\":" << jnl(c.when_created) << ",";
    o << "\"when_changed\":" << jnl(c.when_changed) << ",";
    o << "\"last_logon\":"   << jnl(c.last_logon)   << ",";
    o << "\"pwd_last_set\":" << jnl(c.pwd_last_set) << ",";

    // ── Domain ────────────────────────────────────────────────────────────────
    o << "\"domain_name\":" << je(c.domain_name);

    o << "}";
    return o.str();
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 29 — load_and_process_computers (private)
// ═════════════════════════════════════════════════════════════════════════════
bool OfflineProcessor::load_and_process_computers(const std::string& raw_path,
                                                   const std::string& out_path)
{
    log_info("[OfflineProcessor] Reading raw_computers.ndjson: " + raw_path);

    auto raw_lines = read_ndjson_lines(raw_path);
    if (raw_lines.empty()) {
        log_err("[OfflineProcessor] File not found or empty: " + raw_path);
        return false;
    }

    log_ok("[OfflineProcessor] " + std::to_string(raw_lines.size()) +
           " raw computers read. Starting analysis...");

    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        log_err("[OfflineProcessor] Could not open output file: " + out_path);
        return false;
    }

    int dc_count          = 0;
    int workstation_count = 0;
    int server_count      = 0;
    int delegation_count  = 0;
    int stale_count       = 0;
    int high_risk_count   = 0;  // risk_score >= 50
    std::vector<std::string> rows;
    rows.reserve(raw_lines.size());

    for (const auto& raw : raw_lines) {
        ProcessedComputer c = parse_raw_computer(raw);

        if (c.is_domain_controller) ++dc_count;
        if (c.is_workstation)       ++workstation_count;
        if (c.is_server)            ++server_count;
        if (c.delegation_effective) ++delegation_count;
        if (c.is_stale)             ++stale_count;
        if (c.risk_score >= 50)     ++high_risk_count;

        rows.push_back(computer_to_json(c));
    }
    write_objects(out, rows, out_path, "[OfflineProcessor]");
    out.close();

    log_ok("[OfflineProcessor] domain_computers written -> " + out_path);
    log_ok("[OfflineProcessor] "
        + std::to_string(raw_lines.size())  + " computers | "
        + std::to_string(dc_count)          + " DCs | "
        + std::to_string(server_count)      + " servers | "
        + std::to_string(workstation_count) + " workstations");
    log_ok("[OfflineProcessor] "
        + std::to_string(delegation_count) + " delegation | "
        + std::to_string(stale_count)      + " stale | "
        + std::to_string(high_risk_count)  + " high-risk (score>=50)");

    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
//  SECTION 30 — Public entry point: process_computers
// ═════════════════════════════════════════════════════════════════════════════

bool OfflineProcessor::process_computers(const OfflineProcessorOptions& opts)
{
    fs::create_directories(opts.output_dir);

    // Group lookup is needed to build token_group_sids for each computer.
    // User lookup provides additional SID → name resolution for RBCD principals.
    load_raw_users_lookup (opts.raw_dir + "/raw_users.ndjson");
    load_raw_groups_lookup(opts.raw_dir + "/raw_groups.ndjson");

    if (!opts.domain_name.empty()) domain_name_ = opts.domain_name;
    if (domain_name_.empty()) domain_name_ = base_dn_to_domain(base_dn_);

    const std::string& ext6 = opts.output_ext.empty() ? "ndjson" : opts.output_ext;
    return load_and_process_computers(
        opts.raw_dir    + "/raw_computers.ndjson",
        opts.output_dir + "/domain_computers." + ext6);
}