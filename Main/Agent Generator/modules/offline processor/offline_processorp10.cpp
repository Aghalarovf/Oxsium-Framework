// ─── offline_processorp_cert.cpp ─────────────────────────────────────────────
//  SECTION CERT — AD CS Offline Processor
//
//  Reads:
//    raw_cache/raw_cert_templates.ndjson  (from CertificateCollector)
//    raw_cache/raw_pki_objects.ndjson     (from CertificateCollector)
//    raw_cache/raw_ca_rpc.ndjson          (from future RPC stage, optional)
//
//  Writes:
//    Domain Objects/domain_cert_templates.ndjson  — one template per line
//    Domain Objects/domain_pki_objects.ndjson     — one PKI object per line
//
//  ESC flags computed here (no ESC modules needed — all flags in one pass):
//    ESC1  : enrollee_supplies_subject AND dangerous_eku AND no_approval AND ra_sig==0
//    ESC2  : eku_empty/any_purpose AND no_approval AND ra_sig==0
//    ESC3  : allow_enroll_on_behalf_of AND ra_sig==0 (enrollment agent template)
//    ESC4  : dangerous_write_acl (non-admin trustee with GenericAll/WriteDACL/WriteOwner)
//    ESC9  : no_security_extension AND ct_flag_enrollee_supplies_subject
//    ESC15 : schema_version==1 AND app_policy_client_auth present without EKU
//
//  ESC5/ESC6/ESC7/ESC8/ESC11 require PKI object / RPC data:
//    ESC5  : non-admin trustee with write rights on PKI objects
//    ESC6  : EditFlags EDITF_ATTRIBUTESUBJECTALTNAME2 (RPC only)
//    ESC7  : CA_ACCESS_ADMIN or CA_ACCESS_OFFICER on low-priv SID (RPC only)
//    ESC8  : HTTP enrollment endpoint reachable without HTTPS (HTTP probe)
//    ESC11 : IF_ENFORCEENCRYPTICERTREQUEST absent (RPC only)
//
//  ESC6/7/8/11 results are forwarded as-is from raw_ca_rpc.ndjson when present.
// ─────────────────────────────────────────────────────────────────────────────
#include "offline_processor.h"
#include <fstream>
#include <sstream>
#include <algorithm>

// ─────────────────────────────────────────────────────────────────────────────
//  EKU OIDs — mirrors EKU_MAP from template_enumeration.py
// ─────────────────────────────────────────────────────────────────────────────
namespace EKU {
    static constexpr const char* CLIENT_AUTH    = "1.3.6.1.5.5.7.3.2";
    static constexpr const char* SMART_CARD     = "1.3.6.1.4.1.311.20.2.2";
    static constexpr const char* PKINIT         = "1.3.6.1.5.2.3.5";
    static constexpr const char* ANY_PURPOSE    = "2.5.29.37.0";
    static constexpr const char* CERT_REQ_AGENT = "1.3.6.1.4.1.311.20.2.1";
}

// ─────────────────────────────────────────────────────────────────────────────
//  msPKI-Enrollment-Flag bits
// ─────────────────────────────────────────────────────────────────────────────
static constexpr int EF_PEND_ALL_REQUESTS       = 0x00000002;  // manager approval
static constexpr int EF_ALLOW_ENROLL_ON_BEHALF  = 0x00000800;  // ESC3
static constexpr int EF_NO_SECURITY_EXTENSION   = 0x00080000;  // ESC9

// ─────────────────────────────────────────────────────────────────────────────
//  msPKI-Certificate-Name-Flag bits
// ─────────────────────────────────────────────────────────────────────────────
static constexpr int CNF_ENROLLEE_SUPPLIES_SUBJECT     = 0x00000001;  // ESC1/ESC9
static constexpr int CNF_ENROLLEE_SUPPLIES_SUBJECT_ALT = 0x00010000;

// ─────────────────────────────────────────────────────────────────────────────
//  Well-known privileged SID suffixes for ESC4/ESC5 ACE filtering
// ─────────────────────────────────────────────────────────────────────────────
static bool is_privileged_sid(const std::string& sid) {
    // Builtin Administrators, SYSTEM
    if (sid == "S-1-5-32-544" || sid == "S-1-5-18") return true;
    // Domain Admins, Enterprise Admins, Domain Controllers, Schema Admins
    for (const char* sfx : {"-512", "-519", "-516", "-518"}) {
        if (sid.size() > strlen(sfx) &&
            sid.compare(sid.size() - strlen(sfx), strlen(sfx), sfx) == 0)
            return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  ProcessedCertTemplate — in-memory enriched template
// ─────────────────────────────────────────────────────────────────────────────
struct CertAce {
    std::string sid;
    unsigned int mask = 0;
    bool is_allow     = false;
    std::string object_type_guid;
};

struct EscFlags {
    bool esc1  = false;   // template-level: enrollee supplies subject + client auth EKU
    bool esc2  = false;   // template-level: any-purpose / empty EKU
    bool esc3  = false;   // template-level: enrollment agent template
    bool esc4  = false;   // template-level: dangerous write ACE by non-admin
    bool esc9  = false;   // template-level: no_security_extension
    bool esc15 = false;   // template-level: schema v1 + app policy client auth
};

struct ProcessedCertTemplate {
    // Identity
    std::string dn;
    std::string cn;
    std::string display_name;
    std::string object_guid;
    std::string when_created;
    std::string when_changed;
    std::string generated_at;

    // Raw flags
    int flags_raw     = 0;
    int revision      = 0;
    int schema_version = 0;

    // msPKI integers
    int ra_signature          = 0;
    int enrollment_flag       = 0;
    int private_key_flag      = 0;
    int certificate_name_flag = 0;
    int minimal_key_size      = 0;
    std::string cert_template_oid;

    // Period
    std::string expiration_period;
    std::string overlap_period;

    // EKU
    std::vector<std::string> extended_key_usage;
    std::vector<std::string> application_policies;
    std::vector<std::string> ra_application_policies;
    std::vector<std::string> supersede_templates;
    std::vector<std::string> ra_policies;

    // ACEs
    std::vector<CertAce> aces;
    std::string sd_hex; // raw hex (forwarded)

    // ── Computed booleans ─────────────────────────────────────────────────────
    bool enrollee_supplies_subject     = false;
    bool enrollee_supplies_subject_alt = false;
    bool no_security_extension         = false;
    bool manager_approval_required     = false;
    bool allow_enroll_on_behalf        = false;
    bool eku_is_empty                  = false;
    bool eku_has_client_auth           = false;
    bool eku_has_any_purpose           = false;
    bool eku_has_smart_card            = false;
    bool eku_has_pkinit                = false;
    bool eku_has_cert_req_agent        = false;
    bool app_policy_client_auth        = false;
    bool app_policy_any_purpose        = false;

    // Who can enroll (non-admin SIDs with enroll right)
    std::vector<std::string> enroll_principals;
    // Non-admin SIDs with dangerous write rights
    std::vector<std::string> write_principals;

    // ESC summary
    EscFlags esc;

    // Risk label for display
    std::string risk_label; // "CRITICAL" | "HIGH" | "MEDIUM" | "INFO" | ""
};

// ─────────────────────────────────────────────────────────────────────────────
//  Forward declarations
// ─────────────────────────────────────────────────────────────────────────────
static ProcessedCertTemplate parse_cert_template(const std::string& line);
static void                  analyze_cert_template(ProcessedCertTemplate& t);
static std::string           cert_template_to_json(const ProcessedCertTemplate& t);
static std::vector<CertAce>  parse_cert_aces(const std::string& sd_hex);

// ─────────────────────────────────────────────────────────────────────────────
//  process_certificates  — public entry point
//  Called from OfflineProcessor::process() alongside other process_ methods.
// ─────────────────────────────────────────────────────────────────────────────
bool OfflineProcessor::process_certificates(const OfflineProcessorOptions& opts) {
    fs::create_directories(opts.output_dir);
    const std::string raw_templates  = opts.raw_dir + "/raw_cert_templates.ndjson";
    const std::string raw_pki        = opts.raw_dir + "/raw_pki_objects.ndjson";
    const std::string out_templates  = opts.output_dir + "/domain_cert_templates." + opts.output_ext;
    const std::string out_pki        = opts.output_dir + "/domain_pki_objects."    + opts.output_ext;

    return load_and_process_cert_templates(raw_templates, out_templates)
        && load_and_process_pki_objects(raw_pki, out_pki);
}

// ─────────────────────────────────────────────────────────────────────────────
//  load_and_process_cert_templates
// ─────────────────────────────────────────────────────────────────────────────
bool OfflineProcessor::load_and_process_cert_templates(
    const std::string& raw_path,
    const std::string& out_path) const
{
    auto lines = read_ndjson_lines(raw_path);
    if (lines.empty()) {
        log_warn("[CertProc] No cert templates found in: " + raw_path);
        return false;
    }

    std::vector<std::string> rows;
    rows.reserve(lines.size());

    for (const auto& line : lines) {
        if (line.empty() || line[0] != '{') continue;
        auto t = parse_cert_template(line);
        analyze_cert_template(t);
        rows.push_back(cert_template_to_json(t));
    }

    std::ofstream f(out_path, std::ios::out | std::ios::trunc);
    if (!f) {
        log_err("[CertProc] Cannot open output: " + out_path);
        return false;
    }
    write_objects(f, rows, out_path, "[CertProc]");

    log_ok("[CertProc] domain_cert_templates -> " + out_path);
    log_ok("[CertProc] " + std::to_string(rows.size()) + " template(s) written");
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  load_and_process_pki_objects
//  PKI objects are forwarded with ESC5 ACE analysis added.
// ─────────────────────────────────────────────────────────────────────────────
bool OfflineProcessor::load_and_process_pki_objects(
    const std::string& raw_path,
    const std::string& out_path) const
{
    auto lines = read_ndjson_lines(raw_path);
    if (lines.empty()) {
        log_warn("[CertProc] No PKI objects found in: " + raw_path);
        return false;
    }

    std::vector<std::string> rows;
    rows.reserve(lines.size());

    for (const auto& line : lines) {
        if (line.empty() || line[0] != '{') continue;

        // Enrich: parse ACEs from nt_security_descriptor_hex,
        // flag non-admin trustees with write rights (ESC5 indicator).
        const std::string sd_hex = jp_str(line, "nt_security_descriptor_hex");
        auto aces = parse_cert_aces(sd_hex);

        // Collect non-admin write principals
        std::vector<std::string> write_principals;
        std::vector<std::string> enroll_principals;
        static constexpr unsigned int WRITE_RIGHTS =
            0x000F01FF |  // GenericAll
            0x40000000 |  // GenericWrite
            0x00040000 |  // WriteDACL
            0x00080000;   // WriteOwner
        static constexpr unsigned int ENROLL_RIGHT = 0x00000100; // CR_PROP extended right

        for (const auto& ace : aces) {
            if (!ace.is_allow) continue;
            if (is_privileged_sid(ace.sid)) continue;
            if (ace.mask & WRITE_RIGHTS)  write_principals.push_back(ace.sid);
            if (ace.mask & ENROLL_RIGHT)  enroll_principals.push_back(ace.sid);
        }

        bool esc5_indicator = !write_principals.empty();

        // Build augmented JSON: append ESC5 fields to existing object
        // Strip trailing "}" and append new fields
        std::string obj = line;
        while (!obj.empty() && obj.back() == '}') obj.pop_back();
        if (!obj.empty() && obj.back() == ',') { /* keep */ }
        else obj += ",";

        obj += "\"esc5_indicator\":" + std::string(esc5_indicator ? "true" : "false") + ",";

        // write_principals array
        obj += "\"esc5_write_principals\":[";
        for (size_t i = 0; i < write_principals.size(); ++i) {
            if (i) obj += ",";
            obj += "\"" + write_principals[i] + "\"";
        }
        obj += "],";

        // enroll_principals array
        obj += "\"enroll_principals\":[";
        for (size_t i = 0; i < enroll_principals.size(); ++i) {
            if (i) obj += ",";
            obj += "\"" + enroll_principals[i] + "\"";
        }
        obj += "]}";

        rows.push_back(obj);
    }

    std::ofstream f(out_path, std::ios::out | std::ios::trunc);
    if (!f) {
        log_err("[CertProc] Cannot open output: " + out_path);
        return false;
    }
    write_objects(f, rows, out_path, "[CertProc]");

    log_ok("[CertProc] domain_pki_objects -> " + out_path);
    log_ok("[CertProc] " + std::to_string(rows.size()) + " PKI object(s) written");
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  parse_cert_template  — NDJSON line → ProcessedCertTemplate
// ─────────────────────────────────────────────────────────────────────────────
static ProcessedCertTemplate parse_cert_template(const std::string& line) {
    ProcessedCertTemplate t;

    t.dn           = OfflineProcessor::jp_str(line, "dn");
    t.cn           = OfflineProcessor::jp_str(line, "cn");
    t.display_name = OfflineProcessor::jp_str(line, "display_name");
    t.object_guid  = OfflineProcessor::jp_str(line, "object_guid");
    t.when_created = OfflineProcessor::jp_str(line, "when_created");
    t.when_changed = OfflineProcessor::jp_str(line, "when_changed");
    t.generated_at = OfflineProcessor::jp_str(line, "generated_at");
    t.cert_template_oid = OfflineProcessor::jp_str(line, "mspki_cert_template_oid");
    t.expiration_period = OfflineProcessor::jp_str(line, "pki_expiration_period");
    t.overlap_period    = OfflineProcessor::jp_str(line, "pki_overlap_period");
    t.sd_hex            = OfflineProcessor::jp_str(line, "nt_security_descriptor_hex");

    t.flags_raw           = OfflineProcessor::jp_int(line, "flags_raw");
    t.revision            = OfflineProcessor::jp_int(line, "revision");
    t.schema_version      = OfflineProcessor::jp_int(line, "mspki_template_schema_version");
    t.ra_signature        = OfflineProcessor::jp_int(line, "mspki_ra_signature");
    t.enrollment_flag     = OfflineProcessor::jp_int(line, "mspki_enrollment_flag");
    t.private_key_flag    = OfflineProcessor::jp_int(line, "mspki_private_key_flag");
    t.certificate_name_flag = OfflineProcessor::jp_int(line, "mspki_certificate_name_flag");
    t.minimal_key_size    = OfflineProcessor::jp_int(line, "mspki_minimal_key_size");

    t.extended_key_usage     = OfflineProcessor::jp_arr(line, "pki_extended_key_usage");
    t.application_policies   = OfflineProcessor::jp_arr(line, "mspki_certificate_application_policy");
    t.ra_application_policies = OfflineProcessor::jp_arr(line, "mspki_ra_application_policies");
    t.supersede_templates    = OfflineProcessor::jp_arr(line, "mspki_supersede_templates");
    t.ra_policies            = OfflineProcessor::jp_arr(line, "mspki_ra_policies");

    // Parse ACEs from SD hex
    if (!t.sd_hex.empty())
        t.aces = parse_cert_aces(t.sd_hex);

    return t;
}

// ─────────────────────────────────────────────────────────────────────────────
//  parse_cert_aces
//  Minimal SECURITY_DESCRIPTOR / DACL parser — same logic as ComputerCollector
//  decode_rbcd_sids but returns CertAce list.
//  Layout: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/
// ─────────────────────────────────────────────────────────────────────────────
static std::string decode_sid_bytes(const unsigned char* buf, size_t len, size_t off) {
    if (off + 8 > len) return "";
    unsigned int sub_count = buf[off + 1];
    if (off + 8 + sub_count * 4 > len) return "";
    // Authority (6 bytes, big-endian)
    unsigned long long auth = 0;
    for (int i = 0; i < 6; ++i) auth = (auth << 8) | buf[off + 2 + i];

    std::string sid = "S-1-" + std::to_string(auth);
    for (unsigned int i = 0; i < sub_count; ++i) {
        unsigned int sub = buf[off + 8 + i * 4]
                         | (buf[off + 9 + i * 4] << 8)
                         | (buf[off + 10 + i * 4] << 16)
                         | ((unsigned int)buf[off + 11 + i * 4] << 24);
        sid += "-" + std::to_string(sub);
    }
    return sid;
}

static std::string format_guid_bytes(const unsigned char* b) {
    char buf[39];
    std::snprintf(buf, sizeof(buf),
        "{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        b[3],b[2],b[1],b[0], b[5],b[4], b[7],b[6],
        b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
    return buf;
}

static std::vector<CertAce> parse_cert_aces(const std::string& sd_hex) {
    std::vector<CertAce> result;
    if (sd_hex.size() < 40) return result; // min SD header

    // Convert hex → bytes
    std::string raw;
    raw.reserve(sd_hex.size() / 2);
    for (size_t i = 0; i + 1 < sd_hex.size(); i += 2) {
        char hi = sd_hex[i], lo = sd_hex[i+1];
        auto hv = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        raw += (char)((hv(hi) << 4) | hv(lo));
    }

    const auto* b = reinterpret_cast<const unsigned char*>(raw.data());
    const size_t len = raw.size();

    // SECURITY_DESCRIPTOR: Revision(1), Sbz1(1), Control(2), OffsetOwner(4),
    //                       OffsetGroup(4), OffsetSacl(4), OffsetDacl(4)
    if (len < 20) return result;
    size_t dacl_off = (size_t)b[16] | ((size_t)b[17] << 8)
                    | ((size_t)b[18] << 16) | ((size_t)b[19] << 24);
    if (dacl_off == 0 || dacl_off + 8 > len) return result;

    // ACL header: AclRevision(1), Sbz1(1), AclSize(2), AceCount(2), Sbz2(2)
    size_t ace_count = b[dacl_off + 4] | (b[dacl_off + 5] << 8);
    size_t pos = dacl_off + 8;

    for (size_t i = 0; i < ace_count && pos + 4 <= len; ++i) {
        unsigned char ace_type = b[pos];
        // unsigned char ace_flags = b[pos + 1];
        size_t ace_size = b[pos + 2] | (b[pos + 3] << 8);
        if (ace_size < 4 || pos + ace_size > len) break;

        // ACCESS_ALLOWED_ACE = 0x00, ACCESS_DENIED_ACE = 0x01
        // ACCESS_ALLOWED_OBJECT_ACE = 0x05, ACCESS_DENIED_OBJECT_ACE = 0x06
        bool is_allow = (ace_type == 0x00 || ace_type == 0x05);
        bool is_object = (ace_type == 0x05 || ace_type == 0x06);

        if (pos + 8 > len) { pos += ace_size; continue; }
        unsigned int mask = b[pos+4] | (b[pos+5]<<8) | (b[pos+6]<<16) | ((unsigned int)b[pos+7]<<24);

        size_t sid_off = pos + 8;
        std::string object_type_guid;

        if (is_object && pos + 12 <= len) {
            // ObjectType flags (4 bytes) after mask
            unsigned int obj_flags = b[pos+8] | (b[pos+9]<<8) | (b[pos+10]<<16) | ((unsigned int)b[pos+11]<<24);
            sid_off = pos + 12;
            if ((obj_flags & 0x01) && sid_off + 16 <= len) {
                // ObjectType GUID present
                object_type_guid = format_guid_bytes(b + sid_off);
                sid_off += 16;
            }
            if ((obj_flags & 0x02) && sid_off + 16 <= len) {
                // InheritedObjectType GUID present — skip
                sid_off += 16;
            }
        }

        std::string sid = decode_sid_bytes(b, len, sid_off);
        if (!sid.empty()) {
            CertAce ace;
            ace.sid              = sid;
            ace.mask             = mask;
            ace.is_allow         = is_allow;
            ace.object_type_guid = object_type_guid;
            result.push_back(ace);
        }
        pos += ace_size;
    }
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  analyze_cert_template  — compute ESC flags
// ─────────────────────────────────────────────────────────────────────────────
static void analyze_cert_template(ProcessedCertTemplate& t) {

    // ── Decode enrollment flag bits ───────────────────────────────────────────
    t.manager_approval_required = (t.enrollment_flag & EF_PEND_ALL_REQUESTS)      != 0;
    t.allow_enroll_on_behalf    = (t.enrollment_flag & EF_ALLOW_ENROLL_ON_BEHALF) != 0;
    t.no_security_extension     = (t.enrollment_flag & EF_NO_SECURITY_EXTENSION)  != 0;

    // ── Decode certificate name flag bits ─────────────────────────────────────
    t.enrollee_supplies_subject     = (t.certificate_name_flag & CNF_ENROLLEE_SUPPLIES_SUBJECT)     != 0;
    t.enrollee_supplies_subject_alt = (t.certificate_name_flag & CNF_ENROLLEE_SUPPLIES_SUBJECT_ALT) != 0;

    // ── EKU analysis ──────────────────────────────────────────────────────────
    t.eku_is_empty = t.extended_key_usage.empty();
    for (const auto& oid : t.extended_key_usage) {
        if (oid == EKU::CLIENT_AUTH)    t.eku_has_client_auth    = true;
        if (oid == EKU::ANY_PURPOSE)    t.eku_has_any_purpose    = true;
        if (oid == EKU::SMART_CARD)     t.eku_has_smart_card     = true;
        if (oid == EKU::PKINIT)         t.eku_has_pkinit         = true;
        if (oid == EKU::CERT_REQ_AGENT) t.eku_has_cert_req_agent = true;
    }
    for (const auto& oid : t.application_policies) {
        if (oid == EKU::CLIENT_AUTH) t.app_policy_client_auth = true;
        if (oid == EKU::ANY_PURPOSE) t.app_policy_any_purpose = true;
    }

    // ── ACE analysis ──────────────────────────────────────────────────────────
    static constexpr unsigned int WRITE_MASK =
        0x000F01FF |  // GenericAll
        0x40000000 |  // GenericWrite
        0x00040000 |  // WriteDACL
        0x00080000;   // WriteOwner
    // Certificate enrollment extended right GUID
    // {0e10c968-78fb-11d2-90d4-00c04f79dc55}
    static const std::string ENROLL_GUID = "{0E10C968-78FB-11D2-90D4-00C04F79DC55}";
    // Certificate AutoEnrollment extended right GUID
    // {a05b8cc2-17bc-4802-a710-e7c15ab866a2}
    static const std::string AUTOENROLL_GUID = "{A05B8CC2-17BC-4802-A710-E7C15AB866A2}";

    for (const auto& ace : t.aces) {
        if (!ace.is_allow) continue;
        if (is_privileged_sid(ace.sid)) continue;

        // Write rights → ESC4 candidate
        if (ace.mask & WRITE_MASK)
            t.write_principals.push_back(ace.sid);

        // Enroll right
        std::string guid_upper = ace.object_type_guid;
        for (char& c : guid_upper) c = (char)toupper((unsigned char)c);
        if (ace.object_type_guid.empty() ||
            guid_upper == ENROLL_GUID || guid_upper == AUTOENROLL_GUID ||
            (ace.mask & 0x00000100)) // ADS_RIGHT_DS_CONTROL_ACCESS
        {
            t.enroll_principals.push_back(ace.sid);
        }
    }

    // ── ESC1 ──────────────────────────────────────────────────────────────────
    // Template allows enrollee to supply subject, has client-auth-capable EKU,
    // no manager approval, and no RA signature requirement.
    bool dangerous_eku = t.eku_is_empty || t.eku_has_any_purpose
                      || t.eku_has_client_auth || t.eku_has_smart_card
                      || t.eku_has_pkinit;
    t.esc.esc1 = t.enrollee_supplies_subject
              && dangerous_eku
              && !t.manager_approval_required
              && t.ra_signature == 0
              && !t.enroll_principals.empty();

    // ── ESC2 ──────────────────────────────────────────────────────────────────
    // Any-purpose or empty EKU, no approval, no RA signature.
    t.esc.esc2 = (t.eku_is_empty || t.eku_has_any_purpose)
              && !t.manager_approval_required
              && t.ra_signature == 0
              && !t.enroll_principals.empty();

    // ── ESC3 ──────────────────────────────────────────────────────────────────
    // Template is an enrollment agent template (allow_enroll_on_behalf),
    // no RA signature required — anyone with Enroll right can act as agent.
    t.esc.esc3 = t.eku_has_cert_req_agent
              && !t.manager_approval_required
              && t.ra_signature == 0
              && !t.enroll_principals.empty();

    // ── ESC4 ──────────────────────────────────────────────────────────────────
    // Non-admin principal has write rights over the template object.
    t.esc.esc4 = !t.write_principals.empty();

    // ── ESC9 ──────────────────────────────────────────────────────────────────
    // Template does not embed szOID_NTDS_CA_SECURITY_EXT (no_security_extension)
    // AND enrollee can supply the subject (SAN).
    t.esc.esc9 = t.no_security_extension && t.enrollee_supplies_subject;

    // ── ESC15 ─────────────────────────────────────────────────────────────────
    // Schema version 1, application policy provides client auth but
    // pKIExtendedKeyUsage is absent or differs — CA applies app policy.
    t.esc.esc15 = t.schema_version == 1
               && t.app_policy_client_auth
               && !t.manager_approval_required
               && t.ra_signature == 0
               && !t.enroll_principals.empty();

    // ── Risk label ────────────────────────────────────────────────────────────
    if      (t.esc.esc1 || t.esc.esc2)         t.risk_label = "CRITICAL";
    else if (t.esc.esc3 || t.esc.esc4)         t.risk_label = "HIGH";
    else if (t.esc.esc9 || t.esc.esc15)        t.risk_label = "MEDIUM";
    else if (!t.enroll_principals.empty())      t.risk_label = "INFO";
    else                                        t.risk_label = "";
}

// ─────────────────────────────────────────────────────────────────────────────
//  cert_template_to_json
// ─────────────────────────────────────────────────────────────────────────────
static std::string ja_sids(const std::vector<std::string>& v) {
    std::string out = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += ",";
        out += "\"" + v[i] + "\"";
    }
    return out + "]";
}

static std::string je_s(const std::string& s) {
    return OfflineProcessor::je(s);
}

static std::string cert_template_to_json(const ProcessedCertTemplate& t) {
    auto jb = [](bool v) { return v ? "true" : "false"; };
    auto ji = [](int v)  { return std::to_string(v); };

    std::ostringstream row;
    row << "{"
        // Identity
        << "\"dn\":"                 << je_s(t.dn)              << ","
        << "\"cn\":"                 << je_s(t.cn)              << ","
        << "\"display_name\":"       << je_s(t.display_name)    << ","
        << "\"object_guid\":"        << je_s(t.object_guid)     << ","
        << "\"when_created\":"       << je_s(t.when_created)    << ","
        << "\"when_changed\":"       << je_s(t.when_changed)    << ","
        // Raw integers
        << "\"flags_raw\":"          << ji(t.flags_raw)          << ","
        << "\"revision\":"           << ji(t.revision)           << ","
        << "\"schema_version\":"     << ji(t.schema_version)     << ","
        << "\"ra_signature\":"       << ji(t.ra_signature)       << ","
        << "\"enrollment_flag\":"    << ji(t.enrollment_flag)    << ","
        << "\"private_key_flag\":"   << ji(t.private_key_flag)   << ","
        << "\"certificate_name_flag\":" << ji(t.certificate_name_flag) << ","
        << "\"minimal_key_size\":"   << ji(t.minimal_key_size)   << ","
        << "\"cert_template_oid\":"  << je_s(t.cert_template_oid)<< ","
        // Periods
        << "\"expiration_period\":"  << je_s(t.expiration_period)<< ","
        << "\"overlap_period\":"     << je_s(t.overlap_period)   << ","
        // EKU arrays (raw OIDs)
        << "\"extended_key_usage\":"        << ja_sids(t.extended_key_usage)       << ","
        << "\"application_policies\":"      << ja_sids(t.application_policies)     << ","
        << "\"ra_application_policies\":"   << ja_sids(t.ra_application_policies)  << ","
        << "\"supersede_templates\":"       << ja_sids(t.supersede_templates)       << ","
        << "\"ra_policies\":"               << ja_sids(t.ra_policies)               << ","
        // Computed booleans
        << "\"enrollee_supplies_subject\":"     << jb(t.enrollee_supplies_subject)     << ","
        << "\"enrollee_supplies_subject_alt\":" << jb(t.enrollee_supplies_subject_alt) << ","
        << "\"no_security_extension\":"         << jb(t.no_security_extension)         << ","
        << "\"manager_approval_required\":"     << jb(t.manager_approval_required)     << ","
        << "\"allow_enroll_on_behalf\":"        << jb(t.allow_enroll_on_behalf)        << ","
        << "\"eku_is_empty\":"                  << jb(t.eku_is_empty)                  << ","
        << "\"eku_has_client_auth\":"           << jb(t.eku_has_client_auth)           << ","
        << "\"eku_has_any_purpose\":"           << jb(t.eku_has_any_purpose)           << ","
        << "\"eku_has_smart_card\":"            << jb(t.eku_has_smart_card)            << ","
        << "\"eku_has_pkinit\":"                << jb(t.eku_has_pkinit)                << ","
        << "\"eku_has_cert_req_agent\":"        << jb(t.eku_has_cert_req_agent)        << ","
        << "\"app_policy_client_auth\":"        << jb(t.app_policy_client_auth)        << ","
        << "\"app_policy_any_purpose\":"        << jb(t.app_policy_any_purpose)        << ","
        // ACE principals
        << "\"enroll_principals\":"  << ja_sids(t.enroll_principals) << ","
        << "\"write_principals\":"   << ja_sids(t.write_principals)  << ","
        // ESC flags
        << "\"esc1\":" << jb(t.esc.esc1) << ","
        << "\"esc2\":" << jb(t.esc.esc2) << ","
        << "\"esc3\":" << jb(t.esc.esc3) << ","
        << "\"esc4\":" << jb(t.esc.esc4) << ","
        << "\"esc9\":" << jb(t.esc.esc9) << ","
        << "\"esc15\":" << jb(t.esc.esc15) << ","
        // Risk
        << "\"risk_label\":" << je_s(t.risk_label) << ","
        // Raw SD forwarded for downstream use
        << "\"nt_security_descriptor_hex\":" << je_s(t.sd_hex) << ","
        << "\"generated_at\":" << je_s(t.generated_at)
        << "}";
    return row.str();
}